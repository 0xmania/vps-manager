package api

import (
	"context"
	"errors"
	"net/http"
	"sync"

	"vpsmanager/services/cloudflareprovider"
	"vpsmanager/services/control-plane/internal/credentials"
	"vpsmanager/services/control-plane/internal/model"
	"vpsmanager/services/control-plane/internal/store"
)

type CloudflareProviderFactory interface {
	// New may use token only for the lifetime of the returned cleanup
	// function. Implementations must copy and wipe any retained token bytes.
	New(accountID string, token []byte) (cloudflareprovider.Provider, func(), error)
}

type defaultCloudflareProviderFactory struct{}

func NewCloudflareProviderFactory() CloudflareProviderFactory {
	return defaultCloudflareProviderFactory{}
}

func (defaultCloudflareProviderFactory) New(accountID string, token []byte) (cloudflareprovider.Provider, func(), error) {
	if !validProviderTokenBytes(token) {
		return nil, nil, errInvalidCloudflareToken
	}
	source := &ephemeralCloudflareTokenSource{token: append([]byte(nil), token...)}
	client, err := cloudflareprovider.New(cloudflareprovider.Config{
		AccountID:  accountID,
		TokenOwner: cloudflareprovider.TokenOwnerUser,
	}, source)
	if err != nil {
		source.destroy()
		return nil, nil, err
	}
	cleanup := func() {
		client.CloseIdleConnections()
		source.destroy()
	}
	return client, cleanup, nil
}

type ephemeralCloudflareTokenSource struct {
	mu    sync.Mutex
	token []byte
}

func (s *ephemeralCloudflareTokenSource) Token(ctx context.Context) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.token) == 0 {
		return nil, errInvalidCloudflareToken
	}
	return append([]byte(nil), s.token...), nil
}

func (s *ephemeralCloudflareTokenSource) destroy() {
	s.mu.Lock()
	defer s.mu.Unlock()
	wipe(s.token)
	s.token = nil
}

var errInvalidCloudflareToken = errors.New("Cloudflare API token is invalid")

type cloudflareExecutionFailure struct {
	code   string
	status int
}

func (e *cloudflareExecutionFailure) Error() string { return e.code }

func (s *Server) executeWorkerDeployment(w http.ResponseWriter, r *http.Request) {
	if !requireGlobalWorkerScope(w, r) {
		return
	}
	if !s.config.CloudflareExecutionEnabled || !s.config.SecretExecutionEnabled || s.cloudflareProviderFactory == nil {
		writeError(w, r, http.StatusServiceUnavailable, "execution_boundary_unavailable", "Cloudflare provider execution is unavailable")
		return
	}
	var input struct{}
	if err := decodeJSON(w, r, &input); err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	workerID, deploymentID := r.PathValue("workerID"), r.PathValue("deploymentID")
	deployment, err := s.repository.GetWorkerDeployment(workerID, deploymentID)
	if err != nil {
		writeStoreError(w, r, err)
		return
	}
	if deployment.State != "ready_for_provider" || deployment.ProviderExecutionAllowed {
		writeError(w, r, http.StatusConflict, "deployment_not_ready", "deployment is not ready for provider execution")
		return
	}
	worker, err := s.repository.GetWorker(workerID)
	if err != nil {
		writeStoreError(w, r, err)
		return
	}
	if worker.DesiredVersionID != deployment.VersionID {
		writeError(w, r, http.StatusConflict, "deployment_superseded", "deployment plan has been superseded by a newer desired version")
		return
	}
	version, err := s.repository.GetWorkerVersion(workerID, deployment.VersionID)
	if err != nil {
		writeStoreError(w, r, err)
		return
	}
	if deployment.Kind == "rollback" && version.Metadata.ProviderVersionID == "" {
		writeError(w, r, http.StatusConflict, "provider_version_required", "rollback target has not been uploaded to Cloudflare")
		return
	}
	token, err := s.repository.GetWorkerToken(workerID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, r, http.StatusConflict, "token_required", "an encrypted Cloudflare token is required")
			return
		}
		writeStoreError(w, r, err)
		return
	}

	var completed model.CloudflareDeployment
	err = s.credentials.Open(r.Context(), token.Envelope, s.workerTokenAAD(workerID, token.Metadata.ID), func(plaintext []byte) error {
		provider, cleanup, createErr := s.cloudflareProviderFactory.New(worker.AccountID, plaintext)
		if createErr != nil || provider == nil {
			return errInvalidCloudflareToken
		}
		if cleanup == nil {
			cleanup = func() {}
		}
		defer cleanup()
		var executeErr error
		completed, executeErr = s.runCloudflareDeployment(r.Context(), worker, version, deployment, provider)
		return executeErr
	})
	if err != nil {
		principal := principalFrom(r.Context())
		switch {
		case errors.Is(err, credentials.ErrUnwrapUnavailable):
			s.audit(r, principal, "cloudflare_deployment.execution_denied", "cloudflare_worker", workerID, "denied", map[string]any{"deploymentId": deploymentID, "reason": "sealing_only"})
			writeError(w, r, http.StatusServiceUnavailable, "execution_boundary_unavailable", "Cloudflare provider execution is unavailable")
		case errors.Is(err, errInvalidCloudflareToken):
			s.audit(r, principal, "cloudflare_deployment.execution_failed", "cloudflare_worker", workerID, "failure", map[string]any{"deploymentId": deploymentID, "errorCode": "provider_token_invalid"})
			writeError(w, r, http.StatusConflict, "provider_token_invalid", "stored Cloudflare token is invalid; replace it before retrying")
		default:
			var failure *cloudflareExecutionFailure
			if errors.As(err, &failure) {
				s.audit(r, principal, "cloudflare_deployment.execution_failed", "cloudflare_worker", workerID, "failure", map[string]any{"deploymentId": deploymentID, "kind": deployment.Kind, "errorCode": failure.code})
				writeError(w, r, failure.status, failure.code, "Cloudflare deployment execution failed")
				return
			}
			if errors.Is(err, store.ErrConflict) {
				writeError(w, r, http.StatusConflict, "deployment_not_ready", "deployment is not ready for provider execution")
				return
			}
			writeError(w, r, http.StatusInternalServerError, "persistence_failure", "deployment execution state could not be saved")
		}
		return
	}
	s.audit(r, principalFrom(r.Context()), "cloudflare_deployment.executed", "cloudflare_worker", workerID, "success", map[string]any{
		"deploymentId": deployment.ID, "kind": deployment.Kind,
		"providerVersionId": completed.ProviderVersionID, "providerDeploymentId": completed.ProviderDeploymentID,
		"providerState": completed.ProviderState,
	})
	writeJSON(w, http.StatusOK, completed)
}

func (s *Server) runCloudflareDeployment(ctx context.Context, worker model.CloudflareWorker, version model.StoredCloudflareWorkerVersion, deployment model.CloudflareDeployment, provider cloudflareprovider.Provider) (model.CloudflareDeployment, error) {
	startedAt := s.now().UTC()
	running := deployment
	running.State = "running"
	running.ProviderExecutionAllowed = true
	running.StartedAt = &startedAt
	if deployment.Kind == "rollback" {
		running.ProviderVersionID = version.Metadata.ProviderVersionID
	}
	if err := s.repository.UpdateWorkerDeployment(running, "ready_for_provider"); err != nil {
		return model.CloudflareDeployment{}, err
	}

	if _, err := provider.ValidateAccess(ctx); err != nil {
		return s.failCloudflareDeployment(running, err)
	}

	providerVersionID := running.ProviderVersionID
	if deployment.Kind == "deploy" {
		uploaded, err := provider.UploadVersion(ctx, cloudflareprovider.PrebuiltModule{
			ScriptName: worker.ScriptName, MainModule: version.Metadata.Entrypoint, Source: version.Module,
			Message: "vpsmanager deployment " + deployment.ID, Tag: deployment.ID,
			IdempotencyKey: deployment.ID + ":upload",
		})
		if err != nil {
			return s.failCloudflareDeployment(running, err)
		}
		if uploaded.ID == "" || uploaded.ScriptName != worker.ScriptName || uploaded.SizeBytes != int64(version.Metadata.SizeBytes) || "sha256:"+uploaded.SHA256 != version.Metadata.SHA256 {
			return s.failCloudflareDeployment(running, &cloudflareprovider.Error{Kind: cloudflareprovider.ErrorProvider, Operation: "upload_version"})
		}
		providerVersionID = uploaded.ID
		uploadedAt := s.now().UTC()
		if uploaded.CreatedAt != nil {
			uploadedAt = uploaded.CreatedAt.UTC()
		}
		if err := s.repository.UpdateWorkerVersionProvider(worker.ID, version.Metadata.ID, uploaded.ID, uploaded.Number, uploadedAt); err != nil {
			return s.failCloudflareDeploymentCode(running, providerVersionID, "persistence_failure", http.StatusInternalServerError)
		}
	}

	var providerDeployment cloudflareprovider.Deployment
	var err error
	message := "vpsmanager deployment " + deployment.ID
	if deployment.Kind == "rollback" {
		providerDeployment, err = provider.Rollback(ctx, cloudflareprovider.RollbackRequest{
			ScriptName: worker.ScriptName, TargetVersionID: providerVersionID, Message: message,
			IdempotencyKey: deployment.ID + ":rollback",
		})
	} else {
		providerDeployment, err = provider.DeployVersion(ctx, cloudflareprovider.DeployRequest{
			ScriptName: worker.ScriptName, VersionID: providerVersionID, Message: message,
			IdempotencyKey: deployment.ID + ":deploy",
		})
	}
	if err != nil {
		running.ProviderVersionID = providerVersionID
		return s.failCloudflareDeployment(running, err)
	}
	if providerDeployment.ID == "" || providerDeployment.ScriptName != worker.ScriptName || providerDeployment.State != cloudflareprovider.DeploymentStateActive {
		running.ProviderVersionID = providerVersionID
		return s.failCloudflareDeployment(running, &cloudflareprovider.Error{Kind: cloudflareprovider.ErrorProvider, Operation: "deployment_result"})
	}

	finishedAt := s.now().UTC()
	succeeded := running
	succeeded.State = "succeeded"
	succeeded.ProviderVersionID = providerVersionID
	succeeded.ProviderDeploymentID = providerDeployment.ID
	succeeded.ProviderState = string(providerDeployment.State)
	succeeded.ErrorCode = ""
	succeeded.FinishedAt = &finishedAt
	if err := s.repository.UpdateWorkerDeployment(succeeded, "running"); err != nil {
		return model.CloudflareDeployment{}, &cloudflareExecutionFailure{code: "persistence_failure", status: http.StatusInternalServerError}
	}
	return succeeded, nil
}

func (s *Server) failCloudflareDeployment(running model.CloudflareDeployment, providerErr error) (model.CloudflareDeployment, error) {
	code, status := classifyCloudflareProviderError(providerErr)
	return s.failCloudflareDeploymentCode(running, running.ProviderVersionID, code, status)
}

func (s *Server) failCloudflareDeploymentCode(running model.CloudflareDeployment, providerVersionID, code string, status int) (model.CloudflareDeployment, error) {
	finishedAt := s.now().UTC()
	failed := running
	failed.State = "failed"
	failed.ProviderVersionID = providerVersionID
	failed.ErrorCode = code
	failed.FinishedAt = &finishedAt
	if err := s.repository.UpdateWorkerDeployment(failed, "running"); err != nil {
		return model.CloudflareDeployment{}, &cloudflareExecutionFailure{code: "persistence_failure", status: http.StatusInternalServerError}
	}
	return failed, &cloudflareExecutionFailure{code: code, status: status}
}

func classifyCloudflareProviderError(err error) (string, int) {
	var providerErr *cloudflareprovider.Error
	if !errors.As(err, &providerErr) {
		return "cloudflare_provider_failed", http.StatusBadGateway
	}
	code := "cloudflare_" + string(providerErr.Kind)
	switch providerErr.Kind {
	case cloudflareprovider.ErrorConflict, cloudflareprovider.ErrorNotFound:
		return code, http.StatusConflict
	case cloudflareprovider.ErrorRateLimited, cloudflareprovider.ErrorTimeout, cloudflareprovider.ErrorTransport:
		return code, http.StatusServiceUnavailable
	default:
		return code, http.StatusBadGateway
	}
}
