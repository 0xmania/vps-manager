package api

import (
	"context"
	"net/http"
	"strings"
	"time"
	"unicode"

	connectorprotocol "vpsmanager/services/connector-protocol"
	"vpsmanager/services/control-plane/internal/auth"
	"vpsmanager/services/control-plane/internal/model"
	"vpsmanager/services/control-plane/internal/store"
	"vpsmanager/services/runbook"
)

type RunbookConnector interface {
	PreviewRunbook(context.Context, connectorprotocol.RunbookPreviewRequest) (connectorprotocol.RunbookPreviewResponse, error)
	ExecuteRunbook(context.Context, connectorprotocol.RunbookExecuteRequest) (connectorprotocol.RunbookExecuteResponse, error)
}

type runbookPreviewRequest struct {
	ActionID   string                              `json:"actionId"`
	Version    int                                 `json:"version"`
	Parameters connectorprotocol.RunbookParameters `json:"parameters"`
}

func (s *Server) previewRunbook(w http.ResponseWriter, r *http.Request) {
	if s.runbooks == nil {
		writeError(w, r, http.StatusServiceUnavailable, "connector_unavailable", "Runbook preview requires the external Connector")
		return
	}
	hostID := r.PathValue("hostID")
	if !s.checkHostScope(w, r, hostID) {
		return
	}
	host, err := s.repository.GetHost(hostID)
	if err != nil {
		writeStoreError(w, r, err)
		return
	}
	if host.HostKey == nil {
		writeError(w, r, http.StatusConflict, "host_key_required", "host key must be confirmed before previewing a runbook")
		return
	}
	credential, err := s.repository.GetCredential(hostID)
	if err != nil {
		writeError(w, r, http.StatusConflict, "credential_required", "an SSH credential is required before previewing a runbook")
		return
	}
	var input runbookPreviewRequest
	if err := decodeJSON(w, r, &input); err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if input.ActionID == "" || input.Version < 1 {
		writeError(w, r, http.StatusBadRequest, "validation_error", "actionId and version are required")
		return
	}
	if _, err := runbook.Build(runbook.ActionID(input.ActionID), input.Version, runbook.Parameters{
		Service: runbook.Service(input.Parameters.Service), Timezone: runbook.Timezone(input.Parameters.Timezone),
		PID: input.Parameters.PID, ProcessStartTicks: input.Parameters.ProcessStartTicks,
	}); err != nil {
		writeError(w, r, http.StatusBadRequest, "validation_error", "runbook action or parameters are invalid")
		return
	}
	principal := principalFrom(r.Context())
	jobID, err := model.NewID("job")
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "internal_error", "could not create runbook job")
		return
	}
	now := s.now().UTC()
	job := model.Job{
		ID: jobID, Type: "runbook", HostID: hostID, State: model.JobQueued,
		RequestedBy: principal.Subject, RequestedSessionID: principal.SessionID,
		CreatedAt: now, Version: 1,
	}
	if err := s.repository.CreateJob(job); err != nil {
		writeStoreError(w, r, err)
		return
	}
	s.audit(r, principal, "runbook.preview_created", "job", job.ID, "success", map[string]any{"hostId": hostID, "actionId": input.ActionID, "version": input.Version})
	job, err = s.repository.MutateJob(job.ID, func(current model.Job) (model.Job, error) {
		return model.TransitionJob(current, model.JobRunning, s.now().UTC())
	})
	if err != nil {
		writeStoreError(w, r, err)
		return
	}
	binding := connectorprotocol.RunbookBinding{
		Action:                    connectorprotocol.RunbookActionRef{ID: input.ActionID, Version: input.Version},
		HostID:                    hostID,
		JobID:                     job.ID,
		Target:                    connectorprotocol.Target{Address: host.Address, Port: host.Port, User: host.Username},
		PinnedHostKeySHA256:       host.HostKey.FingerprintSHA256,
		CredentialPublicKeySHA256: credential.Metadata.PublicKeyFingerprint,
		Parameters:                input.Parameters,
	}
	ctx, cancel := context.WithTimeout(r.Context(), s.config.JobTimeout)
	defer cancel()
	preview, err := s.runbooks.PreviewRunbook(ctx, connectorprotocol.RunbookPreviewRequest{Binding: binding})
	if err != nil || preview.ScopeDigest == "" || preview.Binding.JobID != job.ID || preview.Binding.HostID != hostID {
		job = s.failRunbookJob(job.ID, principal, "preview_failed", "Runbook preview failed")
		writeError(w, r, http.StatusBadGateway, "preview_failed", "Connector could not preview the runbook")
		return
	}
	storedPreview := runbookPreviewModel(preview)
	storedPreview.ExecutionEnabled = storedPreview.ExecutionEnabled && (!storedPreview.Mutating || s.config.MutationsEnabled)
	job, err = s.repository.MutateJob(job.ID, func(current model.Job) (model.Job, error) {
		updated, transitionErr := model.TransitionJob(current, model.JobAwaitingApproval, s.now().UTC())
		if transitionErr != nil {
			return model.Job{}, transitionErr
		}
		updated.RunbookPreview = &storedPreview
		return updated, nil
	})
	if err != nil {
		writeStoreError(w, r, err)
		return
	}
	s.audit(r, principal, "runbook.previewed", "job", job.ID, "success", map[string]any{
		"hostId": hostID, "actionId": input.ActionID, "mutating": preview.Mutating,
	})
	w.Header().Set("Location", "/api/v1/jobs/"+job.ID)
	writeJSON(w, http.StatusCreated, job)
}

type runbookExecuteRequest struct {
	ScopeDigest string `json:"scopeDigest"`
	Reason      string `json:"reason"`
	IncidentID  string `json:"incidentId,omitempty"`
}

func (s *Server) executeRunbook(w http.ResponseWriter, r *http.Request) {
	if s.runbooks == nil || !s.config.DevMode || !s.config.SecretExecutionEnabled {
		writeError(w, r, http.StatusServiceUnavailable, "execution_boundary_unavailable", "Runbook execution requires a development execution identity with credential decryption")
		return
	}
	var input runbookExecuteRequest
	if err := decodeJSON(w, r, &input); err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	input.Reason = strings.TrimSpace(input.Reason)
	input.IncidentID = strings.TrimSpace(input.IncidentID)
	if input.ScopeDigest == "" || !validRunbookReason(input.Reason) ||
		(input.IncidentID != "" && !validRunbookIdentifier(input.IncidentID, 128)) {
		writeError(w, r, http.StatusBadRequest, "validation_error", "scopeDigest, reason, or incidentId is invalid")
		return
	}
	job, err := s.repository.GetJob(r.PathValue("jobID"))
	if err != nil {
		writeStoreError(w, r, err)
		return
	}
	if !s.checkHostScope(w, r, job.HostID) {
		return
	}
	if job.Type != "runbook" || job.State != model.JobAwaitingApproval || job.RunbookPreview == nil {
		writeError(w, r, http.StatusConflict, "runbook_not_awaiting_approval", "runbook job is not awaiting execution approval")
		return
	}
	principal := principalFrom(r.Context())
	authorized, ok := s.sessions.AuthorizeSession(job.RequestedSessionID, auth.RunbooksExecute, job.HostID)
	if !ok || authorized.SessionID != principal.SessionID || authorized.Subject != principal.Subject {
		writeError(w, r, http.StatusForbidden, "authorization_expired", "runbook authorization expired or was revoked")
		return
	}
	preview := job.RunbookPreview
	if !constantStringEqual(input.ScopeDigest, preview.ScopeDigest) {
		writeError(w, r, http.StatusConflict, "scope_changed", "runbook scope digest does not match the preview")
		return
	}
	if preview.Emergency && input.IncidentID == "" {
		writeError(w, r, http.StatusBadRequest, "incident_required", "emergency runbooks require an incidentId")
		return
	}
	if preview.Mutating && !s.config.MutationsEnabled {
		writeError(w, r, http.StatusServiceUnavailable, "mutations_disabled", "mutating runbooks require VPSMGR_ENABLE_MUTATIONS=true")
		return
	}
	if !preview.ExecutionEnabled {
		writeError(w, r, http.StatusServiceUnavailable, "runbook_execution_disabled", "Connector execution is disabled for this runbook")
		return
	}
	host, err := s.repository.GetHost(job.HostID)
	if err != nil || host.HostKey == nil {
		writeError(w, r, http.StatusConflict, "host_key_required", "host key must remain confirmed")
		return
	}
	credential, err := s.repository.GetCredential(job.HostID)
	if err != nil || credential.Metadata.ID == "" {
		writeError(w, r, http.StatusConflict, "credential_required", "SSH credential is no longer available")
		return
	}
	job, err = s.repository.MutateJob(job.ID, func(current model.Job) (model.Job, error) {
		return model.TransitionJob(current, model.JobRunning, s.now().UTC())
	})
	if err != nil {
		writeStoreError(w, r, err)
		return
	}
	now := s.now().UTC()
	request := connectorprotocol.RunbookExecuteRequest{
		Binding: preview.Binding,
		Approval: connectorprotocol.RunbookApprovalSummary{
			Decision: "approved", Action: preview.Binding.Action, HostID: job.HostID, JobID: job.ID,
			ScopeDigest: preview.ScopeDigest, ApprovedAt: now, ExpiresAt: now.Add(5 * time.Minute),
		},
		Reason:        input.Reason,
		PinnedHostKey: host.HostKey.PublicKey,
	}
	if preview.Emergency {
		request.Emergency = connectorprotocol.RunbookEmergencyGrant{IncidentID: input.IncidentID, ExpiresAt: now.Add(5 * time.Minute)}
	}
	ctx, cancel := context.WithTimeout(r.Context(), s.config.JobTimeout)
	defer cancel()
	var execution connectorprotocol.RunbookExecuteResponse
	err = s.credentials.Open(ctx, credential.Envelope, s.credentialAAD(job.HostID, credential.Metadata.ID), func(plaintext []byte) error {
		connectorCredential, decodeErr := decodeConnectorCredential(plaintext)
		if decodeErr != nil {
			return decodeErr
		}
		defer wipeConnectorCredential(&connectorCredential)
		request.Credential = connectorCredential
		response, executeErr := s.runbooks.ExecuteRunbook(ctx, request)
		wipeConnectorCredential(&request.Credential)
		execution = response
		return executeErr
	})
	if err != nil || !constantStringEqual(execution.ScopeDigest, preview.ScopeDigest) || execution.Binding.JobID != job.ID {
		job = s.failRunbookJob(job.ID, principal, "execution_failed", "Runbook execution failed")
		writeError(w, r, http.StatusBadGateway, "execution_failed", "Connector could not execute the runbook")
		return
	}
	storedExecution := runbookExecutionModel(execution)
	state := model.JobSucceeded
	if execution.Status != "succeeded" {
		state = model.JobFailed
	}
	job, err = s.repository.MutateJob(job.ID, func(current model.Job) (model.Job, error) {
		updated, transitionErr := model.TransitionJob(current, state, s.now().UTC())
		if transitionErr != nil {
			return model.Job{}, transitionErr
		}
		updated.RunbookExecution = &storedExecution
		if state == model.JobFailed {
			updated.Error = &model.JobError{Code: "runbook_failed", Message: "one or more reviewed runbook steps failed"}
		}
		return updated, nil
	})
	if err != nil {
		writeStoreError(w, r, err)
		return
	}
	stepAudit := make([]map[string]any, 0, len(storedExecution.Steps))
	for _, step := range storedExecution.Steps {
		stepAudit = append(stepAudit, map[string]any{"id": step.ID, "state": step.State, "exitCode": step.ExitCode, "errorCode": step.ErrorCode})
	}
	s.audit(r, principal, "runbook.executed", "job", job.ID, execution.Status, map[string]any{
		"hostId": job.HostID, "actionId": preview.Binding.Action.ID, "incidentId": input.IncidentID, "steps": stepAudit,
	})
	writeJSON(w, http.StatusOK, job)
}

func validRunbookReason(value string) bool {
	if len(value) < 8 || len(value) > 500 {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func validRunbookIdentifier(value string, max int) bool {
	if len(value) < 1 || len(value) > max {
		return false
	}
	for index, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || (index > 0 && strings.ContainsRune("._:-", character)) {
			continue
		}
		return false
	}
	return true
}

func runbookPreviewModel(value connectorprotocol.RunbookPreviewResponse) model.RunbookPreviewResult {
	return model.RunbookPreviewResult{
		ProtocolVersion: value.ProtocolVersion, RequestID: value.RequestID, Action: value.Action,
		CatalogVersion: value.CatalogVersion, Binding: value.Binding, ScopeDigest: value.ScopeDigest,
		Title: value.Title, Mutating: value.Mutating, Emergency: value.Emergency,
		ExecutionEnabled: value.ExecutionEnabled, RetryPolicy: value.RetryPolicy,
		Steps: append([]connectorprotocol.RunbookStepPreview(nil), value.Steps...),
	}
}

func runbookExecutionModel(value connectorprotocol.RunbookExecuteResponse) model.RunbookExecutionResult {
	steps := make([]model.RunbookStepExecution, 0, len(value.Steps))
	for _, step := range value.Steps {
		steps = append(steps, model.RunbookStepExecution{
			ID: step.ID, Phase: step.Phase, State: step.State,
			Stdout: safeRemoteOutput(step.Stdout), Stderr: safeRemoteOutput(step.Stderr),
			ExitCode: step.ExitCode, DurationMillis: step.DurationMillis, ErrorCode: step.ErrorCode,
		})
	}
	return model.RunbookExecutionResult{
		ProtocolVersion: value.ProtocolVersion, RequestID: value.RequestID, Action: value.Action,
		CatalogVersion: value.CatalogVersion, Binding: value.Binding, ScopeDigest: value.ScopeDigest,
		Status: value.Status, Stopped: value.Stopped, Retryable: value.Retryable,
		IdempotentReplay: value.IdempotentReplay, Steps: steps,
	}
}

func (s *Server) failRunbookJob(jobID string, principal auth.Principal, code, message string) model.Job {
	job, err := s.repository.MutateJob(jobID, func(current model.Job) (model.Job, error) {
		if current.State != model.JobRunning {
			return model.Job{}, store.ErrConflict
		}
		updated, transitionErr := model.TransitionJob(current, model.JobFailed, s.now().UTC())
		if transitionErr != nil {
			return model.Job{}, transitionErr
		}
		updated.Error = &model.JobError{Code: code, Message: message}
		return updated, nil
	})
	if err == nil {
		s.auditWithRequestID("", principal, "runbook.failed", "job", jobID, "failed", map[string]any{"hostId": job.HostID, "errorCode": code})
	}
	return job
}

var _ RunbookConnector = (*connectorprotocol.Client)(nil)
