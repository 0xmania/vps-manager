package api

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"vpsmanager/services/control-plane/internal/credentials"
	"vpsmanager/services/control-plane/internal/model"
	"vpsmanager/services/control-plane/internal/store"
)

const maxWorkerModuleBytes = 256 << 10

var (
	cloudflareAccountPattern = regexp.MustCompile(`^[a-fA-F0-9]{32}$`)
	workerScriptPattern      = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	cloudflareTokenPattern   = regexp.MustCompile(`^[A-Za-z0-9_-]{20,512}$`)
	cloudflareGlobalKey      = regexp.MustCompile(`^[A-Fa-f0-9]{32,37}$`)
)

type createWorkerRequest struct {
	Name       string `json:"name"`
	AccountID  string `json:"accountId"`
	ScriptName string `json:"scriptName"`
}

func (s *Server) createWorker(w http.ResponseWriter, r *http.Request) {
	if !requireGlobalWorkerScope(w, r) {
		return
	}
	var input createWorkerRequest
	if err := decodeJSON(w, r, &input); err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	input.Name, input.AccountID, input.ScriptName = strings.TrimSpace(input.Name), strings.TrimSpace(input.AccountID), strings.TrimSpace(input.ScriptName)
	if len(input.Name) < 1 || len(input.Name) > 100 || containsUnsafeText(input.Name) {
		writeError(w, r, http.StatusBadRequest, "validation_error", "name must contain 1 to 100 printable characters")
		return
	}
	if !cloudflareAccountPattern.MatchString(input.AccountID) {
		writeError(w, r, http.StatusBadRequest, "validation_error", "accountId must be a 32-character hexadecimal Cloudflare account id")
		return
	}
	if !workerScriptPattern.MatchString(input.ScriptName) {
		writeError(w, r, http.StatusBadRequest, "validation_error", "scriptName must use lowercase letters, digits, and internal hyphens")
		return
	}
	id, err := model.NewID("worker")
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "internal_error", "could not create worker")
		return
	}
	now := s.now().UTC()
	worker := model.CloudflareWorker{ID: id, Name: input.Name, AccountID: strings.ToLower(input.AccountID), ScriptName: input.ScriptName, Version: 1, CreatedAt: now, UpdatedAt: now}
	if err := s.repository.CreateWorker(worker); err != nil {
		writeStoreError(w, r, err)
		return
	}
	principal := principalFrom(r.Context())
	s.audit(r, principal, "cloudflare_worker.created", "cloudflare_worker", worker.ID, "success", map[string]any{"scriptName": worker.ScriptName})
	writeJSON(w, http.StatusCreated, worker)
}

func (s *Server) listWorkers(w http.ResponseWriter, r *http.Request) {
	if !requireGlobalWorkerScope(w, r) {
		return
	}
	workers, err := s.repository.ListWorkers()
	if err != nil {
		writeStoreError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": workers})
}

func (s *Server) getWorker(w http.ResponseWriter, r *http.Request) {
	if !requireGlobalWorkerScope(w, r) {
		return
	}
	worker, err := s.repository.GetWorker(r.PathValue("workerID"))
	if err != nil {
		writeStoreError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, worker)
}

type workerTokenRequest struct {
	Token string `json:"token"`
}

func (s *Server) putWorkerToken(w http.ResponseWriter, r *http.Request) {
	if !requireGlobalWorkerScope(w, r) {
		return
	}
	workerID := r.PathValue("workerID")
	if _, err := s.repository.GetWorker(workerID); err != nil {
		writeStoreError(w, r, err)
		return
	}
	var input workerTokenRequest
	if err := decodeJSON(w, r, &input); err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_request", "token payload is invalid")
		return
	}
	if !validProviderToken(input.Token) {
		writeError(w, r, http.StatusBadRequest, "validation_error", "token must contain 20 to 512 printable non-whitespace ASCII characters")
		return
	}
	id, err := model.NewID("cftok")
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "internal_error", "could not store token")
		return
	}
	plaintext := []byte(input.Token)
	input.Token = ""
	defer wipe(plaintext)
	envelope, err := s.credentials.Seal(r.Context(), plaintext, s.workerTokenAAD(workerID, id))
	if err != nil {
		writeError(w, r, http.StatusServiceUnavailable, "kms_unavailable", "token encryption is unavailable")
		return
	}
	principal := principalFrom(r.Context())
	metadata := model.CloudflareTokenMetadata{ID: id, WorkerID: workerID, Kind: "cloudflare_api_token", KeyID: envelope.KeyID, CreatedAt: s.now().UTC(), CreatedBy: principal.Subject}
	if err := s.repository.PutWorkerToken(model.StoredCloudflareToken{Metadata: metadata, Envelope: envelope}); err != nil {
		writeStoreError(w, r, err)
		return
	}
	s.audit(r, principal, "cloudflare_token.stored", "cloudflare_worker", workerID, "success", map[string]any{"tokenId": id})
	writeJSON(w, http.StatusCreated, metadata)
}

func (s *Server) getWorkerToken(w http.ResponseWriter, r *http.Request) {
	if !requireGlobalWorkerScope(w, r) {
		return
	}
	token, err := s.repository.GetWorkerToken(r.PathValue("workerID"))
	if err != nil {
		writeStoreError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, token.Metadata)
}

func (s *Server) deleteWorkerToken(w http.ResponseWriter, r *http.Request) {
	if !requireGlobalWorkerScope(w, r) {
		return
	}
	workerID := r.PathValue("workerID")
	if err := s.repository.DeleteWorkerToken(workerID); err != nil {
		writeStoreError(w, r, err)
		return
	}
	s.audit(r, principalFrom(r.Context()), "cloudflare_token.deleted", "cloudflare_worker", workerID, "success", nil)
	w.WriteHeader(http.StatusNoContent)
}

type createWorkerVersionRequest struct {
	ModuleBase64 string `json:"moduleBase64"`
	ContentType  string `json:"contentType"`
	Entrypoint   string `json:"entrypoint"`
}

func (s *Server) createWorkerVersion(w http.ResponseWriter, r *http.Request) {
	if !requireGlobalWorkerScope(w, r) {
		return
	}
	workerID := r.PathValue("workerID")
	if _, err := s.repository.GetWorker(workerID); err != nil {
		writeStoreError(w, r, err)
		return
	}
	var input createWorkerVersionRequest
	if err := decodeJSON(w, r, &input); err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if input.ContentType != "application/javascript" || input.Entrypoint != "index.js" {
		writeError(w, r, http.StatusBadRequest, "validation_error", "only an application/javascript module with entrypoint index.js is accepted")
		return
	}
	module, err := base64.StdEncoding.Strict().DecodeString(input.ModuleBase64)
	input.ModuleBase64 = ""
	if err != nil || len(module) == 0 || len(module) > maxWorkerModuleBytes || !utf8.Valid(module) || strings.IndexByte(string(module), 0) >= 0 {
		writeError(w, r, http.StatusBadRequest, "validation_error", "moduleBase64 must encode 1 to 262144 bytes of UTF-8 JavaScript")
		return
	}
	if containsLikelyEmbeddedSecret(module) {
		writeError(w, r, http.StatusBadRequest, "embedded_secret_detected", "module appears to contain an embedded secret; use provider secret bindings instead")
		return
	}
	id, idErr := model.NewID("wver")
	if idErr != nil {
		writeError(w, r, http.StatusInternalServerError, "internal_error", "could not create worker version")
		return
	}
	digest := sha256.Sum256(module)
	principal := principalFrom(r.Context())
	metadata := model.CloudflareWorkerVersion{
		ID: id, WorkerID: workerID, SHA256: "sha256:" + hex.EncodeToString(digest[:]), SizeBytes: len(module),
		ContentType: input.ContentType, Entrypoint: input.Entrypoint, State: "staged", CreatedAt: s.now().UTC(), CreatedBy: principal.Subject,
	}
	if err := s.repository.CreateWorkerVersion(model.StoredCloudflareWorkerVersion{Metadata: metadata, Module: module}); err != nil {
		writeStoreError(w, r, err)
		return
	}
	s.audit(r, principal, "cloudflare_worker_version.uploaded", "cloudflare_worker", workerID, "success", map[string]any{"versionId": id, "sha256": metadata.SHA256, "sizeBytes": metadata.SizeBytes})
	writeJSON(w, http.StatusCreated, metadata)
}

func (s *Server) listWorkerVersions(w http.ResponseWriter, r *http.Request) {
	if !requireGlobalWorkerScope(w, r) {
		return
	}
	workerID := r.PathValue("workerID")
	if _, err := s.repository.GetWorker(workerID); err != nil {
		writeStoreError(w, r, err)
		return
	}
	versions, err := s.repository.ListWorkerVersions(workerID)
	if err != nil {
		writeStoreError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": versions})
}

type createWorkerDeploymentRequest struct {
	VersionID string `json:"versionId"`
	Kind      string `json:"kind"`
}

func (s *Server) createWorkerDeployment(w http.ResponseWriter, r *http.Request) {
	if !requireGlobalWorkerScope(w, r) {
		return
	}
	workerID := r.PathValue("workerID")
	var input createWorkerDeploymentRequest
	if err := decodeJSON(w, r, &input); err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if !strings.HasPrefix(input.VersionID, "wver_") || len(input.VersionID) > 128 || (input.Kind != "deploy" && input.Kind != "rollback") {
		writeError(w, r, http.StatusBadRequest, "validation_error", "versionId and kind deploy or rollback are required")
		return
	}
	worker, err := s.repository.GetWorker(workerID)
	if err != nil {
		writeStoreError(w, r, err)
		return
	}
	if _, err := s.repository.GetWorkerVersion(workerID, input.VersionID); err != nil {
		writeStoreError(w, r, err)
		return
	}
	if _, err := s.repository.GetWorkerToken(workerID); err != nil {
		writeError(w, r, http.StatusConflict, "token_required", "an encrypted Cloudflare token is required before planning a deployment")
		return
	}
	id, err := model.NewID("cfdep")
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "internal_error", "could not create deployment plan")
		return
	}
	principal := principalFrom(r.Context())
	deployment := model.CloudflareDeployment{
		ID: id, WorkerID: workerID, VersionID: input.VersionID, PreviousDesiredVersionID: worker.DesiredVersionID,
		Kind: input.Kind, State: "ready_for_provider", ProviderExecutionAllowed: false, CreatedAt: s.now().UTC(), CreatedBy: principal.Subject,
	}
	updated := worker
	updated.DesiredVersionID, updated.UpdatedAt, updated.Version = input.VersionID, deployment.CreatedAt, worker.Version+1
	if err := s.repository.PlanWorkerDeployment(deployment, updated); err != nil {
		if errors.Is(err, store.ErrConflict) {
			writeError(w, r, http.StatusConflict, "version_conflict", "deployment plan conflicts with current desired state")
		} else {
			writeStoreError(w, r, err)
		}
		return
	}
	s.audit(r, principal, "cloudflare_deployment.planned", "cloudflare_worker", workerID, "success", map[string]any{"deploymentId": id, "versionId": input.VersionID, "kind": input.Kind, "providerExecutionAllowed": false})
	writeJSON(w, http.StatusCreated, deployment)
}

func (s *Server) listWorkerDeployments(w http.ResponseWriter, r *http.Request) {
	if !requireGlobalWorkerScope(w, r) {
		return
	}
	workerID := r.PathValue("workerID")
	if _, err := s.repository.GetWorker(workerID); err != nil {
		writeStoreError(w, r, err)
		return
	}
	deployments, err := s.repository.ListWorkerDeployments(workerID)
	if err != nil {
		writeStoreError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": deployments})
}

func requireGlobalWorkerScope(w http.ResponseWriter, r *http.Request) bool {
	if principalFrom(r.Context()).AllHosts {
		return true
	}
	writeError(w, r, http.StatusForbidden, "global_scope_required", "Cloudflare worker resources require a global session scope")
	return false
}

func validProviderToken(token string) bool {
	return validProviderTokenBytes([]byte(token))
}

func validProviderTokenBytes(token []byte) bool {
	return cloudflareTokenPattern.Match(token) && !cloudflareGlobalKey.Match(token)
}

func containsUnsafeText(value string) bool {
	for _, char := range value {
		if unicode.IsControl(char) {
			return true
		}
	}
	return false
}

func containsLikelyEmbeddedSecret(module []byte) bool {
	lower := strings.ToLower(string(module))
	for _, marker := range []string{"-----begin private key-----", "authorization: bearer ", "secret_access_key", "api_token="} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func workerTokenAAD(workerID, tokenID string) []byte {
	aad, _ := credentials.ContextAAD("development", workerID, tokenID, "cloudflare_api_token")
	return aad
}
