package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode"

	connectorprotocol "vpsmanager/services/connector-protocol"
	"vpsmanager/services/connector/sshconnector"
	"vpsmanager/services/runbook"

	"golang.org/x/crypto/ssh"
)

const (
	defaultRunbookBodyLimit   int64 = 128 << 10
	defaultRunbookConcurrency       = 4
	maxApprovalLifetime             = 15 * time.Minute
	maxEmergencyLifetime            = 4 * time.Hour
)

type RunbookSSHRunner interface {
	RunRunbookStep(context.Context, sshconnector.Config, runbook.Step) (runbook.CommandResult, error)
}

type RunbookOptions struct {
	KeyID               string
	HMACKey             []byte
	MutationsEnabled    bool
	AllowPrivateTargets bool
	MaxConcurrent       int
	MaxRequestBodyBytes int64
	MaxOutputBytes      int64
	ConnectTimeout      time.Duration
	MaxTrackedNonces    int
	MaxIdempotencyJobs  int
	AuthenticationSkew  time.Duration
	Now                 func() time.Time
	Runner              RunbookSSHRunner
}

type RunbookHandler struct {
	verifier            *connectorprotocol.Verifier
	runner              RunbookSSHRunner
	mutationsEnabled    bool
	allowPrivateTargets bool
	bodyLimit           int64
	outputLimit         int64
	connectTimeout      time.Duration
	concurrency         chan struct{}
	now                 func() time.Time
	ledger              *runbookLedger
}

func NewRunbookHandler(options RunbookOptions) (*RunbookHandler, error) {
	verifier, err := connectorprotocol.NewVerifier(connectorprotocol.VerifierConfig{
		KeyID: options.KeyID, Key: options.HMACKey, MaxSkew: options.AuthenticationSkew,
		MaxNonces: options.MaxTrackedNonces, Now: options.Now,
	})
	if err != nil {
		return nil, err
	}
	if options.MaxConcurrent <= 0 {
		options.MaxConcurrent = defaultRunbookConcurrency
	}
	if options.MaxConcurrent > 32 {
		return nil, errors.New("runbook concurrency limit must not exceed 32")
	}
	if options.MaxRequestBodyBytes <= 0 {
		options.MaxRequestBodyBytes = defaultRunbookBodyLimit
	}
	if options.MaxRequestBodyBytes > 1<<20 {
		return nil, errors.New("runbook request body limit must not exceed 1 MiB")
	}
	if options.MaxOutputBytes <= 0 {
		options.MaxOutputBytes = defaultOutputLimit
	}
	if options.MaxOutputBytes > 4<<20 {
		return nil, errors.New("runbook output limit must not exceed 4 MiB")
	}
	if options.ConnectTimeout <= 0 {
		options.ConnectTimeout = 10 * time.Second
	}
	if options.ConnectTimeout > 30*time.Second {
		return nil, errors.New("runbook connect timeout must not exceed 30 seconds")
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.Runner == nil {
		options.Runner = sshconnector.New()
	}
	return &RunbookHandler{
		verifier: verifier, runner: options.Runner, mutationsEnabled: options.MutationsEnabled,
		allowPrivateTargets: options.AllowPrivateTargets, bodyLimit: options.MaxRequestBodyBytes,
		outputLimit: options.MaxOutputBytes, connectTimeout: options.ConnectTimeout,
		concurrency: make(chan struct{}, options.MaxConcurrent), now: options.Now,
		ledger: newRunbookLedger(options.MaxIdempotencyJobs),
	}, nil
}

// Wrap adds only the two authenticated runbook endpoints. All other requests
// pass untouched to the existing connector handler.
func (h *RunbookHandler) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != connectorprotocol.RunbookPreviewPath && request.URL.Path != connectorprotocol.RunbookExecutePath {
			next.ServeHTTP(writer, request)
			return
		}
		requestID := newRequestID()
		secureHeaders(writer, requestID)
		defer func() {
			if recover() != nil {
				writeError(writer, http.StatusInternalServerError, requestID, "internal_error", "connector request failed", false)
			}
		}()
		if request.URL.RawQuery != "" {
			writeError(writer, http.StatusBadRequest, requestID, "query_not_allowed", "query parameters are not allowed", false)
			return
		}
		if request.Method != http.MethodPost {
			methodNotAllowed(writer, requestID, http.MethodPost)
			return
		}
		switch request.URL.Path {
		case connectorprotocol.RunbookPreviewPath:
			h.handlePreview(writer, request, requestID)
		case connectorprotocol.RunbookExecutePath:
			h.handleExecute(writer, request, requestID)
		}
	})
}

func (h *RunbookHandler) handlePreview(writer http.ResponseWriter, request *http.Request, requestID string) {
	body, ok := h.authenticateJSON(writer, request, requestID)
	if !ok {
		return
	}
	defer wipe(body)
	var payload connectorprotocol.RunbookPreviewRequest
	if err := decodeStrictJSON(body, &payload); err != nil {
		writeError(writer, http.StatusBadRequest, requestID, "invalid_json", "request must be one valid JSON object with only supported fields", false)
		return
	}
	plan, digest, err := buildBoundPlan(payload.ProtocolVersion, payload.Binding)
	if err != nil {
		writeError(writer, http.StatusBadRequest, requestID, "invalid_runbook", "runbook binding is invalid", false)
		return
	}
	definition := plan.Definition()
	steps := plan.Steps()
	preview := make([]connectorprotocol.RunbookStepPreview, 0, len(steps))
	for _, step := range steps {
		preview = append(preview, connectorprotocol.RunbookStepPreview{
			ID: step.ID(), Phase: string(step.Phase()), Description: step.Description(),
			TimeoutSeconds: int(step.Timeout().Seconds()),
		})
	}
	writeJSON(writer, http.StatusOK, connectorprotocol.RunbookPreviewResponse{
		ProtocolVersion: connectorprotocol.ProtocolVersion, RequestID: requestID,
		Action: connectorprotocol.ActionRunbookPreview, CatalogVersion: runbook.CatalogVersion,
		Binding: payload.Binding, ScopeDigest: digest, Title: definition.Title,
		Mutating: definition.Mutating, Emergency: definition.Emergency,
		ExecutionEnabled: !definition.Mutating || h.mutationsEnabled,
		RetryPolicy:      definition.RetryPolicy, Steps: preview,
	})
}

func (h *RunbookHandler) handleExecute(writer http.ResponseWriter, request *http.Request, requestID string) {
	body, ok := h.authenticateJSON(writer, request, requestID)
	if !ok {
		return
	}
	defer wipe(body)
	if !h.acquire(writer, requestID) {
		return
	}
	defer h.release()
	var payload connectorprotocol.RunbookExecuteRequest
	if err := decodeStrictJSON(body, &payload); err != nil {
		writeError(writer, http.StatusBadRequest, requestID, "invalid_json", "request must be one valid JSON object with only supported fields", false)
		return
	}
	defer wipe(payload.Credential.PrivateKeyPEM)
	defer wipe(payload.Credential.Passphrase)
	plan, digest, err := buildBoundPlan(payload.ProtocolVersion, payload.Binding)
	if err != nil {
		writeError(writer, http.StatusBadRequest, requestID, "invalid_runbook", "runbook binding is invalid", false)
		return
	}
	definition := plan.Definition()
	if definition.Mutating && !h.mutationsEnabled {
		writeError(writer, http.StatusForbidden, requestID, "mutations_disabled", "mutating runbooks are disabled by connector policy", false)
		return
	}
	now := h.now()
	if err := validateApproval(payload, definition, digest, now); err != nil {
		writeError(writer, http.StatusForbidden, requestID, "approval_invalid", "runbook approval, reason, or emergency grant is invalid", false)
		return
	}
	pinnedKey, signer, err := validateRunbookSSHMaterial(payload)
	if err != nil {
		writeError(writer, http.StatusBadRequest, requestID, "ssh_material_invalid", "SSH target, host key, or credential does not match the approved binding", false)
		return
	}
	claim, replay := h.ledger.claim(payload.Binding.JobID, digest, now)
	switch claim {
	case claimReplay:
		replay.RequestID = requestID
		replay.IdempotentReplay = true
		writeJSON(writer, http.StatusOK, replay)
		return
	case claimConflict:
		writeError(writer, http.StatusConflict, requestID, "job_scope_conflict", "job ID was already bound to a different operation", false)
		return
	case claimInProgress:
		writeError(writer, http.StatusConflict, requestID, "job_in_progress", "job is already executing and is never started twice", false)
		return
	case claimFull:
		writeError(writer, http.StatusServiceUnavailable, requestID, "idempotency_capacity", "runbook idempotency ledger is at capacity", false)
		return
	}
	sshConfig := sshconnector.Config{
		Address: payload.Binding.Target.Address, Port: payload.Binding.Target.Port,
		User: payload.Binding.Target.User, Auth: ssh.PublicKeys(signer), PinnedHostKey: pinnedKey,
		ConnectTimeout: h.connectTimeout, MaxOutputBytes: h.outputLimit,
		AllowPrivateTargets: h.allowPrivateTargets,
	}
	runner := &configuredRunbookRunner{runner: h.runner, cfg: sshConfig}
	totalTimeout := 5 * time.Second
	for _, step := range plan.Steps() {
		totalTimeout += h.connectTimeout + step.Timeout()
	}
	if totalTimeout > 5*time.Minute {
		totalTimeout = 5 * time.Minute
	}
	ctx, cancel := context.WithTimeout(request.Context(), totalTimeout)
	execution, executeErr := runbook.Execute(ctx, plan, runner)
	cancel()
	if executeErr != nil {
		execution.Status = "failed"
		execution.Stopped = true
	}
	response := connectorprotocol.RunbookExecuteResponse{
		ProtocolVersion: connectorprotocol.ProtocolVersion, RequestID: requestID,
		Action: connectorprotocol.ActionRunbookExecute, CatalogVersion: runbook.CatalogVersion,
		Binding: payload.Binding, ScopeDigest: digest, Status: execution.Status,
		Stopped: execution.Stopped, Retryable: false,
		Steps: make([]connectorprotocol.RunbookStepResult, 0, len(execution.Steps)),
	}
	for _, step := range execution.Steps {
		response.Steps = append(response.Steps, connectorprotocol.RunbookStepResult{
			ID: step.ID, Phase: string(step.Phase), State: string(step.State),
			Stdout: step.Stdout, Stderr: step.Stderr, ExitCode: step.ExitCode,
			DurationMillis: step.Duration.Milliseconds(), ErrorCode: step.ErrorCode,
		})
	}
	h.ledger.complete(payload.Binding.JobID, digest, response)
	writeJSON(writer, http.StatusOK, response)
}

type configuredRunbookRunner struct {
	runner RunbookSSHRunner
	cfg    sshconnector.Config
}

func (r *configuredRunbookRunner) RunRunbookStep(ctx context.Context, step runbook.Step) (runbook.CommandResult, error) {
	return r.runner.RunRunbookStep(ctx, r.cfg, step)
}

func buildBoundPlan(protocolVersion string, binding connectorprotocol.RunbookBinding) (runbook.Plan, string, error) {
	if protocolVersion != connectorprotocol.ProtocolVersion || !validIdentifier(binding.HostID, 128) || !validIdentifier(binding.JobID, 128) {
		return runbook.Plan{}, "", errors.New("invalid protocol or identifiers")
	}
	if err := validateBoundTarget(binding); err != nil {
		return runbook.Plan{}, "", err
	}
	plan, err := runbook.Build(runbook.ActionID(binding.Action.ID), binding.Action.Version, runbook.Parameters{
		Service: runbook.Service(binding.Parameters.Service), Timezone: runbook.Timezone(binding.Parameters.Timezone),
		PID: binding.Parameters.PID, ProcessStartTicks: binding.Parameters.ProcessStartTicks,
	})
	if err != nil {
		return runbook.Plan{}, "", err
	}
	baseDigest, err := runbook.ScopeDigest(binding.HostID, binding.JobID, plan)
	if err != nil {
		return runbook.Plan{}, "", err
	}
	canonical := strings.Join([]string{
		baseDigest, binding.Target.Address, strconv.Itoa(binding.Target.Port), binding.Target.User,
		binding.PinnedHostKeySHA256, binding.CredentialPublicKeySHA256,
	}, "\n")
	digest := sha256.Sum256([]byte(canonical))
	return plan, hex.EncodeToString(digest[:]), nil
}

func validateBoundTarget(binding connectorprotocol.RunbookBinding) error {
	if strings.TrimSpace(binding.Target.Address) == "" || binding.Target.Address != strings.TrimSpace(binding.Target.Address) || len(binding.Target.Address) > 253 ||
		binding.Target.Port < 1 || binding.Target.Port > 65535 ||
		strings.TrimSpace(binding.Target.User) == "" || binding.Target.User != strings.TrimSpace(binding.Target.User) || len(binding.Target.User) > 64 ||
		!validSSHFingerprint(binding.PinnedHostKeySHA256) || !validSSHFingerprint(binding.CredentialPublicKeySHA256) {
		return errors.New("invalid bound SSH target")
	}
	for _, value := range binding.Target.Address + binding.Target.User {
		if unicode.IsControl(value) {
			return errors.New("target contains control characters")
		}
	}
	return nil
}

func validateApproval(payload connectorprotocol.RunbookExecuteRequest, definition runbook.Definition, digest string, now time.Time) error {
	approval := payload.Approval
	if approval.Decision != "approved" || approval.Action != payload.Binding.Action ||
		approval.HostID != payload.Binding.HostID || approval.JobID != payload.Binding.JobID || approval.ScopeDigest != digest {
		return errors.New("approval does not match binding")
	}
	if approval.ApprovedAt.IsZero() || approval.ExpiresAt.IsZero() || approval.ApprovedAt.After(now.Add(30*time.Second)) ||
		approval.ApprovedAt.Before(now.Add(-maxApprovalLifetime)) || !approval.ExpiresAt.After(now) ||
		approval.ExpiresAt.After(approval.ApprovedAt.Add(maxApprovalLifetime)) {
		return errors.New("approval is expired or outside its maximum lifetime")
	}
	if !validReason(payload.Reason) {
		return errors.New("reason is invalid")
	}
	if definition.Emergency {
		if !validIdentifier(payload.Emergency.IncidentID, 128) || payload.Emergency.ExpiresAt.IsZero() ||
			!payload.Emergency.ExpiresAt.After(now) || payload.Emergency.ExpiresAt.After(now.Add(maxEmergencyLifetime)) {
			return errors.New("emergency grant is invalid")
		}
	} else if payload.Emergency.IncidentID != "" || !payload.Emergency.ExpiresAt.IsZero() {
		return errors.New("non-emergency action included an emergency grant")
	}
	return nil
}

func validateRunbookSSHMaterial(payload connectorprotocol.RunbookExecuteRequest) (ssh.PublicKey, ssh.Signer, error) {
	if len(payload.PinnedHostKey) == 0 || len(payload.PinnedHostKey) > 16<<10 ||
		len(payload.Credential.PrivateKeyPEM) == 0 || len(payload.Credential.PrivateKeyPEM) > 48<<10 || len(payload.Credential.Passphrase) > 4<<10 {
		return nil, nil, errors.New("SSH material size is invalid")
	}
	pinned, err := sshconnector.ParsePinnedHostKey(payload.PinnedHostKey)
	if err != nil || ssh.FingerprintSHA256(pinned) != payload.Binding.PinnedHostKeySHA256 {
		return nil, nil, errors.New("pinned host key does not match binding")
	}
	var signer ssh.Signer
	if len(payload.Credential.Passphrase) == 0 {
		signer, err = ssh.ParsePrivateKey(payload.Credential.PrivateKeyPEM)
	} else {
		signer, err = ssh.ParsePrivateKeyWithPassphrase(payload.Credential.PrivateKeyPEM, payload.Credential.Passphrase)
	}
	if err != nil || ssh.FingerprintSHA256(signer.PublicKey()) != payload.Binding.CredentialPublicKeySHA256 {
		return nil, nil, errors.New("credential does not match binding")
	}
	return pinned, signer, nil
}

func validIdentifier(value string, max int) bool {
	if len(value) < 1 || len(value) > max || value != strings.TrimSpace(value) {
		return false
	}
	for index, char := range value {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') ||
			(index > 0 && (char == '.' || char == '_' || char == ':' || char == '-')) {
			continue
		}
		return false
	}
	return true
}

func validSSHFingerprint(value string) bool {
	if !strings.HasPrefix(value, "SHA256:") || len(value) < 20 || len(value) > 96 {
		return false
	}
	for _, char := range strings.TrimPrefix(value, "SHA256:") {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || char == '+' || char == '/' || char == '-' || char == '_' {
			continue
		}
		return false
	}
	return true
}

func validReason(value string) bool {
	if len(value) < 8 || len(value) > 500 || value != strings.TrimSpace(value) {
		return false
	}
	for _, char := range value {
		if unicode.IsControl(char) {
			return false
		}
	}
	return true
}

func (h *RunbookHandler) authenticateJSON(writer http.ResponseWriter, request *http.Request, requestID string) ([]byte, bool) {
	mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		writeError(writer, http.StatusUnsupportedMediaType, requestID, "invalid_content_type", "Content-Type must be application/json", false)
		return nil, false
	}
	if request.ContentLength > h.bodyLimit {
		writeError(writer, http.StatusRequestEntityTooLarge, requestID, "request_too_large", "request body exceeds the configured limit", false)
		return nil, false
	}
	request.Body = http.MaxBytesReader(writer, request.Body, h.bodyLimit)
	body, err := io.ReadAll(request.Body)
	if err != nil {
		writeError(writer, http.StatusRequestEntityTooLarge, requestID, "request_too_large", "request body exceeds the configured limit", false)
		return nil, false
	}
	if err := h.verifier.Verify(request, body); err != nil {
		writeError(writer, http.StatusUnauthorized, requestID, "unauthorized", "request authentication failed", false)
		return nil, false
	}
	return body, true
}

func (h *RunbookHandler) acquire(writer http.ResponseWriter, requestID string) bool {
	select {
	case h.concurrency <- struct{}{}:
		return true
	default:
		writer.Header().Set("Retry-After", "1")
		writeError(writer, http.StatusTooManyRequests, requestID, "runbook_concurrency_limit", "runbook concurrency limit reached", true)
		return false
	}
}

func (h *RunbookHandler) release() { <-h.concurrency }
