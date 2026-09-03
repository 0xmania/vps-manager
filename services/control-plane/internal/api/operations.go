package api

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"
	"unicode"

	"golang.org/x/crypto/ssh"

	"vpsmanager/services/ai"
	"vpsmanager/services/connector/sshconnector"
	"vpsmanager/services/control-plane/internal/anomaly"
	"vpsmanager/services/control-plane/internal/auth"
	"vpsmanager/services/control-plane/internal/model"
	"vpsmanager/services/control-plane/internal/snapshot"
)

type readOnlyCommandRequest struct {
	CommandID  string            `json:"commandId"`
	Parameters map[string]string `json:"parameters,omitempty"`
}

func (s *Server) createReadOnlyCommand(w http.ResponseWriter, r *http.Request) {
	principal := principalFrom(r.Context())
	host, ok := s.requireSSHJobTarget(w, r)
	if !ok {
		return
	}
	var input readOnlyCommandRequest
	if err := decodeJSON(w, r, &input); err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	command, descriptor, err := parseReadOnlyCommand(input)
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "validation_error", err.Error())
		return
	}
	_ = command // Validated now and reconstructed again immediately before execution.
	job, jobContext, ok := s.enqueueSSHJob(w, r, principal, host.ID, "read_only_command", &descriptor)
	if !ok {
		return
	}
	go s.runReadOnlyCommandJob(jobContext, job.ID, principal)
	w.Header().Set("Location", "/api/v1/jobs/"+job.ID)
	writeJSON(w, http.StatusAccepted, job)
}

func parseReadOnlyCommand(input readOnlyCommandRequest) (sshconnector.Command, model.CommandDescriptor, error) {
	if len(input.Parameters) > 1 {
		return sshconnector.Command{}, model.CommandDescriptor{}, errors.New("command accepts at most one known parameter")
	}
	for key := range input.Parameters {
		if key != "service" {
			return sshconnector.Command{}, model.CommandDescriptor{}, errors.New("command contains an unknown parameter")
		}
	}
	request := sshconnector.ReadOnlyCommandRequest{ID: sshconnector.CommandID(input.CommandID)}
	if service, ok := input.Parameters["service"]; ok {
		request.Service = sshconnector.ServiceTarget(service)
	}
	command, err := sshconnector.ReadOnlyCommand(request)
	if err != nil {
		return sshconnector.Command{}, model.CommandDescriptor{}, err
	}
	parameters := make(map[string]string, len(input.Parameters))
	for key, value := range input.Parameters {
		parameters[key] = value
	}
	if len(parameters) == 0 {
		parameters = nil
	}
	return command, model.CommandDescriptor{ID: string(command.ID()), Parameters: parameters}, nil
}

func (s *Server) createAnomalyScan(w http.ResponseWriter, r *http.Request) {
	principal := principalFrom(r.Context())
	host, ok := s.requireSSHJobTarget(w, r)
	if !ok {
		return
	}
	var input struct{}
	if err := decodeJSON(w, r, &input); err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	job, jobContext, ok := s.enqueueSSHJob(w, r, principal, host.ID, "process_anomaly_scan", nil)
	if !ok {
		return
	}
	go s.runAnomalyScanJob(jobContext, job.ID, principal)
	w.Header().Set("Location", "/api/v1/jobs/"+job.ID)
	writeJSON(w, http.StatusAccepted, job)
}

func (s *Server) requireSSHJobTarget(w http.ResponseWriter, r *http.Request) (model.Host, bool) {
	hostID := r.PathValue("hostID")
	if !s.checkHostScope(w, r, hostID) {
		return model.Host{}, false
	}
	if !s.config.SecretExecutionEnabled {
		writeError(w, r, http.StatusServiceUnavailable, "execution_boundary_unavailable", "SSH execution requires the independent secret handoff service")
		return model.Host{}, false
	}
	host, err := s.repository.GetHost(hostID)
	if err != nil {
		writeStoreError(w, r, err)
		return model.Host{}, false
	}
	if host.HostKey == nil {
		writeError(w, r, http.StatusConflict, "host_key_required", "host key must be confirmed before SSH jobs can run")
		return model.Host{}, false
	}
	if _, err := s.repository.GetCredential(hostID); err != nil {
		writeError(w, r, http.StatusConflict, "credential_required", "an SSH credential is required before SSH jobs can run")
		return model.Host{}, false
	}
	return host, true
}

func (s *Server) enqueueSSHJob(w http.ResponseWriter, r *http.Request, principal auth.Principal, hostID, jobType string, command *model.CommandDescriptor) (model.Job, context.Context, bool) {
	id, err := model.NewID("job")
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "internal_error", "could not create job")
		return model.Job{}, nil, false
	}
	job := model.Job{
		ID: id, Type: jobType, HostID: hostID, State: model.JobQueued, RequestedBy: principal.Subject,
		RequestedSessionID: principal.SessionID, CreatedAt: s.now().UTC(), Version: 1, Command: command,
	}
	if err := s.repository.CreateJob(job); err != nil {
		writeError(w, r, http.StatusConflict, "conflict", "could not create job")
		return model.Job{}, nil, false
	}
	s.audit(r, principal, "job.created", "job", job.ID, "success", map[string]any{"hostId": hostID, "type": job.Type, "commandId": commandID(command)})
	jobContext, cancel := context.WithCancel(context.Background())
	s.jobsMu.Lock()
	s.jobCancels[job.ID] = cancel
	s.jobsMu.Unlock()
	return job, jobContext, true
}

func commandID(command *model.CommandDescriptor) string {
	if command == nil {
		return ""
	}
	return command.ID
}

func (s *Server) runReadOnlyCommandJob(parent context.Context, jobID string, principal auth.Principal) {
	ctx, cancel := context.WithTimeout(parent, s.config.JobTimeout)
	defer cancel()
	defer s.unregisterJob(jobID)
	job, ok := s.startAuthorizedJob(ctx, jobID, principal, auth.CommandsRun)
	if !ok {
		return
	}
	if job.Command == nil {
		s.finishOperationJob(jobID, principal, nil, nil, model.JobFailed, "catalog_invalid", "stored command is not in the catalog")
		return
	}
	command, _, err := parseReadOnlyCommand(readOnlyCommandRequest{CommandID: job.Command.ID, Parameters: job.Command.Parameters})
	if err != nil {
		s.finishOperationJob(jobID, principal, nil, nil, model.JobFailed, "catalog_invalid", "stored command is not in the catalog")
		return
	}
	result, err := s.executeCatalog(ctx, job, auth.CommandsRun, command, 64<<10)
	if err != nil {
		state, code, message := safeOperationError(err, "command")
		s.finishOperationJob(jobID, principal, nil, nil, state, code, message)
		return
	}
	commandResult := &model.CommandResult{
		CommandID: string(command.ID()), Stdout: safeRemoteOutput(result.Stdout), Stderr: safeRemoteOutput(result.Stderr),
		ExitCode: result.ExitCode, DurationMillis: result.Duration.Milliseconds(), Truncated: false,
	}
	s.finishOperationJob(jobID, principal, commandResult, nil, model.JobSucceeded, "", "")
}

func (s *Server) runAnomalyScanJob(parent context.Context, jobID string, principal auth.Principal) {
	ctx, cancel := context.WithTimeout(parent, s.config.JobTimeout)
	defer cancel()
	defer s.unregisterJob(jobID)
	job, ok := s.startAuthorizedJob(ctx, jobID, principal, auth.AnomalyScansRun)
	if !ok {
		return
	}
	result, err := s.executeCatalog(ctx, job, auth.AnomalyScansRun, sshconnector.ProcessInventoryCommand(), 256<<10)
	if err != nil {
		state, code, message := safeOperationError(err, "anomaly scan")
		s.finishOperationJob(jobID, principal, nil, nil, state, code, message)
		return
	}
	processes, err := anomaly.ParseProcessInventory(result.Stdout)
	if err != nil {
		s.finishOperationJob(jobID, principal, nil, nil, model.JobFailed, "inventory_invalid", "process inventory could not be safely parsed")
		return
	}
	scan := anomaly.Scan(processes, s.now().UTC())
	analysis, err := s.aiAnalysis.Analyze(ctx, scan.Findings)
	if err != nil {
		s.auditWithRequestID("", principal, "anomaly_scan.ai_analyzed", "job", jobID, "failed", map[string]any{"mode": "unavailable", "reason": "analysis_error"})
		s.finishOperationJob(jobID, principal, nil, nil, model.JobFailed, "ai_analysis_failed", "anomaly findings could not be analyzed")
		return
	}
	scan.AIAnalysis = &ai.Outcome{
		Analysis: analysis.Analysis, Mode: analysis.Mode, FallbackReason: analysis.FallbackReason,
	}
	s.auditWithRequestID("", principal, "anomaly_scan.ai_analyzed", "job", jobID, "success", map[string]any{
		"mode": analysis.Mode, "reason": analysis.FallbackReason,
	})
	s.finishOperationJob(jobID, principal, nil, &scan, model.JobSucceeded, "", "")
}

func (s *Server) startAuthorizedJob(ctx context.Context, jobID string, principal auth.Principal, permission auth.Permission) (model.Job, bool) {
	queued, err := s.repository.GetJob(jobID)
	if err != nil {
		return model.Job{}, false
	}
	if _, ok := s.sessions.AuthorizeSession(queued.RequestedSessionID, permission, queued.HostID); !ok {
		s.finishQueuedCancellation(jobID, principal, "authorization_expired", "job authorization expired or was revoked")
		return model.Job{}, false
	}
	select {
	case <-ctx.Done():
		s.finishQueuedCancellation(jobID, principal, "cancelled", "job was cancelled")
		return model.Job{}, false
	default:
	}
	job, err := s.repository.MutateJob(jobID, func(job model.Job) (model.Job, error) {
		return model.TransitionJob(job, model.JobRunning, s.now().UTC())
	})
	if err != nil {
		return model.Job{}, false
	}
	return job, true
}

func (s *Server) executeCatalog(ctx context.Context, job model.Job, permission auth.Permission, command sshconnector.Command, maxOutput int64) (sshconnector.Result, error) {
	host, err := s.repository.GetHost(job.HostID)
	if err != nil {
		return sshconnector.Result{}, errors.New("target host is unavailable")
	}
	credential, err := s.repository.GetCredential(job.HostID)
	if err != nil {
		return sshconnector.Result{}, errors.New("SSH credential is unavailable")
	}
	_, ok := s.sessions.AuthorizeSession(job.RequestedSessionID, permission, job.HostID)
	if !ok {
		return sshconnector.Result{}, errAuthorizationExpired
	}
	var result sshconnector.Result
	err = s.credentials.Open(ctx, credential.Envelope, s.credentialAAD(job.HostID, credential.Metadata.ID), func(plaintext []byte) error {
		signer, parseErr := snapshot.ParseCredentialSigner(plaintext)
		if parseErr != nil {
			return parseErr
		}
		var runErr error
		result, runErr = s.collector.ExecuteCatalogCommand(ctx, host, ssh.PublicKeys(signer), command, 20*time.Second, maxOutput)
		return runErr
	})
	return result, err
}

var errAuthorizationExpired = errors.New("job authorization expired")

func (s *Server) unregisterJob(jobID string) {
	s.jobsMu.Lock()
	delete(s.jobCancels, jobID)
	s.jobsMu.Unlock()
}

func (s *Server) finishOperationJob(jobID string, principal auth.Principal, command *model.CommandResult, scan *model.AnomalyScanResult, state model.JobState, code, message string) {
	job, err := s.repository.MutateJob(jobID, func(job model.Job) (model.Job, error) {
		updated, transitionErr := model.TransitionJob(job, state, s.now().UTC())
		if transitionErr != nil {
			return model.Job{}, transitionErr
		}
		updated.CommandResult, updated.AnomalyScan = command, scan
		if code != "" {
			updated.Error = &model.JobError{Code: code, Message: message}
		}
		return updated, nil
	})
	if err == nil {
		s.auditWithRequestID("", principal, "job.finished", "job", jobID, string(state), map[string]any{"hostId": job.HostID, "errorCode": code, "type": job.Type})
	}
}

func safeOperationError(err error, operation string) (model.JobState, string, string) {
	if errors.Is(err, errAuthorizationExpired) {
		return model.JobCancelled, "authorization_expired", "job authorization expired or was revoked"
	}
	if errors.Is(err, context.Canceled) {
		return model.JobCancelled, "cancelled", "job was cancelled"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return model.JobTimedOut, "timeout", operation + " timed out"
	}
	if errors.Is(err, sshconnector.ErrHostKeyMismatch) || errors.Is(err, sshconnector.ErrHostKeyRequired) {
		return model.JobFailed, "host_key_verification_failed", "SSH host key verification failed"
	}
	if errors.Is(err, sshconnector.ErrOutputLimit) {
		return model.JobFailed, "output_limit", operation + " exceeded its output limit"
	}
	if errors.Is(err, sshconnector.ErrTargetDenied) {
		return model.JobFailed, "target_denied", "SSH target is blocked by network policy"
	}
	return model.JobFailed, "operation_failed", operation + " failed"
}

func safeRemoteOutput(value []byte) string {
	text := strings.ToValidUTF8(string(value), "�")
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' || !unicode.IsControl(r) {
			return r
		}
		return ' '
	}, text)
}
