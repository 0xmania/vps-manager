package api

import (
	"context"
	"crypto/rsa"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"

	connectorprotocol "vpsmanager/services/connector-protocol"
	"vpsmanager/services/connector/sshconnector"
	"vpsmanager/services/control-plane/internal/aianalysis"
	"vpsmanager/services/control-plane/internal/audit"
	"vpsmanager/services/control-plane/internal/auth"
	"vpsmanager/services/control-plane/internal/credentials"
	"vpsmanager/services/control-plane/internal/model"
	"vpsmanager/services/control-plane/internal/snapshot"
	"vpsmanager/services/control-plane/internal/store"
	"vpsmanager/services/websshgateway"
)

const (
	defaultJobTimeout = 100 * time.Second
	maxJSONBody       = 512 << 10
)

type Config struct {
	DevMode                    bool
	DevBootstrapToken          string
	SessionTTL                 time.Duration
	JobTimeout                 time.Duration
	ProbeTimeout               time.Duration
	AllowPrivateTargets        bool
	IdentityVerifier           IdentityAssertionVerifier
	InstallationID             string
	SecretExecutionEnabled     bool
	ReadinessChecks            []DependencyProbe
	AIAnalyzer                 *aianalysis.Adapter
	ConnectorClient            *connectorprotocol.Client
	WebSSHConfig               *websshgateway.Config
	RunbookConnector           RunbookConnector
	MutationsEnabled           bool
	CloudflareExecutionEnabled bool
	CloudflareProviderFactory  CloudflareProviderFactory
}

type DependencyProbe interface {
	VerifyRuntime(context.Context) error
}

type IdentityAssertionVerifier interface {
	Verify(string) (auth.Principal, error)
}

type HostKeyProber interface {
	ProbeHostKey(context.Context, string, int, bool) (sshconnector.HostKeyObservation, error)
}

type Server struct {
	config                    Config
	repository                store.Repository
	sessions                  *auth.Sessions
	credentials               *credentials.Service
	collector                 *snapshot.Collector
	prober                    HostKeyProber
	aiAnalysis                *aianalysis.Adapter
	runbooks                  RunbookConnector
	webSSH                    *websshgateway.Broker
	cloudflareProviderFactory CloudflareProviderFactory
	now                       func() time.Time
	handler                   http.Handler
	jobsMu                    sync.Mutex
	jobCancels                map[string]context.CancelFunc
	probeSlots                chan struct{}
	auditFailed               atomic.Bool
}

func NewServer(config Config, repository store.Repository, sessions *auth.Sessions, credentialService *credentials.Service, collector *snapshot.Collector, prober HostKeyProber) (*Server, error) {
	if repository == nil || sessions == nil || credentialService == nil || collector == nil || prober == nil {
		return nil, errors.New("all server dependencies are required")
	}
	if config.DevMode && len(config.DevBootstrapToken) < 32 {
		return nil, errors.New("development bootstrap token must contain at least 32 bytes")
	}
	if config.InstallationID == "" {
		if !config.DevMode {
			return nil, errors.New("production installation id is required")
		}
		config.InstallationID = "development"
	}
	if config.DevMode {
		config.SecretExecutionEnabled = true
	} else if config.SecretExecutionEnabled {
		return nil, errors.New("control-plane secret execution is forbidden in production")
	}
	if config.SessionTTL <= 0 {
		config.SessionTTL = time.Hour
	}
	if config.SessionTTL > 8*time.Hour {
		return nil, errors.New("session ttl may not exceed eight hours")
	}
	if config.JobTimeout <= 0 {
		config.JobTimeout = defaultJobTimeout
	}
	if config.ProbeTimeout <= 0 {
		config.ProbeTimeout = 12 * time.Second
	}
	if config.AIAnalyzer == nil {
		var err error
		config.AIAnalyzer, err = aianalysis.NewOffline()
		if err != nil {
			return nil, err
		}
	}
	server := &Server{
		config: config, repository: repository, sessions: sessions,
		credentials: credentialService, collector: collector, prober: prober, now: time.Now,
		aiAnalysis: config.AIAnalyzer, runbooks: config.RunbookConnector,
		cloudflareProviderFactory: config.CloudflareProviderFactory,
		jobCancels:                make(map[string]context.CancelFunc),
		probeSlots:                make(chan struct{}, 4),
	}
	if config.WebSSHConfig != nil && config.DevMode && config.SecretExecutionEnabled {
		if config.ConnectorClient == nil {
			return nil, errors.New("WebSSH requires the external Connector client")
		}
		broker, err := websshgateway.New(*config.WebSSHConfig, config.ConnectorClient,
			websshgateway.AuthorizerFunc(server.authorizeWebSSH), websshgateway.AuditorFunc(server.auditWebSSH))
		if err != nil {
			return nil, err
		}
		server.webSSH = broker
	}
	server.handler = server.routes()
	return server, nil
}

func (s *Server) Handler() http.Handler { return s.handler }

func (s *Server) Close() error {
	if s.webSSH != nil {
		return s.webSSH.Close()
	}
	return nil
}

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.health)
	mux.HandleFunc("POST /api/v1/dev/sessions", s.createDevSession)
	mux.HandleFunc("POST /api/v1/identity/sessions", s.createIdentitySession)
	mux.Handle("DELETE /api/v1/sessions/current", s.require(auth.SessionRevokeSelf, http.HandlerFunc(s.revokeCurrentSession)))
	mux.HandleFunc("GET /readyz", s.ready)
	mux.Handle("GET /api/v1/hosts", s.require(auth.HostsRead, http.HandlerFunc(s.listHosts)))
	mux.Handle("POST /api/v1/hosts", s.require(auth.HostsWrite, http.HandlerFunc(s.createHost)))
	mux.Handle("GET /api/v1/hosts/{hostID}", s.require(auth.HostsRead, http.HandlerFunc(s.getHost)))
	mux.Handle("PATCH /api/v1/hosts/{hostID}", s.require(auth.HostsWrite, http.HandlerFunc(s.updateHost)))
	mux.Handle("DELETE /api/v1/hosts/{hostID}", s.require(auth.HostsDelete, http.HandlerFunc(s.deleteHost)))
	mux.Handle("PUT /api/v1/hosts/{hostID}/host-key", s.require(auth.HostKeyPin, http.HandlerFunc(s.pinHostKey)))
	mux.Handle("POST /api/v1/hosts/{hostID}/host-key/probe", s.require(auth.HostKeyPin, http.HandlerFunc(s.probeHostKey)))
	mux.Handle("GET /api/v1/hosts/{hostID}/credential", s.require(auth.CredentialsManage, http.HandlerFunc(s.getCredential)))
	mux.Handle("POST /api/v1/hosts/{hostID}/credential", s.require(auth.CredentialsManage, http.HandlerFunc(s.putCredential)))
	mux.Handle("DELETE /api/v1/hosts/{hostID}/credential", s.require(auth.CredentialsManage, http.HandlerFunc(s.deleteCredential)))
	mux.Handle("POST /api/v1/hosts/{hostID}/runtime-snapshots", s.require(auth.SnapshotsRun, http.HandlerFunc(s.createRuntimeSnapshot)))
	mux.Handle("POST /api/v1/hosts/{hostID}/commands", s.require(auth.CommandsRun, http.HandlerFunc(s.createReadOnlyCommand)))
	mux.Handle("POST /api/v1/hosts/{hostID}/anomaly-scans", s.require(auth.AnomalyScansRun, http.HandlerFunc(s.createAnomalyScan)))
	mux.Handle("POST /api/v1/hosts/{hostID}/terminal-sessions", s.require(auth.TerminalSessionsOpen, http.HandlerFunc(s.createTerminalSession)))
	mux.Handle("POST /api/v1/hosts/{hostID}/runbooks/preview", s.require(auth.RunbooksPreview, http.HandlerFunc(s.previewRunbook)))
	mux.Handle(websshgateway.ConnectPath, s.webSSHHandler())
	mux.Handle("GET /api/v1/jobs", s.require(auth.JobsRead, http.HandlerFunc(s.listJobs)))
	mux.Handle("GET /api/v1/jobs/{jobID}", s.require(auth.JobsRead, http.HandlerFunc(s.getJob)))
	mux.Handle("POST /api/v1/jobs/{jobID}/cancel", s.require(auth.JobsCancel, http.HandlerFunc(s.cancelJob)))
	mux.Handle("POST /api/v1/jobs/{jobID}/runbook-execute", s.require(auth.RunbooksExecute, http.HandlerFunc(s.executeRunbook)))
	mux.Handle("GET /api/v1/audit-events", s.require(auth.AuditRead, http.HandlerFunc(s.listAuditEvents)))
	mux.Handle("GET /api/v1/cloudflare/workers", s.require(auth.WorkersRead, http.HandlerFunc(s.listWorkers)))
	mux.Handle("POST /api/v1/cloudflare/workers", s.require(auth.WorkersWrite, http.HandlerFunc(s.createWorker)))
	mux.Handle("GET /api/v1/cloudflare/workers/{workerID}", s.require(auth.WorkersRead, http.HandlerFunc(s.getWorker)))
	mux.Handle("GET /api/v1/cloudflare/workers/{workerID}/token", s.require(auth.WorkerTokensManage, http.HandlerFunc(s.getWorkerToken)))
	mux.Handle("POST /api/v1/cloudflare/workers/{workerID}/token", s.require(auth.WorkerTokensManage, http.HandlerFunc(s.putWorkerToken)))
	mux.Handle("DELETE /api/v1/cloudflare/workers/{workerID}/token", s.require(auth.WorkerTokensManage, http.HandlerFunc(s.deleteWorkerToken)))
	mux.Handle("GET /api/v1/cloudflare/workers/{workerID}/versions", s.require(auth.WorkersRead, http.HandlerFunc(s.listWorkerVersions)))
	mux.Handle("POST /api/v1/cloudflare/workers/{workerID}/versions", s.require(auth.WorkersWrite, http.HandlerFunc(s.createWorkerVersion)))
	mux.Handle("GET /api/v1/cloudflare/workers/{workerID}/deployments", s.require(auth.WorkersRead, http.HandlerFunc(s.listWorkerDeployments)))
	mux.Handle("POST /api/v1/cloudflare/workers/{workerID}/deployments", s.require(auth.WorkerDeploymentsPlan, http.HandlerFunc(s.createWorkerDeployment)))
	mux.Handle("POST /api/v1/cloudflare/workers/{workerID}/deployments/{deploymentID}/execute", s.require(auth.WorkerDeploymentsRun, http.HandlerFunc(s.executeWorkerDeployment)))
	return securityHeaders(requestIDMiddleware(mux))
}

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "storage": s.repository.StorageMode(), "devAuth": s.config.DevMode, "identityBridge": s.config.IdentityVerifier != nil, "secretExecution": s.config.SecretExecutionEnabled})
}

func (s *Server) ready(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	if s.auditFailed.Load() || s.repository.Ready(ctx) != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"status": "unavailable", "storage": s.repository.StorageMode()})
		return
	}
	for _, dependency := range s.config.ReadinessChecks {
		if dependency == nil || dependency.VerifyRuntime(ctx) != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"status": "unavailable", "storage": s.repository.StorageMode()})
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ready", "storage": s.repository.StorageMode()})
}

type devSessionRequest struct {
	Subject  string    `json:"subject"`
	Role     auth.Role `json:"role"`
	AllHosts bool      `json:"allHosts"`
	HostIDs  []string  `json:"hostIds,omitempty"`
}

func (s *Server) createDevSession(w http.ResponseWriter, r *http.Request) {
	if !s.config.DevMode {
		writeError(w, r, http.StatusNotFound, "not_found", "resource not found")
		return
	}
	if !auth.SecureTokenEqual(r.Header.Get("X-Dev-Bootstrap"), s.config.DevBootstrapToken) {
		writeError(w, r, http.StatusUnauthorized, "unauthorized", "development bootstrap authentication failed")
		return
	}
	var input devSessionRequest
	if err := decodeJSON(w, r, &input); err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	input.Subject = strings.TrimSpace(input.Subject)
	if len(input.Subject) < 1 || len(input.Subject) > 128 || !auth.ValidRole(input.Role) || (input.AllHosts && len(input.HostIDs) > 0) {
		writeError(w, r, http.StatusBadRequest, "validation_error", "subject and valid role are required")
		return
	}
	for _, hostID := range input.HostIDs {
		if !strings.HasPrefix(hostID, "host_") || len(hostID) > 128 {
			writeError(w, r, http.StatusBadRequest, "validation_error", "hostIds contains an invalid host id")
			return
		}
	}
	token, session, err := s.sessions.Issue(auth.Principal{Subject: input.Subject, Role: input.Role, AllHosts: input.AllHosts, HostIDs: input.HostIDs}, s.config.SessionTTL)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "internal_error", "could not issue development session")
		return
	}
	s.audit(r, session.Principal, "session.created", "session", "", "success", nil)
	writeJSON(w, http.StatusCreated, map[string]any{
		"token": token, "tokenType": "Bearer", "subject": input.Subject,
		"role": input.Role, "allHosts": session.Principal.AllHosts, "hostIds": session.Principal.HostIDs,
		"expiresAt": session.ExpiresAt,
	})
}

type identitySessionRequest struct {
	Assertion string `json:"assertion"`
}

func (s *Server) createIdentitySession(w http.ResponseWriter, r *http.Request) {
	if s.config.IdentityVerifier == nil {
		writeError(w, r, http.StatusNotFound, "not_found", "resource not found")
		return
	}
	if r.ContentLength > 16<<10 {
		writeError(w, r, http.StatusRequestEntityTooLarge, "request_too_large", "identity assertion request is too large")
		return
	}
	var input identitySessionRequest
	if err := decodeJSON(w, r, &input); err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	principal, err := s.config.IdentityVerifier.Verify(input.Assertion)
	input.Assertion = ""
	if err != nil {
		writeError(w, r, http.StatusUnauthorized, "identity_assertion_rejected", "identity assertion was rejected")
		return
	}
	token, session, err := s.sessions.Issue(principal, s.config.SessionTTL)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "internal_error", "could not issue session")
		return
	}
	s.audit(r, session.Principal, "session.identity_exchanged", "session", "", "success", nil)
	writeJSON(w, http.StatusCreated, map[string]any{
		"token": token, "tokenType": "Bearer", "subject": session.Principal.Subject,
		"role": session.Principal.Role, "allHosts": session.Principal.AllHosts,
		"hostIds": session.Principal.HostIDs, "expiresAt": session.ExpiresAt,
	})
}

func (s *Server) revokeCurrentSession(w http.ResponseWriter, r *http.Request) {
	principal := principalFrom(r.Context())
	s.audit(r, principal, "session.revoked", "session", "", "success", nil)
	if !s.sessions.Revoke(r.Header.Get("Authorization")) {
		writeError(w, r, http.StatusUnauthorized, "unauthorized", "session is no longer active")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type createHostRequest struct {
	Name     string            `json:"name"`
	Address  string            `json:"address"`
	Port     int               `json:"port,omitempty"`
	Username string            `json:"username"`
	Labels   map[string]string `json:"labels,omitempty"`
}

func (s *Server) createHost(w http.ResponseWriter, r *http.Request) {
	principal := principalFrom(r.Context())
	if !principal.AllHosts {
		writeError(w, r, http.StatusForbidden, "host_scope_required", "creating hosts requires an all-hosts session scope")
		return
	}
	var input createHostRequest
	if err := decodeJSON(w, r, &input); err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if input.Port == 0 {
		input.Port = 22
	}
	if err := validateHost(input.Name, input.Address, input.Port, input.Username, input.Labels, s.config.AllowPrivateTargets); err != nil {
		writeError(w, r, http.StatusBadRequest, "validation_error", err.Error())
		return
	}
	id, err := model.NewID("host")
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "internal_error", "could not create host")
		return
	}
	now := s.now().UTC()
	host := model.Host{
		ID: id, Name: strings.TrimSpace(input.Name), Address: normalizeAddress(input.Address), Port: input.Port,
		Username: strings.TrimSpace(input.Username), Labels: input.Labels, Version: 1, CreatedAt: now, UpdatedAt: now,
	}
	if err := s.repository.CreateHost(host); err != nil {
		writeError(w, r, http.StatusConflict, "conflict", "host could not be created")
		return
	}
	s.audit(r, principal, "host.created", "host", host.ID, "success", map[string]any{"name": host.Name})
	w.Header().Set("Location", "/api/v1/hosts/"+host.ID)
	writeJSON(w, http.StatusCreated, host)
}

func (s *Server) listHosts(w http.ResponseWriter, r *http.Request) {
	principal := principalFrom(r.Context())
	hosts, err := s.repository.ListHosts()
	if err != nil {
		writeStoreError(w, r, err)
		return
	}
	filtered := hosts[:0]
	for _, host := range hosts {
		if auth.CanAccessHost(principal, host.ID) {
			filtered = append(filtered, host)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": filtered})
}

func (s *Server) getHost(w http.ResponseWriter, r *http.Request) {
	if !s.checkHostScope(w, r, r.PathValue("hostID")) {
		return
	}
	host, err := s.repository.GetHost(r.PathValue("hostID"))
	if err != nil {
		writeStoreError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, host)
}

type updateHostRequest struct {
	Version  uint64             `json:"version"`
	Name     *string            `json:"name,omitempty"`
	Address  *string            `json:"address,omitempty"`
	Port     *int               `json:"port,omitempty"`
	Username *string            `json:"username,omitempty"`
	Labels   *map[string]string `json:"labels,omitempty"`
}

func (s *Server) updateHost(w http.ResponseWriter, r *http.Request) {
	principal := principalFrom(r.Context())
	if !s.checkHostScope(w, r, r.PathValue("hostID")) {
		return
	}
	host, err := s.repository.GetHost(r.PathValue("hostID"))
	if err != nil {
		writeStoreError(w, r, err)
		return
	}
	var input updateHostRequest
	if err := decodeJSON(w, r, &input); err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if input.Version == 0 {
		writeError(w, r, http.StatusBadRequest, "validation_error", "version is required")
		return
	}
	oldAddress, oldPort := host.Address, host.Port
	if input.Name != nil {
		host.Name = strings.TrimSpace(*input.Name)
	}
	if input.Address != nil {
		host.Address = normalizeAddress(*input.Address)
	}
	if input.Port != nil {
		host.Port = *input.Port
	}
	if input.Username != nil {
		host.Username = strings.TrimSpace(*input.Username)
	}
	if input.Labels != nil {
		host.Labels = *input.Labels
	}
	if err := validateHost(host.Name, host.Address, host.Port, host.Username, host.Labels, s.config.AllowPrivateTargets); err != nil {
		writeError(w, r, http.StatusBadRequest, "validation_error", err.Error())
		return
	}
	trustReset := oldAddress != host.Address || oldPort != host.Port
	if trustReset {
		host.HostKey = nil
	}
	host.Version = input.Version + 1
	host.UpdatedAt = s.now().UTC()
	if err := s.repository.UpdateHost(host, input.Version); err != nil {
		writeStoreError(w, r, err)
		return
	}
	s.audit(r, principal, "host.updated", "host", host.ID, "success", map[string]any{"hostKeyReset": trustReset})
	writeJSON(w, http.StatusOK, host)
}

func (s *Server) deleteHost(w http.ResponseWriter, r *http.Request) {
	principal := principalFrom(r.Context())
	id := r.PathValue("hostID")
	if !s.checkHostScope(w, r, id) {
		return
	}
	if err := s.repository.DeleteHost(id); err != nil {
		writeStoreError(w, r, err)
		return
	}
	s.audit(r, principal, "host.deleted", "host", id, "success", nil)
	w.WriteHeader(http.StatusNoContent)
}

type pinHostKeyRequest struct {
	Version                    uint64 `json:"version"`
	PublicKey                  string `json:"publicKey"`
	ExpectedFingerprintSHA256  string `json:"expectedFingerprintSha256"`
	Replace                    bool   `json:"replace,omitempty"`
	ExpectedCurrentFingerprint string `json:"expectedCurrentFingerprintSha256,omitempty"`
}

type hostKeyProbeResponse struct {
	Algorithm         string    `json:"algorithm"`
	FingerprintSHA256 string    `json:"fingerprintSha256"`
	PublicKey         string    `json:"publicKey"`
	ResolvedAddress   string    `json:"resolvedAddress"`
	ObservedAt        time.Time `json:"observedAt"`
	Trusted           bool      `json:"trusted"`
}

func (s *Server) probeHostKey(w http.ResponseWriter, r *http.Request) {
	principal := principalFrom(r.Context())
	hostID := r.PathValue("hostID")
	if !s.checkHostScope(w, r, hostID) {
		return
	}
	host, err := s.repository.GetHost(hostID)
	if err != nil {
		writeStoreError(w, r, err)
		return
	}
	select {
	case s.probeSlots <- struct{}{}:
		defer func() { <-s.probeSlots }()
	default:
		writeError(w, r, http.StatusTooManyRequests, "probe_capacity", "too many host-key probes are running")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), s.config.ProbeTimeout)
	defer cancel()
	observation, err := s.prober.ProbeHostKey(ctx, host.Address, host.Port, s.config.AllowPrivateTargets)
	if err != nil {
		code, message := "probe_failed", "SSH host-key probe failed"
		if errors.Is(err, context.DeadlineExceeded) {
			code, message = "probe_timeout", "SSH host-key probe timed out"
		} else if errors.Is(err, sshconnector.ErrTargetDenied) {
			code, message = "target_denied", "SSH target is blocked by network policy"
		}
		s.audit(r, principal, "host_key.probed", "host", hostID, "failed", map[string]any{"errorCode": code})
		writeError(w, r, http.StatusBadGateway, code, message)
		return
	}
	key, parseErr := sshconnector.ParsePinnedHostKey(observation.PublicKey)
	if parseErr != nil || validateHostKeyAlgorithm(key) != nil || ssh.FingerprintSHA256(key) != observation.FingerprintSHA256 {
		s.audit(r, principal, "host_key.probed", "host", hostID, "failed", map[string]any{"errorCode": "invalid_observation"})
		writeError(w, r, http.StatusBadGateway, "invalid_observation", "SSH server returned an unsupported host key")
		return
	}
	response := hostKeyProbeResponse{
		Algorithm: key.Type(), FingerprintSHA256: observation.FingerprintSHA256,
		PublicKey: observation.PublicKey, ResolvedAddress: observation.ResolvedAddress,
		ObservedAt: s.now().UTC(), Trusted: false,
	}
	s.audit(r, principal, "host_key.probed", "host", hostID, "success", map[string]any{
		"fingerprint": observation.FingerprintSHA256, "algorithm": key.Type(),
		"resolvedAddress": observation.ResolvedAddress,
	})
	writeJSON(w, http.StatusOK, response)
}

func (s *Server) pinHostKey(w http.ResponseWriter, r *http.Request) {
	principal := principalFrom(r.Context())
	if !s.checkHostScope(w, r, r.PathValue("hostID")) {
		return
	}
	host, err := s.repository.GetHost(r.PathValue("hostID"))
	if err != nil {
		writeStoreError(w, r, err)
		return
	}
	var input pinHostKeyRequest
	if err := decodeJSON(w, r, &input); err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if input.Version == 0 || strings.TrimSpace(input.ExpectedFingerprintSHA256) == "" {
		writeError(w, r, http.StatusBadRequest, "validation_error", "version and independently verified expected fingerprint are required")
		return
	}
	key, err := sshconnector.ParsePinnedHostKey(input.PublicKey)
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "validation_error", "publicKey must contain exactly one valid OpenSSH public key")
		return
	}
	if err := validateHostKeyAlgorithm(key); err != nil {
		writeError(w, r, http.StatusBadRequest, "validation_error", err.Error())
		return
	}
	fingerprint := ssh.FingerprintSHA256(key)
	if !constantStringEqual(fingerprint, strings.TrimSpace(input.ExpectedFingerprintSHA256)) {
		writeError(w, r, http.StatusBadRequest, "fingerprint_mismatch", "supplied host key does not match the independently verified fingerprint")
		return
	}
	replacing := host.HostKey != nil && host.HostKey.FingerprintSHA256 != fingerprint
	if replacing {
		if !input.Replace || !auth.Allowed(principal.Role, auth.HostKeyReplace) {
			writeError(w, r, http.StatusConflict, "host_key_change", "host key changes require an administrator and explicit replacement confirmation")
			return
		}
		if !constantStringEqual(host.HostKey.FingerprintSHA256, input.ExpectedCurrentFingerprint) {
			writeError(w, r, http.StatusConflict, "host_key_change", "current host key fingerprint confirmation did not match")
			return
		}
	}
	now := s.now().UTC()
	host.HostKey = &model.HostKeyPin{
		Algorithm: key.Type(), FingerprintSHA256: fingerprint,
		PublicKey:   strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key))),
		ConfirmedAt: now, ConfirmedBy: principal.Subject,
	}
	host.Version = input.Version + 1
	host.UpdatedAt = now
	if err := s.repository.UpdateHost(host, input.Version); err != nil {
		writeStoreError(w, r, err)
		return
	}
	action := "host_key.pinned"
	if replacing {
		action = "host_key.replaced"
	}
	s.audit(r, principal, action, "host", host.ID, "success", map[string]any{"fingerprint": fingerprint, "algorithm": key.Type()})
	writeJSON(w, http.StatusOK, host)
}

type credentialRequest struct {
	PrivateKey string `json:"privateKey"`
	Passphrase string `json:"passphrase,omitempty"`
}

func (s *Server) putCredential(w http.ResponseWriter, r *http.Request) {
	principal := principalFrom(r.Context())
	hostID := r.PathValue("hostID")
	if !s.checkHostScope(w, r, hostID) {
		return
	}
	if _, err := s.repository.GetHost(hostID); err != nil {
		writeStoreError(w, r, err)
		return
	}
	var input credentialRequest
	if err := decodeJSON(w, r, &input); err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_request", "credential payload is invalid")
		return
	}
	if len(input.PrivateKey) == 0 || len(input.PrivateKey) > 256<<10 || len(input.Passphrase) > 4096 {
		writeError(w, r, http.StatusBadRequest, "validation_error", "private key is required and must be within the size limit")
		return
	}
	var signer ssh.Signer
	var err error
	if input.Passphrase == "" {
		signer, err = ssh.ParsePrivateKey([]byte(input.PrivateKey))
	} else {
		signer, err = ssh.ParsePrivateKeyWithPassphrase([]byte(input.PrivateKey), []byte(input.Passphrase))
	}
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_credential", "SSH private key or passphrase is invalid")
		return
	}
	id, err := model.NewID("cred")
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "internal_error", "could not store credential")
		return
	}
	plaintext, err := json.Marshal(input)
	input.PrivateKey, input.Passphrase = "", ""
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "internal_error", "could not store credential")
		return
	}
	defer wipe(plaintext)
	aad := s.credentialAAD(hostID, id)
	envelope, err := s.credentials.Seal(r.Context(), plaintext, aad)
	if err != nil {
		writeError(w, r, http.StatusServiceUnavailable, "kms_unavailable", "credential encryption is unavailable")
		return
	}
	metadata := model.CredentialMetadata{
		ID: id, HostID: hostID, Kind: "ssh_private_key", PublicKeyFingerprint: ssh.FingerprintSHA256(signer.PublicKey()),
		KeyID: envelope.KeyID, CreatedAt: s.now().UTC(), CreatedBy: principal.Subject,
	}
	if err := s.repository.PutCredential(model.StoredCredential{Metadata: metadata, Envelope: envelope}); err != nil {
		writeStoreError(w, r, err)
		return
	}
	s.audit(r, principal, "credential.stored", "host", hostID, "success", map[string]any{"credentialId": id, "publicKeyFingerprint": metadata.PublicKeyFingerprint})
	writeJSON(w, http.StatusCreated, metadata)
}

func (s *Server) getCredential(w http.ResponseWriter, r *http.Request) {
	if !s.checkHostScope(w, r, r.PathValue("hostID")) {
		return
	}
	credential, err := s.repository.GetCredential(r.PathValue("hostID"))
	if err != nil {
		writeStoreError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, credential.Metadata)
}

func (s *Server) deleteCredential(w http.ResponseWriter, r *http.Request) {
	principal := principalFrom(r.Context())
	hostID := r.PathValue("hostID")
	if !s.checkHostScope(w, r, hostID) {
		return
	}
	if err := s.repository.DeleteCredential(hostID); err != nil {
		writeStoreError(w, r, err)
		return
	}
	s.audit(r, principal, "credential.deleted", "host", hostID, "success", nil)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) createRuntimeSnapshot(w http.ResponseWriter, r *http.Request) {
	principal := principalFrom(r.Context())
	hostID := r.PathValue("hostID")
	if !s.checkHostScope(w, r, hostID) {
		return
	}
	if !s.config.SecretExecutionEnabled {
		writeError(w, r, http.StatusServiceUnavailable, "execution_boundary_unavailable", "SSH execution requires the independent secret handoff service")
		return
	}
	host, err := s.repository.GetHost(hostID)
	if err != nil {
		writeStoreError(w, r, err)
		return
	}
	if host.HostKey == nil {
		writeError(w, r, http.StatusConflict, "host_key_required", "host key must be confirmed before SSH jobs can run")
		return
	}
	if _, err := s.repository.GetCredential(hostID); err != nil {
		writeError(w, r, http.StatusConflict, "credential_required", "an SSH credential is required before SSH jobs can run")
		return
	}
	id, err := model.NewID("job")
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "internal_error", "could not create job")
		return
	}
	job := model.Job{ID: id, Type: "runtime_snapshot", HostID: hostID, State: model.JobQueued, RequestedBy: principal.Subject, RequestedSessionID: principal.SessionID, CreatedAt: s.now().UTC(), Version: 1}
	if err := s.repository.CreateJob(job); err != nil {
		writeError(w, r, http.StatusConflict, "conflict", "could not create job")
		return
	}
	s.audit(r, principal, "job.created", "job", job.ID, "success", map[string]any{"hostId": hostID, "type": job.Type})
	jobContext, cancel := context.WithCancel(context.Background())
	s.jobsMu.Lock()
	s.jobCancels[job.ID] = cancel
	s.jobsMu.Unlock()
	go s.runSnapshotJob(jobContext, job.ID, principal)
	w.Header().Set("Location", "/api/v1/jobs/"+job.ID)
	writeJSON(w, http.StatusAccepted, job)
}

func (s *Server) runSnapshotJob(parent context.Context, jobID string, principal auth.Principal) {
	ctx, cancel := context.WithTimeout(parent, s.config.JobTimeout)
	defer cancel()
	defer func() {
		s.jobsMu.Lock()
		delete(s.jobCancels, jobID)
		s.jobsMu.Unlock()
	}()
	queued, err := s.repository.GetJob(jobID)
	if err != nil {
		return
	}
	if _, ok := s.sessions.AuthorizeSession(queued.RequestedSessionID, auth.SnapshotsRun, queued.HostID); !ok {
		s.finishQueuedCancellation(jobID, principal, "authorization_expired", "job authorization expired or was revoked")
		return
	}
	select {
	case <-ctx.Done():
		s.finishQueuedCancellation(jobID, principal, "cancelled", "job was cancelled")
		return
	default:
	}
	now := s.now().UTC()
	job, err := s.repository.MutateJob(jobID, func(job model.Job) (model.Job, error) {
		return model.TransitionJob(job, model.JobRunning, now)
	})
	if err != nil {
		return
	}
	host, err := s.repository.GetHost(job.HostID)
	if err != nil {
		s.finishJob(jobID, principal, nil, model.JobFailed, "host_unavailable", "target host is unavailable")
		return
	}
	credential, err := s.repository.GetCredential(job.HostID)
	if err != nil {
		s.finishJob(jobID, principal, nil, model.JobFailed, "credential_unavailable", "SSH credential is unavailable")
		return
	}
	// Re-check permissions, object scope, expiry, and revocation immediately
	// before decrypting credentials or opening a network connection.
	executionPrincipal, ok := s.sessions.AuthorizeSession(job.RequestedSessionID, auth.SnapshotsRun, job.HostID)
	if !ok {
		s.finishJob(jobID, principal, nil, model.JobCancelled, "authorization_expired", "job authorization expired or was revoked")
		return
	}
	principal = executionPrincipal
	var collected model.RuntimeSnapshot
	err = s.credentials.Open(ctx, credential.Envelope, s.credentialAAD(job.HostID, credential.Metadata.ID), func(plaintext []byte) error {
		signer, parseErr := snapshot.ParseCredentialSigner(plaintext)
		if parseErr != nil {
			return parseErr
		}
		result, collectErr := s.collector.Collect(ctx, host, ssh.PublicKeys(signer))
		if collectErr == nil {
			collected = result
		}
		return collectErr
	})
	if err != nil {
		state, code, message := safeJobError(err)
		s.finishJob(jobID, principal, nil, state, code, message)
		return
	}
	s.finishJob(jobID, principal, &collected, model.JobSucceeded, "", "")
}

func (s *Server) finishQueuedCancellation(jobID string, principal auth.Principal, code, message string) {
	now := s.now().UTC()
	_, err := s.repository.MutateJob(jobID, func(job model.Job) (model.Job, error) {
		updated, transitionErr := model.TransitionJob(job, model.JobCancelled, now)
		if transitionErr != nil {
			return model.Job{}, transitionErr
		}
		updated.Error = &model.JobError{Code: code, Message: message}
		return updated, nil
	})
	if err == nil {
		s.auditWithRequestID("", principal, "job.finished", "job", jobID, "cancelled", map[string]any{"errorCode": code})
	}
}

func (s *Server) finishJob(jobID string, principal auth.Principal, result *model.RuntimeSnapshot, state model.JobState, code, message string) {
	now := s.now().UTC()
	job, err := s.repository.MutateJob(jobID, func(job model.Job) (model.Job, error) {
		updated, err := model.TransitionJob(job, state, now)
		if err != nil {
			return model.Job{}, err
		}
		updated.Snapshot = result
		if code != "" {
			updated.Error = &model.JobError{Code: code, Message: message}
		}
		return updated, nil
	})
	if err != nil {
		return
	}
	s.auditWithRequestID("", principal, "job.finished", "job", jobID, string(state), map[string]any{"hostId": job.HostID, "errorCode": code})
}

func (s *Server) listJobs(w http.ResponseWriter, r *http.Request) {
	principal := principalFrom(r.Context())
	jobs, err := s.repository.ListJobs()
	if err != nil {
		writeStoreError(w, r, err)
		return
	}
	filtered := jobs[:0]
	for _, job := range jobs {
		if auth.CanAccessHost(principal, job.HostID) {
			filtered = append(filtered, job)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": filtered})
}

func (s *Server) getJob(w http.ResponseWriter, r *http.Request) {
	job, err := s.repository.GetJob(r.PathValue("jobID"))
	if err != nil {
		writeStoreError(w, r, err)
		return
	}
	if !s.checkHostScope(w, r, job.HostID) {
		return
	}
	writeJSON(w, http.StatusOK, job)
}

func (s *Server) cancelJob(w http.ResponseWriter, r *http.Request) {
	principal := principalFrom(r.Context())
	job, err := s.repository.GetJob(r.PathValue("jobID"))
	if err != nil {
		writeStoreError(w, r, err)
		return
	}
	if !s.checkHostScope(w, r, job.HostID) {
		return
	}
	if job.State != model.JobQueued && job.State != model.JobRunning {
		writeError(w, r, http.StatusConflict, "job_terminal", "job is already in a terminal state")
		return
	}
	s.jobsMu.Lock()
	cancel, ok := s.jobCancels[job.ID]
	s.jobsMu.Unlock()
	if !ok {
		writeError(w, r, http.StatusConflict, "job_not_cancellable", "job can no longer be cancelled")
		return
	}
	cancel()
	s.audit(r, principal, "job.cancel_requested", "job", job.ID, "success", map[string]any{"hostId": job.HostID})
	writeJSON(w, http.StatusAccepted, job)
}

func (s *Server) listAuditEvents(w http.ResponseWriter, r *http.Request) {
	limit := 100
	if value := r.URL.Query().Get("limit"); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil || parsed < 1 || parsed > 500 {
			writeError(w, r, http.StatusBadRequest, "validation_error", "limit must be between 1 and 500")
			return
		}
		limit = parsed
	}
	principal := principalFrom(r.Context())
	events, err := s.repository.ListAudits(500)
	if err != nil {
		writeStoreError(w, r, err)
		return
	}
	filtered := make([]model.AuditEvent, 0, limit)
	for _, event := range events {
		if len(filtered) >= limit {
			break
		}
		hostID, _ := event.Details["hostId"].(string)
		if event.TargetType == "host" {
			hostID = event.TargetID
		}
		if (hostID == "" && (principal.AllHosts || event.Actor == principal.Subject)) || (hostID != "" && auth.CanAccessHost(principal, hostID)) {
			filtered = append(filtered, event)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": filtered})
}

type principalKey struct{}

func (s *Server) require(permission auth.Permission, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal, ok := s.sessions.Authenticate(r.Header.Get("Authorization"))
		if !ok {
			writeError(w, r, http.StatusUnauthorized, "unauthorized", "a valid bearer session is required")
			return
		}
		if !auth.Allowed(principal.Role, permission) {
			s.audit(r, principal, "authorization.denied", "permission", string(permission), "denied", nil)
			writeError(w, r, http.StatusForbidden, "forbidden", "the current role cannot perform this action")
			return
		}
		ctx := context.WithValue(r.Context(), principalKey{}, principal)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func principalFrom(ctx context.Context) auth.Principal {
	principal, _ := ctx.Value(principalKey{}).(auth.Principal)
	return principal
}

func (s *Server) checkHostScope(w http.ResponseWriter, r *http.Request, hostID string) bool {
	if auth.CanAccessHost(principalFrom(r.Context()), hostID) {
		return true
	}
	// Return 404 rather than revealing whether an out-of-scope object exists.
	writeError(w, r, http.StatusNotFound, "not_found", "resource not found")
	return false
}

func (s *Server) audit(r *http.Request, principal auth.Principal, action, targetType, targetID, outcome string, details map[string]any) {
	s.auditWithRequestID(requestIDFrom(r.Context()), principal, action, targetType, targetID, outcome, details)
}

func (s *Server) auditWithRequestID(requestID string, principal auth.Principal, action, targetType, targetID, outcome string, details map[string]any) {
	id, err := model.NewID("audit")
	if err != nil {
		return
	}
	err = s.repository.AppendAudit(model.AuditEvent{
		ID: id, Timestamp: s.now().UTC(), Actor: principal.Subject, Role: principal.Role,
		Action: action, TargetType: targetType, TargetID: targetID, Outcome: outcome,
		RequestID: requestID, Details: audit.SanitizeDetails(details),
	})
	s.auditFailed.Store(err != nil)
}

func safeJobError(err error) (model.JobState, string, string) {
	if errors.Is(err, context.Canceled) {
		return model.JobCancelled, "cancelled", "job was cancelled"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return model.JobTimedOut, "timeout", "snapshot collection timed out"
	}
	if errors.Is(err, sshconnector.ErrHostKeyMismatch) || errors.Is(err, sshconnector.ErrHostKeyRequired) {
		return model.JobFailed, "host_key_verification_failed", "SSH host key verification failed"
	}
	if errors.Is(err, sshconnector.ErrOutputLimit) {
		return model.JobFailed, "output_limit", "snapshot collector exceeded its output limit"
	}
	if errors.Is(err, sshconnector.ErrTargetDenied) {
		return model.JobFailed, "target_denied", "SSH target is blocked by network policy"
	}
	return model.JobFailed, "snapshot_failed", "snapshot collection failed"
}

func credentialAAD(hostID, credentialID string) []byte {
	aad, _ := credentials.ContextAAD("development", hostID, credentialID, "ssh_private_key")
	return aad
}

func (s *Server) credentialAAD(hostID, credentialID string) []byte {
	aad, _ := credentials.ContextAAD(s.config.InstallationID, hostID, credentialID, "ssh_private_key")
	return aad
}

func (s *Server) workerTokenAAD(workerID, tokenID string) []byte {
	aad, _ := credentials.ContextAAD(s.config.InstallationID, workerID, tokenID, "cloudflare_api_token")
	return aad
}

func validateHost(name, address string, port int, username string, labels map[string]string, allowPrivateTargets bool) error {
	name, address, username = strings.TrimSpace(name), strings.TrimSpace(address), strings.TrimSpace(username)
	if len(name) < 1 || len(name) > 100 {
		return errors.New("name must contain 1 to 100 characters")
	}
	if !validAddress(address) {
		return errors.New("address must be an IPv4, IPv6, or DNS hostname without a scheme or port")
	}
	if err := sshconnector.ValidateTargetLiteral(normalizeAddress(address), allowPrivateTargets); err != nil {
		return errors.New("address is blocked by the SSH destination policy")
	}
	if port < 1 || port > 65535 {
		return errors.New("port must be between 1 and 65535")
	}
	if !usernamePattern.MatchString(username) {
		return errors.New("username is not a valid SSH username")
	}
	if len(labels) > 20 {
		return errors.New("at most 20 labels are allowed")
	}
	for key, value := range labels {
		if !labelKeyPattern.MatchString(key) || len(value) > 128 || strings.ContainsAny(value, "\r\n\x00") {
			return errors.New("labels contain an invalid key or value")
		}
	}
	return nil
}

var (
	usernamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]{0,63}$`)
	dnsPattern      = regexp.MustCompile(`(?i)^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	labelKeyPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$`)
)

func validAddress(value string) bool {
	value = normalizeAddress(value)
	if len(value) == 0 || len(value) > 253 || strings.ContainsAny(value, " /\\\r\n\t\x00@") {
		return false
	}
	if net.ParseIP(value) != nil {
		return true
	}
	return dnsPattern.MatchString(value)
}

func normalizeAddress(value string) string {
	value = strings.TrimSpace(value)
	if strings.HasPrefix(value, "[") && strings.HasSuffix(value, "]") {
		value = strings.TrimSuffix(strings.TrimPrefix(value, "["), "]")
	}
	return strings.ToLower(value)
}

func validateHostKeyAlgorithm(key ssh.PublicKey) error {
	switch key.Type() {
	case ssh.KeyAlgoED25519, ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521,
		ssh.KeyAlgoSKECDSA256, ssh.KeyAlgoSKED25519:
		return nil
	case ssh.KeyAlgoRSA:
		cryptoKey, ok := key.(ssh.CryptoPublicKey)
		if !ok {
			return errors.New("RSA host key could not be inspected")
		}
		rsaKey, ok := cryptoKey.CryptoPublicKey().(*rsa.PublicKey)
		if !ok || rsaKey.N.BitLen() < 3072 {
			return errors.New("RSA host keys must contain at least 3072 bits")
		}
		return nil
	default:
		return errors.New("host key algorithm is not allowed")
	}
}

func constantStringEqual(left, right string) bool {
	if len(left) != len(right) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(left), []byte(right)) == 1
}

func decodeJSON(w http.ResponseWriter, r *http.Request, destination any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxJSONBody)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			return errors.New("request body exceeds the size limit")
		}
		return errors.New("request body must be valid JSON with known fields")
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return errors.New("request body must contain exactly one JSON value")
	}
	return nil
}

type errorResponse struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
	RequestID string `json:"requestId,omitempty"`
}

func writeError(w http.ResponseWriter, r *http.Request, status int, code, message string) {
	var body errorResponse
	body.Error.Code, body.Error.Message = code, message
	body.RequestID = requestIDFrom(r.Context())
	writeJSON(w, status, body)
}

func writeStoreError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, r, http.StatusNotFound, "not_found", "resource not found")
	case errors.Is(err, store.ErrConflict):
		writeError(w, r, http.StatusConflict, "version_conflict", "resource was changed; reload and retry")
	default:
		writeError(w, r, http.StatusInternalServerError, "internal_error", "request could not be completed")
	}
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

type requestIDKey struct{}

func requestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, err := model.NewID("req")
		if err != nil {
			id = "req_unavailable"
		}
		w.Header().Set("X-Request-ID", id)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), requestIDKey{}, id)))
	})
}

func requestIDFrom(ctx context.Context) string {
	id, _ := ctx.Value(requestIDKey{}).(string)
	return id
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
}

func wipe(value []byte) {
	for i := range value {
		value[i] = 0
	}
}
