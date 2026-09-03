// Package service implements the isolated, authenticated SSH Connector HTTP
// boundary. Only fixed catalog actions are routed to sshconnector.
package service

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"
	"time"

	connectorprotocol "vpsmanager/services/connector-protocol"
	"vpsmanager/services/connector/sshconnector"

	"golang.org/x/crypto/ssh"
)

const (
	defaultBodyLimit   int64 = 64 << 10
	defaultOutputLimit int64 = 1 << 20
	defaultConcurrency       = 8
)

type Runner interface {
	ProbeHostKey(context.Context, string, int, bool) (sshconnector.HostKeyObservation, error)
	Run(context.Context, sshconnector.Config, sshconnector.Command) (sshconnector.Result, error)
}

type Options struct {
	KeyID               string
	HMACKey             []byte
	ServiceVersion      string
	AllowPrivateTargets bool
	MaxConcurrent       int
	MaxRequestBodyBytes int64
	MaxOutputBytes      int64
	ConnectTimeout      time.Duration
	CommandTimeout      time.Duration
	AuthenticationSkew  time.Duration
	MaxTrackedNonces    int
	Now                 func() time.Time
	Runner              Runner
	WebSSH              WebSSHOptions
}

type Server struct {
	verifier            *connectorprotocol.Verifier
	runner              Runner
	serviceVersion      string
	allowPrivateTargets bool
	bodyLimit           int64
	outputLimit         int64
	connectTimeout      time.Duration
	commandTimeout      time.Duration
	concurrency         chan struct{}
	webSSH              *webSSHManager
}

func New(options Options) (*Server, error) {
	verifier, err := connectorprotocol.NewVerifier(connectorprotocol.VerifierConfig{
		KeyID: options.KeyID, Key: options.HMACKey, MaxSkew: options.AuthenticationSkew,
		MaxNonces: options.MaxTrackedNonces, Now: options.Now,
	})
	if err != nil {
		return nil, err
	}
	if options.MaxConcurrent <= 0 {
		options.MaxConcurrent = defaultConcurrency
	}
	if options.MaxConcurrent > 256 {
		return nil, errors.New("connector concurrency limit must not exceed 256")
	}
	if options.MaxRequestBodyBytes <= 0 {
		options.MaxRequestBodyBytes = defaultBodyLimit
	}
	if options.MaxRequestBodyBytes > 1<<20 {
		return nil, errors.New("connector request body limit must not exceed 1 MiB")
	}
	if options.MaxOutputBytes <= 0 {
		options.MaxOutputBytes = defaultOutputLimit
	}
	if options.MaxOutputBytes > 4<<20 {
		return nil, errors.New("connector output limit must not exceed 4 MiB")
	}
	if options.ConnectTimeout <= 0 {
		options.ConnectTimeout = 10 * time.Second
	}
	if options.ConnectTimeout > 30*time.Second {
		return nil, errors.New("connector connect timeout must not exceed 30 seconds")
	}
	if options.CommandTimeout <= 0 {
		options.CommandTimeout = 30 * time.Second
	}
	if options.CommandTimeout > 5*time.Minute {
		return nil, errors.New("connector command timeout must not exceed five minutes")
	}
	if strings.TrimSpace(options.ServiceVersion) == "" {
		options.ServiceVersion = "dev"
	}
	if options.Runner == nil {
		options.Runner = sshconnector.New()
	}
	webSSH, err := newWebSSHManager(options.WebSSH)
	if err != nil {
		return nil, fmt.Errorf("configure web SSH: %w", err)
	}
	return &Server{
		verifier: verifier, runner: options.Runner, serviceVersion: options.ServiceVersion,
		allowPrivateTargets: options.AllowPrivateTargets, bodyLimit: options.MaxRequestBodyBytes,
		outputLimit: options.MaxOutputBytes, connectTimeout: options.ConnectTimeout,
		commandTimeout: options.CommandTimeout, concurrency: make(chan struct{}, options.MaxConcurrent),
		webSSH: webSSH,
	}, nil
}

func (s *Server) Close() {
	if s != nil && s.webSSH != nil {
		s.webSSH.Close()
	}
}

func (s *Server) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
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
	switch request.URL.Path {
	case connectorprotocol.HealthPath:
		if request.Method != http.MethodGet {
			methodNotAllowed(writer, requestID, http.MethodGet)
			return
		}
		writeJSON(writer, http.StatusOK, connectorprotocol.HealthResponse{Status: "ok", ProtocolVersion: connectorprotocol.ProtocolVersion})
	case connectorprotocol.VersionPath:
		if request.Method != http.MethodGet {
			methodNotAllowed(writer, requestID, http.MethodGet)
			return
		}
		writeJSON(writer, http.StatusOK, connectorprotocol.VersionResponse{
			ServiceVersion: s.serviceVersion, ProtocolVersion: connectorprotocol.ProtocolVersion,
			Actions: s.actions(),
		})
	case connectorprotocol.RuntimeSnapshotPath:
		if request.Method != http.MethodPost {
			methodNotAllowed(writer, requestID, http.MethodPost)
			return
		}
		s.handleRuntimeSnapshot(writer, request, requestID)
	case connectorprotocol.HostKeyProbePath:
		if request.Method != http.MethodPost {
			methodNotAllowed(writer, requestID, http.MethodPost)
			return
		}
		s.handleHostKeyProbe(writer, request, requestID)
	case connectorprotocol.WebSSHTicketPath:
		if request.Method != http.MethodPost {
			methodNotAllowed(writer, requestID, http.MethodPost)
			return
		}
		s.handleWebSSHTicket(writer, request, requestID)
	case connectorprotocol.WebSSHConnectPath:
		if request.Method != http.MethodGet {
			methodNotAllowed(writer, requestID, http.MethodGet)
			return
		}
		s.handleWebSSHConnect(writer, request, requestID)
	default:
		writeError(writer, http.StatusNotFound, requestID, "not_found", "connector endpoint not found", false)
	}
}

func (s *Server) actions() []string {
	actions := []string{connectorprotocol.ActionRuntimeSnapshot, connectorprotocol.ActionHostKeyProbe}
	if s.webSSH != nil && s.webSSH.enabled {
		actions = append(actions, connectorprotocol.ActionWebSSH)
	}
	return actions
}

func (s *Server) handleRuntimeSnapshot(writer http.ResponseWriter, request *http.Request, requestID string) {
	body, ok := s.authenticateJSON(writer, request, requestID)
	if !ok {
		return
	}
	defer wipe(body)
	if !s.acquire(writer, requestID) {
		return
	}
	defer s.release()
	var payload connectorprotocol.RuntimeSnapshotRequest
	if err := decodeStrictJSON(body, &payload); err != nil {
		writeError(writer, http.StatusBadRequest, requestID, "invalid_json", "request must be one valid JSON object with only supported fields", false)
		return
	}
	defer wipe(payload.Credential.PrivateKeyPEM)
	defer wipe(payload.Credential.Passphrase)
	if err := validateRuntimeRequest(payload); err != nil {
		writeError(writer, http.StatusBadRequest, requestID, "invalid_request", "runtime snapshot request is invalid", false)
		return
	}
	pinnedKey, err := sshconnector.ParsePinnedHostKey(payload.PinnedHostKey)
	if err != nil {
		writeError(writer, http.StatusBadRequest, requestID, "invalid_host_key", "pinned host key is invalid", false)
		return
	}
	var signer ssh.Signer
	if len(payload.Credential.Passphrase) == 0 {
		signer, err = ssh.ParsePrivateKey(payload.Credential.PrivateKeyPEM)
	} else {
		signer, err = ssh.ParsePrivateKeyWithPassphrase(payload.Credential.PrivateKeyPEM, payload.Credential.Passphrase)
	}
	if err != nil {
		writeError(writer, http.StatusBadRequest, requestID, "invalid_credential", "SSH private key could not be parsed", false)
		return
	}
	operationTimeout := s.connectTimeout + s.commandTimeout + 5*time.Second
	ctx, cancel := context.WithTimeout(request.Context(), operationTimeout)
	defer cancel()
	result, err := s.runner.Run(ctx, sshconnector.Config{
		Address: payload.Target.Address, Port: payload.Target.Port, User: payload.Target.User,
		Auth: ssh.PublicKeys(signer), PinnedHostKey: pinnedKey, ConnectTimeout: s.connectTimeout,
		CommandTimeout: s.commandTimeout, MaxOutputBytes: s.outputLimit,
		AllowPrivateTargets: s.allowPrivateTargets,
	}, sshconnector.RuntimeSnapshotCommand())
	if err != nil {
		s.writeExecutionError(writer, requestID, err)
		return
	}
	writeJSON(writer, http.StatusOK, connectorprotocol.RuntimeSnapshotResponse{
		ProtocolVersion: connectorprotocol.ProtocolVersion, RequestID: requestID,
		Action: connectorprotocol.ActionRuntimeSnapshot,
		Result: connectorprotocol.ExecutionResult{
			Stdout: result.Stdout, Stderr: result.Stderr, ExitCode: result.ExitCode,
			DurationMillis: connectorprotocol.DurationMillis(result.Duration),
		},
	})
}

func (s *Server) handleHostKeyProbe(writer http.ResponseWriter, request *http.Request, requestID string) {
	body, ok := s.authenticateJSON(writer, request, requestID)
	if !ok {
		return
	}
	defer wipe(body)
	if !s.acquire(writer, requestID) {
		return
	}
	defer s.release()
	var payload connectorprotocol.HostKeyProbeRequest
	if err := decodeStrictJSON(body, &payload); err != nil {
		writeError(writer, http.StatusBadRequest, requestID, "invalid_json", "request must be one valid JSON object with only supported fields", false)
		return
	}
	if payload.ProtocolVersion != connectorprotocol.ProtocolVersion ||
		strings.TrimSpace(payload.Target.Address) == "" || len(payload.Target.Address) > 253 ||
		payload.Target.Port < 1 || payload.Target.Port > 65535 {
		writeError(writer, http.StatusBadRequest, requestID, "invalid_request", "host-key probe request is invalid", false)
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), s.connectTimeout+5*time.Second)
	defer cancel()
	result, err := s.runner.ProbeHostKey(ctx, payload.Target.Address, payload.Target.Port, s.allowPrivateTargets)
	if err != nil {
		s.writeExecutionError(writer, requestID, err)
		return
	}
	writeJSON(writer, http.StatusOK, connectorprotocol.HostKeyProbeResponse{
		ProtocolVersion: connectorprotocol.ProtocolVersion, RequestID: requestID,
		Action: connectorprotocol.ActionHostKeyProbe, Algorithm: result.Algorithm,
		FingerprintSHA256: result.FingerprintSHA256, PublicKey: result.PublicKey,
		ResolvedAddress: result.ResolvedAddress,
	})
}

func (s *Server) authenticateJSON(writer http.ResponseWriter, request *http.Request, requestID string) ([]byte, bool) {
	mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		writeError(writer, http.StatusUnsupportedMediaType, requestID, "invalid_content_type", "Content-Type must be application/json", false)
		return nil, false
	}
	if request.ContentLength > s.bodyLimit {
		writeError(writer, http.StatusRequestEntityTooLarge, requestID, "request_too_large", "request body exceeds the configured limit", false)
		return nil, false
	}
	request.Body = http.MaxBytesReader(writer, request.Body, s.bodyLimit)
	body, err := io.ReadAll(request.Body)
	if err != nil {
		writeError(writer, http.StatusRequestEntityTooLarge, requestID, "request_too_large", "request body exceeds the configured limit", false)
		return nil, false
	}
	if err := s.verifier.Verify(request, body); err != nil {
		writeError(writer, http.StatusUnauthorized, requestID, "unauthorized", "request authentication failed", false)
		return nil, false
	}
	return body, true
}

func (s *Server) acquire(writer http.ResponseWriter, requestID string) bool {
	select {
	case s.concurrency <- struct{}{}:
		return true
	default:
		writer.Header().Set("Retry-After", "1")
		writeError(writer, http.StatusTooManyRequests, requestID, "concurrency_limit", "connector concurrency limit reached", true)
		return false
	}
}

func (s *Server) release() { <-s.concurrency }

func (s *Server) writeExecutionError(writer http.ResponseWriter, requestID string, err error) {
	switch {
	case errors.Is(err, context.Canceled):
		writeError(writer, http.StatusRequestTimeout, requestID, "request_canceled", "connector request was canceled", true)
	case errors.Is(err, context.DeadlineExceeded):
		writeError(writer, http.StatusGatewayTimeout, requestID, "execution_timeout", "connector action timed out", true)
	case errors.Is(err, sshconnector.ErrTargetDenied):
		writeError(writer, http.StatusBadRequest, requestID, "target_denied", "SSH target is denied by connector network policy", false)
	case errors.Is(err, sshconnector.ErrHostKeyRequired):
		writeError(writer, http.StatusBadRequest, requestID, "host_key_required", "a pinned SSH host key is required", false)
	case errors.Is(err, sshconnector.ErrHostKeyMismatch):
		writeError(writer, http.StatusConflict, requestID, "host_key_mismatch", "SSH host key does not match the pinned key", false)
	case errors.Is(err, sshconnector.ErrOutputLimit):
		writeError(writer, http.StatusUnprocessableEntity, requestID, "output_limit", "connector action exceeded its output limit", false)
	default:
		writeError(writer, http.StatusBadGateway, requestID, "ssh_action_failed", "SSH connector action failed", true)
	}
}

func validateRuntimeRequest(payload connectorprotocol.RuntimeSnapshotRequest) error {
	if payload.ProtocolVersion != connectorprotocol.ProtocolVersion ||
		strings.TrimSpace(payload.Target.Address) == "" || len(payload.Target.Address) > 253 ||
		payload.Target.Port < 1 || payload.Target.Port > 65535 ||
		strings.TrimSpace(payload.Target.User) == "" || len(payload.Target.User) > 64 ||
		len(payload.PinnedHostKey) == 0 || len(payload.PinnedHostKey) > 16<<10 ||
		len(payload.Credential.PrivateKeyPEM) == 0 || len(payload.Credential.PrivateKeyPEM) > 48<<10 ||
		len(payload.Credential.Passphrase) > 4<<10 {
		return errors.New("invalid runtime request")
	}
	return nil
}

func decodeStrictJSON(body []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values are not allowed")
		}
		return err
	}
	return nil
}

func methodNotAllowed(writer http.ResponseWriter, requestID, allowed string) {
	writer.Header().Set("Allow", allowed)
	writeError(writer, http.StatusMethodNotAllowed, requestID, "method_not_allowed", "HTTP method is not allowed", false)
}

func writeError(writer http.ResponseWriter, status int, requestID, code, message string, retryable bool) {
	writeJSON(writer, status, connectorprotocol.ErrorEnvelope{Error: connectorprotocol.ErrorDetail{
		Code: code, Message: message, RequestID: requestID, Retryable: retryable,
	}})
}

func writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}

func secureHeaders(writer http.ResponseWriter, requestID string) {
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.Header().Set("X-Request-Id", requestID)
}

func newRequestID() string {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "request-id-unavailable"
	}
	return hex.EncodeToString(value)
}

func wipe(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
