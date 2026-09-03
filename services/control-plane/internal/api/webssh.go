package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	connectorprotocol "vpsmanager/services/connector-protocol"
	"vpsmanager/services/control-plane/internal/auth"
	"vpsmanager/services/control-plane/internal/store"
	"vpsmanager/services/websshgateway"
)

type terminalSessionRequest struct {
	Reason  string `json:"reason"`
	Columns uint16 `json:"columns"`
	Rows    uint16 `json:"rows"`
}

type terminalSessionResponse struct {
	websshgateway.IssueResponse
	Protocol string                `json:"protocol"`
	Binding  websshgateway.Binding `json:"binding"`
}

func (s *Server) createTerminalSession(w http.ResponseWriter, r *http.Request) {
	if s.webSSH == nil || !s.config.DevMode || !s.config.SecretExecutionEnabled {
		writeError(w, r, http.StatusServiceUnavailable, "execution_boundary_unavailable", "WebSSH requires a development execution identity with credential decryption")
		return
	}
	principal := principalFrom(r.Context())
	host, ok := s.requireSSHJobTarget(w, r)
	if !ok {
		return
	}
	var input terminalSessionRequest
	if err := decodeJSON(w, r, &input); err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if input.Columns == 0 {
		input.Columns = 80
	}
	if input.Rows == 0 {
		input.Rows = 24
	}
	credential, err := s.repository.GetCredential(host.ID)
	if err != nil {
		writeStoreError(w, r, err)
		return
	}
	binding := websshgateway.Binding{
		PrincipalID:  principal.Subject,
		SessionID:    principal.SessionID,
		Roles:        []string{string(principal.Role)},
		HostID:       host.ID,
		CredentialID: credential.Metadata.ID,
		Action:       connectorprotocol.ActionWebSSH,
	}
	var issued websshgateway.IssueResponse
	err = s.credentials.Open(r.Context(), credential.Envelope, s.credentialAAD(host.ID, credential.Metadata.ID), func(plaintext []byte) error {
		connectorCredential, decodeErr := decodeConnectorCredential(plaintext)
		if decodeErr != nil {
			return decodeErr
		}
		defer wipeConnectorCredential(&connectorCredential)
		var issueErr error
		issued, issueErr = s.webSSH.Issue(r.Context(), &websshgateway.IssueRequest{
			Binding:       binding,
			Target:        connectorprotocol.Target{Address: host.Address, Port: host.Port, User: host.Username},
			PinnedHostKey: host.HostKey.PublicKey,
			Credential:    connectorCredential,
			InitialSize:   connectorprotocol.TerminalSize{Columns: input.Columns, Rows: input.Rows},
			Reason:        input.Reason,
		})
		return issueErr
	})
	if err != nil {
		status, code, message := webSSHError(err)
		s.audit(r, principal, "webssh.issue", "host", host.ID, "failed", map[string]any{"errorCode": code})
		writeError(w, r, status, code, message)
		return
	}
	writeJSON(w, http.StatusCreated, terminalSessionResponse{
		IssueResponse: issued,
		Protocol:      connectorprotocol.WebSSHSubprotocol,
		Binding:       binding,
	})
}

func (s *Server) webSSHHandler() http.Handler {
	if s.webSSH != nil {
		return s.webSSH.Handler()
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeError(w, r, http.StatusServiceUnavailable, "execution_boundary_unavailable", "WebSSH is not available for this control-plane identity")
	})
}

func (s *Server) authorizeWebSSH(_ context.Context, authorization websshgateway.Authorization) error {
	binding := authorization.Binding
	if binding.Action != connectorprotocol.ActionWebSSH || len(binding.Roles) != 1 {
		return websshgateway.ErrUnauthorized
	}
	principal, ok := s.sessions.AuthorizeSession(binding.SessionID, auth.TerminalSessionsOpen, binding.HostID)
	if !ok || principal.Subject != binding.PrincipalID || string(principal.Role) != binding.Roles[0] {
		return websshgateway.ErrUnauthorized
	}
	host, err := s.repository.GetHost(binding.HostID)
	if err != nil || host.HostKey == nil {
		return websshgateway.ErrUnauthorized
	}
	credential, err := s.repository.GetCredential(binding.HostID)
	if err != nil || credential.Metadata.ID != binding.CredentialID {
		return websshgateway.ErrUnauthorized
	}
	return nil
}

func (s *Server) auditWebSSH(_ context.Context, event websshgateway.AuditEvent) error {
	role := auth.Role("")
	if len(event.Roles) == 1 {
		role = auth.Role(event.Roles[0])
	}
	s.auditWithRequestID("", auth.Principal{Subject: event.PrincipalID, Role: role, SessionID: event.SessionID},
		"webssh."+event.Event, "host", event.HostID, "recorded", map[string]any{
			"credentialId":   event.CredentialID,
			"connectionId":   event.ConnectionID,
			"disconnectType": event.DisconnectType,
			"reason":         event.Reason,
		})
	return nil
}

func decodeConnectorCredential(plaintext []byte) (connectorprotocol.Credential, error) {
	var payload struct {
		PrivateKey string `json:"privateKey"`
		Passphrase string `json:"passphrase,omitempty"`
	}
	decoder := json.NewDecoder(bytes.NewReader(plaintext))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil {
		return connectorprotocol.Credential{}, errors.New("stored credential payload is invalid")
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return connectorprotocol.Credential{}, errors.New("stored credential payload is invalid")
	}
	if payload.PrivateKey == "" {
		return connectorprotocol.Credential{}, errors.New("stored credential payload is invalid")
	}
	credential := connectorprotocol.Credential{
		PrivateKeyPEM: []byte(payload.PrivateKey),
		Passphrase:    []byte(payload.Passphrase),
	}
	payload.PrivateKey, payload.Passphrase = "", ""
	return credential, nil
}

func wipeConnectorCredential(credential *connectorprotocol.Credential) {
	if credential == nil {
		return
	}
	wipe(credential.PrivateKeyPEM)
	wipe(credential.Passphrase)
	credential.PrivateKeyPEM = nil
	credential.Passphrase = nil
}

func webSSHError(err error) (int, string, string) {
	switch {
	case errors.Is(err, websshgateway.ErrInvalidRequest):
		return http.StatusBadRequest, "validation_error", "terminal session request is invalid"
	case errors.Is(err, websshgateway.ErrUnauthorized):
		return http.StatusForbidden, "authorization_expired", "terminal session authorization is no longer valid"
	case errors.Is(err, websshgateway.ErrCapacity):
		return http.StatusTooManyRequests, "terminal_capacity", "terminal session capacity is currently full"
	case errors.Is(err, websshgateway.ErrConnector):
		return http.StatusBadGateway, "connector_unavailable", "Connector could not issue a terminal ticket"
	case errors.Is(err, websshgateway.ErrClosed), errors.Is(err, store.ErrNotFound):
		return http.StatusServiceUnavailable, "execution_boundary_unavailable", "terminal execution boundary is unavailable"
	default:
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return http.StatusGatewayTimeout, "terminal_timeout", "terminal ticket issuance timed out"
		}
		if strings.Contains(err.Error(), "credential") {
			return http.StatusServiceUnavailable, "credential_unavailable", "SSH credential could not be opened"
		}
		return http.StatusServiceUnavailable, "execution_boundary_unavailable", "terminal execution boundary is unavailable"
	}
}
