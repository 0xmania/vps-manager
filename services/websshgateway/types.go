// Package websshgateway implements the control-plane WebSSH ticket broker and
// same-origin WebSocket gateway. SSH credentials cross only the authenticated
// local Connector channel and are not returned to a browser.
package websshgateway

import (
	"context"
	"io"
	"time"

	connectorprotocol "vpsmanager/services/connector-protocol"
)

const (
	// ConnectPath is the only browser-facing WebSocket route handled by Broker.
	ConnectPath = "/api/v1/webssh/connect"

	ProtocolVersion = "v1"
	MessageHello    = "hello"
)

// Binding is repeated by the browser during its first WebSocket frame. Roles
// are canonicalized by New/Issue; authorization callbacks receive this exact
// immutable authorization snapshot on every check.
type Binding struct {
	PrincipalID  string   `json:"principalId"`
	SessionID    string   `json:"sessionId"`
	Roles        []string `json:"roles"`
	HostID       string   `json:"hostId"`
	CredentialID string   `json:"credentialId"`
	Action       string   `json:"action"`
}

// IssueRequest is consumed by Issue. Issue clears Credential.PrivateKeyPEM
// and Credential.Passphrase before it returns, including on failure.
type IssueRequest struct {
	Binding       Binding                        `json:"binding"`
	Target        connectorprotocol.Target       `json:"target"`
	PinnedHostKey string                         `json:"pinnedHostKey"`
	Credential    connectorprotocol.Credential   `json:"credential"`
	InitialSize   connectorprotocol.TerminalSize `json:"initialSize"`
	Reason        string                         `json:"reason"`
}

// IssueResponse contains only the independent, short-lived browser ticket.
// The Connector ticket, Connector session ID, and SSH credential are absent
// from this type.
type IssueResponse struct {
	ProtocolVersion string    `json:"protocolVersion"`
	Ticket          string    `json:"ticket"`
	ConnectionID    string    `json:"connectionId"`
	ExpiresAt       time.Time `json:"expiresAt"`
	WebSocketURL    string    `json:"webSocketUrl"`
}

// HelloMessage must be the browser's first text frame. Every binding field is
// checked against the consumed ticket before any Connector connection occurs.
type HelloMessage struct {
	Type         string  `json:"type"`
	Ticket       string  `json:"ticket"`
	ConnectionID string  `json:"connectionId"`
	Binding      Binding `json:"binding"`
}

// Authorization is passed to Authorizer both before the Connector WebSocket
// is opened and periodically for the lifetime of the PTY.
type Authorization struct {
	Binding Binding
	Reason  string
}

type Authorizer interface {
	AuthorizeWebSSH(context.Context, Authorization) error
}

type AuthorizerFunc func(context.Context, Authorization) error

func (f AuthorizerFunc) AuthorizeWebSSH(ctx context.Context, authorization Authorization) error {
	return f(ctx, authorization)
}

// AuditEvent contains metadata only. Terminal frames, tickets,
// target addresses, host keys, and credential bytes are not representable.
type AuditEvent struct {
	At             time.Time
	Event          string
	PrincipalID    string
	SessionID      string
	Roles          []string
	HostID         string
	CredentialID   string
	Action         string
	ConnectionID   string
	Reason         string
	DisconnectType string
}

type Auditor interface {
	AuditWebSSH(context.Context, AuditEvent) error
}

type AuditorFunc func(context.Context, AuditEvent) error

func (f AuditorFunc) AuditWebSSH(ctx context.Context, event AuditEvent) error {
	return f(ctx, event)
}

// Config fixes both the public and Connector endpoints at construction time.
// ConnectorBaseURL and ConnectorUnixSocket use the same mutually-exclusive
// addressing rules as connectorprotocol.NewClient.
type Config struct {
	PublicWebSocketURL string
	Development        bool
	AllowedOrigins     []string

	ConnectorBaseURL    string
	ConnectorUnixSocket string
	ConnectorOrigin     string

	TicketTTL             time.Duration
	HandshakeTimeout      time.Duration
	ConnectorDialTimeout  time.Duration
	AuthorizationTimeout  time.Duration
	AuthorizationInterval time.Duration
	IdleTimeout           time.Duration
	AbsoluteTimeout       time.Duration
	WriteTimeout          time.Duration
	MaxConcurrent         int
	MaxOutstandingTickets int
	MaxInputMessageBytes  int
	MaxOutputMessageBytes int
	InputBytesPerSecond   int64
	OutputBytesPerSecond  int64

	// Now and Random optionally replace the default clock and random source.
	Now    func() time.Time
	Random io.Reader
}
