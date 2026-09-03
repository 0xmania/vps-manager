package connectorprotocol

import "time"

const (
	ActionWebSSH        = "web_ssh_v1"
	WebSSHTicketPath    = "/v1/webssh/tickets"
	WebSSHConnectPath   = "/v1/webssh/connect"
	WebSSHSubprotocol   = "vpsmgr.webssh.v1"
	WebSSHMessageHello  = "hello"
	WebSSHMessageInput  = "input"
	WebSSHMessageResize = "resize"
	WebSSHMessageReady  = "ready"
	WebSSHMessageOutput = "output"
	WebSSHMessageExit   = "exit"
	WebSSHMessageError  = "error"
)

// WebSSHBinding is repeated during the WebSocket hello and must exactly match
// the HMAC-authenticated ticket request. It prevents a ticket issued for one
// principal, host, credential, or action from being confused with another.
type WebSSHBinding struct {
	PrincipalID  string `json:"principalId"`
	HostID       string `json:"hostId"`
	CredentialID string `json:"credentialId"`
	Action       string `json:"action"`
}

type TerminalSize struct {
	Columns      uint16 `json:"columns"`
	Rows         uint16 `json:"rows"`
	WidthPixels  uint16 `json:"widthPixels,omitempty"`
	HeightPixels uint16 `json:"heightPixels,omitempty"`
}

type WebSSHTicketRequest struct {
	ProtocolVersion string        `json:"protocolVersion"`
	Binding         WebSSHBinding `json:"binding"`
	Target          Target        `json:"target"`
	PinnedHostKey   string        `json:"pinnedHostKey"`
	Credential      Credential    `json:"credential"`
	InitialSize     TerminalSize  `json:"initialSize"`
}

type WebSSHTicketResponse struct {
	ProtocolVersion string    `json:"protocolVersion"`
	RequestID       string    `json:"requestId"`
	Ticket          string    `json:"ticket"`
	SessionID       string    `json:"sessionId"`
	ExpiresAt       time.Time `json:"expiresAt"`
}

type WebSSHHelloMessage struct {
	Type      string        `json:"type"`
	Ticket    string        `json:"ticket"`
	SessionID string        `json:"sessionId"`
	Binding   WebSSHBinding `json:"binding"`
}

type WebSSHInputMessage struct {
	Type string `json:"type"`
	Data []byte `json:"data"`
}

type WebSSHResizeMessage struct {
	Type string       `json:"type"`
	Size TerminalSize `json:"size"`
}

type WebSSHReadyMessage struct {
	Type      string       `json:"type"`
	SessionID string       `json:"sessionId"`
	Size      TerminalSize `json:"size"`
}

// WebSSHOutputMessage carries raw PTY bytes as JSON base64. The Connector does
// not parse terminal control sequences and never converts terminal data to HTML.
type WebSSHOutputMessage struct {
	Type string `json:"type"`
	Data []byte `json:"data"`
}

type WebSSHExitMessage struct {
	Type     string `json:"type"`
	ExitCode int    `json:"exitCode"`
	Reason   string `json:"reason"`
}

type WebSSHErrorMessage struct {
	Type      string `json:"type"`
	Code      string `json:"code"`
	Message   string `json:"message"`
	Retryable bool   `json:"retryable"`
}
