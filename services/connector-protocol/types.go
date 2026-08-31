// Package connectorprotocol defines the authenticated, fixed-action protocol
// shared by the control plane and the isolated SSH Connector service.
package connectorprotocol

import "time"

const (
	ProtocolVersion = "v1"

	ActionRuntimeSnapshot = "runtime_snapshot_v1"
	ActionHostKeyProbe    = "host_key_probe_v1"

	RuntimeSnapshotPath = "/v1/actions/runtime-snapshot"
	HostKeyProbePath    = "/v1/actions/host-key-probe"
	HealthPath          = "/healthz"
	VersionPath         = "/version"
)

type Target struct {
	Address string `json:"address"`
	Port    int    `json:"port"`
	User    string `json:"user"`
}

type ProbeTarget struct {
	Address string `json:"address"`
	Port    int    `json:"port"`
}

// Credential carries private key bytes only over the authenticated local
// connector channel. JSON encodes byte slices as base64. Servers wipe these
// request-owned slices after parsing them.
type Credential struct {
	PrivateKeyPEM []byte `json:"privateKeyPem"`
	Passphrase    []byte `json:"passphrase,omitempty"`
}

type RuntimeSnapshotRequest struct {
	ProtocolVersion string     `json:"protocolVersion"`
	Target          Target     `json:"target"`
	PinnedHostKey   string     `json:"pinnedHostKey"`
	Credential      Credential `json:"credential"`
}

type RuntimeSnapshotResponse struct {
	ProtocolVersion string          `json:"protocolVersion"`
	RequestID       string          `json:"requestId"`
	Action          string          `json:"action"`
	Result          ExecutionResult `json:"result"`
}

type ExecutionResult struct {
	Stdout         []byte `json:"stdout"`
	Stderr         []byte `json:"stderr"`
	ExitCode       int    `json:"exitCode"`
	DurationMillis int64  `json:"durationMillis"`
}

type HostKeyProbeRequest struct {
	ProtocolVersion string      `json:"protocolVersion"`
	Target          ProbeTarget `json:"target"`
}

type HostKeyProbeResponse struct {
	ProtocolVersion   string `json:"protocolVersion"`
	RequestID         string `json:"requestId"`
	Action            string `json:"action"`
	Algorithm         string `json:"algorithm"`
	FingerprintSHA256 string `json:"fingerprintSha256"`
	PublicKey         string `json:"publicKey"`
	ResolvedAddress   string `json:"resolvedAddress"`
}

type HealthResponse struct {
	Status          string `json:"status"`
	ProtocolVersion string `json:"protocolVersion"`
}

type VersionResponse struct {
	ServiceVersion  string   `json:"serviceVersion"`
	ProtocolVersion string   `json:"protocolVersion"`
	Actions         []string `json:"actions"`
}

type ErrorEnvelope struct {
	Error ErrorDetail `json:"error"`
}

type ErrorDetail struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	RequestID string `json:"requestId"`
	Retryable bool   `json:"retryable"`
}

type RemoteError struct {
	StatusCode int
	Detail     ErrorDetail
}

func (e *RemoteError) Error() string {
	if e.Detail.Code == "" {
		return "connector returned an error"
	}
	return "connector returned error: " + e.Detail.Code
}

func DurationMillis(value time.Duration) int64 { return value.Milliseconds() }
