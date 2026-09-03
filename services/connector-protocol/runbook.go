package connectorprotocol

import "time"

const (
	ActionRunbookPreview = "runbook_preview_v1"
	ActionRunbookExecute = "runbook_execute_v1"

	RunbookPreviewPath = "/v1/runbooks/preview"
	RunbookExecutePath = "/v1/runbooks/execute"
)

type RunbookActionRef struct {
	ID      string `json:"id"`
	Version int    `json:"version"`
}

type RunbookParameters struct {
	Service           string `json:"service,omitempty"`
	Timezone          string `json:"timezone,omitempty"`
	PID               int    `json:"pid,omitempty"`
	ProcessStartTicks uint64 `json:"processStartTicks,omitempty"`
}

// RunbookBinding is included in the scope digest returned by preview. HostID
// and JobID are control-plane identifiers; SSH network coordinates are kept
// separate so approvals cannot silently move between assets or attempts.
type RunbookBinding struct {
	Action                    RunbookActionRef  `json:"action"`
	HostID                    string            `json:"hostId"`
	JobID                     string            `json:"jobId"`
	Target                    Target            `json:"target"`
	PinnedHostKeySHA256       string            `json:"pinnedHostKeySha256"`
	CredentialPublicKeySHA256 string            `json:"credentialPublicKeySha256"`
	Parameters                RunbookParameters `json:"parameters"`
}

type RunbookApprovalSummary struct {
	Decision    string           `json:"decision"`
	Action      RunbookActionRef `json:"action"`
	HostID      string           `json:"hostId"`
	JobID       string           `json:"jobId"`
	ScopeDigest string           `json:"scopeDigest"`
	ApprovedAt  time.Time        `json:"approvedAt"`
	ExpiresAt   time.Time        `json:"expiresAt"`
}

type RunbookEmergencyGrant struct {
	IncidentID string    `json:"incidentId"`
	ExpiresAt  time.Time `json:"expiresAt"`
}

type RunbookPreviewRequest struct {
	ProtocolVersion string         `json:"protocolVersion"`
	Binding         RunbookBinding `json:"binding"`
}

type RunbookStepPreview struct {
	ID             string `json:"id"`
	Phase          string `json:"phase"`
	Description    string `json:"description"`
	TimeoutSeconds int    `json:"timeoutSeconds"`
}

type RunbookPreviewResponse struct {
	ProtocolVersion  string               `json:"protocolVersion"`
	RequestID        string               `json:"requestId"`
	Action           string               `json:"action"`
	CatalogVersion   string               `json:"catalogVersion"`
	Binding          RunbookBinding       `json:"binding"`
	ScopeDigest      string               `json:"scopeDigest"`
	Title            string               `json:"title"`
	Mutating         bool                 `json:"mutating"`
	Emergency        bool                 `json:"emergency"`
	ExecutionEnabled bool                 `json:"executionEnabled"`
	RetryPolicy      string               `json:"retryPolicy"`
	Steps            []RunbookStepPreview `json:"steps"`
}

type RunbookExecuteRequest struct {
	ProtocolVersion string                 `json:"protocolVersion"`
	Binding         RunbookBinding         `json:"binding"`
	Approval        RunbookApprovalSummary `json:"approval"`
	Emergency       RunbookEmergencyGrant  `json:"emergency"`
	Reason          string                 `json:"reason"`
	PinnedHostKey   string                 `json:"pinnedHostKey"`
	Credential      Credential             `json:"credential"`
}

type RunbookStepResult struct {
	ID             string `json:"id"`
	Phase          string `json:"phase"`
	State          string `json:"state"`
	Stdout         []byte `json:"stdout"`
	Stderr         []byte `json:"stderr"`
	ExitCode       int    `json:"exitCode"`
	DurationMillis int64  `json:"durationMillis"`
	ErrorCode      string `json:"errorCode,omitempty"`
}

type RunbookExecuteResponse struct {
	ProtocolVersion  string              `json:"protocolVersion"`
	RequestID        string              `json:"requestId"`
	Action           string              `json:"action"`
	CatalogVersion   string              `json:"catalogVersion"`
	Binding          RunbookBinding      `json:"binding"`
	ScopeDigest      string              `json:"scopeDigest"`
	Status           string              `json:"status"`
	Stopped          bool                `json:"stopped"`
	Retryable        bool                `json:"retryable"`
	IdempotentReplay bool                `json:"idempotentReplay"`
	Steps            []RunbookStepResult `json:"steps"`
}
