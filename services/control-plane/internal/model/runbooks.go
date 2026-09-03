package model

import connectorprotocol "vpsmanager/services/connector-protocol"

type RunbookPreviewResult struct {
	ProtocolVersion  string                                 `json:"protocolVersion"`
	RequestID        string                                 `json:"requestId"`
	Action           string                                 `json:"action"`
	CatalogVersion   string                                 `json:"catalogVersion"`
	Binding          connectorprotocol.RunbookBinding       `json:"binding"`
	ScopeDigest      string                                 `json:"scopeDigest"`
	Title            string                                 `json:"title"`
	Mutating         bool                                   `json:"mutating"`
	Emergency        bool                                   `json:"emergency"`
	ExecutionEnabled bool                                   `json:"executionEnabled"`
	RetryPolicy      string                                 `json:"retryPolicy"`
	Steps            []connectorprotocol.RunbookStepPreview `json:"steps"`
}

type RunbookStepExecution struct {
	ID             string `json:"id"`
	Phase          string `json:"phase"`
	State          string `json:"state"`
	Stdout         string `json:"stdout"`
	Stderr         string `json:"stderr"`
	ExitCode       int    `json:"exitCode"`
	DurationMillis int64  `json:"durationMillis"`
	ErrorCode      string `json:"errorCode,omitempty"`
}

type RunbookExecutionResult struct {
	ProtocolVersion  string                           `json:"protocolVersion"`
	RequestID        string                           `json:"requestId"`
	Action           string                           `json:"action"`
	CatalogVersion   string                           `json:"catalogVersion"`
	Binding          connectorprotocol.RunbookBinding `json:"binding"`
	ScopeDigest      string                           `json:"scopeDigest"`
	Status           string                           `json:"status"`
	Stopped          bool                             `json:"stopped"`
	Retryable        bool                             `json:"retryable"`
	IdempotentReplay bool                             `json:"idempotentReplay"`
	Steps            []RunbookStepExecution           `json:"steps"`
}
