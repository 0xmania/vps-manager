package model

import (
	"time"

	"vpsmanager/services/ai"
	"vpsmanager/services/control-plane/internal/credentials"
)

type CommandDescriptor struct {
	ID         string            `json:"id"`
	Parameters map[string]string `json:"parameters,omitempty"`
}

type CommandResult struct {
	CommandID      string `json:"commandId"`
	Stdout         string `json:"stdout"`
	Stderr         string `json:"stderr"`
	ExitCode       int    `json:"exitCode"`
	DurationMillis int64  `json:"durationMillis"`
	Truncated      bool   `json:"truncated"`
}

type FindingEvidence struct {
	PID            int     `json:"pid"`
	ParentPID      int     `json:"parentPid,omitempty"`
	User           string  `json:"user,omitempty"`
	ProcessName    string  `json:"processName,omitempty"`
	CPUPercent     float64 `json:"cpuPercent,omitempty"`
	ElapsedSeconds uint64  `json:"elapsedSeconds,omitempty"`
}

type ProcessFinding struct {
	ID                string          `json:"id"`
	RuleID            string          `json:"ruleId"`
	Title             string          `json:"title"`
	Severity          string          `json:"severity"`
	Confidence        float64         `json:"confidence"`
	Evidence          FindingEvidence `json:"evidence"`
	FalsePositiveNote string          `json:"falsePositiveNote"`
}

type AnomalyScanResult struct {
	ObservedAt         time.Time        `json:"observedAt"`
	Engine             string           `json:"engine"`
	AIExecutionAllowed bool             `json:"aiExecutionAllowed"`
	ProcessesEvaluated int              `json:"processesEvaluated"`
	Findings           []ProcessFinding `json:"findings"`
	AIAnalysis         *ai.Outcome      `json:"aiAnalysis,omitempty"`
}

type CloudflareWorker struct {
	ID               string    `json:"id"`
	Name             string    `json:"name"`
	AccountID        string    `json:"accountId"`
	ScriptName       string    `json:"scriptName"`
	DesiredVersionID string    `json:"desiredVersionId,omitempty"`
	Version          uint64    `json:"version"`
	CreatedAt        time.Time `json:"createdAt"`
	UpdatedAt        time.Time `json:"updatedAt"`
}

type CloudflareTokenMetadata struct {
	ID        string    `json:"id"`
	WorkerID  string    `json:"workerId"`
	Kind      string    `json:"kind"`
	KeyID     string    `json:"keyId"`
	CreatedAt time.Time `json:"createdAt"`
	CreatedBy string    `json:"createdBy"`
}

type StoredCloudflareToken struct {
	Metadata CloudflareTokenMetadata `json:"metadata"`
	Envelope credentials.Envelope    `json:"-"`
}

type CloudflareWorkerVersion struct {
	ID                    string     `json:"id"`
	WorkerID              string     `json:"workerId"`
	SHA256                string     `json:"sha256"`
	SizeBytes             int        `json:"sizeBytes"`
	ContentType           string     `json:"contentType"`
	Entrypoint            string     `json:"entrypoint"`
	State                 string     `json:"state"`
	ProviderVersionID     string     `json:"providerVersionId,omitempty"`
	ProviderVersionNumber int64      `json:"providerVersionNumber,omitempty"`
	ProviderUploadedAt    *time.Time `json:"providerUploadedAt,omitempty"`
	CreatedAt             time.Time  `json:"createdAt"`
	CreatedBy             string     `json:"createdBy"`
}

type StoredCloudflareWorkerVersion struct {
	Metadata CloudflareWorkerVersion `json:"metadata"`
	Module   []byte                  `json:"-"`
}

type CloudflareDeployment struct {
	ID                       string     `json:"id"`
	WorkerID                 string     `json:"workerId"`
	VersionID                string     `json:"versionId"`
	PreviousDesiredVersionID string     `json:"previousDesiredVersionId,omitempty"`
	Kind                     string     `json:"kind"`
	State                    string     `json:"state"`
	ProviderExecutionAllowed bool       `json:"providerExecutionAllowed"`
	ProviderVersionID        string     `json:"providerVersionId,omitempty"`
	ProviderDeploymentID     string     `json:"providerDeploymentId,omitempty"`
	ProviderState            string     `json:"providerState,omitempty"`
	ErrorCode                string     `json:"errorCode,omitempty"`
	StartedAt                *time.Time `json:"startedAt,omitempty"`
	FinishedAt               *time.Time `json:"finishedAt,omitempty"`
	CreatedAt                time.Time  `json:"createdAt"`
	CreatedBy                string     `json:"createdBy"`
}
