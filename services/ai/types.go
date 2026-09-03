package ai

const (
	SchemaVersion = "vpsmanager.ai-analysis.v1"
	MaxFindings   = 128
)

type Evidence struct {
	PID            int     `json:"pid"`
	ParentPID      int     `json:"parentPid,omitempty"`
	User           string  `json:"user,omitempty"`
	ProcessName    string  `json:"processName,omitempty"`
	CPUPercent     float64 `json:"cpuPercent,omitempty"`
	ElapsedSeconds uint64  `json:"elapsedSeconds,omitempty"`
}

type Finding struct {
	ID                string   `json:"id"`
	RuleID            string   `json:"ruleId"`
	Title             string   `json:"title"`
	Severity          string   `json:"severity"`
	Confidence        float64  `json:"confidence"`
	Evidence          Evidence `json:"evidence"`
	FalsePositiveNote string   `json:"falsePositiveNote"`
}

type RankedFinding struct {
	FindingID string `json:"findingId"`
	Rank      int    `json:"rank"`
	Rationale string `json:"rationale"`
}

type HumanVerificationStep struct {
	FindingID   string `json:"findingId"`
	Description string `json:"description"`
}

type Recommendation struct {
	FindingID string `json:"findingId"`
	Priority  string `json:"priority"`
	Advice    string `json:"advice"`
}

type Analysis struct {
	SchemaVersion          string                  `json:"schemaVersion"`
	Summary                string                  `json:"summary"`
	RankedFindings         []RankedFinding         `json:"rankedFindings"`
	HumanVerificationSteps []HumanVerificationStep `json:"humanVerificationSteps"`
	Recommendations        []Recommendation        `json:"recommendations"`
	ExecutionAllowed       bool                    `json:"executionAllowed"`
}

type Mode string

const (
	ModeGateway       Mode = "gateway"
	ModeRulesFallback Mode = "rules_fallback"
)

type FallbackReason string

const (
	FallbackNone                  FallbackReason = ""
	FallbackGatewayDisabled       FallbackReason = "gateway_disabled"
	FallbackCredentialUnavailable FallbackReason = "credential_unavailable"
	FallbackTimeout               FallbackReason = "timeout"
	FallbackRedirectBlocked       FallbackReason = "redirect_blocked"
	FallbackTransportError        FallbackReason = "transport_error"
	FallbackHTTPError             FallbackReason = "http_error"
	FallbackResponseTooLarge      FallbackReason = "response_too_large"
	FallbackInvalidResponse       FallbackReason = "invalid_response"
)

type Outcome struct {
	Analysis       Analysis       `json:"analysis"`
	Mode           Mode           `json:"mode"`
	FallbackReason FallbackReason `json:"fallbackReason,omitempty"`
}
