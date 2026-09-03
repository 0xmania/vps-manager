package cloudflareprovider

import (
	"context"
	"time"
)

const OfficialAPIBaseURL = "https://api.cloudflare.com/client/v4"

type TokenOwner string

const (
	TokenOwnerUser    TokenOwner = "user"
	TokenOwnerAccount TokenOwner = "account"
)

type Config struct {
	AccountID             string
	TokenOwner            TokenOwner
	RequestTimeout        time.Duration
	PollInterval          time.Duration
	PollTimeout           time.Duration
	MaxModuleBytes        int64
	MaxResponseBytes      int64
	MaxIdempotencyEntries int
}

// Provider uploads and deploys prebuilt Worker modules.
type Provider interface {
	ValidateAccess(context.Context) (AccountAccess, error)
	UploadVersion(context.Context, PrebuiltModule) (Version, error)
	DeployVersion(context.Context, DeployRequest) (Deployment, error)
	Rollback(context.Context, RollbackRequest) (Deployment, error)
}

type AccountAccess struct {
	AccountID   string
	AccountName string
	TokenID     string
	TokenStatus string
	NotBefore   *time.Time
	ExpiresAt   *time.Time
}

// PrebuiltModule is an already-built, single-file ES module. The provider does
// not transpile, bundle, resolve imports, or execute this source.
type PrebuiltModule struct {
	ScriptName     string
	MainModule     string
	Source         []byte
	Message        string
	Tag            string
	IdempotencyKey string
}

type Version struct {
	ID         string
	Number     int64
	CreatedAt  *time.Time
	ScriptName string
	SHA256     string
	SizeBytes  int64
}

type DeploymentState string

const (
	DeploymentStatePending DeploymentState = "pending"
	DeploymentStateActive  DeploymentState = "active"
)

type DeploymentVersion struct {
	VersionID  string
	Percentage float64
}

type Deployment struct {
	ID         string
	ScriptName string
	State      DeploymentState
	CreatedAt  *time.Time
	Source     string
	Versions   []DeploymentVersion
}

type DeployRequest struct {
	ScriptName     string
	VersionID      string
	Message        string
	IdempotencyKey string
}

type RollbackRequest struct {
	ScriptName      string
	TargetVersionID string
	Message         string
	IdempotencyKey  string
}

type WaitDeploymentRequest struct {
	ScriptName   string
	DeploymentID string
	VersionID    string
}
