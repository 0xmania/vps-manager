// Package persistence defines control-plane storage records and operations.
package persistence

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

var (
	ErrNotFound   = errors.New("record not found")
	ErrConflict   = errors.New("record version conflict")
	ErrUnsafeJSON = errors.New("payload may contain secret material")
)

const (
	DefaultListLimit = 100
	MaxListLimit     = 500
	MaxJSONBytes     = 1 << 20
)

var identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)

type HostKeyPin struct {
	Algorithm         string    `json:"algorithm"`
	FingerprintSHA256 string    `json:"fingerprintSha256"`
	PublicKey         string    `json:"publicKey"`
	ConfirmedAt       time.Time `json:"confirmedAt"`
	ConfirmedBy       string    `json:"confirmedBy"`
}

type Asset struct {
	InstallationID string            `json:"installationId"`
	ID             string            `json:"id"`
	Name           string            `json:"name"`
	Address        string            `json:"address"`
	Port           int               `json:"port"`
	Username       string            `json:"username"`
	Labels         map[string]string `json:"labels,omitempty"`
	HostKey        *HostKeyPin       `json:"hostKey,omitempty"`
	Version        uint64            `json:"version"`
	CreatedAt      time.Time         `json:"createdAt"`
	UpdatedAt      time.Time         `json:"updatedAt"`
}

// CredentialEnvelope stores encrypted credential data. MarshalJSON returns its metadata.
type CredentialEnvelope struct {
	InstallationID  string          `json:"-"`
	CredentialID    string          `json:"credentialId"`
	Version         uint64          `json:"version"`
	Kind            string          `json:"kind"`
	KeyID           string          `json:"keyId"`
	Ciphertext      []byte          `json:"-"`
	CipherNonce     []byte          `json:"-"`
	WrappedKey      []byte          `json:"-"`
	WrappedKeyNonce []byte          `json:"-"`
	Metadata        json.RawMessage `json:"metadata,omitempty"`
	CreatedAt       time.Time       `json:"createdAt"`
}

func (CredentialEnvelope) String() string   { return "[encrypted credential]" }
func (CredentialEnvelope) GoString() string { return "persistence.CredentialEnvelope{[redacted]}" }

func (e CredentialEnvelope) MarshalJSON() ([]byte, error) {
	metadata := e.Metadata
	if validateSafeJSONObject(metadata) != nil {
		metadata = nil
	}
	return json.Marshal(struct {
		CredentialID string          `json:"credentialId"`
		Version      uint64          `json:"version"`
		Kind         string          `json:"kind"`
		KeyID        string          `json:"keyId"`
		Metadata     json.RawMessage `json:"metadata,omitempty"`
		CreatedAt    time.Time       `json:"createdAt"`
		Encrypted    bool            `json:"encrypted"`
	}{e.CredentialID, e.Version, e.Kind, e.KeyID, metadata, e.CreatedAt, true})
}

type Job struct {
	InstallationID string          `json:"installationId"`
	ID             string          `json:"id"`
	Type           string          `json:"type"`
	AssetID        string          `json:"assetId"`
	State          string          `json:"state"`
	RequestedBy    string          `json:"requestedBy"`
	RequestID      string          `json:"requestId,omitempty"`
	IdempotencyKey string          `json:"idempotencyKey,omitempty"`
	Parameters     json.RawMessage `json:"parameters,omitempty"`
	Result         json.RawMessage `json:"result,omitempty"`
	ErrorCode      string          `json:"errorCode,omitempty"`
	ErrorMessage   string          `json:"errorMessage,omitempty"`
	Version        uint64          `json:"version"`
	CreatedAt      time.Time       `json:"createdAt"`
	StartedAt      *time.Time      `json:"startedAt,omitempty"`
	FinishedAt     *time.Time      `json:"finishedAt,omitempty"`
	UpdatedAt      time.Time       `json:"updatedAt"`
}

type AuditEvent struct {
	InstallationID string          `json:"installationId"`
	ID             string          `json:"id"`
	Timestamp      time.Time       `json:"timestamp"`
	Actor          string          `json:"actor"`
	Role           string          `json:"role"`
	Action         string          `json:"action"`
	TargetType     string          `json:"targetType"`
	TargetID       string          `json:"targetId,omitempty"`
	Outcome        string          `json:"outcome"`
	RequestID      string          `json:"requestId,omitempty"`
	JobID          string          `json:"jobId,omitempty"`
	Details        json.RawMessage `json:"details,omitempty"`
}

type AuditFilter struct {
	InstallationID string
	Before         time.Time
	BeforeID       string
	Limit          int
}

type Repository interface {
	CreateAsset(context.Context, Asset) error
	GetAsset(context.Context, string, string) (Asset, error)
	ListAssets(context.Context, string, int, string) ([]Asset, error)
	UpdateAsset(context.Context, Asset, uint64) error
	DeleteAsset(context.Context, string, string, uint64) error

	PutCredentialEnvelope(context.Context, CredentialEnvelope) error
	GetCredentialEnvelope(context.Context, string, string, uint64) (CredentialEnvelope, error)

	CreateJob(context.Context, Job) error
	GetJob(context.Context, string, string) (Job, error)
	ListJobs(context.Context, string, int, string) ([]Job, error)
	UpdateJob(context.Context, Job, uint64) error

	AppendAudit(context.Context, AuditEvent) error
	ListAudit(context.Context, AuditFilter) ([]AuditEvent, error)
}

func normalizeLimit(limit int) int {
	if limit <= 0 {
		return DefaultListLimit
	}
	if limit > MaxListLimit {
		return MaxListLimit
	}
	return limit
}

func validateIdentifier(label, value string) error {
	if !identifierPattern.MatchString(value) {
		return fmt.Errorf("%s is invalid", label)
	}
	return nil
}

func validateEnvironment(environment string) error {
	switch environment {
	case "production", "development", "test":
		return nil
	default:
		return errors.New("environment must be production, development, or test")
	}
}

func validateAsset(asset Asset) error {
	if err := validateIdentifier("installation id", asset.InstallationID); err != nil {
		return err
	}
	if err := validateIdentifier("asset id", asset.ID); err != nil {
		return err
	}
	if strings.TrimSpace(asset.Name) == "" || len(asset.Name) > 200 {
		return errors.New("asset name is invalid")
	}
	if strings.TrimSpace(asset.Address) == "" || len(asset.Address) > 255 {
		return errors.New("asset address is invalid")
	}
	if asset.Port < 1 || asset.Port > 65535 {
		return errors.New("asset port is invalid")
	}
	if strings.TrimSpace(asset.Username) == "" || len(asset.Username) > 128 {
		return errors.New("asset username is invalid")
	}
	for key, value := range asset.Labels {
		if len(key) == 0 || len(key) > 128 || len(value) > 512 || isSecretField(key) {
			return errors.New("asset labels are invalid")
		}
	}
	return nil
}

func validateCredential(envelope CredentialEnvelope) error {
	if err := validateIdentifier("installation id", envelope.InstallationID); err != nil {
		return err
	}
	if err := validateIdentifier("credential id", envelope.CredentialID); err != nil {
		return err
	}
	if envelope.Version == 0 || !identifierPattern.MatchString(envelope.Kind) || envelope.KeyID == "" || len(envelope.KeyID) > 512 {
		return errors.New("credential envelope metadata is incomplete")
	}
	if len(envelope.Ciphertext) == 0 || len(envelope.WrappedKey) == 0 {
		return errors.New("credential envelope is incomplete")
	}
	return validateSafeJSONObject(envelope.Metadata)
}

func validateJob(job Job) error {
	if err := validateIdentifier("installation id", job.InstallationID); err != nil {
		return err
	}
	if err := validateIdentifier("job id", job.ID); err != nil {
		return err
	}
	if err := validateIdentifier("asset id", job.AssetID); err != nil {
		return err
	}
	if !identifierPattern.MatchString(job.Type) || !validJobState(job.State) || job.RequestedBy == "" || len(job.RequestedBy) > 256 {
		return errors.New("job metadata is incomplete")
	}
	if job.RequestID != "" {
		if err := validateIdentifier("request id", job.RequestID); err != nil {
			return err
		}
	}
	if job.IdempotencyKey != "" {
		if err := validateIdentifier("idempotency key", job.IdempotencyKey); err != nil {
			return err
		}
	}
	if err := validateSafeJSONObject(job.Parameters); err != nil {
		return fmt.Errorf("job parameters: %w", err)
	}
	if err := validateSafeJSONObject(job.Result); err != nil {
		return fmt.Errorf("job result: %w", err)
	}
	if len(job.ErrorCode) > 128 || isSecretField(job.ErrorCode) || len(job.ErrorMessage) > 4096 {
		return errors.New("job error is invalid")
	}
	return nil
}

func validateAudit(event AuditEvent) error {
	if err := validateIdentifier("installation id", event.InstallationID); err != nil {
		return err
	}
	if err := validateIdentifier("audit id", event.ID); err != nil {
		return err
	}
	if event.Actor == "" || event.Action == "" || event.TargetType == "" || event.Outcome == "" {
		return errors.New("audit event is incomplete")
	}
	if err := validateSafeJSONObject(event.Details); err != nil {
		return fmt.Errorf("audit details: %w", err)
	}
	return nil
}

// ValidateSafeJSON rejects oversized or malformed JSON whose object keys
// indicate secret-bearing data. It is a final persistence boundary,
// not a replacement for upstream redaction of free-form values.
func ValidateSafeJSON(raw json.RawMessage) error {
	if len(raw) == 0 {
		return nil
	}
	if len(raw) > MaxJSONBytes || !json.Valid(raw) {
		return errors.New("JSON payload is invalid or too large")
	}
	var value any
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		return errors.New("JSON payload is invalid")
	}
	if containsSecretField(value, 0) {
		return ErrUnsafeJSON
	}
	return nil
}

func validateSafeJSONObject(raw json.RawMessage) error {
	if len(raw) == 0 {
		return nil
	}
	if err := ValidateSafeJSON(raw); err != nil {
		return err
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil || object == nil {
		return errors.New("JSON payload must be an object")
	}
	return nil
}

func validJobState(state string) bool {
	switch state {
	case "created", "prechecking", "awaiting_approval", "queued", "running", "verifying", "succeeded", "failed", "timed_out", "cancelled", "orphaned", "reconciling":
		return true
	default:
		return false
	}
}

func containsSecretField(value any, depth int) bool {
	if depth > 64 {
		return true
	}
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			if isSecretField(key) || containsSecretField(child, depth+1) {
				return true
			}
		}
	case []any:
		for _, child := range typed {
			if containsSecretField(child, depth+1) {
				return true
			}
		}
	}
	return false
}

func isSecretField(key string) bool {
	normalized := strings.ToLower(strings.NewReplacer("-", "_", ".", "_", " ", "_").Replace(key))
	if strings.HasSuffix(normalized, "_id") || strings.HasSuffix(normalized, "_version") || strings.HasSuffix(normalized, "_fingerprint") {
		return false
	}
	switch normalized {
	case "password", "passwd", "passphrase", "private_key", "privatekey", "secret", "client_secret", "api_token", "access_token", "refresh_token", "authorization", "cookie", "set_cookie", "credential", "credentials", "ciphertext", "wrapped_key":
		return true
	default:
		return false
	}
}
