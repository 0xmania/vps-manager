package model

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"vpsmanager/services/control-plane/internal/auth"
	"vpsmanager/services/control-plane/internal/credentials"
)

type Host struct {
	ID        string            `json:"id"`
	Name      string            `json:"name"`
	Address   string            `json:"address"`
	Port      int               `json:"port"`
	Username  string            `json:"username"`
	Labels    map[string]string `json:"labels,omitempty"`
	HostKey   *HostKeyPin       `json:"hostKey,omitempty"`
	Version   uint64            `json:"version"`
	CreatedAt time.Time         `json:"createdAt"`
	UpdatedAt time.Time         `json:"updatedAt"`
}

type HostKeyPin struct {
	Algorithm         string    `json:"algorithm"`
	FingerprintSHA256 string    `json:"fingerprintSha256"`
	PublicKey         string    `json:"publicKey"`
	ConfirmedAt       time.Time `json:"confirmedAt"`
	ConfirmedBy       string    `json:"confirmedBy"`
}

type CredentialMetadata struct {
	ID                   string    `json:"id"`
	HostID               string    `json:"hostId"`
	Kind                 string    `json:"kind"`
	PublicKeyFingerprint string    `json:"publicKeyFingerprint"`
	KeyID                string    `json:"keyId"`
	CreatedAt            time.Time `json:"createdAt"`
	CreatedBy            string    `json:"createdBy"`
}

type StoredCredential struct {
	Metadata CredentialMetadata   `json:"metadata"`
	Envelope credentials.Envelope `json:"-"`
}

type JobState string

const (
	JobQueued           JobState = "queued"
	JobRunning          JobState = "running"
	JobAwaitingApproval JobState = "awaiting_approval"
	JobSucceeded        JobState = "succeeded"
	JobFailed           JobState = "failed"
	JobTimedOut         JobState = "timed_out"
	JobCancelled        JobState = "cancelled"
)

type Job struct {
	ID                 string                  `json:"id"`
	Type               string                  `json:"type"`
	HostID             string                  `json:"hostId"`
	State              JobState                `json:"state"`
	RequestedBy        string                  `json:"requestedBy"`
	RequestedSessionID string                  `json:"-"`
	CreatedAt          time.Time               `json:"createdAt"`
	StartedAt          *time.Time              `json:"startedAt,omitempty"`
	FinishedAt         *time.Time              `json:"finishedAt,omitempty"`
	Snapshot           *RuntimeSnapshot        `json:"snapshot,omitempty"`
	Command            *CommandDescriptor      `json:"command,omitempty"`
	CommandResult      *CommandResult          `json:"commandResult,omitempty"`
	AnomalyScan        *AnomalyScanResult      `json:"anomalyScan,omitempty"`
	RunbookPreview     *RunbookPreviewResult   `json:"runbookPreview,omitempty"`
	RunbookExecution   *RunbookExecutionResult `json:"runbookExecution,omitempty"`
	Error              *JobError               `json:"error,omitempty"`
	Version            uint64                  `json:"version"`
}

type JobError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type RuntimeSnapshot struct {
	ObservedAt           time.Time         `json:"observedAt"`
	Hostname             string            `json:"hostname,omitempty"`
	Kernel               string            `json:"kernel,omitempty"`
	UptimeSeconds        uint64            `json:"uptimeSeconds,omitempty"`
	Load                 [3]float64        `json:"load"`
	MemoryTotalBytes     uint64            `json:"memoryTotalBytes,omitempty"`
	MemoryAvailableBytes uint64            `json:"memoryAvailableBytes,omitempty"`
	CPUModel             string            `json:"cpuModel,omitempty"`
	CPULogicalCores      uint32            `json:"cpuLogicalCores,omitempty"`
	Filesystems          []FilesystemUsage `json:"filesystems,omitempty"`
	FieldErrors          map[string]string `json:"fieldErrors,omitempty"`
}

type FilesystemUsage struct {
	Mount      string `json:"mount"`
	TotalBytes uint64 `json:"totalBytes"`
	UsedBytes  uint64 `json:"usedBytes"`
	FreeBytes  uint64 `json:"freeBytes"`
}

type AuditEvent struct {
	ID         string         `json:"id"`
	Timestamp  time.Time      `json:"timestamp"`
	Actor      string         `json:"actor"`
	Role       auth.Role      `json:"role"`
	Action     string         `json:"action"`
	TargetType string         `json:"targetType"`
	TargetID   string         `json:"targetId,omitempty"`
	Outcome    string         `json:"outcome"`
	RequestID  string         `json:"requestId,omitempty"`
	Details    map[string]any `json:"details,omitempty"`
}

func NewID(prefix string) (string, error) {
	if prefix == "" || strings.ContainsAny(prefix, " /\\") {
		return "", errors.New("invalid id prefix")
	}
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return prefix + "_" + base64.RawURLEncoding.EncodeToString(raw), nil
}

func CanTransition(from, to JobState) bool {
	switch from {
	case JobQueued:
		return to == JobRunning || to == JobCancelled
	case JobAwaitingApproval:
		return to == JobRunning || to == JobCancelled
	case JobRunning:
		return to == JobAwaitingApproval || to == JobSucceeded || to == JobFailed || to == JobTimedOut || to == JobCancelled
	default:
		return false
	}
}

func TransitionJob(job Job, to JobState, now time.Time) (Job, error) {
	if !CanTransition(job.State, to) {
		return Job{}, fmt.Errorf("invalid job transition %s -> %s", job.State, to)
	}
	now = now.UTC()
	job.State = to
	job.Version++
	if to == JobRunning {
		job.StartedAt = &now
	}
	if to == JobSucceeded || to == JobFailed || to == JobTimedOut || to == JobCancelled {
		job.FinishedAt = &now
	}
	return job, nil
}
