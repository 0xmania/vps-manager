package store

import (
	"context"
	"errors"
	"sort"
	"sync"

	"vpsmanager/services/control-plane/internal/audit"
	"vpsmanager/services/control-plane/internal/model"
)

var (
	ErrNotFound = errors.New("record not found")
	ErrConflict = errors.New("record version conflict")
)

// Memory is an ephemeral in-process repository for development mode. Its API
// keeps persistence concerns out of handlers.
type Memory struct {
	mu                sync.RWMutex
	hosts             map[string]model.Host
	credentials       map[string]model.StoredCredential // keyed by host id
	jobs              map[string]model.Job
	audits            []model.AuditEvent
	workers           map[string]model.CloudflareWorker
	workerTokens      map[string]model.StoredCloudflareToken
	workerVersions    map[string]model.StoredCloudflareWorkerVersion
	workerDeployments map[string]model.CloudflareDeployment
}

func NewMemory() *Memory {
	return &Memory{
		hosts:             make(map[string]model.Host),
		credentials:       make(map[string]model.StoredCredential),
		jobs:              make(map[string]model.Job),
		workers:           make(map[string]model.CloudflareWorker),
		workerTokens:      make(map[string]model.StoredCloudflareToken),
		workerVersions:    make(map[string]model.StoredCloudflareWorkerVersion),
		workerDeployments: make(map[string]model.CloudflareDeployment),
	}
}

func (m *Memory) CreateHost(host model.Host) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.hosts[host.ID]; exists {
		return ErrConflict
	}
	m.hosts[host.ID] = cloneHost(host)
	return nil
}

func (m *Memory) GetHost(id string) (model.Host, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	host, ok := m.hosts[id]
	if !ok {
		return model.Host{}, ErrNotFound
	}
	return cloneHost(host), nil
}

func (m *Memory) ListHosts() ([]model.Host, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([]model.Host, 0, len(m.hosts))
	for _, host := range m.hosts {
		result = append(result, cloneHost(host))
	}
	sort.Slice(result, func(i, j int) bool { return result[i].CreatedAt.Before(result[j].CreatedAt) })
	return result, nil
}

func (m *Memory) UpdateHost(host model.Host, expectedVersion uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	current, ok := m.hosts[host.ID]
	if !ok {
		return ErrNotFound
	}
	if current.Version != expectedVersion {
		return ErrConflict
	}
	m.hosts[host.ID] = cloneHost(host)
	return nil
}

func (m *Memory) DeleteHost(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.hosts[id]; !ok {
		return ErrNotFound
	}
	delete(m.hosts, id)
	delete(m.credentials, id)
	return nil
}

func (m *Memory) PutCredential(credential model.StoredCredential) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.hosts[credential.Metadata.HostID]; !ok {
		return ErrNotFound
	}
	m.credentials[credential.Metadata.HostID] = cloneCredential(credential)
	return nil
}

func (m *Memory) GetCredential(hostID string) (model.StoredCredential, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	credential, ok := m.credentials[hostID]
	if !ok {
		return model.StoredCredential{}, ErrNotFound
	}
	return cloneCredential(credential), nil
}

func (m *Memory) DeleteCredential(hostID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.credentials[hostID]; !ok {
		return ErrNotFound
	}
	delete(m.credentials, hostID)
	return nil
}

func (m *Memory) CreateJob(job model.Job) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.jobs[job.ID]; exists {
		return ErrConflict
	}
	m.jobs[job.ID] = cloneJob(job)
	return nil
}

func (m *Memory) GetJob(id string) (model.Job, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	job, ok := m.jobs[id]
	if !ok {
		return model.Job{}, ErrNotFound
	}
	return cloneJob(job), nil
}

func (m *Memory) ListJobs() ([]model.Job, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([]model.Job, 0, len(m.jobs))
	for _, job := range m.jobs {
		result = append(result, cloneJob(job))
	}
	sort.Slice(result, func(i, j int) bool { return result[i].CreatedAt.After(result[j].CreatedAt) })
	return result, nil
}

// MutateJob updates a job atomically under the repository lock.
func (m *Memory) MutateJob(id string, mutate func(model.Job) (model.Job, error)) (model.Job, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	job, ok := m.jobs[id]
	if !ok {
		return model.Job{}, ErrNotFound
	}
	updated, err := mutate(cloneJob(job))
	if err != nil {
		return model.Job{}, err
	}
	m.jobs[id] = cloneJob(updated)
	return cloneJob(updated), nil
}

func (m *Memory) AppendAudit(event model.AuditEvent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.audits = append(m.audits, cloneAudit(event))
	return nil
}

func (m *Memory) ListAudits(limit int) ([]model.AuditEvent, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	start := len(m.audits) - limit
	if start < 0 {
		start = 0
	}
	result := make([]model.AuditEvent, 0, len(m.audits)-start)
	for i := len(m.audits) - 1; i >= start; i-- {
		result = append(result, cloneAudit(m.audits[i]))
	}
	return result, nil
}

func (*Memory) StorageMode() string         { return "ephemeral" }
func (*Memory) Ready(context.Context) error { return nil }
func (*Memory) Close()                      {}

func cloneHost(host model.Host) model.Host {
	copy := host
	if host.Labels != nil {
		copy.Labels = make(map[string]string, len(host.Labels))
		for key, value := range host.Labels {
			copy.Labels[key] = value
		}
	}
	if host.HostKey != nil {
		pin := *host.HostKey
		copy.HostKey = &pin
	}
	return copy
}

func cloneCredential(credential model.StoredCredential) model.StoredCredential {
	copy := credential
	copy.Envelope.Ciphertext = append([]byte(nil), credential.Envelope.Ciphertext...)
	copy.Envelope.Nonce = append([]byte(nil), credential.Envelope.Nonce...)
	copy.Envelope.WrappedKey = append([]byte(nil), credential.Envelope.WrappedKey...)
	copy.Envelope.KeyNonce = append([]byte(nil), credential.Envelope.KeyNonce...)
	return copy
}

func cloneJob(job model.Job) model.Job {
	copy := job
	if job.Snapshot != nil {
		snapshot := *job.Snapshot
		snapshot.Filesystems = append([]model.FilesystemUsage(nil), job.Snapshot.Filesystems...)
		if job.Snapshot.FieldErrors != nil {
			snapshot.FieldErrors = make(map[string]string, len(job.Snapshot.FieldErrors))
			for key, value := range job.Snapshot.FieldErrors {
				snapshot.FieldErrors[key] = value
			}
		}
		copy.Snapshot = &snapshot
	}
	if job.Command != nil {
		command := *job.Command
		if job.Command.Parameters != nil {
			command.Parameters = make(map[string]string, len(job.Command.Parameters))
			for key, value := range job.Command.Parameters {
				command.Parameters[key] = value
			}
		}
		copy.Command = &command
	}
	if job.CommandResult != nil {
		result := *job.CommandResult
		copy.CommandResult = &result
	}
	if job.AnomalyScan != nil {
		scan := *job.AnomalyScan
		scan.Findings = append([]model.ProcessFinding(nil), job.AnomalyScan.Findings...)
		if job.AnomalyScan.AIAnalysis != nil {
			outcome := *job.AnomalyScan.AIAnalysis
			outcome.Analysis.RankedFindings = append(outcome.Analysis.RankedFindings[:0:0], job.AnomalyScan.AIAnalysis.Analysis.RankedFindings...)
			outcome.Analysis.HumanVerificationSteps = append(outcome.Analysis.HumanVerificationSteps[:0:0], job.AnomalyScan.AIAnalysis.Analysis.HumanVerificationSteps...)
			outcome.Analysis.Recommendations = append(outcome.Analysis.Recommendations[:0:0], job.AnomalyScan.AIAnalysis.Analysis.Recommendations...)
			scan.AIAnalysis = &outcome
		}
		copy.AnomalyScan = &scan
	}
	if job.RunbookPreview != nil {
		preview := *job.RunbookPreview
		preview.Steps = append(preview.Steps[:0:0], job.RunbookPreview.Steps...)
		copy.RunbookPreview = &preview
	}
	if job.RunbookExecution != nil {
		execution := *job.RunbookExecution
		execution.Steps = append(execution.Steps[:0:0], job.RunbookExecution.Steps...)
		copy.RunbookExecution = &execution
	}
	if job.Error != nil {
		errCopy := *job.Error
		copy.Error = &errCopy
	}
	return copy
}

func cloneAudit(event model.AuditEvent) model.AuditEvent {
	copy := event
	copy.Details = audit.SanitizeDetails(event.Details)
	return copy
}
