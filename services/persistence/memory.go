package persistence

import (
	"context"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// MemoryRepository stores development data in the current process.
type MemoryRepository struct {
	mu          sync.RWMutex
	assets      map[string]Asset
	credentials map[string]CredentialEnvelope
	jobs        map[string]Job
	audits      []AuditEvent
}

func NewMemoryRepository() *MemoryRepository {
	return &MemoryRepository{
		assets:      make(map[string]Asset),
		credentials: make(map[string]CredentialEnvelope),
		jobs:        make(map[string]Job),
	}
}

func composite(parts ...string) string {
	var result strings.Builder
	for _, part := range parts {
		result.WriteString(strconv.Itoa(len(part)))
		result.WriteByte(':')
		result.WriteString(part)
		result.WriteByte('|')
	}
	return result.String()
}

func (m *MemoryRepository) CreateAsset(_ context.Context, asset Asset) error {
	if err := validateAsset(asset); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	key := composite(asset.InstallationID, asset.ID)
	if _, exists := m.assets[key]; exists {
		return ErrConflict
	}
	m.assets[key] = cloneAsset(asset)
	return nil
}

func (m *MemoryRepository) GetAsset(_ context.Context, installationID, id string) (Asset, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	asset, exists := m.assets[composite(installationID, id)]
	if !exists {
		return Asset{}, ErrNotFound
	}
	return cloneAsset(asset), nil
}

func (m *MemoryRepository) ListAssets(_ context.Context, installationID string, limit int, afterID string) ([]Asset, error) {
	if err := validateIdentifier("installation id", installationID); err != nil {
		return nil, err
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	items := make([]Asset, 0)
	for _, asset := range m.assets {
		if asset.InstallationID == installationID && asset.ID > afterID {
			items = append(items, cloneAsset(asset))
		}
	}
	sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
	limit = normalizeLimit(limit)
	if len(items) > limit {
		items = items[:limit]
	}
	return items, nil
}

func (m *MemoryRepository) UpdateAsset(_ context.Context, asset Asset, expectedVersion uint64) error {
	if err := validateAsset(asset); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	key := composite(asset.InstallationID, asset.ID)
	current, exists := m.assets[key]
	if !exists {
		return ErrNotFound
	}
	if current.Version != expectedVersion || asset.Version != expectedVersion+1 {
		return ErrConflict
	}
	m.assets[key] = cloneAsset(asset)
	return nil
}

func (m *MemoryRepository) DeleteAsset(_ context.Context, installationID, id string, expectedVersion uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := composite(installationID, id)
	current, exists := m.assets[key]
	if !exists {
		return ErrNotFound
	}
	if current.Version != expectedVersion {
		return ErrConflict
	}
	delete(m.assets, key)
	return nil
}

func (m *MemoryRepository) PutCredentialEnvelope(_ context.Context, envelope CredentialEnvelope) error {
	if err := validateCredential(envelope); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	key := composite(envelope.InstallationID, envelope.CredentialID, strconv.FormatUint(envelope.Version, 10))
	if _, exists := m.credentials[key]; exists {
		return ErrConflict
	}
	m.credentials[key] = cloneCredential(envelope)
	return nil
}

func (m *MemoryRepository) GetCredentialEnvelope(_ context.Context, installationID, credentialID string, version uint64) (CredentialEnvelope, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	value, exists := m.credentials[composite(installationID, credentialID, strconv.FormatUint(version, 10))]
	if !exists {
		return CredentialEnvelope{}, ErrNotFound
	}
	return cloneCredential(value), nil
}

func (m *MemoryRepository) CreateJob(_ context.Context, job Job) error {
	if err := validateJob(job); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	key := composite(job.InstallationID, job.ID)
	if _, exists := m.jobs[key]; exists {
		return ErrConflict
	}
	m.jobs[key] = cloneJob(job)
	return nil
}

func (m *MemoryRepository) GetJob(_ context.Context, installationID, id string) (Job, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	job, exists := m.jobs[composite(installationID, id)]
	if !exists {
		return Job{}, ErrNotFound
	}
	return cloneJob(job), nil
}

func (m *MemoryRepository) ListJobs(_ context.Context, installationID string, limit int, afterID string) ([]Job, error) {
	if err := validateIdentifier("installation id", installationID); err != nil {
		return nil, err
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	items := make([]Job, 0)
	for _, job := range m.jobs {
		if job.InstallationID == installationID && job.ID > afterID {
			items = append(items, cloneJob(job))
		}
	}
	sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
	limit = normalizeLimit(limit)
	if len(items) > limit {
		items = items[:limit]
	}
	return items, nil
}

func (m *MemoryRepository) UpdateJob(_ context.Context, job Job, expectedVersion uint64) error {
	if err := validateJob(job); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	key := composite(job.InstallationID, job.ID)
	current, exists := m.jobs[key]
	if !exists {
		return ErrNotFound
	}
	if current.Version != expectedVersion || job.Version != expectedVersion+1 {
		return ErrConflict
	}
	m.jobs[key] = cloneJob(job)
	return nil
}

func (m *MemoryRepository) AppendAudit(_ context.Context, event AuditEvent) error {
	if err := validateAudit(event); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, existing := range m.audits {
		if existing.InstallationID == event.InstallationID && existing.ID == event.ID {
			return ErrConflict
		}
	}
	m.audits = append(m.audits, cloneAudit(event))
	return nil
}

func (m *MemoryRepository) ListAudit(_ context.Context, filter AuditFilter) ([]AuditEvent, error) {
	if err := validateIdentifier("installation id", filter.InstallationID); err != nil {
		return nil, err
	}
	beforeID := filter.BeforeID
	if beforeID == "" {
		beforeID = "~"
	} else if err := validateIdentifier("audit cursor id", beforeID); err != nil {
		return nil, err
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	items := make([]AuditEvent, 0)
	for _, event := range m.audits {
		if event.InstallationID != filter.InstallationID {
			continue
		}
		if !filter.Before.IsZero() {
			if event.Timestamp.After(filter.Before) {
				continue
			}
			if event.Timestamp.Equal(filter.Before) && event.ID >= beforeID {
				continue
			}
		}
		items = append(items, cloneAudit(event))
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Timestamp.Equal(items[j].Timestamp) {
			return items[i].ID > items[j].ID
		}
		return items[i].Timestamp.After(items[j].Timestamp)
	})
	limit := normalizeLimit(filter.Limit)
	if len(items) > limit {
		items = items[:limit]
	}
	return items, nil
}

func cloneAsset(asset Asset) Asset {
	copyValue := asset
	copyValue.Labels = make(map[string]string, len(asset.Labels))
	for key, value := range asset.Labels {
		copyValue.Labels[key] = value
	}
	if asset.HostKey != nil {
		pin := *asset.HostKey
		copyValue.HostKey = &pin
	}
	return copyValue
}

func cloneCredential(value CredentialEnvelope) CredentialEnvelope {
	copyValue := value
	copyValue.Ciphertext = append([]byte(nil), value.Ciphertext...)
	copyValue.CipherNonce = append([]byte(nil), value.CipherNonce...)
	copyValue.WrappedKey = append([]byte(nil), value.WrappedKey...)
	copyValue.WrappedKeyNonce = append([]byte(nil), value.WrappedKeyNonce...)
	copyValue.Metadata = append([]byte(nil), value.Metadata...)
	return copyValue
}

func cloneJob(job Job) Job {
	copyValue := job
	copyValue.Parameters = append([]byte(nil), job.Parameters...)
	copyValue.Result = append([]byte(nil), job.Result...)
	copyValue.StartedAt = cloneTime(job.StartedAt)
	copyValue.FinishedAt = cloneTime(job.FinishedAt)
	return copyValue
}

func cloneAudit(event AuditEvent) AuditEvent {
	copyValue := event
	copyValue.Details = append([]byte(nil), event.Details...)
	return copyValue
}

func cloneTime(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	copyValue := *value
	return &copyValue
}
