package store

import (
	"sort"

	"vpsmanager/services/control-plane/internal/model"
)

func (m *Memory) CreateWorker(worker model.CloudflareWorker) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.workers[worker.ID]; exists {
		return ErrConflict
	}
	m.workers[worker.ID] = worker
	return nil
}

func (m *Memory) GetWorker(id string) (model.CloudflareWorker, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	worker, ok := m.workers[id]
	if !ok {
		return model.CloudflareWorker{}, ErrNotFound
	}
	return worker, nil
}

func (m *Memory) ListWorkers() ([]model.CloudflareWorker, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	workers := make([]model.CloudflareWorker, 0, len(m.workers))
	for _, worker := range m.workers {
		workers = append(workers, worker)
	}
	sort.Slice(workers, func(i, j int) bool { return workers[i].CreatedAt.Before(workers[j].CreatedAt) })
	return workers, nil
}

func (m *Memory) PutWorkerToken(token model.StoredCloudflareToken) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.workers[token.Metadata.WorkerID]; !ok {
		return ErrNotFound
	}
	m.workerTokens[token.Metadata.WorkerID] = cloneWorkerToken(token)
	return nil
}

func (m *Memory) GetWorkerToken(workerID string) (model.StoredCloudflareToken, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	token, ok := m.workerTokens[workerID]
	if !ok {
		return model.StoredCloudflareToken{}, ErrNotFound
	}
	return cloneWorkerToken(token), nil
}

func (m *Memory) DeleteWorkerToken(workerID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.workerTokens[workerID]; !ok {
		return ErrNotFound
	}
	delete(m.workerTokens, workerID)
	return nil
}

func (m *Memory) CreateWorkerVersion(version model.StoredCloudflareWorkerVersion) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.workers[version.Metadata.WorkerID]; !ok {
		return ErrNotFound
	}
	if _, exists := m.workerVersions[version.Metadata.ID]; exists {
		return ErrConflict
	}
	m.workerVersions[version.Metadata.ID] = cloneWorkerVersion(version)
	return nil
}

func (m *Memory) GetWorkerVersion(workerID, versionID string) (model.StoredCloudflareWorkerVersion, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	version, ok := m.workerVersions[versionID]
	if !ok || version.Metadata.WorkerID != workerID {
		return model.StoredCloudflareWorkerVersion{}, ErrNotFound
	}
	return cloneWorkerVersion(version), nil
}

func (m *Memory) ListWorkerVersions(workerID string) ([]model.CloudflareWorkerVersion, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	versions := make([]model.CloudflareWorkerVersion, 0)
	for _, version := range m.workerVersions {
		if version.Metadata.WorkerID == workerID {
			versions = append(versions, cloneWorkerVersion(version).Metadata)
		}
	}
	sort.Slice(versions, func(i, j int) bool { return versions[i].CreatedAt.After(versions[j].CreatedAt) })
	return versions, nil
}

// PlanWorkerDeployment records desired state only. It atomically verifies the
// encrypted token and module exist, but never decrypts the token or contacts
// Cloudflare. A separate provider adapter must later consume this plan.
func (m *Memory) PlanWorkerDeployment(deployment model.CloudflareDeployment, updatedAt model.CloudflareWorker) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	worker, ok := m.workers[deployment.WorkerID]
	if (deployment.Kind != "deploy" && deployment.Kind != "rollback") || deployment.State != "ready_for_provider" || deployment.ProviderExecutionAllowed {
		return ErrConflict
	}
	if !ok {
		return ErrNotFound
	}
	version, ok := m.workerVersions[deployment.VersionID]
	if !ok || version.Metadata.WorkerID != worker.ID {
		return ErrNotFound
	}
	if _, ok := m.workerTokens[worker.ID]; !ok {
		return ErrNotFound
	}
	if _, exists := m.workerDeployments[deployment.ID]; exists {
		return ErrConflict
	}
	if deployment.PreviousDesiredVersionID != worker.DesiredVersionID {
		return ErrConflict
	}
	if deployment.Kind == "rollback" && (worker.DesiredVersionID == "" || worker.DesiredVersionID == deployment.VersionID) {
		return ErrConflict
	}
	if updatedAt.ID != worker.ID || updatedAt.Version != worker.Version+1 || updatedAt.DesiredVersionID != deployment.VersionID {
		return ErrConflict
	}
	m.workerDeployments[deployment.ID] = cloneWorkerDeployment(deployment)
	m.workers[worker.ID] = updatedAt
	return nil
}

func (m *Memory) ListWorkerDeployments(workerID string) ([]model.CloudflareDeployment, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	deployments := make([]model.CloudflareDeployment, 0)
	for _, deployment := range m.workerDeployments {
		if deployment.WorkerID == workerID {
			deployments = append(deployments, cloneWorkerDeployment(deployment))
		}
	}
	sort.Slice(deployments, func(i, j int) bool { return deployments[i].CreatedAt.After(deployments[j].CreatedAt) })
	return deployments, nil
}

func cloneWorkerToken(token model.StoredCloudflareToken) model.StoredCloudflareToken {
	copy := token
	copy.Envelope.Ciphertext = append([]byte(nil), token.Envelope.Ciphertext...)
	copy.Envelope.Nonce = append([]byte(nil), token.Envelope.Nonce...)
	copy.Envelope.WrappedKey = append([]byte(nil), token.Envelope.WrappedKey...)
	copy.Envelope.KeyNonce = append([]byte(nil), token.Envelope.KeyNonce...)
	return copy
}

func cloneWorkerVersion(version model.StoredCloudflareWorkerVersion) model.StoredCloudflareWorkerVersion {
	copy := version
	copy.Module = append([]byte(nil), version.Module...)
	if version.Metadata.ProviderUploadedAt != nil {
		uploaded := *version.Metadata.ProviderUploadedAt
		copy.Metadata.ProviderUploadedAt = &uploaded
	}
	return copy
}
