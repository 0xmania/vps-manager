package store

import (
	"time"

	"vpsmanager/services/control-plane/internal/model"
)

func (m *Memory) UpdateWorkerVersionProvider(workerID, versionID, providerVersionID string, providerVersionNumber int64, uploadedAt time.Time) error {
	if workerID == "" || versionID == "" || providerVersionID == "" || providerVersionNumber < 0 || uploadedAt.IsZero() {
		return ErrConflict
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	version, ok := m.workerVersions[versionID]
	if !ok || version.Metadata.WorkerID != workerID {
		return ErrNotFound
	}
	uploadedAt = uploadedAt.UTC()
	version.Metadata.ProviderVersionID = providerVersionID
	version.Metadata.ProviderVersionNumber = providerVersionNumber
	version.Metadata.ProviderUploadedAt = &uploadedAt
	m.workerVersions[versionID] = cloneWorkerVersion(version)
	return nil
}

func (m *Memory) GetWorkerDeployment(workerID, deploymentID string) (model.CloudflareDeployment, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	deployment, ok := m.workerDeployments[deploymentID]
	if !ok || deployment.WorkerID != workerID {
		return model.CloudflareDeployment{}, ErrNotFound
	}
	return cloneWorkerDeployment(deployment), nil
}

// UpdateWorkerDeployment applies a compare-and-swap state transition.
func (m *Memory) UpdateWorkerDeployment(updated model.CloudflareDeployment, expectedState string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	current, ok := m.workerDeployments[updated.ID]
	if !ok || current.WorkerID != updated.WorkerID {
		return ErrNotFound
	}
	if current.State != expectedState || !validWorkerDeploymentTransition(current, updated) {
		return ErrConflict
	}
	m.workerDeployments[updated.ID] = cloneWorkerDeployment(updated)
	return nil
}

func validWorkerDeploymentTransition(current, updated model.CloudflareDeployment) bool {
	if updated.ID != current.ID || updated.WorkerID != current.WorkerID || updated.VersionID != current.VersionID ||
		updated.PreviousDesiredVersionID != current.PreviousDesiredVersionID || updated.Kind != current.Kind ||
		!updated.CreatedAt.Equal(current.CreatedAt) || updated.CreatedBy != current.CreatedBy || !updated.ProviderExecutionAllowed {
		return false
	}
	switch {
	case current.State == "ready_for_provider" && updated.State == "running":
		return updated.StartedAt != nil && updated.FinishedAt == nil && updated.ErrorCode == "" &&
			updated.ProviderDeploymentID == "" && updated.ProviderState == "" &&
			!updated.StartedAt.Before(updated.CreatedAt)
	case current.State == "running" && updated.State == "succeeded":
		return validFinishedDeployment(updated) && updated.ErrorCode == "" && updated.ProviderVersionID != "" &&
			updated.ProviderDeploymentID != "" && updated.ProviderState == "active"
	case current.State == "running" && updated.State == "failed":
		return validFinishedDeployment(updated) && updated.ErrorCode != "" && len(updated.ErrorCode) <= 128
	default:
		return false
	}
}

func validFinishedDeployment(deployment model.CloudflareDeployment) bool {
	return deployment.StartedAt != nil && deployment.FinishedAt != nil &&
		!deployment.StartedAt.Before(deployment.CreatedAt) && !deployment.FinishedAt.Before(*deployment.StartedAt)
}

func cloneWorkerDeployment(deployment model.CloudflareDeployment) model.CloudflareDeployment {
	copy := deployment
	if deployment.StartedAt != nil {
		started := *deployment.StartedAt
		copy.StartedAt = &started
	}
	if deployment.FinishedAt != nil {
		finished := *deployment.FinishedAt
		copy.FinishedAt = &finished
	}
	return copy
}
