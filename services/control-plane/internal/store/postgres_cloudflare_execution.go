package store

import (
	"time"

	"vpsmanager/services/control-plane/internal/model"
	"vpsmanager/services/persistence"
)

func (p *Postgres) UpdateWorkerVersionProvider(workerID, versionID, providerVersionID string, providerVersionNumber int64, uploadedAt time.Time) error {
	ctx, cancel := p.operationContext()
	defer cancel()
	return mapPersistenceError(p.repository.UpdateWorkerVersionProvider(ctx, p.installationID, workerID, versionID, providerVersionID, providerVersionNumber, uploadedAt))
}

func (p *Postgres) GetWorkerDeployment(workerID, deploymentID string) (model.CloudflareDeployment, error) {
	ctx, cancel := p.operationContext()
	defer cancel()
	deployment, err := p.repository.GetWorkerDeployment(ctx, p.installationID, workerID, deploymentID)
	if err != nil {
		return model.CloudflareDeployment{}, mapPersistenceError(err)
	}
	return persistenceToWorkerDeployment(deployment), nil
}

func (p *Postgres) UpdateWorkerDeployment(updated model.CloudflareDeployment, expectedState string) error {
	ctx, cancel := p.operationContext()
	defer cancel()
	current, err := p.repository.GetWorkerDeployment(ctx, p.installationID, updated.WorkerID, updated.ID)
	if err != nil {
		return mapPersistenceError(err)
	}
	if current.State != expectedState || !validWorkerDeploymentTransition(persistenceToWorkerDeployment(current), updated) {
		return ErrConflict
	}
	persisted := workerDeploymentToPersistence(p.installationID, updated)
	return mapPersistenceError(p.repository.UpdateWorkerDeployment(ctx, persisted, expectedState))
}

func workerDeploymentToPersistence(installationID string, deployment model.CloudflareDeployment) persistence.WorkerDeployment {
	return persistence.WorkerDeployment{
		InstallationID: installationID, ID: deployment.ID, WorkerID: deployment.WorkerID, VersionID: deployment.VersionID,
		PreviousDesiredVersion: deployment.PreviousDesiredVersionID, Kind: deployment.Kind, State: deployment.State,
		ProviderExecution: deployment.ProviderExecutionAllowed, ProviderVersionID: deployment.ProviderVersionID,
		ProviderDeploymentID: deployment.ProviderDeploymentID, ProviderState: deployment.ProviderState, ErrorCode: deployment.ErrorCode,
		StartedAt: deployment.StartedAt, FinishedAt: deployment.FinishedAt, CreatedAt: deployment.CreatedAt, CreatedBy: deployment.CreatedBy,
	}
}

func persistenceToWorkerDeployment(deployment persistence.WorkerDeployment) model.CloudflareDeployment {
	return model.CloudflareDeployment{
		ID: deployment.ID, WorkerID: deployment.WorkerID, VersionID: deployment.VersionID,
		PreviousDesiredVersionID: deployment.PreviousDesiredVersion, Kind: deployment.Kind, State: deployment.State,
		ProviderExecutionAllowed: deployment.ProviderExecution, ProviderVersionID: deployment.ProviderVersionID,
		ProviderDeploymentID: deployment.ProviderDeploymentID, ProviderState: deployment.ProviderState, ErrorCode: deployment.ErrorCode,
		StartedAt: deployment.StartedAt, FinishedAt: deployment.FinishedAt, CreatedAt: deployment.CreatedAt, CreatedBy: deployment.CreatedBy,
	}
}
