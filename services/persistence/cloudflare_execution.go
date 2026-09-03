package persistence

import (
	"context"
	"time"
)

func (p *PostgresRepository) UpdateWorkerVersionProvider(ctx context.Context, installationID, workerID, versionID, providerVersionID string, providerVersionNumber int64, uploadedAt time.Time) error {
	if installationID == "" || workerID == "" || versionID == "" || providerVersionID == "" || providerVersionNumber < 0 || uploadedAt.IsZero() {
		return ErrConflict
	}
	result, err := p.pool.Exec(ctx, `
		UPDATE vps_manager.cloudflare_worker_versions
		SET provider_version_id=$4, provider_version_number=$5, provider_uploaded_at=$6
		WHERE installation_id=$1 AND worker_id=$2 AND id=$3
	`, installationID, workerID, versionID, providerVersionID, providerVersionNumber, uploadedAt.UTC())
	return mapCASResult(result, err)
}

func (p *PostgresRepository) GetWorkerDeployment(ctx context.Context, installationID, workerID, deploymentID string) (WorkerDeployment, error) {
	var item WorkerDeployment
	var previous *string
	err := p.pool.QueryRow(ctx, `
		SELECT installation_id,id,worker_id,version_id,previous_desired_version_id,kind,state,provider_execution_allowed,
		       COALESCE(provider_version_id,''),COALESCE(provider_deployment_id,''),COALESCE(provider_state,''),COALESCE(error_code,''),
		       started_at,finished_at,created_at,created_by
		FROM vps_manager.cloudflare_deployments
		WHERE installation_id=$1 AND worker_id=$2 AND id=$3
	`, installationID, workerID, deploymentID).Scan(
		&item.InstallationID, &item.ID, &item.WorkerID, &item.VersionID, &previous, &item.Kind, &item.State, &item.ProviderExecution,
		&item.ProviderVersionID, &item.ProviderDeploymentID, &item.ProviderState, &item.ErrorCode,
		&item.StartedAt, &item.FinishedAt, &item.CreatedAt, &item.CreatedBy,
	)
	if err != nil {
		return WorkerDeployment{}, mapPostgresError(err)
	}
	if previous != nil {
		item.PreviousDesiredVersion = *previous
	}
	return item, nil
}

func (p *PostgresRepository) UpdateWorkerDeployment(ctx context.Context, updated WorkerDeployment, expectedState string) error {
	if updated.InstallationID == "" || updated.ID == "" || updated.WorkerID == "" || expectedState == "" {
		return ErrConflict
	}
	if updated.State != "running" && updated.State != "succeeded" && updated.State != "failed" {
		return ErrConflict
	}
	result, err := p.pool.Exec(ctx, `
		UPDATE vps_manager.cloudflare_deployments
		SET state=$4,provider_execution_allowed=$5,provider_version_id=$6,provider_deployment_id=$7,
		    provider_state=$8,error_code=$9,started_at=$10,finished_at=$11
		WHERE installation_id=$1 AND worker_id=$2 AND id=$3 AND state=$12
	`, updated.InstallationID, updated.WorkerID, updated.ID, updated.State, updated.ProviderExecution,
		nullString(updated.ProviderVersionID), nullString(updated.ProviderDeploymentID), nullString(updated.ProviderState),
		nullString(updated.ErrorCode), updated.StartedAt, updated.FinishedAt, expectedState)
	return mapCASResult(result, err)
}
