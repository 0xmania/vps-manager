package persistence

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

const (
	SecretScopeHost              = "host"
	SecretScopeCloudflareWorker  = "cloudflare_worker"
	MaxControlPlaneCollectionLen = 10000
)

// SecretBinding points to one immutable encrypted envelope. The current
// pointer may rotate or be removed; historical envelope rows are never
// updated or returned by list APIs.
type SecretBinding struct {
	InstallationID string
	ScopeType      string
	ScopeID        string
	CredentialID   string
	Version        uint64
	Envelope       CredentialEnvelope
}

type Worker struct {
	InstallationID string
	ID             string
	Name           string
	AccountID      string
	ScriptName     string
	DesiredVersion string
	Version        uint64
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

type WorkerVersion struct {
	InstallationID        string
	ID                    string
	WorkerID              string
	SHA256                string
	SizeBytes             int
	ContentType           string
	Entrypoint            string
	State                 string
	Module                []byte
	ProviderVersionID     string
	ProviderVersionNumber int64
	ProviderUploadedAt    *time.Time
	CreatedAt             time.Time
	CreatedBy             string
}

type WorkerDeployment struct {
	InstallationID         string
	ID                     string
	WorkerID               string
	VersionID              string
	PreviousDesiredVersion string
	Kind                   string
	State                  string
	ProviderExecution      bool
	ProviderVersionID      string
	ProviderDeploymentID   string
	ProviderState          string
	ErrorCode              string
	StartedAt              *time.Time
	FinishedAt             *time.Time
	CreatedAt              time.Time
	CreatedBy              string
}

func (p *PostgresRepository) Ping(ctx context.Context) error {
	if err := p.pool.Ping(ctx); err != nil {
		return errors.New("ping PostgreSQL")
	}
	return nil
}

func (p *PostgresRepository) ListAllAssets(ctx context.Context, installationID string) ([]Asset, error) {
	if err := validateIdentifier("installation id", installationID); err != nil {
		return nil, err
	}
	rows, err := p.pool.Query(ctx, `
		SELECT installation_id,id,name,address,port,username,labels,host_key,version,created_at,updated_at
		FROM vps_manager.assets WHERE installation_id=$1 ORDER BY created_at,id LIMIT $2
	`, installationID, MaxControlPlaneCollectionLen)
	if err != nil {
		return nil, errors.New("list PostgreSQL assets")
	}
	defer rows.Close()
	items := make([]Asset, 0)
	for rows.Next() {
		var item Asset
		var labels, hostKey []byte
		if err := rows.Scan(&item.InstallationID, &item.ID, &item.Name, &item.Address, &item.Port, &item.Username, &labels, &hostKey, &item.Version, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, errors.New("scan PostgreSQL asset")
		}
		if err := decodeAssetJSON(&item, labels, hostKey); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.New("iterate PostgreSQL assets")
	}
	return items, nil
}

func (p *PostgresRepository) PutCurrentSecret(ctx context.Context, binding SecretBinding) error {
	if err := validateSecretBinding(binding); err != nil {
		return err
	}
	tx, err := p.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return errors.New("begin PostgreSQL secret rotation")
	}
	defer tx.Rollback(ctx)
	if err := verifySecretScope(ctx, tx, binding); err != nil {
		return err
	}
	envelope := binding.Envelope
	_, err = tx.Exec(ctx, `
		INSERT INTO vps_manager.credential_envelopes
		(installation_id,credential_id,version,kind,key_id,ciphertext,cipher_nonce,wrapped_key,wrapped_key_nonce,metadata,created_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
	`, envelope.InstallationID, envelope.CredentialID, envelope.Version, envelope.Kind, envelope.KeyID, envelope.Ciphertext, nonNilBytes(envelope.CipherNonce), envelope.WrappedKey, nonNilBytes(envelope.WrappedKeyNonce), normalizedJSON(envelope.Metadata), envelope.CreatedAt.UTC())
	if err != nil {
		return mapPostgresError(err)
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO vps_manager.current_secret_bindings
		(installation_id,scope_type,scope_id,credential_id,credential_version,updated_at)
		VALUES ($1,$2,$3,$4,$5,$6)
		ON CONFLICT (installation_id,scope_type,scope_id) DO UPDATE
		SET credential_id=EXCLUDED.credential_id,credential_version=EXCLUDED.credential_version,updated_at=EXCLUDED.updated_at
	`, binding.InstallationID, binding.ScopeType, binding.ScopeID, binding.CredentialID, binding.Version, envelope.CreatedAt.UTC())
	if err != nil {
		return mapPostgresError(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return mapPostgresError(err)
	}
	return nil
}

func (p *PostgresRepository) GetCurrentSecret(ctx context.Context, installationID, scopeType, scopeID string) (SecretBinding, error) {
	var binding SecretBinding
	var envelope CredentialEnvelope
	err := p.pool.QueryRow(ctx, `
		SELECT b.installation_id,b.scope_type,b.scope_id,b.credential_id,b.credential_version,
		       e.kind,e.key_id,e.ciphertext,e.cipher_nonce,e.wrapped_key,e.wrapped_key_nonce,e.metadata,e.created_at
		FROM vps_manager.current_secret_bindings b
		JOIN vps_manager.credential_envelopes e
		  ON e.installation_id=b.installation_id AND e.credential_id=b.credential_id AND e.version=b.credential_version
		WHERE b.installation_id=$1 AND b.scope_type=$2 AND b.scope_id=$3
	`, installationID, scopeType, scopeID).Scan(
		&binding.InstallationID, &binding.ScopeType, &binding.ScopeID, &binding.CredentialID, &binding.Version,
		&envelope.Kind, &envelope.KeyID, &envelope.Ciphertext, &envelope.CipherNonce, &envelope.WrappedKey, &envelope.WrappedKeyNonce, &envelope.Metadata, &envelope.CreatedAt,
	)
	if err != nil {
		return SecretBinding{}, mapPostgresError(err)
	}
	envelope.InstallationID, envelope.CredentialID, envelope.Version = binding.InstallationID, binding.CredentialID, binding.Version
	binding.Envelope = envelope
	return binding, nil
}

func (p *PostgresRepository) DeleteCurrentSecret(ctx context.Context, installationID, scopeType, scopeID string) error {
	result, err := p.pool.Exec(ctx, `DELETE FROM vps_manager.current_secret_bindings WHERE installation_id=$1 AND scope_type=$2 AND scope_id=$3`, installationID, scopeType, scopeID)
	if err != nil {
		return mapPostgresError(err)
	}
	if result.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func validateSecretBinding(binding SecretBinding) error {
	if err := validateIdentifier("installation id", binding.InstallationID); err != nil {
		return err
	}
	if err := validateIdentifier("secret scope id", binding.ScopeID); err != nil {
		return err
	}
	if binding.ScopeType != SecretScopeHost && binding.ScopeType != SecretScopeCloudflareWorker {
		return errors.New("secret scope is invalid")
	}
	if binding.CredentialID != binding.Envelope.CredentialID || binding.Version != binding.Envelope.Version || binding.InstallationID != binding.Envelope.InstallationID {
		return errors.New("secret binding does not match envelope")
	}
	return validateCredential(binding.Envelope)
}

func verifySecretScope(ctx context.Context, tx pgx.Tx, binding SecretBinding) error {
	table := "vps_manager.assets"
	if binding.ScopeType == SecretScopeCloudflareWorker {
		table = "vps_manager.cloudflare_workers"
	}
	var exists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM `+table+` WHERE installation_id=$1 AND id=$2)`, binding.InstallationID, binding.ScopeID).Scan(&exists); err != nil {
		return errors.New("verify PostgreSQL secret scope")
	}
	if !exists {
		return ErrNotFound
	}
	return nil
}

func (p *PostgresRepository) MutateJob(ctx context.Context, installationID, id string, mutate func(Job) (Job, error)) (Job, error) {
	if mutate == nil {
		return Job{}, errors.New("job mutation is required")
	}
	tx, err := p.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return Job{}, errors.New("begin PostgreSQL job mutation")
	}
	defer tx.Rollback(ctx)
	current, err := getJobForUpdate(ctx, tx, installationID, id)
	if err != nil {
		return Job{}, err
	}
	updated, err := mutate(current)
	if err != nil {
		return Job{}, err
	}
	if updated.InstallationID != current.InstallationID || updated.ID != current.ID || updated.Version != current.Version+1 {
		return Job{}, ErrConflict
	}
	if err := validateJob(updated); err != nil {
		return Job{}, err
	}
	result, err := tx.Exec(ctx, `
		UPDATE vps_manager.jobs SET state=$3,result=$4,error_code=$5,error_message=$6,version=$7,started_at=$8,finished_at=$9,updated_at=$10
		WHERE installation_id=$1 AND id=$2 AND version=$11
	`, updated.InstallationID, updated.ID, updated.State, normalizedJSON(updated.Result), nullString(updated.ErrorCode), nullString(updated.ErrorMessage), updated.Version, updated.StartedAt, updated.FinishedAt, updated.UpdatedAt.UTC(), current.Version)
	if err := mapCASResult(result, err); err != nil {
		return Job{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Job{}, mapPostgresError(err)
	}
	return updated, nil
}

func getJobForUpdate(ctx context.Context, tx pgx.Tx, installationID, id string) (Job, error) {
	var job Job
	var requestID, idempotencyKey, errorCode, errorMessage *string
	err := tx.QueryRow(ctx, `
		SELECT installation_id,id,type,asset_id,state,requested_by,request_id,idempotency_key,parameters,result,error_code,error_message,version,created_at,started_at,finished_at,updated_at
		FROM vps_manager.jobs WHERE installation_id=$1 AND id=$2 FOR UPDATE
	`, installationID, id).Scan(&job.InstallationID, &job.ID, &job.Type, &job.AssetID, &job.State, &job.RequestedBy, &requestID, &idempotencyKey, &job.Parameters, &job.Result, &errorCode, &errorMessage, &job.Version, &job.CreatedAt, &job.StartedAt, &job.FinishedAt, &job.UpdatedAt)
	if err != nil {
		return Job{}, mapPostgresError(err)
	}
	assignOptionalStrings(&job, requestID, idempotencyKey, errorCode, errorMessage)
	return job, nil
}

func (p *PostgresRepository) ListAllJobs(ctx context.Context, installationID string) ([]Job, error) {
	rows, err := p.pool.Query(ctx, `
		SELECT installation_id,id,type,asset_id,state,requested_by,request_id,idempotency_key,parameters,result,error_code,error_message,version,created_at,started_at,finished_at,updated_at
		FROM vps_manager.jobs WHERE installation_id=$1 ORDER BY created_at DESC,id DESC LIMIT $2
	`, installationID, MaxControlPlaneCollectionLen)
	if err != nil {
		return nil, errors.New("list PostgreSQL jobs")
	}
	defer rows.Close()
	items := make([]Job, 0)
	for rows.Next() {
		var item Job
		var requestID, idempotencyKey, errorCode, errorMessage *string
		if err := rows.Scan(&item.InstallationID, &item.ID, &item.Type, &item.AssetID, &item.State, &item.RequestedBy, &requestID, &idempotencyKey, &item.Parameters, &item.Result, &errorCode, &errorMessage, &item.Version, &item.CreatedAt, &item.StartedAt, &item.FinishedAt, &item.UpdatedAt); err != nil {
			return nil, errors.New("scan PostgreSQL job")
		}
		assignOptionalStrings(&item, requestID, idempotencyKey, errorCode, errorMessage)
		items = append(items, item)
	}
	return items, rows.Err()
}

func (p *PostgresRepository) CreateWorker(ctx context.Context, worker Worker) error {
	_, err := p.pool.Exec(ctx, `
		INSERT INTO vps_manager.cloudflare_workers
		(installation_id,id,name,account_id,script_name,desired_version_id,version,created_at,updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
	`, worker.InstallationID, worker.ID, worker.Name, worker.AccountID, worker.ScriptName, nullString(worker.DesiredVersion), worker.Version, worker.CreatedAt.UTC(), worker.UpdatedAt.UTC())
	return mapPostgresError(err)
}

func (p *PostgresRepository) GetWorker(ctx context.Context, installationID, id string) (Worker, error) {
	var worker Worker
	var desired *string
	err := p.pool.QueryRow(ctx, `SELECT installation_id,id,name,account_id,script_name,desired_version_id,version,created_at,updated_at FROM vps_manager.cloudflare_workers WHERE installation_id=$1 AND id=$2`, installationID, id).Scan(
		&worker.InstallationID, &worker.ID, &worker.Name, &worker.AccountID, &worker.ScriptName, &desired, &worker.Version, &worker.CreatedAt, &worker.UpdatedAt,
	)
	if err != nil {
		return Worker{}, mapPostgresError(err)
	}
	if desired != nil {
		worker.DesiredVersion = *desired
	}
	return worker, nil
}

func (p *PostgresRepository) ListWorkers(ctx context.Context, installationID string) ([]Worker, error) {
	rows, err := p.pool.Query(ctx, `SELECT installation_id,id,name,account_id,script_name,desired_version_id,version,created_at,updated_at FROM vps_manager.cloudflare_workers WHERE installation_id=$1 ORDER BY created_at,id LIMIT $2`, installationID, MaxControlPlaneCollectionLen)
	if err != nil {
		return nil, errors.New("list PostgreSQL workers")
	}
	defer rows.Close()
	items := make([]Worker, 0)
	for rows.Next() {
		var item Worker
		var desired *string
		if err := rows.Scan(&item.InstallationID, &item.ID, &item.Name, &item.AccountID, &item.ScriptName, &desired, &item.Version, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, errors.New("scan PostgreSQL worker")
		}
		if desired != nil {
			item.DesiredVersion = *desired
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (p *PostgresRepository) CreateWorkerVersion(ctx context.Context, version WorkerVersion) error {
	_, err := p.pool.Exec(ctx, `
		INSERT INTO vps_manager.cloudflare_worker_versions
		(installation_id,id,worker_id,sha256,size_bytes,content_type,entrypoint,state,module,created_at,created_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
	`, version.InstallationID, version.ID, version.WorkerID, version.SHA256, version.SizeBytes, version.ContentType, version.Entrypoint, version.State, version.Module, version.CreatedAt.UTC(), version.CreatedBy)
	return mapPostgresError(err)
}

func (p *PostgresRepository) GetWorkerVersion(ctx context.Context, installationID, workerID, id string) (WorkerVersion, error) {
	var version WorkerVersion
	err := p.pool.QueryRow(ctx, `SELECT installation_id,id,worker_id,sha256,size_bytes,content_type,entrypoint,state,module,COALESCE(provider_version_id,''),COALESCE(provider_version_number,0),provider_uploaded_at,created_at,created_by FROM vps_manager.cloudflare_worker_versions WHERE installation_id=$1 AND worker_id=$2 AND id=$3`, installationID, workerID, id).Scan(
		&version.InstallationID, &version.ID, &version.WorkerID, &version.SHA256, &version.SizeBytes, &version.ContentType, &version.Entrypoint, &version.State, &version.Module, &version.ProviderVersionID, &version.ProviderVersionNumber, &version.ProviderUploadedAt, &version.CreatedAt, &version.CreatedBy,
	)
	if err != nil {
		return WorkerVersion{}, mapPostgresError(err)
	}
	return version, nil
}

func (p *PostgresRepository) ListWorkerVersions(ctx context.Context, installationID, workerID string) ([]WorkerVersion, error) {
	rows, err := p.pool.Query(ctx, `SELECT installation_id,id,worker_id,sha256,size_bytes,content_type,entrypoint,state,module,COALESCE(provider_version_id,''),COALESCE(provider_version_number,0),provider_uploaded_at,created_at,created_by FROM vps_manager.cloudflare_worker_versions WHERE installation_id=$1 AND worker_id=$2 ORDER BY created_at DESC,id DESC LIMIT $3`, installationID, workerID, MaxControlPlaneCollectionLen)
	if err != nil {
		return nil, errors.New("list PostgreSQL worker versions")
	}
	defer rows.Close()
	items := make([]WorkerVersion, 0)
	for rows.Next() {
		var item WorkerVersion
		if err := rows.Scan(&item.InstallationID, &item.ID, &item.WorkerID, &item.SHA256, &item.SizeBytes, &item.ContentType, &item.Entrypoint, &item.State, &item.Module, &item.ProviderVersionID, &item.ProviderVersionNumber, &item.ProviderUploadedAt, &item.CreatedAt, &item.CreatedBy); err != nil {
			return nil, errors.New("scan PostgreSQL worker version")
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (p *PostgresRepository) PlanWorkerDeployment(ctx context.Context, deployment WorkerDeployment, updated Worker) error {
	tx, err := p.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return errors.New("begin PostgreSQL deployment plan")
	}
	defer tx.Rollback(ctx)
	var currentVersion uint64
	var desired *string
	if err := tx.QueryRow(ctx, `SELECT version,desired_version_id FROM vps_manager.cloudflare_workers WHERE installation_id=$1 AND id=$2 FOR UPDATE`, deployment.InstallationID, deployment.WorkerID).Scan(&currentVersion, &desired); err != nil {
		return mapPostgresError(err)
	}
	currentDesired := ""
	if desired != nil {
		currentDesired = *desired
	}
	if deployment.PreviousDesiredVersion != currentDesired || updated.Version != currentVersion+1 || updated.DesiredVersion != deployment.VersionID || deployment.ProviderExecution {
		return ErrConflict
	}
	var versionExists, tokenExists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM vps_manager.cloudflare_worker_versions WHERE installation_id=$1 AND worker_id=$2 AND id=$3)`, deployment.InstallationID, deployment.WorkerID, deployment.VersionID).Scan(&versionExists); err != nil {
		return errors.New("verify PostgreSQL worker version")
	}
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM vps_manager.current_secret_bindings WHERE installation_id=$1 AND scope_type='cloudflare_worker' AND scope_id=$2)`, deployment.InstallationID, deployment.WorkerID).Scan(&tokenExists); err != nil {
		return errors.New("verify PostgreSQL worker token")
	}
	if !versionExists || !tokenExists {
		return ErrNotFound
	}
	if deployment.Kind == "rollback" && (currentDesired == "" || currentDesired == deployment.VersionID) {
		return ErrConflict
	}
	_, err = tx.Exec(ctx, `INSERT INTO vps_manager.cloudflare_deployments (installation_id,id,worker_id,version_id,previous_desired_version_id,kind,state,provider_execution_allowed,created_at,created_by) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, deployment.InstallationID, deployment.ID, deployment.WorkerID, deployment.VersionID, nullString(deployment.PreviousDesiredVersion), deployment.Kind, deployment.State, deployment.ProviderExecution, deployment.CreatedAt.UTC(), deployment.CreatedBy)
	if err != nil {
		return mapPostgresError(err)
	}
	result, err := tx.Exec(ctx, `UPDATE vps_manager.cloudflare_workers SET desired_version_id=$3,version=$4,updated_at=$5 WHERE installation_id=$1 AND id=$2 AND version=$6`, updated.InstallationID, updated.ID, updated.DesiredVersion, updated.Version, updated.UpdatedAt.UTC(), currentVersion)
	if err := mapCASResult(result, err); err != nil {
		return err
	}
	return mapPostgresError(tx.Commit(ctx))
}

func (p *PostgresRepository) ListWorkerDeployments(ctx context.Context, installationID, workerID string) ([]WorkerDeployment, error) {
	rows, err := p.pool.Query(ctx, `SELECT installation_id,id,worker_id,version_id,previous_desired_version_id,kind,state,provider_execution_allowed,COALESCE(provider_version_id,''),COALESCE(provider_deployment_id,''),COALESCE(provider_state,''),COALESCE(error_code,''),started_at,finished_at,created_at,created_by FROM vps_manager.cloudflare_deployments WHERE installation_id=$1 AND worker_id=$2 ORDER BY created_at DESC,id DESC LIMIT $3`, installationID, workerID, MaxControlPlaneCollectionLen)
	if err != nil {
		return nil, errors.New("list PostgreSQL worker deployments")
	}
	defer rows.Close()
	items := make([]WorkerDeployment, 0)
	for rows.Next() {
		var item WorkerDeployment
		var previous *string
		if err := rows.Scan(&item.InstallationID, &item.ID, &item.WorkerID, &item.VersionID, &previous, &item.Kind, &item.State, &item.ProviderExecution, &item.ProviderVersionID, &item.ProviderDeploymentID, &item.ProviderState, &item.ErrorCode, &item.StartedAt, &item.FinishedAt, &item.CreatedAt, &item.CreatedBy); err != nil {
			return nil, errors.New("scan PostgreSQL worker deployment")
		}
		if previous != nil {
			item.PreviousDesiredVersion = *previous
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func metadataObject(value any) json.RawMessage {
	encoded, _ := json.Marshal(value)
	return encoded
}
