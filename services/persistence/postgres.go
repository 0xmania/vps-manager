package persistence

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	postgresRolePattern    = regexp.MustCompile(`^[a-z_][a-z0-9_]{0,62}$`)
	postgresAppNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)
)

type PostgresConfig struct {
	URL                      string
	Environment              string
	ExpectedRole             string
	ApplicationName          string
	MaxConnections           int32
	MinConnections           int32
	ConnectTimeout           time.Duration
	AllowInsecureDevelopment bool
}

func (PostgresConfig) String() string   { return "PostgresConfig{URL:[redacted]}" }
func (PostgresConfig) GoString() string { return "persistence.PostgresConfig{URL:[redacted]}" }

func (c PostgresConfig) Validate() error {
	if err := validateEnvironment(c.Environment); err != nil {
		return err
	}
	if strings.TrimSpace(c.URL) == "" {
		return errors.New("PostgreSQL URL is required")
	}
	parsed, err := url.Parse(c.URL)
	if err != nil || (parsed.Scheme != "postgres" && parsed.Scheme != "postgresql") || parsed.Hostname() == "" {
		return errors.New("PostgreSQL URL must be a postgres URL with a host")
	}
	sslModes := parsed.Query()["sslmode"]
	verifiedTLS := len(sslModes) == 1 && sslModes[0] == "verify-full"
	if c.Environment == "production" {
		if c.AllowInsecureDevelopment {
			return errors.New("insecure PostgreSQL mode is forbidden in production")
		}
		if !verifiedTLS {
			return errors.New("production PostgreSQL requires sslmode=verify-full")
		}
		if !postgresRolePattern.MatchString(c.ExpectedRole) {
			return errors.New("production PostgreSQL expected role is required")
		}
	} else if !verifiedTLS && !c.AllowInsecureDevelopment {
		return errors.New("PostgreSQL TLS downgrade requires explicit development-only opt-in")
	} else if c.AllowInsecureDevelopment && c.Environment != "development" && c.Environment != "test" {
		return errors.New("PostgreSQL insecure mode is development-only")
	}
	if c.ExpectedRole != "" && !postgresRolePattern.MatchString(c.ExpectedRole) {
		return errors.New("PostgreSQL expected role is invalid")
	}
	if c.MinConnections < 0 || c.MaxConnections < 0 || (c.MaxConnections > 0 && c.MinConnections > c.MaxConnections) {
		return errors.New("PostgreSQL connection limits are invalid")
	}
	if c.ConnectTimeout < 0 || c.ConnectTimeout > time.Minute {
		return errors.New("PostgreSQL connect timeout is invalid")
	}
	if c.ApplicationName != "" && !postgresAppNamePattern.MatchString(c.ApplicationName) {
		return errors.New("PostgreSQL application name is invalid")
	}
	return nil
}

type PostgresRepository struct {
	pool         *pgxpool.Pool
	expectedRole string
	production   bool
}

func (*PostgresRepository) String() string { return "PostgresRepository{pool:[redacted]}" }
func (*PostgresRepository) GoString() string {
	return "persistence.PostgresRepository{pool:[redacted]}"
}

func OpenPostgres(ctx context.Context, config PostgresConfig) (*PostgresRepository, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	poolConfig, err := pgxpool.ParseConfig(config.URL)
	if err != nil {
		return nil, errors.New("parse PostgreSQL configuration")
	}
	if config.ApplicationName == "" {
		config.ApplicationName = "vps-manager-control-plane"
	}
	poolConfig.ConnConfig.RuntimeParams["application_name"] = config.ApplicationName
	if config.MaxConnections > 0 {
		poolConfig.MaxConns = config.MaxConnections
	}
	if config.MinConnections > 0 {
		poolConfig.MinConns = config.MinConnections
	}
	if config.ConnectTimeout == 0 {
		config.ConnectTimeout = 5 * time.Second
	}
	poolConfig.ConnConfig.ConnectTimeout = config.ConnectTimeout
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return nil, errors.New("create PostgreSQL pool")
	}
	repository := &PostgresRepository{pool: pool, expectedRole: config.ExpectedRole, production: config.Environment == "production"}
	if err := repository.VerifyRuntime(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return repository, nil
}

func (p *PostgresRepository) Close() { p.pool.Close() }

// VerifyRuntime rejects privileged application roles and non-TLS production
// connections. Migrations must run under a distinct owner identity.
func (p *PostgresRepository) VerifyRuntime(ctx context.Context) error {
	var role string
	var sslEnabled bool
	var superuser, createRole, createDB, replication, bypassRLS bool
	err := p.pool.QueryRow(ctx, `
		SELECT current_user,
		       COALESCE((SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid()), false),
		       r.rolsuper, r.rolcreaterole, r.rolcreatedb, r.rolreplication, r.rolbypassrls
		FROM pg_roles r WHERE r.rolname = current_user
	`).Scan(&role, &sslEnabled, &superuser, &createRole, &createDB, &replication, &bypassRLS)
	if err != nil {
		return errors.New("verify PostgreSQL runtime identity")
	}
	if p.expectedRole != "" && role != p.expectedRole {
		return errors.New("PostgreSQL runtime role does not match expected role")
	}
	if p.production && !sslEnabled {
		return errors.New("PostgreSQL production connection is not using TLS")
	}
	if superuser || createRole || createDB || replication || bypassRLS {
		return errors.New("PostgreSQL application role has forbidden cluster privileges")
	}
	var schemaUsage, schemaCreate, requiredTables, forbiddenTables, sequenceUsage bool
	err = p.pool.QueryRow(ctx, `
		SELECT
		  has_schema_privilege(current_user, 'vps_manager', 'USAGE'),
		  has_schema_privilege(current_user, 'vps_manager', 'CREATE'),
		  (SELECT bool_and(has_table_privilege(current_user, object_name, privilege))
		   FROM (VALUES
		     ('vps_manager.assets','SELECT'),('vps_manager.assets','INSERT'),('vps_manager.assets','UPDATE'),('vps_manager.assets','DELETE'),
		     ('vps_manager.credential_envelopes','SELECT'),('vps_manager.credential_envelopes','INSERT'),
		     ('vps_manager.current_secret_bindings','SELECT'),('vps_manager.current_secret_bindings','INSERT'),
		     ('vps_manager.current_secret_bindings','UPDATE'),('vps_manager.current_secret_bindings','DELETE'),
		     ('vps_manager.cloudflare_workers','SELECT'),('vps_manager.cloudflare_workers','INSERT'),('vps_manager.cloudflare_workers','UPDATE'),
		     ('vps_manager.cloudflare_worker_versions','SELECT'),('vps_manager.cloudflare_worker_versions','INSERT'),('vps_manager.cloudflare_worker_versions','UPDATE'),
		     ('vps_manager.cloudflare_deployments','SELECT'),('vps_manager.cloudflare_deployments','INSERT'),('vps_manager.cloudflare_deployments','UPDATE'),
		     ('vps_manager.jobs','SELECT'),('vps_manager.jobs','INSERT'),('vps_manager.jobs','UPDATE'),
		     ('vps_manager.audit_events','SELECT'),('vps_manager.audit_events','INSERT')
		   ) AS required(object_name, privilege)),
		  (SELECT bool_or(has_table_privilege(current_user, object_name, privilege))
		   FROM (VALUES
		     ('vps_manager.credential_envelopes','UPDATE'),('vps_manager.credential_envelopes','DELETE'),
		     ('vps_manager.jobs','DELETE'),
		     ('vps_manager.cloudflare_workers','DELETE'),
		     ('vps_manager.cloudflare_worker_versions','DELETE'),
		     ('vps_manager.cloudflare_deployments','DELETE'),
		     ('vps_manager.audit_events','UPDATE'),('vps_manager.audit_events','DELETE')
		   ) AS forbidden(object_name, privilege)),
		  has_sequence_privilege(current_user, 'vps_manager.audit_events_sequence_seq', 'USAGE')
	`).Scan(&schemaUsage, &schemaCreate, &requiredTables, &forbiddenTables, &sequenceUsage)
	if err != nil {
		return errors.New("verify PostgreSQL schema privileges")
	}
	if !schemaUsage || !requiredTables || !sequenceUsage {
		return errors.New("PostgreSQL application role lacks required privileges")
	}
	if schemaCreate || forbiddenTables {
		return errors.New("PostgreSQL application role has forbidden data privileges")
	}
	if err := p.pool.Ping(ctx); err != nil {
		return errors.New("ping PostgreSQL")
	}
	return nil
}

func (p *PostgresRepository) CreateAsset(ctx context.Context, asset Asset) error {
	if err := validateAsset(asset); err != nil {
		return err
	}
	labels, _ := json.Marshal(asset.Labels)
	hostKey, _ := json.Marshal(asset.HostKey)
	_, err := p.pool.Exec(ctx, `
		INSERT INTO vps_manager.assets
		(installation_id, id, name, address, port, username, labels, host_key, version, created_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
	`, asset.InstallationID, asset.ID, asset.Name, asset.Address, asset.Port, asset.Username, labels, nullableHostKey(asset.HostKey, hostKey), asset.Version, asset.CreatedAt.UTC(), asset.UpdatedAt.UTC())
	return mapPostgresError(err)
}

func (p *PostgresRepository) GetAsset(ctx context.Context, installationID, id string) (Asset, error) {
	if err := validateIdentifier("installation id", installationID); err != nil {
		return Asset{}, err
	}
	if err := validateIdentifier("asset id", id); err != nil {
		return Asset{}, err
	}
	var asset Asset
	var labels, hostKey []byte
	err := p.pool.QueryRow(ctx, `
		SELECT installation_id,id,name,address,port,username,labels,host_key,version,created_at,updated_at
		FROM vps_manager.assets WHERE installation_id=$1 AND id=$2
	`, installationID, id).Scan(&asset.InstallationID, &asset.ID, &asset.Name, &asset.Address, &asset.Port, &asset.Username, &labels, &hostKey, &asset.Version, &asset.CreatedAt, &asset.UpdatedAt)
	if err != nil {
		return Asset{}, mapPostgresError(err)
	}
	if err := decodeAssetJSON(&asset, labels, hostKey); err != nil {
		return Asset{}, err
	}
	return asset, nil
}

func (p *PostgresRepository) ListAssets(ctx context.Context, installationID string, limit int, afterID string) ([]Asset, error) {
	if err := validateIdentifier("installation id", installationID); err != nil {
		return nil, err
	}
	rows, err := p.pool.Query(ctx, `
		SELECT installation_id,id,name,address,port,username,labels,host_key,version,created_at,updated_at
		FROM vps_manager.assets WHERE installation_id=$1 AND id>$2 ORDER BY id LIMIT $3
	`, installationID, afterID, normalizeLimit(limit))
	if err != nil {
		return nil, errors.New("list PostgreSQL assets")
	}
	defer rows.Close()
	assets := make([]Asset, 0)
	for rows.Next() {
		var asset Asset
		var labels, hostKey []byte
		if err := rows.Scan(&asset.InstallationID, &asset.ID, &asset.Name, &asset.Address, &asset.Port, &asset.Username, &labels, &hostKey, &asset.Version, &asset.CreatedAt, &asset.UpdatedAt); err != nil {
			return nil, errors.New("scan PostgreSQL asset")
		}
		if err := decodeAssetJSON(&asset, labels, hostKey); err != nil {
			return nil, err
		}
		assets = append(assets, asset)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.New("iterate PostgreSQL assets")
	}
	return assets, nil
}

func (p *PostgresRepository) UpdateAsset(ctx context.Context, asset Asset, expectedVersion uint64) error {
	if err := validateAsset(asset); err != nil {
		return err
	}
	if asset.Version != expectedVersion+1 {
		return ErrConflict
	}
	labels, _ := json.Marshal(asset.Labels)
	hostKey, _ := json.Marshal(asset.HostKey)
	result, err := p.pool.Exec(ctx, `
		UPDATE vps_manager.assets SET name=$3,address=$4,port=$5,username=$6,labels=$7,host_key=$8,version=$9,updated_at=$10
		WHERE installation_id=$1 AND id=$2 AND version=$11
	`, asset.InstallationID, asset.ID, asset.Name, asset.Address, asset.Port, asset.Username, labels, nullableHostKey(asset.HostKey, hostKey), asset.Version, asset.UpdatedAt.UTC(), expectedVersion)
	return mapCASResult(result, err)
}

func (p *PostgresRepository) DeleteAsset(ctx context.Context, installationID, id string, expectedVersion uint64) error {
	result, err := p.pool.Exec(ctx, `DELETE FROM vps_manager.assets WHERE installation_id=$1 AND id=$2 AND version=$3`, installationID, id, expectedVersion)
	return mapCASResult(result, err)
}

func (p *PostgresRepository) PutCredentialEnvelope(ctx context.Context, envelope CredentialEnvelope) error {
	if err := validateCredential(envelope); err != nil {
		return err
	}
	_, err := p.pool.Exec(ctx, `
		INSERT INTO vps_manager.credential_envelopes
		(installation_id,credential_id,version,kind,key_id,ciphertext,cipher_nonce,wrapped_key,wrapped_key_nonce,metadata,created_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
	`, envelope.InstallationID, envelope.CredentialID, envelope.Version, envelope.Kind, envelope.KeyID, envelope.Ciphertext, nonNilBytes(envelope.CipherNonce), envelope.WrappedKey, nonNilBytes(envelope.WrappedKeyNonce), normalizedJSON(envelope.Metadata), envelope.CreatedAt.UTC())
	return mapPostgresError(err)
}

func (p *PostgresRepository) GetCredentialEnvelope(ctx context.Context, installationID, credentialID string, version uint64) (CredentialEnvelope, error) {
	var envelope CredentialEnvelope
	err := p.pool.QueryRow(ctx, `
		SELECT installation_id,credential_id,version,kind,key_id,ciphertext,cipher_nonce,wrapped_key,wrapped_key_nonce,metadata,created_at
		FROM vps_manager.credential_envelopes WHERE installation_id=$1 AND credential_id=$2 AND version=$3
	`, installationID, credentialID, version).Scan(&envelope.InstallationID, &envelope.CredentialID, &envelope.Version, &envelope.Kind, &envelope.KeyID, &envelope.Ciphertext, &envelope.CipherNonce, &envelope.WrappedKey, &envelope.WrappedKeyNonce, &envelope.Metadata, &envelope.CreatedAt)
	if err != nil {
		return CredentialEnvelope{}, mapPostgresError(err)
	}
	return envelope, nil
}

func (p *PostgresRepository) CreateJob(ctx context.Context, job Job) error {
	if err := validateJob(job); err != nil {
		return err
	}
	_, err := p.pool.Exec(ctx, `
		INSERT INTO vps_manager.jobs
		(installation_id,id,type,asset_id,state,requested_by,request_id,idempotency_key,parameters,result,error_code,error_message,version,created_at,started_at,finished_at,updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)
	`, job.InstallationID, job.ID, job.Type, job.AssetID, job.State, job.RequestedBy, nullString(job.RequestID), nullString(job.IdempotencyKey), normalizedJSON(job.Parameters), normalizedJSON(job.Result), nullString(job.ErrorCode), nullString(job.ErrorMessage), job.Version, job.CreatedAt.UTC(), job.StartedAt, job.FinishedAt, job.UpdatedAt.UTC())
	return mapPostgresError(err)
}

func (p *PostgresRepository) GetJob(ctx context.Context, installationID, id string) (Job, error) {
	var job Job
	var requestID, idempotencyKey, errorCode, errorMessage *string
	err := p.pool.QueryRow(ctx, `
		SELECT installation_id,id,type,asset_id,state,requested_by,request_id,idempotency_key,parameters,result,error_code,error_message,version,created_at,started_at,finished_at,updated_at
		FROM vps_manager.jobs WHERE installation_id=$1 AND id=$2
	`, installationID, id).Scan(&job.InstallationID, &job.ID, &job.Type, &job.AssetID, &job.State, &job.RequestedBy, &requestID, &idempotencyKey, &job.Parameters, &job.Result, &errorCode, &errorMessage, &job.Version, &job.CreatedAt, &job.StartedAt, &job.FinishedAt, &job.UpdatedAt)
	if err != nil {
		return Job{}, mapPostgresError(err)
	}
	assignOptionalStrings(&job, requestID, idempotencyKey, errorCode, errorMessage)
	return job, nil
}

func (p *PostgresRepository) ListJobs(ctx context.Context, installationID string, limit int, afterID string) ([]Job, error) {
	if err := validateIdentifier("installation id", installationID); err != nil {
		return nil, err
	}
	rows, err := p.pool.Query(ctx, `
		SELECT installation_id,id,type,asset_id,state,requested_by,request_id,idempotency_key,parameters,result,error_code,error_message,version,created_at,started_at,finished_at,updated_at
		FROM vps_manager.jobs WHERE installation_id=$1 AND id>$2 ORDER BY id LIMIT $3
	`, installationID, afterID, normalizeLimit(limit))
	if err != nil {
		return nil, errors.New("list PostgreSQL jobs")
	}
	defer rows.Close()
	jobs := make([]Job, 0)
	for rows.Next() {
		var job Job
		var requestID, idempotencyKey, errorCode, errorMessage *string
		if err := rows.Scan(&job.InstallationID, &job.ID, &job.Type, &job.AssetID, &job.State, &job.RequestedBy, &requestID, &idempotencyKey, &job.Parameters, &job.Result, &errorCode, &errorMessage, &job.Version, &job.CreatedAt, &job.StartedAt, &job.FinishedAt, &job.UpdatedAt); err != nil {
			return nil, errors.New("scan PostgreSQL job")
		}
		assignOptionalStrings(&job, requestID, idempotencyKey, errorCode, errorMessage)
		jobs = append(jobs, job)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.New("iterate PostgreSQL jobs")
	}
	return jobs, nil
}

func (p *PostgresRepository) UpdateJob(ctx context.Context, job Job, expectedVersion uint64) error {
	if err := validateJob(job); err != nil {
		return err
	}
	if job.Version != expectedVersion+1 {
		return ErrConflict
	}
	result, err := p.pool.Exec(ctx, `
		UPDATE vps_manager.jobs SET state=$3,result=$4,error_code=$5,error_message=$6,version=$7,started_at=$8,finished_at=$9,updated_at=$10
		WHERE installation_id=$1 AND id=$2 AND version=$11
	`, job.InstallationID, job.ID, job.State, normalizedJSON(job.Result), nullString(job.ErrorCode), nullString(job.ErrorMessage), job.Version, job.StartedAt, job.FinishedAt, job.UpdatedAt.UTC(), expectedVersion)
	return mapCASResult(result, err)
}

func (p *PostgresRepository) AppendAudit(ctx context.Context, event AuditEvent) error {
	if err := validateAudit(event); err != nil {
		return err
	}
	_, err := p.pool.Exec(ctx, `
		INSERT INTO vps_manager.audit_events
		(installation_id,event_id,occurred_at,actor,role,action,target_type,target_id,outcome,request_id,job_id,details)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
	`, event.InstallationID, event.ID, event.Timestamp.UTC(), event.Actor, event.Role, event.Action, event.TargetType, nullString(event.TargetID), event.Outcome, nullString(event.RequestID), nullString(event.JobID), normalizedJSON(event.Details))
	return mapPostgresError(err)
}

func (p *PostgresRepository) ListAudit(ctx context.Context, filter AuditFilter) ([]AuditEvent, error) {
	if err := validateIdentifier("installation id", filter.InstallationID); err != nil {
		return nil, err
	}
	before := filter.Before
	beforeID := filter.BeforeID
	if before.IsZero() {
		before = time.Now().UTC().Add(time.Second)
		beforeID = "~"
	} else if beforeID == "" {
		beforeID = "~"
	} else if err := validateIdentifier("audit cursor id", beforeID); err != nil {
		return nil, err
	}
	rows, err := p.pool.Query(ctx, `
		SELECT installation_id,event_id,occurred_at,actor,role,action,target_type,target_id,outcome,request_id,job_id,details
		FROM vps_manager.audit_events
		WHERE installation_id=$1 AND (occurred_at<$2 OR (occurred_at=$2 AND event_id<$3))
		ORDER BY occurred_at DESC,event_id DESC LIMIT $4
	`, filter.InstallationID, before.UTC(), beforeID, normalizeLimit(filter.Limit))
	if err != nil {
		return nil, errors.New("list PostgreSQL audit events")
	}
	defer rows.Close()
	events := make([]AuditEvent, 0)
	for rows.Next() {
		var event AuditEvent
		var targetID, requestID, jobID *string
		if err := rows.Scan(&event.InstallationID, &event.ID, &event.Timestamp, &event.Actor, &event.Role, &event.Action, &event.TargetType, &targetID, &event.Outcome, &requestID, &jobID, &event.Details); err != nil {
			return nil, errors.New("scan PostgreSQL audit event")
		}
		if targetID != nil {
			event.TargetID = *targetID
		}
		if requestID != nil {
			event.RequestID = *requestID
		}
		if jobID != nil {
			event.JobID = *jobID
		}
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.New("iterate PostgreSQL audit events")
	}
	return events, nil
}

func decodeAssetJSON(asset *Asset, labels, hostKey []byte) error {
	if err := json.Unmarshal(labels, &asset.Labels); err != nil {
		return errors.New("decode PostgreSQL asset labels")
	}
	if len(hostKey) > 0 && string(hostKey) != "null" {
		if err := json.Unmarshal(hostKey, &asset.HostKey); err != nil {
			return errors.New("decode PostgreSQL host key")
		}
	}
	return nil
}

func nullableHostKey(pin *HostKeyPin, encoded []byte) any {
	if pin == nil {
		return nil
	}
	return encoded
}

func normalizedJSON(raw json.RawMessage) []byte {
	if len(raw) == 0 {
		return []byte(`{}`)
	}
	return raw
}

func nonNilBytes(value []byte) []byte {
	if value == nil {
		return []byte{}
	}
	return value
}

func nullString(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func assignOptionalStrings(job *Job, requestID, idempotencyKey, errorCode, errorMessage *string) {
	if requestID != nil {
		job.RequestID = *requestID
	}
	if idempotencyKey != nil {
		job.IdempotencyKey = *idempotencyKey
	}
	if errorCode != nil {
		job.ErrorCode = *errorCode
	}
	if errorMessage != nil {
		job.ErrorMessage = *errorMessage
	}
}

func mapCASResult(result pgconn.CommandTag, err error) error {
	if err != nil {
		return mapPostgresError(err)
	}
	if result.RowsAffected() == 0 {
		return ErrConflict
	}
	return nil
}

func mapPostgresError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	var pgError *pgconn.PgError
	if errors.As(err, &pgError) {
		switch pgError.Code {
		case "23505", "40001", "40P01":
			return ErrConflict
		}
	}
	return fmt.Errorf("PostgreSQL operation failed")
}
