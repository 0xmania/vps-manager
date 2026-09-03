package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"time"

	"vpsmanager/services/control-plane/internal/audit"
	"vpsmanager/services/control-plane/internal/auth"
	"vpsmanager/services/control-plane/internal/credentials"
	"vpsmanager/services/control-plane/internal/model"
	"vpsmanager/services/persistence"
)

const defaultPostgresOperationTimeout = 5 * time.Second

// Postgres maps the control-plane domain model onto the durable persistence
// package. The installation identifier is applied internally and is never
// accepted from an HTTP request.
type Postgres struct {
	repository     *persistence.PostgresRepository
	installationID string
	timeout        time.Duration
}

func NewPostgres(repository *persistence.PostgresRepository, installationID string, timeout time.Duration) (*Postgres, error) {
	if repository == nil || installationID == "" {
		return nil, errors.New("PostgreSQL repository and installation id are required")
	}
	if timeout <= 0 {
		timeout = defaultPostgresOperationTimeout
	}
	if timeout > time.Minute {
		return nil, errors.New("PostgreSQL operation timeout may not exceed one minute")
	}
	return &Postgres{repository: repository, installationID: installationID, timeout: timeout}, nil
}

func (p *Postgres) operationContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), p.timeout)
}

func (p *Postgres) StorageMode() string             { return "durable" }
func (p *Postgres) Ready(ctx context.Context) error { return p.repository.Ping(ctx) }
func (p *Postgres) Close()                          { p.repository.Close() }

func (p *Postgres) CreateHost(host model.Host) error {
	ctx, cancel := p.operationContext()
	defer cancel()
	return mapPersistenceError(p.repository.CreateAsset(ctx, hostToAsset(p.installationID, host)))
}

func (p *Postgres) GetHost(id string) (model.Host, error) {
	ctx, cancel := p.operationContext()
	defer cancel()
	asset, err := p.repository.GetAsset(ctx, p.installationID, id)
	if err != nil {
		return model.Host{}, mapPersistenceError(err)
	}
	return assetToHost(asset), nil
}

func (p *Postgres) ListHosts() ([]model.Host, error) {
	ctx, cancel := p.operationContext()
	defer cancel()
	assets, err := p.repository.ListAllAssets(ctx, p.installationID)
	if err != nil {
		return nil, mapPersistenceError(err)
	}
	hosts := make([]model.Host, 0, len(assets))
	for _, asset := range assets {
		hosts = append(hosts, assetToHost(asset))
	}
	return hosts, nil
}

func (p *Postgres) UpdateHost(host model.Host, expectedVersion uint64) error {
	ctx, cancel := p.operationContext()
	defer cancel()
	return mapPersistenceError(p.repository.UpdateAsset(ctx, hostToAsset(p.installationID, host), expectedVersion))
}

func (p *Postgres) DeleteHost(id string) error {
	ctx, cancel := p.operationContext()
	defer cancel()
	asset, err := p.repository.GetAsset(ctx, p.installationID, id)
	if err != nil {
		return mapPersistenceError(err)
	}
	if err := p.repository.DeleteCurrentSecret(ctx, p.installationID, persistence.SecretScopeHost, id); err != nil && !errors.Is(err, persistence.ErrNotFound) {
		return mapPersistenceError(err)
	}
	return mapPersistenceError(p.repository.DeleteAsset(ctx, p.installationID, id, asset.Version))
}

func (p *Postgres) PutCredential(credential model.StoredCredential) error {
	metadata, err := json.Marshal(credential.Metadata)
	if err != nil {
		return err
	}
	envelope := persistence.CredentialEnvelope{
		InstallationID: p.installationID, CredentialID: credential.Metadata.ID, Version: 1,
		Kind: credential.Metadata.Kind, KeyID: credential.Envelope.KeyID,
		Ciphertext: credential.Envelope.Ciphertext, CipherNonce: credential.Envelope.Nonce,
		WrappedKey: credential.Envelope.WrappedKey, WrappedKeyNonce: credential.Envelope.KeyNonce,
		Metadata: metadata, CreatedAt: credential.Metadata.CreatedAt,
	}
	ctx, cancel := p.operationContext()
	defer cancel()
	return mapPersistenceError(p.repository.PutCurrentSecret(ctx, persistence.SecretBinding{
		InstallationID: p.installationID, ScopeType: persistence.SecretScopeHost, ScopeID: credential.Metadata.HostID,
		CredentialID: credential.Metadata.ID, Version: 1, Envelope: envelope,
	}))
}

func (p *Postgres) GetCredential(hostID string) (model.StoredCredential, error) {
	ctx, cancel := p.operationContext()
	defer cancel()
	binding, err := p.repository.GetCurrentSecret(ctx, p.installationID, persistence.SecretScopeHost, hostID)
	if err != nil {
		return model.StoredCredential{}, mapPersistenceError(err)
	}
	var metadata model.CredentialMetadata
	if err := decodeStoredMetadata(binding.Envelope.Metadata, &metadata); err != nil || metadata.ID != binding.CredentialID || metadata.HostID != hostID {
		return model.StoredCredential{}, errors.New("stored SSH credential metadata is invalid")
	}
	return model.StoredCredential{Metadata: metadata, Envelope: persistenceToEnvelope(binding.Envelope)}, nil
}

func (p *Postgres) DeleteCredential(hostID string) error {
	ctx, cancel := p.operationContext()
	defer cancel()
	return mapPersistenceError(p.repository.DeleteCurrentSecret(ctx, p.installationID, persistence.SecretScopeHost, hostID))
}

func (p *Postgres) CreateJob(job model.Job) error {
	persisted, err := modelToJob(p.installationID, job)
	if err != nil {
		return err
	}
	ctx, cancel := p.operationContext()
	defer cancel()
	return mapPersistenceError(p.repository.CreateJob(ctx, persisted))
}

func (p *Postgres) GetJob(id string) (model.Job, error) {
	ctx, cancel := p.operationContext()
	defer cancel()
	job, err := p.repository.GetJob(ctx, p.installationID, id)
	if err != nil {
		return model.Job{}, mapPersistenceError(err)
	}
	return jobToModel(job)
}

func (p *Postgres) ListJobs() ([]model.Job, error) {
	ctx, cancel := p.operationContext()
	defer cancel()
	jobs, err := p.repository.ListAllJobs(ctx, p.installationID)
	if err != nil {
		return nil, mapPersistenceError(err)
	}
	result := make([]model.Job, 0, len(jobs))
	for _, job := range jobs {
		mapped, err := jobToModel(job)
		if err != nil {
			return nil, err
		}
		result = append(result, mapped)
	}
	return result, nil
}

func (p *Postgres) MutateJob(id string, mutate func(model.Job) (model.Job, error)) (model.Job, error) {
	ctx, cancel := p.operationContext()
	defer cancel()
	updated, err := p.repository.MutateJob(ctx, p.installationID, id, func(current persistence.Job) (persistence.Job, error) {
		modelCurrent, err := jobToModel(current)
		if err != nil {
			return persistence.Job{}, err
		}
		modelUpdated, err := mutate(modelCurrent)
		if err != nil {
			return persistence.Job{}, err
		}
		return modelToJob(p.installationID, modelUpdated)
	})
	if err != nil {
		return model.Job{}, mapPersistenceError(err)
	}
	return jobToModel(updated)
}

func (p *Postgres) AppendAudit(event model.AuditEvent) error {
	details, err := json.Marshal(audit.SanitizeDetails(event.Details))
	if err != nil {
		return err
	}
	ctx, cancel := p.operationContext()
	defer cancel()
	return mapPersistenceError(p.repository.AppendAudit(ctx, persistence.AuditEvent{
		InstallationID: p.installationID, ID: event.ID, Timestamp: event.Timestamp,
		Actor: event.Actor, Role: string(event.Role), Action: event.Action, TargetType: event.TargetType,
		TargetID: event.TargetID, Outcome: event.Outcome, RequestID: event.RequestID, Details: details,
	}))
}

func (p *Postgres) ListAudits(limit int) ([]model.AuditEvent, error) {
	ctx, cancel := p.operationContext()
	defer cancel()
	events, err := p.repository.ListAudit(ctx, persistence.AuditFilter{InstallationID: p.installationID, Limit: limit})
	if err != nil {
		return nil, mapPersistenceError(err)
	}
	result := make([]model.AuditEvent, 0, len(events))
	for _, event := range events {
		var details map[string]any
		if len(event.Details) > 0 {
			if err := json.Unmarshal(event.Details, &details); err != nil {
				return nil, errors.New("stored audit details are invalid")
			}
		}
		result = append(result, model.AuditEvent{ID: event.ID, Timestamp: event.Timestamp, Actor: event.Actor, Role: auth.Role(event.Role), Action: event.Action, TargetType: event.TargetType, TargetID: event.TargetID, Outcome: event.Outcome, RequestID: event.RequestID, Details: details})
	}
	return result, nil
}

func (p *Postgres) CreateWorker(worker model.CloudflareWorker) error {
	ctx, cancel := p.operationContext()
	defer cancel()
	return mapPersistenceError(p.repository.CreateWorker(ctx, workerToPersistence(p.installationID, worker)))
}

func (p *Postgres) GetWorker(id string) (model.CloudflareWorker, error) {
	ctx, cancel := p.operationContext()
	defer cancel()
	worker, err := p.repository.GetWorker(ctx, p.installationID, id)
	if err != nil {
		return model.CloudflareWorker{}, mapPersistenceError(err)
	}
	return persistenceToWorker(worker), nil
}

func (p *Postgres) ListWorkers() ([]model.CloudflareWorker, error) {
	ctx, cancel := p.operationContext()
	defer cancel()
	workers, err := p.repository.ListWorkers(ctx, p.installationID)
	if err != nil {
		return nil, mapPersistenceError(err)
	}
	result := make([]model.CloudflareWorker, 0, len(workers))
	for _, worker := range workers {
		result = append(result, persistenceToWorker(worker))
	}
	return result, nil
}

func (p *Postgres) PutWorkerToken(token model.StoredCloudflareToken) error {
	metadata, err := json.Marshal(token.Metadata)
	if err != nil {
		return err
	}
	envelope := persistence.CredentialEnvelope{
		InstallationID: p.installationID, CredentialID: token.Metadata.ID, Version: 1,
		Kind: token.Metadata.Kind, KeyID: token.Envelope.KeyID,
		Ciphertext: token.Envelope.Ciphertext, CipherNonce: token.Envelope.Nonce,
		WrappedKey: token.Envelope.WrappedKey, WrappedKeyNonce: token.Envelope.KeyNonce,
		Metadata: metadata, CreatedAt: token.Metadata.CreatedAt,
	}
	ctx, cancel := p.operationContext()
	defer cancel()
	return mapPersistenceError(p.repository.PutCurrentSecret(ctx, persistence.SecretBinding{
		InstallationID: p.installationID, ScopeType: persistence.SecretScopeCloudflareWorker, ScopeID: token.Metadata.WorkerID,
		CredentialID: token.Metadata.ID, Version: 1, Envelope: envelope,
	}))
}

func (p *Postgres) GetWorkerToken(workerID string) (model.StoredCloudflareToken, error) {
	ctx, cancel := p.operationContext()
	defer cancel()
	binding, err := p.repository.GetCurrentSecret(ctx, p.installationID, persistence.SecretScopeCloudflareWorker, workerID)
	if err != nil {
		return model.StoredCloudflareToken{}, mapPersistenceError(err)
	}
	var metadata model.CloudflareTokenMetadata
	if err := decodeStoredMetadata(binding.Envelope.Metadata, &metadata); err != nil || metadata.ID != binding.CredentialID || metadata.WorkerID != workerID {
		return model.StoredCloudflareToken{}, errors.New("stored Cloudflare token metadata is invalid")
	}
	return model.StoredCloudflareToken{Metadata: metadata, Envelope: persistenceToEnvelope(binding.Envelope)}, nil
}

func (p *Postgres) DeleteWorkerToken(workerID string) error {
	ctx, cancel := p.operationContext()
	defer cancel()
	return mapPersistenceError(p.repository.DeleteCurrentSecret(ctx, p.installationID, persistence.SecretScopeCloudflareWorker, workerID))
}

func (p *Postgres) CreateWorkerVersion(version model.StoredCloudflareWorkerVersion) error {
	ctx, cancel := p.operationContext()
	defer cancel()
	metadata := version.Metadata
	return mapPersistenceError(p.repository.CreateWorkerVersion(ctx, persistence.WorkerVersion{
		InstallationID: p.installationID, ID: metadata.ID, WorkerID: metadata.WorkerID, SHA256: metadata.SHA256,
		SizeBytes: metadata.SizeBytes, ContentType: metadata.ContentType, Entrypoint: metadata.Entrypoint,
		State: metadata.State, Module: append([]byte(nil), version.Module...), CreatedAt: metadata.CreatedAt, CreatedBy: metadata.CreatedBy,
	}))
}

func (p *Postgres) GetWorkerVersion(workerID, versionID string) (model.StoredCloudflareWorkerVersion, error) {
	ctx, cancel := p.operationContext()
	defer cancel()
	version, err := p.repository.GetWorkerVersion(ctx, p.installationID, workerID, versionID)
	if err != nil {
		return model.StoredCloudflareWorkerVersion{}, mapPersistenceError(err)
	}
	return persistenceToWorkerVersion(version), nil
}

func (p *Postgres) ListWorkerVersions(workerID string) ([]model.CloudflareWorkerVersion, error) {
	ctx, cancel := p.operationContext()
	defer cancel()
	versions, err := p.repository.ListWorkerVersions(ctx, p.installationID, workerID)
	if err != nil {
		return nil, mapPersistenceError(err)
	}
	result := make([]model.CloudflareWorkerVersion, 0, len(versions))
	for _, version := range versions {
		result = append(result, persistenceToWorkerVersion(version).Metadata)
	}
	return result, nil
}

func (p *Postgres) PlanWorkerDeployment(deployment model.CloudflareDeployment, updated model.CloudflareWorker) error {
	ctx, cancel := p.operationContext()
	defer cancel()
	persisted := persistence.WorkerDeployment{
		InstallationID: p.installationID, ID: deployment.ID, WorkerID: deployment.WorkerID, VersionID: deployment.VersionID,
		PreviousDesiredVersion: deployment.PreviousDesiredVersionID, Kind: deployment.Kind, State: deployment.State,
		ProviderExecution: deployment.ProviderExecutionAllowed, CreatedAt: deployment.CreatedAt, CreatedBy: deployment.CreatedBy,
	}
	return mapPersistenceError(p.repository.PlanWorkerDeployment(ctx, persisted, workerToPersistence(p.installationID, updated)))
}

func (p *Postgres) ListWorkerDeployments(workerID string) ([]model.CloudflareDeployment, error) {
	ctx, cancel := p.operationContext()
	defer cancel()
	items, err := p.repository.ListWorkerDeployments(ctx, p.installationID, workerID)
	if err != nil {
		return nil, mapPersistenceError(err)
	}
	result := make([]model.CloudflareDeployment, 0, len(items))
	for _, item := range items {
		result = append(result, persistenceToWorkerDeployment(item))
	}
	return result, nil
}

func hostToAsset(installationID string, host model.Host) persistence.Asset {
	asset := persistence.Asset{InstallationID: installationID, ID: host.ID, Name: host.Name, Address: host.Address, Port: host.Port, Username: host.Username, Labels: host.Labels, Version: host.Version, CreatedAt: host.CreatedAt, UpdatedAt: host.UpdatedAt}
	if host.HostKey != nil {
		asset.HostKey = &persistence.HostKeyPin{Algorithm: host.HostKey.Algorithm, FingerprintSHA256: host.HostKey.FingerprintSHA256, PublicKey: host.HostKey.PublicKey, ConfirmedAt: host.HostKey.ConfirmedAt, ConfirmedBy: host.HostKey.ConfirmedBy}
	}
	return asset
}

func assetToHost(asset persistence.Asset) model.Host {
	host := model.Host{ID: asset.ID, Name: asset.Name, Address: asset.Address, Port: asset.Port, Username: asset.Username, Labels: asset.Labels, Version: asset.Version, CreatedAt: asset.CreatedAt, UpdatedAt: asset.UpdatedAt}
	if asset.HostKey != nil {
		host.HostKey = &model.HostKeyPin{Algorithm: asset.HostKey.Algorithm, FingerprintSHA256: asset.HostKey.FingerprintSHA256, PublicKey: asset.HostKey.PublicKey, ConfirmedAt: asset.HostKey.ConfirmedAt, ConfirmedBy: asset.HostKey.ConfirmedBy}
	}
	return host
}

type persistedJobParameters struct {
	RequestedSessionID string                   `json:"requestedSessionId,omitempty"`
	Command            *model.CommandDescriptor `json:"command,omitempty"`
}

type persistedJobResult struct {
	Snapshot         *model.RuntimeSnapshot        `json:"snapshot,omitempty"`
	CommandResult    *model.CommandResult          `json:"commandResult,omitempty"`
	AnomalyScan      *model.AnomalyScanResult      `json:"anomalyScan,omitempty"`
	RunbookPreview   *model.RunbookPreviewResult   `json:"runbookPreview,omitempty"`
	RunbookExecution *model.RunbookExecutionResult `json:"runbookExecution,omitempty"`
}

func modelToJob(installationID string, job model.Job) (persistence.Job, error) {
	parameters, err := json.Marshal(persistedJobParameters{RequestedSessionID: job.RequestedSessionID, Command: job.Command})
	if err != nil {
		return persistence.Job{}, err
	}
	result, err := json.Marshal(persistedJobResult{
		Snapshot: job.Snapshot, CommandResult: job.CommandResult, AnomalyScan: job.AnomalyScan,
		RunbookPreview: job.RunbookPreview, RunbookExecution: job.RunbookExecution,
	})
	if err != nil {
		return persistence.Job{}, err
	}
	updatedAt := job.CreatedAt
	if job.StartedAt != nil {
		updatedAt = *job.StartedAt
	}
	if job.FinishedAt != nil {
		updatedAt = *job.FinishedAt
	}
	persisted := persistence.Job{InstallationID: installationID, ID: job.ID, Type: job.Type, AssetID: job.HostID, State: string(job.State), RequestedBy: job.RequestedBy, Parameters: parameters, Result: result, Version: job.Version, CreatedAt: job.CreatedAt, StartedAt: job.StartedAt, FinishedAt: job.FinishedAt, UpdatedAt: updatedAt}
	if job.Error != nil {
		persisted.ErrorCode, persisted.ErrorMessage = job.Error.Code, job.Error.Message
	}
	return persisted, nil
}

func jobToModel(job persistence.Job) (model.Job, error) {
	var parameters persistedJobParameters
	if err := json.Unmarshal(job.Parameters, &parameters); err != nil {
		return model.Job{}, errors.New("stored job parameters are invalid")
	}
	var result persistedJobResult
	if err := json.Unmarshal(job.Result, &result); err != nil {
		return model.Job{}, errors.New("stored job result is invalid")
	}
	mapped := model.Job{
		ID: job.ID, Type: job.Type, HostID: job.AssetID, State: model.JobState(job.State),
		RequestedBy: job.RequestedBy, RequestedSessionID: parameters.RequestedSessionID,
		CreatedAt: job.CreatedAt, StartedAt: job.StartedAt, FinishedAt: job.FinishedAt,
		Snapshot: result.Snapshot, Command: parameters.Command, CommandResult: result.CommandResult,
		AnomalyScan: result.AnomalyScan, RunbookPreview: result.RunbookPreview,
		RunbookExecution: result.RunbookExecution, Version: job.Version,
	}
	if job.ErrorCode != "" {
		mapped.Error = &model.JobError{Code: job.ErrorCode, Message: job.ErrorMessage}
	}
	return mapped, nil
}

func persistenceToEnvelope(envelope persistence.CredentialEnvelope) credentials.Envelope {
	return credentials.Envelope{Ciphertext: append([]byte(nil), envelope.Ciphertext...), Nonce: append([]byte(nil), envelope.CipherNonce...), WrappedKey: append([]byte(nil), envelope.WrappedKey...), KeyNonce: append([]byte(nil), envelope.WrappedKeyNonce...), KeyID: envelope.KeyID}
}

func decodeStoredMetadata(raw []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	return nil
}

func workerToPersistence(installationID string, worker model.CloudflareWorker) persistence.Worker {
	return persistence.Worker{InstallationID: installationID, ID: worker.ID, Name: worker.Name, AccountID: worker.AccountID, ScriptName: worker.ScriptName, DesiredVersion: worker.DesiredVersionID, Version: worker.Version, CreatedAt: worker.CreatedAt, UpdatedAt: worker.UpdatedAt}
}

func persistenceToWorker(worker persistence.Worker) model.CloudflareWorker {
	return model.CloudflareWorker{ID: worker.ID, Name: worker.Name, AccountID: worker.AccountID, ScriptName: worker.ScriptName, DesiredVersionID: worker.DesiredVersion, Version: worker.Version, CreatedAt: worker.CreatedAt, UpdatedAt: worker.UpdatedAt}
}

func persistenceToWorkerVersion(version persistence.WorkerVersion) model.StoredCloudflareWorkerVersion {
	return model.StoredCloudflareWorkerVersion{Metadata: model.CloudflareWorkerVersion{ID: version.ID, WorkerID: version.WorkerID, SHA256: version.SHA256, SizeBytes: version.SizeBytes, ContentType: version.ContentType, Entrypoint: version.Entrypoint, State: version.State, ProviderVersionID: version.ProviderVersionID, ProviderVersionNumber: version.ProviderVersionNumber, ProviderUploadedAt: version.ProviderUploadedAt, CreatedAt: version.CreatedAt, CreatedBy: version.CreatedBy}, Module: append([]byte(nil), version.Module...)}
}

func mapPersistenceError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, persistence.ErrNotFound):
		return ErrNotFound
	case errors.Is(err, persistence.ErrConflict):
		return ErrConflict
	default:
		return err
	}
}
