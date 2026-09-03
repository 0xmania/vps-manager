package store

import (
	"context"
	"time"

	"vpsmanager/services/control-plane/internal/model"
)

// Repository is the complete, secret-safe persistence boundary used by the
// HTTP API. Implementations must clone mutable input/output values and make
// MutateJob atomic.
type Repository interface {
	CreateHost(model.Host) error
	GetHost(string) (model.Host, error)
	ListHosts() ([]model.Host, error)
	UpdateHost(model.Host, uint64) error
	DeleteHost(string) error

	PutCredential(model.StoredCredential) error
	GetCredential(string) (model.StoredCredential, error)
	DeleteCredential(string) error

	CreateJob(model.Job) error
	GetJob(string) (model.Job, error)
	ListJobs() ([]model.Job, error)
	MutateJob(string, func(model.Job) (model.Job, error)) (model.Job, error)

	AppendAudit(model.AuditEvent) error
	ListAudits(int) ([]model.AuditEvent, error)

	CreateWorker(model.CloudflareWorker) error
	GetWorker(string) (model.CloudflareWorker, error)
	ListWorkers() ([]model.CloudflareWorker, error)
	PutWorkerToken(model.StoredCloudflareToken) error
	GetWorkerToken(string) (model.StoredCloudflareToken, error)
	DeleteWorkerToken(string) error
	CreateWorkerVersion(model.StoredCloudflareWorkerVersion) error
	GetWorkerVersion(string, string) (model.StoredCloudflareWorkerVersion, error)
	ListWorkerVersions(string) ([]model.CloudflareWorkerVersion, error)
	UpdateWorkerVersionProvider(string, string, string, int64, time.Time) error
	PlanWorkerDeployment(model.CloudflareDeployment, model.CloudflareWorker) error
	GetWorkerDeployment(string, string) (model.CloudflareDeployment, error)
	ListWorkerDeployments(string) ([]model.CloudflareDeployment, error)
	UpdateWorkerDeployment(model.CloudflareDeployment, string) error

	StorageMode() string
	Ready(context.Context) error
	Close()
}

var _ Repository = (*Memory)(nil)
