BEGIN;

ALTER TABLE vps_manager.cloudflare_deployments
    DROP CONSTRAINT cloudflare_deployments_execution_time_check,
    DROP CONSTRAINT cloudflare_deployments_provider_identifiers_check,
    DROP CONSTRAINT cloudflare_deployments_execution_lifecycle_check,
    DROP CONSTRAINT cloudflare_deployments_state_check,
    DROP COLUMN finished_at,
    DROP COLUMN started_at,
    DROP COLUMN error_code,
    DROP COLUMN provider_state,
    DROP COLUMN provider_deployment_id,
    DROP COLUMN provider_version_id,
    ADD CONSTRAINT cloudflare_deployments_state_check CHECK (state = 'ready_for_provider'),
    ADD CONSTRAINT cloudflare_deployments_provider_execution_allowed_check CHECK (provider_execution_allowed = false);

ALTER TABLE vps_manager.cloudflare_worker_versions
    DROP CONSTRAINT cloudflare_worker_versions_provider_metadata_check,
    DROP COLUMN provider_uploaded_at,
    DROP COLUMN provider_version_number,
    DROP COLUMN provider_version_id;

COMMIT;
