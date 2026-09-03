BEGIN;

ALTER TABLE vps_manager.cloudflare_worker_versions
    ADD COLUMN provider_version_id text,
    ADD COLUMN provider_version_number bigint,
    ADD COLUMN provider_uploaded_at timestamptz,
    ADD CONSTRAINT cloudflare_worker_versions_provider_metadata_check CHECK (
        (provider_version_id IS NULL AND provider_version_number IS NULL AND provider_uploaded_at IS NULL)
        OR
        (provider_version_id IS NOT NULL AND char_length(provider_version_id) BETWEEN 1 AND 128
         AND provider_version_number >= 0 AND provider_uploaded_at IS NOT NULL)
    );

ALTER TABLE vps_manager.cloudflare_deployments
    DROP CONSTRAINT cloudflare_deployments_state_check,
    DROP CONSTRAINT cloudflare_deployments_provider_execution_allowed_check,
    ADD COLUMN provider_version_id text,
    ADD COLUMN provider_deployment_id text,
    ADD COLUMN provider_state text,
    ADD COLUMN error_code text,
    ADD COLUMN started_at timestamptz,
    ADD COLUMN finished_at timestamptz,
    ADD CONSTRAINT cloudflare_deployments_state_check CHECK (state IN ('ready_for_provider', 'running', 'succeeded', 'failed')),
    ADD CONSTRAINT cloudflare_deployments_execution_lifecycle_check CHECK (
        (state = 'ready_for_provider' AND provider_execution_allowed = false AND started_at IS NULL AND finished_at IS NULL AND error_code IS NULL)
        OR
        (state = 'running' AND provider_execution_allowed = true AND started_at IS NOT NULL AND finished_at IS NULL AND error_code IS NULL)
        OR
        (state = 'succeeded' AND provider_execution_allowed = true AND started_at IS NOT NULL AND finished_at IS NOT NULL
         AND provider_version_id IS NOT NULL AND provider_deployment_id IS NOT NULL AND provider_state = 'active' AND error_code IS NULL)
        OR
        (state = 'failed' AND provider_execution_allowed = true AND started_at IS NOT NULL AND finished_at IS NOT NULL AND error_code IS NOT NULL)
    ),
    ADD CONSTRAINT cloudflare_deployments_provider_identifiers_check CHECK (
        (provider_version_id IS NULL OR char_length(provider_version_id) BETWEEN 1 AND 128)
        AND (provider_deployment_id IS NULL OR char_length(provider_deployment_id) BETWEEN 1 AND 128)
        AND (provider_state IS NULL OR provider_state IN ('pending', 'active'))
        AND (error_code IS NULL OR error_code ~ '^[a-z0-9_]{1,128}$')
    ),
    ADD CONSTRAINT cloudflare_deployments_execution_time_check CHECK (
        (started_at IS NULL OR started_at >= created_at)
        AND (finished_at IS NULL OR (started_at IS NOT NULL AND finished_at >= started_at))
    );

COMMIT;
