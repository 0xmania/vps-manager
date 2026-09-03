BEGIN;

CREATE TABLE vps_manager.current_secret_bindings (
    installation_id text NOT NULL,
    scope_type text NOT NULL CHECK (scope_type IN ('host', 'cloudflare_worker')),
    scope_id text NOT NULL,
    credential_id text NOT NULL,
    credential_version bigint NOT NULL CHECK (credential_version > 0),
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (installation_id, scope_type, scope_id),
    FOREIGN KEY (installation_id, credential_id, credential_version)
        REFERENCES vps_manager.credential_envelopes (installation_id, credential_id, version)
        ON DELETE RESTRICT
);

CREATE INDEX current_secret_envelope_idx
    ON vps_manager.current_secret_bindings (installation_id, credential_id, credential_version);

CREATE TABLE vps_manager.cloudflare_workers (
    installation_id text NOT NULL,
    id text NOT NULL,
    name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 100),
    account_id text NOT NULL CHECK (account_id ~ '^[a-f0-9]{32}$'),
    script_name text NOT NULL CHECK (script_name ~ '^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$'),
    desired_version_id text,
    version bigint NOT NULL CHECK (version > 0),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (installation_id, id),
    UNIQUE (installation_id, account_id, script_name),
    CHECK (updated_at >= created_at)
);

CREATE TABLE vps_manager.cloudflare_worker_versions (
    installation_id text NOT NULL,
    id text NOT NULL,
    worker_id text NOT NULL,
    sha256 text NOT NULL CHECK (sha256 ~ '^sha256:[a-f0-9]{64}$'),
    size_bytes integer NOT NULL CHECK (size_bytes BETWEEN 1 AND 262144),
    content_type text NOT NULL CHECK (content_type = 'application/javascript'),
    entrypoint text NOT NULL CHECK (entrypoint = 'index.js'),
    state text NOT NULL CHECK (state = 'staged'),
    module bytea NOT NULL CHECK (octet_length(module) = size_bytes),
    created_at timestamptz NOT NULL,
    created_by text NOT NULL CHECK (char_length(created_by) BETWEEN 1 AND 256),
    PRIMARY KEY (installation_id, id),
    FOREIGN KEY (installation_id, worker_id)
        REFERENCES vps_manager.cloudflare_workers (installation_id, id)
        ON DELETE RESTRICT
);

ALTER TABLE vps_manager.cloudflare_workers
    ADD CONSTRAINT cloudflare_workers_desired_version_fk
    FOREIGN KEY (installation_id, desired_version_id)
    REFERENCES vps_manager.cloudflare_worker_versions (installation_id, id)
    DEFERRABLE INITIALLY DEFERRED;

CREATE INDEX cloudflare_worker_versions_timeline_idx
    ON vps_manager.cloudflare_worker_versions (installation_id, worker_id, created_at DESC, id DESC);

CREATE TABLE vps_manager.cloudflare_deployments (
    installation_id text NOT NULL,
    id text NOT NULL,
    worker_id text NOT NULL,
    version_id text NOT NULL,
    previous_desired_version_id text,
    kind text NOT NULL CHECK (kind IN ('deploy', 'rollback')),
    state text NOT NULL CHECK (state = 'ready_for_provider'),
    provider_execution_allowed boolean NOT NULL CHECK (provider_execution_allowed = false),
    created_at timestamptz NOT NULL,
    created_by text NOT NULL CHECK (char_length(created_by) BETWEEN 1 AND 256),
    PRIMARY KEY (installation_id, id),
    FOREIGN KEY (installation_id, worker_id)
        REFERENCES vps_manager.cloudflare_workers (installation_id, id)
        ON DELETE RESTRICT,
    FOREIGN KEY (installation_id, version_id)
        REFERENCES vps_manager.cloudflare_worker_versions (installation_id, id)
        ON DELETE RESTRICT
);

CREATE INDEX cloudflare_deployments_timeline_idx
    ON vps_manager.cloudflare_deployments (installation_id, worker_id, created_at DESC, id DESC);

COMMIT;
