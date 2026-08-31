BEGIN;

CREATE SCHEMA IF NOT EXISTS vps_manager;

CREATE TABLE vps_manager.assets (
    installation_id text NOT NULL,
    id text NOT NULL,
    name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 200),
    address text NOT NULL CHECK (char_length(address) BETWEEN 1 AND 255),
    port integer NOT NULL CHECK (port BETWEEN 1 AND 65535),
    username text NOT NULL CHECK (char_length(username) BETWEEN 1 AND 128),
    labels jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(labels) = 'object'),
    host_key jsonb,
    version bigint NOT NULL CHECK (version >= 0),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (installation_id, id),
    CHECK (updated_at >= created_at)
);

CREATE TABLE vps_manager.credential_envelopes (
    installation_id text NOT NULL,
    credential_id text NOT NULL,
    version bigint NOT NULL CHECK (version > 0),
    kind text NOT NULL CHECK (char_length(kind) BETWEEN 1 AND 128),
    key_id text NOT NULL CHECK (char_length(key_id) BETWEEN 1 AND 512),
    ciphertext bytea NOT NULL CHECK (octet_length(ciphertext) > 0),
    cipher_nonce bytea NOT NULL,
    wrapped_key bytea NOT NULL CHECK (octet_length(wrapped_key) > 0),
    wrapped_key_nonce bytea NOT NULL,
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(metadata) = 'object'),
    created_at timestamptz NOT NULL,
    PRIMARY KEY (installation_id, credential_id, version)
);

CREATE TABLE vps_manager.jobs (
    installation_id text NOT NULL,
    id text NOT NULL,
    type text NOT NULL CHECK (char_length(type) BETWEEN 1 AND 128),
    asset_id text NOT NULL,
    state text NOT NULL CHECK (state IN ('created','prechecking','awaiting_approval','queued','running','verifying','succeeded','failed','timed_out','cancelled','orphaned','reconciling')),
    requested_by text NOT NULL CHECK (char_length(requested_by) BETWEEN 1 AND 256),
    request_id text,
    idempotency_key text,
    parameters jsonb NOT NULL DEFAULT '{}'::jsonb,
    result jsonb NOT NULL DEFAULT '{}'::jsonb,
    error_code text,
    error_message text CHECK (error_message IS NULL OR char_length(error_message) <= 4096),
    version bigint NOT NULL CHECK (version >= 0),
    created_at timestamptz NOT NULL,
    started_at timestamptz,
    finished_at timestamptz,
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (installation_id, id),
    FOREIGN KEY (installation_id, asset_id)
        REFERENCES vps_manager.assets (installation_id, id)
        ON DELETE RESTRICT,
    UNIQUE (installation_id, idempotency_key),
    CHECK (jsonb_typeof(parameters) = 'object'),
    CHECK (jsonb_typeof(result) = 'object'),
    CHECK (updated_at >= created_at),
    CHECK (started_at IS NULL OR started_at >= created_at),
    CHECK (finished_at IS NULL OR started_at IS NOT NULL)
);

CREATE INDEX jobs_dispatch_idx
    ON vps_manager.jobs (installation_id, state, created_at, id)
    WHERE state IN ('queued', 'running', 'orphaned', 'reconciling');

CREATE INDEX jobs_asset_idx
    ON vps_manager.jobs (installation_id, asset_id, created_at DESC);

CREATE TABLE vps_manager.audit_events (
    sequence bigint GENERATED ALWAYS AS IDENTITY,
    installation_id text NOT NULL,
    event_id text NOT NULL,
    occurred_at timestamptz NOT NULL,
    actor text NOT NULL CHECK (char_length(actor) BETWEEN 1 AND 256),
    role text NOT NULL,
    action text NOT NULL,
    target_type text NOT NULL,
    target_id text,
    outcome text NOT NULL,
    request_id text,
    job_id text,
    details jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(details) = 'object'),
    PRIMARY KEY (sequence),
    UNIQUE (installation_id, event_id)
);

CREATE INDEX audit_events_timeline_idx
    ON vps_manager.audit_events (installation_id, occurred_at DESC, event_id DESC);

CREATE INDEX audit_events_request_idx
    ON vps_manager.audit_events (installation_id, request_id)
    WHERE request_id IS NOT NULL;

CREATE INDEX audit_events_job_idx
    ON vps_manager.audit_events (installation_id, job_id)
    WHERE job_id IS NOT NULL;

CREATE FUNCTION vps_manager.reject_audit_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'audit events are append-only' USING ERRCODE = '42501';
END;
$$;

CREATE TRIGGER audit_events_append_only
BEFORE UPDATE OR DELETE ON vps_manager.audit_events
FOR EACH ROW EXECUTE FUNCTION vps_manager.reject_audit_mutation();

COMMIT;

