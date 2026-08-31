BEGIN;

DROP TRIGGER IF EXISTS audit_events_append_only ON vps_manager.audit_events;
DROP FUNCTION IF EXISTS vps_manager.reject_audit_mutation();
DROP TABLE IF EXISTS vps_manager.audit_events;
DROP TABLE IF EXISTS vps_manager.jobs;
DROP TABLE IF EXISTS vps_manager.credential_envelopes;
DROP TABLE IF EXISTS vps_manager.assets;
DROP SCHEMA IF EXISTS vps_manager;

COMMIT;

