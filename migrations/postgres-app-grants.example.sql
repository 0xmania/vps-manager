-- Run as the schema owner after all numbered migrations have been applied.
-- Replace vpsmgr_app with the non-login/group role chosen by the operator.
-- The application's login role should inherit only this role and must not own
-- the schema, tables, sequences, functions, or migration history.

REVOKE ALL ON SCHEMA vps_manager FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA vps_manager FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA vps_manager FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA vps_manager FROM PUBLIC;

GRANT USAGE ON SCHEMA vps_manager TO vpsmgr_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON vps_manager.assets TO vpsmgr_app;
GRANT SELECT, INSERT ON vps_manager.credential_envelopes TO vpsmgr_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON vps_manager.current_secret_bindings TO vpsmgr_app;
GRANT SELECT, INSERT, UPDATE ON vps_manager.cloudflare_workers TO vpsmgr_app;
GRANT SELECT, INSERT, UPDATE ON vps_manager.cloudflare_worker_versions TO vpsmgr_app;
GRANT SELECT, INSERT, UPDATE ON vps_manager.cloudflare_deployments TO vpsmgr_app;
GRANT SELECT, INSERT, UPDATE ON vps_manager.jobs TO vpsmgr_app;
GRANT SELECT, INSERT ON vps_manager.audit_events TO vpsmgr_app;
GRANT USAGE, SELECT ON SEQUENCE vps_manager.audit_events_sequence_seq TO vpsmgr_app;

ALTER DEFAULT PRIVILEGES IN SCHEMA vps_manager REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA vps_manager REVOKE ALL ON SEQUENCES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA vps_manager REVOKE ALL ON FUNCTIONS FROM PUBLIC;
