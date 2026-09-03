BEGIN;

DROP TABLE IF EXISTS vps_manager.cloudflare_deployments;
ALTER TABLE IF EXISTS vps_manager.cloudflare_workers
    DROP CONSTRAINT IF EXISTS cloudflare_workers_desired_version_fk;
DROP TABLE IF EXISTS vps_manager.cloudflare_worker_versions;
DROP TABLE IF EXISTS vps_manager.current_secret_bindings;
DROP TABLE IF EXISTS vps_manager.cloudflare_workers;

COMMIT;
