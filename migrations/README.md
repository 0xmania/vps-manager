# Durable adapter migrations

Apply migrations in numeric order with a dedicated migration owner, never with the runtime application identity:

- `000001_durable_control_plane` creates assets, immutable credential-envelope versions, CAS-versioned jobs and the append-only audit index.
- `000002_control_plane_models` adds the remaining control-plane models used by the production repository.
- `000003_cloudflare_execution` adds Cloudflare execution state and Provider result fields.

Operational sequence:

1. Back up and test restore in the target environment.
2. Apply every pending numbered migration in a transaction using the migration owner.
3. Replace the role name in `postgres-app-grants.example.sql`, review it, and apply the grants as the owner.
4. Configure the application with `sslmode=verify-full`, the expected non-privileged login role, and a CA trust path supported by PostgreSQL/pgx.
5. Render `redis-acl.example` outside version control with a generated password. Use a distinct Redis database/cluster identity and `rediss://`.
6. Run adapter startup verification before serving traffic.

The down migration is destructive and is for disposable environments only. Production rollback must be a reviewed forward migration; audit retention and credential destruction require a separate approved procedure.

Redis is not a source of truth. It stores only short-lived opaque lease tokens, result references, idempotency records and cancellation flags. All user-supplied key material is hashed before becoming a Redis key.
