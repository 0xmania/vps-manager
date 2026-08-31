# Key manager adapter

`VaultTransit` implements key wrapping for envelope encryption. A 32-byte per-object data key is sent to Vault Transit `encrypt`; only the returned `vault:vN:...` ciphertext is persisted. Unwrap calls Transit `decrypt` with the same context.

Configuration rules:

- Vault uses HTTPS with normal certificate verification; a private CA may be supplied.
- The address cannot contain credentials, query parameters or an API path.
- Transit mount and key names are validated.
- Environment HTTP proxies and redirects are disabled.
- An identity can be configured as `WrapOnly` or `UnwrapOnly`.
- Tokens come from a `TokenSource` and are omitted from formatted configuration and errors.

The Transit key must be a derived key because `installation_id + credential_id + version + credential_type` is sent as Vault `context`. Separate policies can grant upload identities access to `transit/encrypt/<key>` and execution identities access to `transit/decrypt/<key>`.

`MemoryManager` is an in-memory development implementation. It is not durable.

This package is an adapter library and is not connected to a runnable service in this codebase.
