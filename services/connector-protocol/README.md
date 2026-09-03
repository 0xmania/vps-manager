# Connector protocol

This package defines the strongly typed client and wire contract for the
isolated SSH Connector. It is independent of the SSH implementation and
contains no arbitrary-command request type.

Signed requests use `VPSMGR-HMAC-SHA256` canonicalization over protocol version,
key ID, Unix timestamp, nonce, HTTP method, request URI, and SHA-256 body hash.
Nonce values contain 192 random bits; the verifier enforces a bounded replay
cache only after the MAC is valid. This HMAC scheme covers the local development
process boundary. Production deployments add Unix socket ownership; deployments
that cross a host boundary replace it with workload identity or mTLS.
