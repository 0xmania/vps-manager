# VPS Manager

VPS Manager is a self-hosted web control plane for managing Linux VPS instances from one place.

The project is being built around four goals:

- manage VPS inventory and SSH access from a browser;
- collect runtime snapshots and run repeatable operations;
- explain suspicious processes with rules and optional AI assistance;
- manage Cloudflare Workers alongside server operations.

## Planned architecture

```text
Web dashboard
    │
Control plane API
    ├── host inventory and jobs
    ├── encrypted credentials
    ├── audit events
    └── Cloudflare deployments
    │
SSH Connector / WebSSH gateway
    │
Linux VPS instances
```

The repository uses Go for the control plane and Connector, and TypeScript for the web application.

## Development status

This first commit establishes the repository, dependency manifests and development conventions. Functional control-plane and web capabilities are introduced in the following stages.

## License

[MIT](LICENSE)
