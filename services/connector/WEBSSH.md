# Web SSH / PTY protocol

Web SSH spans the Connector, control-plane gateway and web terminal. The
Connector owns the SSH/PTY session and single-use ticket; the control plane
proxies the browser connection without returning SSH credentials.

## Enablement

Web SSH is disabled when `VPSMGR_CONNECTOR_WEBSSH_ALLOWED_ORIGINS` is empty.
Enable it with one or more exact, comma-separated origins; wildcards and a
missing `Origin` header are rejected.

```text
VPSMGR_CONNECTOR_WEBSSH_ALLOWED_ORIGINS=https://console.example.com
VPSMGR_CONNECTOR_WEBSSH_IDLE_TIMEOUT=10m
VPSMGR_CONNECTOR_WEBSSH_ABSOLUTE_TIMEOUT=1h
VPSMGR_CONNECTOR_WEBSSH_MAX_CONCURRENT=4
```

The WebSocket implementation is pinned to `github.com/coder/websocket
v1.8.15`, compression is disabled, and the required subprotocol is
`vpsmgr.webssh.v1`.

## Control-plane integration sequence

1. After its own authorization and step-up checks, the control plane sends an
   HMAC-authenticated `POST /v1/webssh/tickets` request.
2. Use `connectorprotocol.WebSSHTicketRequest`. Set
   `protocolVersion="v1"` and bind `principalId`, `hostId`, `credentialId`, and
   `action="web_ssh_v1"`. Include the target, pinned host public key, SSH
   private-key credential, and initial terminal size.
3. The Connector validates the fixed action, IDs, target policy, exact pinned
   key, private key, and PTY dimensions. It returns a random ticket, random
   session ID, and expiry. The default ticket lifetime is 30 seconds.
4. The authorized browser or a control-plane WebSocket proxy connects to
   `GET /v1/webssh/connect` with the exact configured Origin and required
   subprotocol. Do not put the ticket in a URL.
5. Within five seconds, the first text frame must be
   `connectorprotocol.WebSSHHelloMessage`. Repeat the ticket, session ID, and
   all four binding fields exactly.
6. The Connector atomically consumes the ticket before SSH connection setup.
   Every attempt—including a binding mismatch—invalidates it. A concurrent or
   later use receives `ticket_replayed` and cannot open another PTY.

HMAC protects request integrity and authenticates the local control-plane
caller; it does not encrypt HTTP. Prefer an owner-restricted Unix socket in
production, or add mTLS/workload identity before allowing this protocol across
hosts. Never expose the Connector listener directly to the public network.

## WebSocket frames

All application frames are JSON text. Go `[]byte` fields are JSON base64.

| Direction | Type | Contract |
| --- | --- | --- |
| client → Connector | `hello` | Single-use ticket, session ID, complete binding |
| client → Connector | `input` | Raw terminal input, at most 16 KiB per message by default |
| client → Connector | `resize` | Columns 20–500, rows 5–300 |
| Connector → client | `ready` | Confirmed session ID and initial size |
| Connector → client | `output` | Raw PTY bytes, at most 16 KiB per message by default |
| Connector → client | `exit` | Sanitized exit status/reason |
| Connector → client | `error` | Stable code, safe message, retryability flag |

PTY output remains terminal bytes. The Connector does not interpret OSC/title
sequences, ANSI escapes, or HTML-like text and never converts output to HTML.
The browser must render through a terminal emulator and must not inject decoded
bytes into the DOM as HTML.

## Enforced boundaries

- Full SSH host-key pin validation is mandatory; there is no TOFU fallback.
- Only a shell on a requested PTY is exposed. There are no Connector APIs for
  agent, TCP, X11, or reverse forwarding, SCP, SFTP, subsystems, environment
  injection, or arbitrary `exec` requests.
- DNS is resolved once; every answer must pass target policy and the connection
  is pinned to a checked IP.
- Input and output messages, byte rates, pending handshakes, active sessions,
  outstanding tickets, ticket lifetime, handshake time, idle time, absolute
  session time, and WebSocket write time are bounded.
- HTTP read/write deadlines stay enabled for ordinary API requests. They are
  cleared only after a successful WebSocket upgrade; WebSocket operations then
  use scoped deadlines and session timeouts.
- Ticket credentials are memory-only and wiped on use, expiry, binding failure,
  capacity rejection, or Connector shutdown. Disconnect cancels the SSH
  session, closes pipes and network connections, and releases capacity.

## Current limits

The development flow uses the existing login session, role and host scope; it
does not provide fresh MFA. Production credential handoff to an unwrap-only
Connector is also not implemented, so this path is currently for development
and isolated-environment use.
