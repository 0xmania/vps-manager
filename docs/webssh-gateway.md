# WebSSH control-plane gateway

`services/websshgateway` is the browser-facing broker between an authorized
control-plane request and the isolated Connector WebSSH endpoint. It forwards
only a bound terminal session. SSH credentials, Connector tickets, and Connector
session IDs remain server-side. The gateway exposes no API for arbitrary
upstream URLs, commands, forwarding, file transfer, or environment access.

## Integration

Construct the existing HMAC client and then the broker:

```go
connector, err := connectorprotocol.NewClient(connectorprotocol.ClientConfig{
    BaseURL: "http://127.0.0.1:9081",
    KeyID:   connectorKeyID,
    Key:     connectorHMACKey,
})
if err != nil { return err }

gateway, err := websshgateway.New(websshgateway.Config{
    PublicWebSocketURL:  "wss://control.example.com/api/v1/webssh/connect",
    AllowedOrigins:     []string{"https://control.example.com"},
    ConnectorBaseURL:   "http://127.0.0.1:9081",
    ConnectorOrigin:    "https://control.example.com",
}, connector, authorizer, auditor)
if err != nil { return err }
defer gateway.Close()

router.Handle(websshgateway.ConnectPath, gateway.Handler())
```

The credential handoff below is development-only. It requires the control plane
to decrypt the credential for one operation. The production control plane is
wrap-only; secret handoff to the unwrap-only Connector is not wired, so WebSSH
through this path is unavailable in production.

After the development control plane has authenticated the user, checked the
current role and host scope, loaded the host and credential, and decrypted the
credential for this one operation, it calls:

```go
issued, err := gateway.Issue(ctx, &websshgateway.IssueRequest{
    Binding: websshgateway.Binding{
        PrincipalID: principal.ID,
        SessionID: session.ID,
        Roles: principal.Roles,
        HostID: host.ID,
        CredentialID: credential.ID,
        Action: connectorprotocol.ActionWebSSH,
    },
    Target: host.Target,
    PinnedHostKey: host.PinnedHostKey,
    Credential: decryptedCredential,
    InitialSize: connectorprotocol.TerminalSize{Columns: 80, Rows: 24},
    Reason: reason,
})
```

`Issue` consumes and clears both credential byte slices. Its response contains
only a short-lived browser ticket, public connection ID, expiry, fixed public
WebSocket URL, and protocol version. The browser connects with exact `Origin`
and subprotocol `vpsmgr.webssh.v1`, then sends `websshgateway.HelloMessage`
with the entire binding exactly as issued. A mismatch consumes the ticket.

`Authorizer.AuthorizeWebSSH` is called at issue, immediately before opening the
Connector WebSocket, and at most every five seconds while connected. It should
re-check the login session, current roles, host access, credential access, and
action permission. An error revokes the live terminal. `Auditor.AuditWebSSH`
receives metadata-only issued/connected/disconnected events and a stable
disconnect type; terminal frames and ticket/credential material are absent
from the audit type.

Production public URLs and origins require TLS (`wss`/`https`). Plain
`ws`/`http` is accepted only when `Development` is true and the host is an IP
literal loopback address. The Connector endpoint is fixed to an IP-literal
loopback HTTP URL or absolute Unix socket. Its transports disable environment
proxies, compression, and redirects.

## Browser frames

After the gateway hello, the browser uses the Connector's fixed JSON text
frames: `input` and `resize` toward the server, and `ready`, `output`, `exit`,
or `error` toward the browser. The gateway translates `ready.sessionId` to the
public connection ID before forwarding the frame to the browser.
Binary frames and any other message type are rejected. Message size, byte
rate, handshake, write, idle, absolute-session, outstanding-ticket, and
concurrent-session limits are enforced.
