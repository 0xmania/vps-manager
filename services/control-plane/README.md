# Control plane

Control plane 提供 VPS inventory、SSH 凭据、异步 Job、运行快照、固定命令、异常扫描、WebSSH、Runbook、Cloudflare Workers 和审计 API。

根目录 [`README.md`](../../README.md) 有完整 Compose 启动方式；这里记录原生启动和接口索引。

## 原生启动

先启动 [`../connector`](../connector/README.md)，然后在仓库根目录运行：

```powershell
$env:VPSMGR_DEV_MODE = 'true'
$env:VPSMGR_DEV_BOOTSTRAP_TOKEN = [Convert]::ToHexString(
  [Security.Cryptography.RandomNumberGenerator]::GetBytes(32)
).ToLowerInvariant()
$env:VPSMGR_CONNECTOR_URL = 'http://127.0.0.1:9081'
$env:VPSMGR_CONNECTOR_HMAC_KEY_ID = 'control-plane-dev'
$env:VPSMGR_CONNECTOR_HMAC_KEY = '<same-base64-key-as-connector>'
$env:VPSMGR_WEBSSH_PUBLIC_URL = 'ws://127.0.0.1:8080/api/v1/webssh/connect'
$env:VPSMGR_WEBSSH_ALLOWED_ORIGINS = 'http://127.0.0.1:3000'

go run ./services/control-plane/cmd/control-plane
```

默认地址是 <http://127.0.0.1:8080>。创建一个本地管理员会话：

```powershell
$headers = @{ 'X-Dev-Bootstrap' = $env:VPSMGR_DEV_BOOTSTRAP_TOKEN }
$body = @{
  subject = 'local-admin'
  role = 'admin'
  allHosts = $true
} | ConvertTo-Json

$session = Invoke-RestMethod `
  -Method Post `
  -Uri http://127.0.0.1:8080/api/v1/dev/sessions `
  -Headers $headers `
  -ContentType application/json `
  -Body $body
```

## Roles

| Role | 主要权限 |
|---|---|
| `viewer` | 查看范围内主机和 Job |
| `operator` | 管理主机、运行快照/命令/扫描、打开终端、执行 Runbook |
| `admin` | 管理凭据、替换 host key、执行 Cloudflare 部署、查看审计 |
| `auditor` | 读取主机、Job 和审计事件，不执行操作 |

会话可以管理全部主机，也可以只绑定 `hostIds`。越过对象范围的查询返回 `404`。

## API index

所有受保护接口使用 `Authorization: Bearer <token>`。

### Hosts and jobs

| Method | Path | 用途 |
|---|---|---|
| `GET/POST` | `/api/v1/hosts` | 查询或添加主机 |
| `GET/PATCH/DELETE` | `/api/v1/hosts/{hostId}` | 读取、更新或删除主机 |
| `POST` | `/api/v1/hosts/{hostId}/host-key/probe` | 探测 SSH host key |
| `PUT` | `/api/v1/hosts/{hostId}/host-key` | 确认或替换 host key |
| `GET/POST/DELETE` | `/api/v1/hosts/{hostId}/credential` | 查询元数据、保存或删除 SSH 凭据 |
| `POST` | `/api/v1/hosts/{hostId}/runtime-snapshots` | 创建运行快照 Job |
| `POST` | `/api/v1/hosts/{hostId}/commands` | 执行固定命令 |
| `POST` | `/api/v1/hosts/{hostId}/anomaly-scans` | 创建异常进程扫描 Job |
| `GET` | `/api/v1/jobs` | 查询 Job |
| `GET` | `/api/v1/jobs/{jobId}` | 查看单个 Job 结果 |
| `POST` | `/api/v1/jobs/{jobId}/cancel` | 取消 Job |

### WebSSH and Runbooks

| Method | Path | 用途 |
|---|---|---|
| `POST` | `/api/v1/hosts/{hostId}/terminal-sessions` | 创建一次性终端票据 |
| `GET` | `/api/v1/webssh/connect` | 浏览器 WebSocket 连接 |
| `POST` | `/api/v1/hosts/{hostId}/runbooks/preview` | 生成 Runbook 预览 |
| `POST` | `/api/v1/jobs/{jobId}/runbook-execute` | 执行已绑定的 Runbook |

### Cloudflare Workers

| Method | Path | 用途 |
|---|---|---|
| `GET/POST` | `/api/v1/cloudflare/workers` | 查询或创建 Worker |
| `GET/POST/DELETE` | `/api/v1/cloudflare/workers/{workerId}/token` | 管理 Token |
| `GET/POST` | `/api/v1/cloudflare/workers/{workerId}/versions` | 查询或上传模块版本 |
| `GET/POST` | `/api/v1/cloudflare/workers/{workerId}/deployments` | 查询或创建部署计划 |
| `POST` | `/api/v1/cloudflare/workers/{workerId}/deployments/{deploymentId}/execute` | 执行 deploy/rollback |

审计事件使用 `GET /api/v1/audit-events?limit=100` 查询。

## 常用配置

| 变量 | 默认值 | 作用 |
|---|---:|---|
| `VPSMGR_LISTEN_ADDR` | `127.0.0.1:8080` | HTTP listener |
| `VPSMGR_SESSION_TTL` | `1h` | 会话有效期 |
| `VPSMGR_JOB_TIMEOUT` | `100s` | SSH 与 Runbook Job 总超时 |
| `VPSMGR_ALLOW_PRIVATE_TARGETS` | `false` | 开发模式连接私网 VPS |
| `VPSMGR_ENABLE_MUTATIONS` | `false` | 允许变更 Runbook |
| `VPSMGR_ENABLE_CLOUDFLARE_EXECUTION` | `false` | 允许调用 Cloudflare Provider |
| `VPSMGR_AI_GATEWAY_ENDPOINT` | 未设置 | 可选 AI 网关；未设置时使用本地结果 |

Connector URL、HMAC key ID 和 HMAC key 必须与 Connector 配置一致。

## 开发与生产

开发模式使用内存 Repository、临时 Dev KMS 和本地会话。生产 runtime 已装配 PostgreSQL、Redis、Vault `wrap-only`、签名 identity bridge 和独立 Connector readiness。

生产 secret handoff、fresh MFA、持久化 Session/dispatcher 和跨实例恢复还没有完成。`wrap-only` 控制面不会自行解密，因此生产环境中需要凭据解密的操作目前返回执行边界不可用。
