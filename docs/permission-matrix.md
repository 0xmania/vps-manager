# 权限矩阵

本文记录控制面当前使用的角色与权限。权限定义以
`services/control-plane/internal/auth/auth.go` 为准。

## 角色

| 角色 | 用途 |
|---|---|
| `viewer` | 查看主机、Job 和 Cloudflare Worker 元数据 |
| `operator` | 管理主机并执行日常运维操作 |
| `admin` | 管理凭据、替换 host key、执行 Cloudflare 发布和查看审计 |
| `auditor` | 查看主机、Job、Worker 元数据和审计事件 |

## 权限

| Permission | viewer | operator | admin | auditor |
|---|:---:|:---:|:---:|:---:|
| `hosts:read` | ✓ | ✓ | ✓ | ✓ |
| `hosts:write` | — | ✓ | ✓ | — |
| `hosts:delete` | — | — | ✓ | — |
| `host_key:pin` | — | ✓ | ✓ | — |
| `host_key:replace` | — | — | ✓ | — |
| `credentials:manage` | — | — | ✓ | — |
| `jobs:read` | ✓ | ✓ | ✓ | ✓ |
| `snapshots:run` | — | ✓ | ✓ | — |
| `commands:run` | — | ✓ | ✓ | — |
| `anomaly_scans:run` | — | ✓ | ✓ | — |
| `terminal_sessions:open` | — | ✓ | ✓ | — |
| `runbooks:preview` | — | ✓ | ✓ | — |
| `runbooks:execute` | — | ✓ | ✓ | — |
| `jobs:cancel` | — | ✓ | ✓ | — |
| `cloudflare_workers:read` | ✓ | ✓ | ✓ | ✓ |
| `cloudflare_workers:write` | — | ✓ | ✓ | — |
| `cloudflare_worker_tokens:manage` | — | — | ✓ | — |
| `cloudflare_worker_deployments:plan` | — | ✓ | ✓ | — |
| `cloudflare_worker_deployments:execute` | — | — | ✓ | — |
| `audit:read` | — | — | ✓ | ✓ |
| `session:revoke_self` | ✓ | ✓ | ✓ | ✓ |

## 对象范围

会话可以绑定全部主机，也可以只绑定一组 `hostIds`。主机、Job、快照、
命令、扫描、终端和 Runbook 都使用该范围。范围外对象按资源不可见处理。

Cloudflare Worker 是全局资源，相关接口要求会话具有 `allHosts=true`。
拥有主机权限不会自动获得 Token 管理或 Provider 执行权限。

## 执行时检查

- HTTP 路由先校验 Bearer 会话和对应 Permission。
- SSH 操作要求主机已固定 host key 并保存凭据。
- 排队任务在开始执行前重新检查原会话的有效期、撤销状态、角色和主机范围。
- WebSSH 票据绑定用户、会话、主机和凭据，活动连接会周期性重新授权。
- Runbook 执行绑定预览生成的 scope digest；变更动作还受运行开关控制。
- Cloudflare Token 与 SSH 私钥接口只返回元数据，不提供明文读取权限。
- 任意 Shell、端口转发、Agent/X11 转发、SFTP 和 SCP 不在当前权限模型中。

## 当前运行边界

开发会话和 Ed25519 identity bridge 都映射到上面的四个角色。Session 与撤销
状态目前保存在进程内。fresh MFA 和 break-glass 票据尚未接入；生产配置中
需要解密凭据的 WebSSH、Runbook、SSH Job 和 Cloudflare Provider 执行不可用。

授权检查位置见 [权限模型实现说明](permission-model-reference.md)。
