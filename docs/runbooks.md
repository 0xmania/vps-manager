# Runbooks

Runbook 是服务端维护的固定运维目录。调用方提交 action、版本和结构化参数，不能提交 Shell 文本。

## 当前目录

| Action | 参数 | 主机变更 |
|---|---|---:|
| `system_capabilities_v1` | 无 | 否 |
| `package_update_check_v1` | 无 | 否 |
| `service_status_v1` | `nginx` / `ssh` / `docker` / `cron` | 否 |
| `service_restart_v1` | 同上 | 是 |
| `timezone_set_v1` | `UTC` / `Asia/Shanghai` / `America/New_York` / `Europe/London` | 是 |
| `process_sigterm_v1` | PID + `/proc` start ticks | 是 |
| `host_reboot_plan_v1` | 无 | 是 |

只读 Runbook 执行 preflight 和 evidence。变更 Runbook 还包含 apply 与 verify。步骤按顺序运行，首个失败后停止，不自动重试。

服务名和时区映射为服务端固定字面量。进程终止同时绑定 PID 与 `/proc` start ticks，避免 PID 被复用后命中另一个进程。

## 请求流程

1. `POST /api/v1/hosts/{hostID}/runbooks/preview` 验证 action、版本和参数，创建 Job，并请求 Connector 生成预览。
2. 预览返回步骤说明、是否变更主机、当前能否执行和 `scopeDigest`；不返回远端命令文本。
3. `POST /api/v1/jobs/{jobID}/runbook-execute` 提交原 digest、原因，以及应急动作需要的 incident ID。
4. Control API 核对当前会话、主机 scope、host key、凭据和预览绑定，再把固定计划交给 Connector。

Connector 请求使用 HMAC 协议。execute 会重新构建计划并核对 action、host、job、digest、host key 和 SSH 公钥指纹。

## 运行开关

变更步骤同时要求控制面与 Connector 开启：

```text
VPSMGR_ENABLE_MUTATIONS=true
VPSMGR_CONNECTOR_ENABLE_MUTATIONS=true
```

开发模式可以打开凭据执行。生产控制面只有 Vault wrap 权限，secret handoff 未接通，因此 Runbook execute 当前不可用。

## 结果与当前限制

结果包含每一步的状态、退出码、有限 stdout/stderr 和耗时。Connector 在单进程内按 job ID 缓存执行结果；相同 digest 的重复请求返回缓存，不重复运行。

该缓存重启后清空。Session、预览和审批摘要也是当前进程状态；没有持久化二次认证或双人审批流程。
