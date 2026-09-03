# SSH Connector

Connector 是独立运行的 SSH 执行进程。它负责 host key 探测、运行快照、WebSSH 和参数化 Runbook，控制面通过本地 HMAC 协议调用它。

## 启动

在 `services/` 目录运行：

```powershell
$bytes = [Security.Cryptography.RandomNumberGenerator]::GetBytes(32)
$env:VPSMGR_CONNECTOR_HMAC_KEY = [Convert]::ToBase64String($bytes)
$env:VPSMGR_CONNECTOR_HMAC_KEY_ID = 'control-plane-dev'
$env:VPSMGR_CONNECTOR_LISTEN = 'tcp://127.0.0.1:9081'
$env:VPSMGR_CONNECTOR_WEBSSH_ALLOWED_ORIGINS = 'http://127.0.0.1:8080'

go run ./connector/cmd/connector
```

生产主机可以改用 Unix socket：

```text
VPSMGR_CONNECTOR_LISTEN=unix:///run/vps-manager/connector.sock
```

健康检查：`GET /healthz`。协议与动作版本：`GET /version`。

## 固定动作

- `runtime_snapshot_v1`
- `host_key_probe_v1`
- `web_ssh_v1`
- Runbook preview / execute

非交互 API 只接受这些结构化动作，没有传入任意 Shell 字符串的请求字段。Runbook 由内置 catalog 生成步骤；变更步骤需要 `VPSMGR_CONNECTOR_ENABLE_MUTATIONS=true`。

WebSSH 是单独的交互路径，使用一次性 ticket。Origin、空闲时间、最长会话和并发数量都由 Connector 配置。详细消息格式见 [`WEBSSH.md`](WEBSSH.md)。

## 与控制面连接

控制面和 Connector 使用相同的 `VPSMGR_CONNECTOR_HMAC_KEY_ID` 与 `VPSMGR_CONNECTOR_HMAC_KEY`。请求签名包含协议版本、时间戳、nonce、HTTP method、URI 和 body digest；重复 nonce 会被拒绝。

开发模式下，独立 Connector 当前承接 readiness、WebSSH 和 Runbook；host key 探测、运行快照、固定命令与异常扫描走控制面内的开发 SSH 执行器。生产模式的 host key 探测和 readiness 已接入独立 Connector，但凭据的 unwrap-only handoff 尚未完成。

## 目标与资源限制

- TCP listener 只接受 IP 字面量回环地址；也可以使用绝对 Unix socket 路径。
- 私网目标需显式启用，loopback、link-local 和云元数据地址仍不会作为 VPS 目标连接。
- SSH 连接、命令、输出、请求体和并发数量都有上限。
- WebSSH 不开放 Agent、TCP、X11 转发或文件传输。
