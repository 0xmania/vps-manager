<div align="center">

# VPS Manager

**面向 Linux VPS 管理的 Go 控制面基础库。**

[![License: MIT](https://img.shields.io/badge/License-MIT-2ea44f.svg)](LICENSE)
![Go](https://img.shields.io/badge/Go-1.26-00ADD8?logo=go&logoColor=white)

</div>

当前代码提供主机与任务模型、SSH host key 校验、Linux 运行快照采集、凭据信封加密、Connector 请求签名及 PostgreSQL 初始表结构。

## 当前内容

| Package | 内容 |
|---|---|
| `control-plane/internal/model` | 主机、host key、凭据元数据、任务、运行快照与审计事件模型 |
| `connector/sshconnector` | SSH host key 探测、固定公钥校验和受限命令执行 |
| `control-plane/internal/snapshot` | Linux 主机信息、负载、内存、CPU 与文件系统快照解析 |
| `control-plane/internal/credentials` | 每份凭据独立数据密钥的 AES-GCM 信封加密 |
| `keymanager` | Vault Transit 适配器与内存开发实现 |
| `connector-protocol` | Connector 消息类型、HMAC 请求签名和重放校验 |
| `control-plane/internal/auth` | 内存会话、角色、权限和主机范围判断 |
| `control-plane/internal/audit` | 审计字段脱敏工具 |
| `migrations` | PostgreSQL 主机、凭据、任务与审计表结构 |

## 代码结构

```text
services/
├── connector-protocol/       Connector 协议与请求签名
├── connector/sshconnector/   SSH 连接与运行快照命令
├── control-plane/internal/   业务模型及基础库
└── keymanager/               密钥包装适配器

migrations/
└── 000001_durable_control_plane.*.sql
```

## 编译

```powershell
cd services
go build ./...
```

当前代码树由可编译的 Go packages 和数据库迁移组成，不包含可启动的 HTTP 服务或 Web 运行时。

## License

MIT © 2026 [0xmania](https://github.com/0xmania)
