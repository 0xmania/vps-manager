# 生产持久化与密钥适配层

生产持久化主流程已接入，外部解密执行尚未接通。

## 已实现

`services/persistence` 提供了不依赖控制面内部类型的生产边界：

- PostgreSQL：资产 CRUD、不可变凭据密文版本、Job 乐观锁更新、追加式审计查询。
- Redis：带随机所有权令牌的任务租约、原子续租/释放、幂等结果引用、带 TTL 的取消信号。
- 内存替身：并发安全的 Repository/Coordinator，仅用于本地开发和故障复现。
- 持久化前安全检查：限制 JSON 大小和深度，拒绝常见秘密字段；凭据密文结构的 JSON 序列化只返回元数据。

`services/keymanager` 提供 Vault Transit 包装/解包适配器及通用 `Wrapper`、`Unwrapper` 接口：

- 默认要求 HTTPS、证书校验、固定请求超时和有限响应体。
- Vault 地址、令牌文件和静态测试令牌均不会经 `String`/`GoString` 回显。
- 非成功响应只返回状态码和受限 request ID，不返回 Vault 响应正文。
- 客户端禁用环境 HTTP 代理和所有重定向，避免 `X-Vault-Token` 离开已配置的 Vault 源站；当前不支持通过代理访问 Vault。
- 生产配置禁止同一身份同时拥有 wrap 与 unwrap 权限。
- Vault context 绑定 `installation_id`、`credential_id`、版本和类型；Transit key 因而必须配置为 derived key。

迁移位于 `migrations/`：运行时账号不拥有 Schema/表，不具备建库、建角色、复制、BYPASSRLS 或超级用户能力；审计表通过触发器禁止更新和删除。Redis ACL 示例仅开放指定 key 前缀和适配器实际使用的命令。

## 严格启动条件

生产进程只有同时满足下列条件才可启动：

1. PostgreSQL URL 使用 `sslmode=verify-full`，连接身份与 `ExpectedRole` 一致，连接实际启用 TLS，且集群级高权限位均为 false。
2. Redis URL 使用 `rediss://`、非 `default` 的专用 ACL 用户，并通过最小读写探针。
3. Vault 使用 HTTPS；上传端选择 `WrapOnly`，Connector/部署器选择 `UnwrapOnly`，令牌由外部认证或只读内存文件注入。
4. migrations 已由独立 owner 应用，运行时 grants 已复核。

开发环境如需明文 localhost PostgreSQL/Redis/Vault，必须同时选择非 production 环境并显式设置对应 `AllowInsecureDevelopment`；production 环境设置该开关会导致启动失败。

## 运行时接线与当前限制

`VPSMGR_DEV_MODE=true` 继续使用 Memory Repository、临时 DevKMS 和进程内 SSH，仅用于本地开发。`VPSMGR_DEV_MODE=false` 会在监听端口前打开并探测 PostgreSQL、Redis 和独立 Connector，同时校验 Vault WrapOnly 配置。Vault Token 文件和远端服务在第一次加密写入时访问；dispatcher 和 Vault readiness 尚未接入。

生产必填配置：

- `VPSMGR_INSTALLATION_ID`、`VPSMGR_POSTGRES_URL`、`VPSMGR_POSTGRES_EXPECTED_ROLE`。
- `VPSMGR_REDIS_URL`、`VPSMGR_REDIS_EXPECTED_USERNAME`，以及私有 CA 场景下的 Redis TLS 文件/服务器名。
- `VPSMGR_VAULT_ADDR`、`VPSMGR_VAULT_KEY_NAME`、绝对路径 `VPSMGR_VAULT_TOKEN_FILE`；可选 mount、namespace 和 TLS CA/服务器名。
- `VPSMGR_CONNECTOR_HMAC_KEY_ID`、base64 编码的 `VPSMGR_CONNECTOR_HMAC_KEY`，以及 loopback `VPSMGR_CONNECTOR_URL` 或绝对 Unix socket。
- 身份桥接 issuer、audience、key id 和 Ed25519 public key；生产不提供 dev bootstrap。

当前边界：

- API 进程只构造 sealing-only 服务并配置 Vault `WrapOnly`，不持有可用的 Unwrap。凭据和 Cloudflare token 可加密轮换、持久化和删除当前指针，但历史密文版本保持不可变。
- 独立 Connector 已接入 host-key probe 和 readiness；在独立 secret handoff/deployer 接线前，所有需要解密的 SSH 快照、固定命令和异常扫描会明确返回 `execution_boundary_unavailable`，不会降级为进程内解密。
- PostgreSQL 是 Host、Job、审计和 Cloudflare 计划的事实库；Job `Mutate` 使用事务行锁和版本 CAS。Redis 当前参与启动/就绪探针并保留租约、幂等和取消适配器，但跨实例 dispatcher/outbox 尚未接入 API。
- Session/revocation 仍是进程内状态；当前不提供多节点 HA 或重启后的 Job 接管。
