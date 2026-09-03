# Persistence adapters

`services/persistence` 提供控制面需要的 PostgreSQL 与 Redis 适配器。`control-plane/cmd/control-plane` 在非开发模式下加载 PostgreSQL 作为业务事实库，并用 Redis 完成启动和 readiness 检查。Redis 适配器已经提供短期租约、幂等引用和取消信号，但 dispatcher 还没有接入这些能力。

开发模式继续使用内存实现，方便快速启动。它不会写入磁盘，重启后数据会清空。

## PostgreSQL

- 迁移位于 [`../../migrations`](../../migrations)。
- 应用账号和迁移账号分开配置。
- Job 更新使用版本号比较，审计事件只追加。
- 凭据表只保存密文、密钥引用和非敏感元数据。

生产配置需要 `VPSMGR_POSTGRES_URL`、`VPSMGR_POSTGRES_EXPECTED_ROLE` 和 `VPSMGR_INSTALLATION_ID`。当前 runtime 会在启动时检查连接、角色和必需表权限。

## Redis

Redis 不保存业务事实，只保存短期协调状态。生产配置使用 `VPSMGR_REDIS_URL` 和专用用户名；ACL 示例见 [`../../migrations/redis-acl.example`](../../migrations/redis-acl.example)。

## 当前限制

- durable dispatcher/outbox 和跨实例 Job 接管未接入；
- Session 和撤销状态仍在进程内；
- 当前不提供多实例故障接管。
