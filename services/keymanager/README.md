# Key manager adapter

`VaultTransit` 为 SSH 私钥和 Cloudflare Token 包装每个对象的数据密钥。控制面生产 runtime 使用 `wrap-only` 身份保存新凭据，数据库只记录 Vault ciphertext、版本和对象上下文。

该包提供进程内 `MemoryManager`；运行中的开发控制面使用自己的临时 Dev KMS。两者都只面向本地开发，重启后无法恢复之前的密文。

## Vault 配置

- Vault 地址使用 HTTPS；私有 CA 可以通过配置文件提供。
- Transit key 使用 derived key，对象上下文由 `installation_id`、对象 ID、版本和凭据类型组成。
- 上传身份只需要 `transit/encrypt/<key>`；真正执行 SSH 或部署的身份应单独持有 `transit/decrypt/<key>`。
- Token 从文件读取，不放进 URL、命令行参数或格式化输出。

当前缺少从 `wrap-only` 控制面向独立 `unwrap-only` Connector/deployer 交接凭据的运行协议。因此生产模式可以登记密文，但需要解密的执行暂不可用。
