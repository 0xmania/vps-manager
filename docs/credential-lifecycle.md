# 凭据与密钥生命周期

本文只描述当前运行时已实现的 SSH 私钥和 Cloudflare API Token。

## 1. 当前对象

| 类型 | 绑定对象 | 保存的元数据 |
|---|---|---|
| SSH 私钥 | Host | 凭据 ID、类型、Key ID、公钥指纹、创建人和时间 |
| Cloudflare API Token | Worker | Token ID、类型、Key ID、创建人和时间 |

每个 Host 和 Worker 各有一个当前凭据绑定。API 支持写入、查看元数据和删除当前绑定，不提供秘密读取接口。

## 2. 存储边界

1. 秘密由凭据服务做信封加密，Repository 只接收 `Envelope` 和元数据。
2. AAD 绑定 installation、Host/Worker、凭据 ID、固定记录版本和凭据类型；复制密文到另一个对象后无法按新上下文打开。
3. `Envelope` 的密文、nonce 和 wrapped key 都排除在 JSON 序列化之外。
4. Job、审计和 API 响应只引用凭据 ID 或返回元数据，不包含私钥、passphrase 或 Token。
5. SSH host key 与 SSH 私钥分别校验，拥有正确私钥不会跳过主机指纹检查。

## 3. 写入、替换与删除

1. Control API 在对象 scope 和权限校验后读取严格 JSON 请求。
2. SSH 私钥由 Go SSH 库解析，并保存公钥 SHA-256 指纹；Cloudflare Token 只接受限定长度的可打印非空白 ASCII。
3. 服务端生成新的凭据 ID，用对象绑定的 AAD 加密秘密。
4. Repository 保存密文并把主机或 Worker 的当前凭据指针切换到新记录。
5. 响应只返回 ID、类型、Key ID、创建信息和公钥指纹等元数据。

再次保存会创建新 ID 并替换当前绑定。删除接口移除当前绑定，之后的执行会得到凭据不存在；PostgreSQL 中已写入的不可变密文记录由独立保留策略处理。

## 4. 凭据使用

开发模式下，SSH、WebSSH、Runbook 和 Cloudflare Provider 在开始操作前读取当前凭据，并在 `Service.Open` 回调中解密。SSH 私钥在回调内解析为 signer；Cloudflare Token 只作为 Provider 请求的 Authorization 值。显式字节缓冲在回调结束时擦除，不写临时文件。

生产控制面只有 Vault `wrap-only` 身份。Connector/deployer 的秘密交接尚未接通，因此所有需要解密的执行入口返回 `execution_boundary_unavailable`，不会回退到控制面内解密。

## 5. 运行模式

| 模式 | 密钥提供器 | 可写入 | 可执行 |
|---|---|---|---|
| Compose / development | 临时 DevKMS | SSH 私钥、Cloudflare Token | 按运行开关执行 SSH、WebSSH、Runbook 和 Provider |
| Production | Vault Transit `wrap-only` | SSH 私钥、Cloudflare Token | 需要秘密的执行当前不可用 |

DevKMS 是进程内临时密钥。控制面重启后无法恢复旧的开发密文，不用于持久化生产凭据。

## 6. 当前限制

- 当前没有凭据状态机、自动轮换、外部撤销或独立 execution grant。
- 重新保存会创建新的凭据 ID 并切换当前绑定，但不会替用户撤销目标主机上的旧公钥或 Cloudflare 上的旧 Token。
- SSH 证书、SSH 口令和 Worker Secret 不在当前凭据接口中。
- Go 运行时无法保证所有内存副本被立即清零；实现通过缩短作用域、避免落盘和擦除显式字节缓冲减少驻留时间。
- 备份、Vault 恢复材料和外部凭据轮换由部署者管理。
