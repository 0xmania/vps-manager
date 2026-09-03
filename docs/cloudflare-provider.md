# Cloudflare Workers Provider Adapter

实现位于 `services/cloudflareprovider`。它是控制面执行 Cloudflare Workers 真实发布动作时使用的窄接口，不是通用 Cloudflare HTTP 客户端。

## 已实现能力

- 仅连接固定官方基址 `https://api.cloudflare.com/client/v4`；生产构造函数没有自定义 URL 参数。
- 仅发送 `Authorization: Bearer <API Token>`；不支持 Basic、`X-Auth-Key`、`X-Auth-Email`，并拒绝常见 Global API Key 形态。
- `ValidateAccess` 先验证用户级或账户级 Token 为 `active`，再读取配置的 Account，并严格比对返回的 Account ID。
- `UploadVersion` 只接收已经构建好的单文件 ES module，使用 multipart Version Upload API 创建真实版本，并返回 Cloudflare Version ID。
- `DeployVersion` 创建 100% 流量 Deployment，轮询具体 Deployment，直到其只引用预期 Version ID；返回真实 Deployment ID。
- `Rollback` 先读取部署历史，确认目标 Version 曾经部署且不是当前 100% 活跃版本，然后创建新的 100% Deployment。它不会自动使用 `force=true` 绕过绑定不兼容保护。
- 所有变更请求必须携带受限格式的幂等键。客户端按“动作 + 脚本 + 幂等键 + 请求指纹”合并并发/重复请求、拒绝同键不同载荷，并转发 `Idempotency-Key` 请求头。
- 关闭环境代理和 HTTP 重定向，启用 TLS 1.2 以上、请求超时、响应上限、模块上限、轮询总时限。
- 错误只保留分类、HTTP 状态和数值型 Provider code；不会包含 Token、响应正文、请求正文或 URL 查询。

Cloudflare 的安全模型要求 Token 至少具有目标账户的 `Workers Scripts Write` 权限。Token 验证接口不会返回调用者的完整有效权限集合，因此适配器能在预检阶段证明 Token 有效且账户范围正确；实际写权限最终由 Version Upload / Deployment API 判定，HTTP 403 会归类为 `permission` 并失败关闭。

## 控制面集成边界

开发控制面已接入 Provider，入口为 `POST /api/v1/cloudflare/workers/{workerID}/deployments/{deploymentID}/execute`。它默认关闭，只有同时满足以下条件才执行：

1. `VPSMGR_ENABLE_CLOUDFLARE_EXECUTION=true`；
2. 当前 runtime 具备 secret execution 能力；
3. Worker 已保存加密 Token，目标 deployment 已处于 `ready_for_provider` 状态；
4. Provider factory 可用且请求通过现有 RBAC、对象范围和审计校验。

开发模式会在 Dev KMS 边界内打开 Token，先执行 `ValidateAccess`。deploy 会上传预构建模块并发布真实 Provider Version；rollback 只使用已经记录的 Provider Version。成功后保存 Provider Version ID、Deployment ID 和状态，错误只保存安全分类。

生产配置把 Token 封装并持久化在 API 一侧，部署器使用独立的 unwrap-only 身份。两者之间的单 Job secret handoff 尚未接通；当前生产控制面只有 Vault `wrap-only` 身份，`secretExecution=false`，execute endpoint 因此拒绝执行 Provider 动作。

包内幂等缓存是单进程有界缓存，重启或多副本之间不共享。控制面保存部署记录；`Idempotency-Key` 请求头不被视为跨重启状态存储。

## 明确限制

- 不做 TypeScript/JavaScript 构建、打包、依赖安装或源码执行。
- 当前只上传一个 ES module，不接受绑定、Secret、Route、KV、D1、R2 或 Durable Object 变更。
- 不接受任意 Provider URL，也不支持 Cloudflare Global API Key。
- “部署完成”表示 Cloudflare 能按 Deployment ID 返回，且内容为目标 Version 的 100% 流量配置；这不代表应用已经通过运行时健康检查。
- 回滚范围受 Cloudflare 返回的部署历史限制；绑定或底层资源发生不兼容变化时，回滚会失败，不会强制越过 Provider 保护。
- 仓库不包含真实 Cloudflare 账户的发布结果或应用级健康检查。

## 官方接口依据

- Token 验证：<https://developers.cloudflare.com/api/resources/user/subresources/tokens/methods/verify/>
- Account 读取：<https://developers.cloudflare.com/api/resources/accounts/methods/get/>
- Version Upload：<https://developers.cloudflare.com/api/resources/workers/subresources/scripts/subresources/versions/methods/create/>
- Deployment 创建：<https://developers.cloudflare.com/api/resources/workers/subresources/scripts/subresources/deployments/methods/create/>
- Deployment 列表：<https://developers.cloudflare.com/api/resources/workers/subresources/scripts/subresources/deployments/methods/list/>
- Workers 回滚约束：<https://developers.cloudflare.com/workers/versions-and-deployments/rollbacks/>
