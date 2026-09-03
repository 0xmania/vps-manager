# ADR-0004：AI 与 Cloudflare 边界

## AI

AI 接收规则引擎生成的结构化发现和有限证据摘要，返回固定 JSON Schema。AI 网关限制目标地址、请求大小和输出大小，不向模型提供 SSH、Vault、Cloudflare 或任务执行工具。AI 不可用时仍返回规则扫描结果。

## Cloudflare Workers

Worker 接口只接受预构建 ES module，不运行用户构建脚本。Provider 使用账号绑定的 API Token，不接受 Global API Key。

Control API 保存 Worker 版本、部署计划和 Provider 返回的状态。开发配置可执行 Provider；生产环境在 Token 秘密交接未接通时不执行发布。代码版本变化不回滚 KV、D1、R2 或 Durable Objects 数据。
