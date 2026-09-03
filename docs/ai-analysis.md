# AI 异常解读

异常扫描以规则结果为准，AI 负责整理风险顺序、解释原因并给出排查建议。

## 流程

1. 控制面完成规则扫描。
2. 适配层发送结构化 Finding；不发送 SSH 私钥、Cloudflare Token、环境变量或完整命令行。
3. 网关返回摘要、排序、核验步骤和建议。
4. 网关未配置、超时或返回无效数据时，使用本地规则排序，扫描任务仍正常完成。

模型没有 SSH、Cloudflare 或 Runbook 工具。需要实际操作时，用户继续使用已有的命令模板和 Runbook。

## 配置

- `VPSMGR_AI_GATEWAY_ENDPOINT`
- `VPSMGR_AI_GATEWAY_ALLOWED_HOSTS`
- `VPSMGR_AI_GATEWAY_TOKEN_FILE`
- `VPSMGR_AI_GATEWAY_TIMEOUT`
- `VPSMGR_AI_GATEWAY_MAX_REQUEST_BYTES`
- `VPSMGR_AI_GATEWAY_MAX_RESPONSE_BYTES`

不配置 endpoint 时自动使用本地排序。
