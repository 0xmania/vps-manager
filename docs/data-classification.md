# 数据分类

| 数据 | 分类 | 当前落点 | 不进入 |
|---|---|---|---|
| SSH 私钥、passphrase、Cloudflare Token | S4 秘密 | 加密 Envelope；开发执行期间的短时内存 | 浏览器响应、URL、日志、Job、审计、AI |
| 控制面会话、WebSSH 票据 | S4 短期秘密 | 服务端摘要与受保护 Cookie | URL、日志、AI |
| 主机地址、系统用户、host key、Cloudflare account ID | S3 受限 | Repository、授权后的 API 响应、审计目标字段 | 未授权响应、AI 默认输入 |
| 命令输出、终端字节、进程证据 | S3 不可信内容 | 有大小上限的 Job 结果或终端通道 | HTML 注入、AI 指令区、无上限日志 |
| 固定命令 ID、Runbook 参数、Job 状态、部署元数据 | S2 运维元数据 | Repository 和结构化审计 | 可复用秘密字段 |
| 静态前端资源与健康状态 | S1 普通 | Web 与健康接口 | 无额外限制 |

新增 API 或审计字段时沿用最接近的数据类别；包含凭据值的字段按 S4 处理。
