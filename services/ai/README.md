# AI 异常解读

该包把规则扫描的结构化 Finding 交给可选 AI 网关，返回风险摘要、排序和排查建议。网关不可用时使用确定性的本地排序。

```go
analyzer, err := ai.New(ai.Config{
    Endpoint:            "https://ai-gateway.example.internal/v1/analyze",
    TokenFile:           "/run/secrets/ai-gateway-token",
    AllowedGatewayHosts: []string{"ai-gateway.example.internal"},
})
```

`Endpoint` 为空时进入离线模式。网关使用 HTTPS、固定主机 allowlist 和 token 文件；请求与响应有大小限制和超时。输入不包含凭据或完整命令行，输出只用于展示，不会直接执行操作。
