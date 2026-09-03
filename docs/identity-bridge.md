# Web 身份到控制面的签名桥接

生产控制面不接受开发 bootstrap。Web 在平台托管登录成功后，为当前用户生成 30 秒有效、Ed25519 签名、单次消费的身份断言；控制面校验签名、`iss`、`aud`、`kid`、时间窗口、角色与主机范围后，签发最长 8 小时且可撤销的随机会话。断言不能直接调用业务 API。

## 密钥与配置

使用独立 Ed25519 密钥。私钥 JWK 注入 Web 的秘密环境，控制面配置 32 字节原始公钥的 Base64。

Web 必须同时配置：

```text
CONTROL_PLANE_IDENTITY_ISSUER=https://<private-site-origin>
CONTROL_PLANE_IDENTITY_AUDIENCE=vps-manager-control-plane
CONTROL_PLANE_IDENTITY_KEY_ID=web-bridge-main
CONTROL_PLANE_IDENTITY_PRIVATE_JWK=<Ed25519 private JWK JSON secret>
CONTROL_PLANE_IDENTITY_BINDINGS_JSON=<exact user/email bindings JSON>
```

绑定使用精确键，不提供默认管理员：

```json
{
  "user:<platform-user-id>": {
    "role": "admin",
    "allHosts": true,
    "hostIds": []
  },
  "email:auditor@example.com": {
    "role": "auditor",
    "allHosts": false,
    "hostIds": ["host_example"]
  }
}
```

控制面必须同时配置：

```text
VPSMGR_DEV_MODE=false
VPSMGR_IDENTITY_ISSUER=https://<private-site-origin>
VPSMGR_IDENTITY_AUDIENCE=vps-manager-control-plane
VPSMGR_IDENTITY_KEY_ID=web-bridge-main
VPSMGR_IDENTITY_PUBLIC_KEY=<raw-Ed25519-public-key-base64>
```

生产身份字段缺失、密钥不合法或用户没有精确绑定时，Control API 拒绝断言。角色或主机范围变更后应撤销已有控制面会话；仅修改绑定不会自动终止旧会话。

## 安全边界

- Web 私钥只能签发身份断言，不能读取 Vault 或 SSH/Cloudflare 凭据。
- 控制面只保存 bearer token 的 SHA-256 摘要；身份断言的 `jti` 也只以摘要保留到过期。
- `alg` 固定为 `EdDSA`，类型固定为 `VPSMGR+JWT`；未知 claims、重复主机范围、混合 `allHosts` 范围、超过 60 秒的断言均拒绝。
- BFF 按用户、角色和范围缓存控制面会话，不把 bearer token返回浏览器。
- 身份桥接不提供新近 MFA。当前生产配置同时关闭需要解密凭据的 WebSSH、Runbook、SSH Job 和 Cloudflare Provider 执行。

开发环境可不配置上述字段，继续使用只绑定回环环境的 `CONTROL_PLANE_DEV_BOOTSTRAP`。只要任一生产字段出现，Web 就不会降级使用开发身份。
