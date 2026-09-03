# ADR-0002：身份与会话边界

## 决策

Web 层使用服务端会话，并通过 Ed25519 签名的短时身份断言连接 Control API。断言绑定 issuer、audience、jti 和会话；Control API 再按角色、权限和对象 scope 授权。

浏览器会话使用 HttpOnly、SameSite Cookie，并同时受空闲和绝对过期时间限制。注销会撤销会话；终端使用另一个短时单次票据。

当前身份桥接用于开发和受控自托管环境。OIDC、二次认证和 break-glass 尚未实现，因此文档和界面不宣称这些能力可用。
