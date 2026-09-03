# 权限模型实现说明

完整 Permission 列表见 [`permission-matrix.md`](permission-matrix.md)。

## 1. 模型概述

控制面使用 RBAC，并在主机相关操作上叠加对象 scope 与运行状态：

```text
Allow = authenticated
     && session_valid
     && role_has_permission
     && resource_in_scope
     && resource_state_allows_action
```

需要 SSH 凭据或 host key 的处理器在业务逻辑中追加对应检查。

## 2. 角色含义

| 运行时角色 | 能力边界 |
|---|---|
| `viewer` | 查看主机、Job 和 Worker 元数据 |
| `operator` | 管理主机，运行快照、固定命令、扫描、终端和 Runbook |
| `admin` | 管理凭据和 host key，执行 Cloudflare Provider，查看审计 |
| `auditor` | 查看主机、Job、Worker 元数据和审计 |

角色只给出 Permission 集合。会话还可以用 `hostIds` 限定 VPS 对象范围；Cloudflare Worker 接口要求 `allHosts=true`，不会从某台主机的 scope 推导全局权限。

## 3. 授权检查位置

- 路由中间件验证 Bearer 会话和 Permission。
- 主机相关处理器检查会话 scope，再读取或修改对象。
- Job 执行前重新检查发起会话；host key 和当前凭据由执行处理器检查。
- WebSSH 票据绑定用户、会话、主机和凭据，连接期间周期性重新授权。
- Runbook 执行要求当前会话与预览会话一致，并核对预览生成的 scope digest。
- Cloudflare Worker 使用全局 scope；Token 管理和 Provider 执行分别要求管理员权限。

## 4. 当前不包含

当前权限系统不包含 OIDC、fresh MFA、审批票据、break-glass、用户管理、角色分配、审计导出、终端录制、Worker Secret 或自由命令。生产环境也没有凭据 secret handoff，因此需要解密的执行接口不可用。

新增能力时同步更新运行时 Permission 常量和 [`permission-matrix.md`](permission-matrix.md)。
