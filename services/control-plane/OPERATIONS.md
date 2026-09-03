# 运维与 Cloudflare Worker API

本文件记录运维接口。所有 API 均要求 Bearer 会话，并沿用现有 RBAC、审计、对象范围和 `Cache-Control: no-store` 策略。

## 预定义只读命令

`POST /api/v1/hosts/{hostID}/commands`

```json
{
  "commandId": "service_status_v1",
  "parameters": {
    "service": "nginx"
  }
}
```

允许的命令只有：

- `disk_usage_v1`：无参数；
- `listening_ports_v1`：无参数；
- `service_status_v1`：`service` 必须是 `nginx`、`ssh`、`docker` 或 `cron`。

请求不接受脚本、命令行、环境变量或未知参数。服务名先映射到服务端审核过的固定字面量，任何用户文本都不会进入远端 shell。执行前必须已固定 SSH host key、已配置加密 SSH 凭据，且队列开始和真正连接前都会复核会话权限与 Host 对象范围。

接口返回 `202 Accepted` 和异步 Job。成功后：

```json
{
  "type": "read_only_command",
  "state": "succeeded",
  "command": {
    "id": "service_status_v1",
    "parameters": { "service": "nginx" }
  },
  "commandResult": {
    "commandId": "service_status_v1",
    "stdout": "ActiveState=active\n",
    "stderr": "",
    "exitCode": 0,
    "durationMillis": 25,
    "truncated": false
  }
}
```

命令单次输出上限为 64 KiB，命令阶段最长 20 秒，同时受全局 Job 超时约束。超限会中断 SSH 连接并使 Job 失败，不会返回未标记的截断输出。`POST /api/v1/jobs/{jobID}/cancel` 可取消排队或运行中的任务。

## 规则式异常进程扫描

`POST /api/v1/hosts/{hostID}/anomaly-scans`

请求体必须是 `{}`。接口返回 `202 Accepted` 和 `process_anomaly_scan` Job。扫描器只采集 PID、父 PID、用户、CPU 百分比、存活秒数和进程短名称；不会采集命令行或环境变量，避免把令牌、密码等内容带回控制面。

成功结果：

```json
{
  "anomalyScan": {
    "observedAt": "2026-08-29T00:00:00Z",
    "engine": "rules_v1",
    "aiExecutionAllowed": false,
    "processesEvaluated": 120,
    "findings": [
      {
        "id": "sustained_high_cpu:123",
        "ruleId": "sustained_high_cpu",
        "title": "进程持续占用高 CPU",
        "severity": "high",
        "confidence": 0.82,
        "evidence": {
          "pid": 123,
          "user": "app",
          "processName": "worker",
          "cpuPercent": 96,
          "elapsedSeconds": 600
        },
        "falsePositiveNote": "编译、压缩、数据库维护和业务峰值可能产生相同行为……"
      }
    ]
  }
}
```

`rules_v1` 包括已知挖矿程序名、持续高 CPU、隐藏样式进程名和非 root 内核线程伪装。Finding 始终包含规则、最小化证据、严重度、置信度及误报说明。规则扫描完成后可以附加本地降级结果或经校验的 AI 解读。AI 只生成说明和排查建议，没有执行、取消、隔离或删除进程的权限。

## Cloudflare Worker 操作链路

Worker 资源当前采用全局会话范围；Host 限定会话会收到 `global_scope_required`。创建 deploy/rollback 计划本身不调用公网 API；只有显式启用 `VPSMGR_ENABLE_CLOUDFLARE_EXECUTION` 后，execute endpoint 才会调用 Cloudflare Provider。

### Worker

- `GET /api/v1/cloudflare/workers`
- `POST /api/v1/cloudflare/workers`
- `GET /api/v1/cloudflare/workers/{workerID}`

创建请求：

```json
{
  "name": "edge api",
  "accountId": "0123456789abcdef0123456789abcdef",
  "scriptName": "edge-api"
}
```

### API Token

- `GET /api/v1/cloudflare/workers/{workerID}/token`
- `POST /api/v1/cloudflare/workers/{workerID}/token`
- `DELETE /api/v1/cloudflare/workers/{workerID}/token`

写入请求为 `{"token":"..."}`。Token 使用现有凭据服务进行信封加密，并绑定 `workerID + tokenID` AAD；响应、审计和模型 JSON 只包含元数据。当前只有 `admin` 能管理 Token。

### 预构建模块版本

- `GET /api/v1/cloudflare/workers/{workerID}/versions`
- `POST /api/v1/cloudflare/workers/{workerID}/versions`

```json
{
  "moduleBase64": "ZXhwb3J0IGRlZmF1bHQge307",
  "contentType": "application/javascript",
  "entrypoint": "index.js"
}
```

只接受最多 256 KiB 的 UTF-8 JavaScript 模块；响应只返回 SHA-256、大小和版本元数据，不返回源码。基础秘密特征检测命中时拒绝上传，运行时秘密通过 Provider secret binding 注入。

### 部署与回滚计划

- `GET /api/v1/cloudflare/workers/{workerID}/deployments`
- `POST /api/v1/cloudflare/workers/{workerID}/deployments`

```json
{
  "versionId": "wver_...",
  "kind": "deploy"
}
```

`kind` 可为 `deploy` 或 `rollback`。计划要求对应模块版本及加密 Token 已存在，并原子更新 Worker 的 `desiredVersionId`。响应固定包含：

```json
{
  "state": "ready_for_provider",
  "providerExecutionAllowed": false
}
```

`ready_for_provider` 表示本地计划已生成，尚未调用公网 API。执行接口会记录 Cloudflare 返回的版本和部署标识；未启用 Provider 或调用失败时，计划不会被标记为线上成功。
