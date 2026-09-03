# ADR-0001：部署与兼容范围

## 决策

平台用于少量自有 VPS 的单租户、自托管管理，不开放公网注册，不提供跨租户共享。目标主机使用 OpenSSH、systemd 与 POSIX shell，主要支持仍在安全支持期内的 Ubuntu LTS 和 Debian stable。

控制面、Web、Connector、PostgreSQL、Redis 和 Vault Transit 分开配置。默认拒绝回环、链路本地、云元数据和未配置的私网地址；私网目标由部署者显式配置 CIDR。

默认运行参数面向小规模实例，可按宿主资源调整任务和终端并发。

## 后果

当前数据模型按单租户运行，同时保留 installation 标识用于对象绑定。公共 SaaS、多租户、Windows 主机、Kubernetes 管理和任意源码构建不在当前范围内。
