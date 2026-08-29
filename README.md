<div align="center">

# VPS Manager

**Linux VPS 管理项目的代码仓库。**

[![License: MIT](https://img.shields.io/badge/License-MIT-2ea44f.svg)](LICENSE)
![Go](https://img.shields.io/badge/Go-1.26-00ADD8?logo=go&logoColor=white)
![Node](https://img.shields.io/badge/Node.js-22.13%2B-339933?logo=nodedotjs&logoColor=white)

</div>

当前仓库包含 Go workspace、Web 依赖清单及代码质量工具配置，尚不包含可启动的服务或网页应用。

## 仓库结构

```text
services/   Go module 与依赖清单
web/        TypeScript 依赖及工具配置
go.work     Go workspace 定义
```

## 环境要求

- Go 1.26.6
- Node.js 22.13 或更高版本
- npm

安装 Web 依赖：

```powershell
npm --prefix web ci
```

当前没有启动命令。

## License

MIT © 2026 [0xmania](https://github.com/0xmania)
