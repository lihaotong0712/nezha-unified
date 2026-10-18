# 开发指南

本指南适用于当前项目骨架。项目以哪吒为基础，使用根目录单一 Go 模块和 `web/admin` 管理前端；本地构建不依赖 `upstream/` 参考仓库。

## 环境要求

| 工具 | 要求 | 用途 |
|---|---|---|
| Go | 1.26.6，与 `go.mod` 一致 | 后端构建、静态检查和测试 |
| Node.js | 26.12.0，与 `.node-version` 一致 | 前端依赖安装、检查和构建 |
| npm | 使用 Node.js 配套版本 | 按 `web/admin/package-lock.json` 安装依赖 |
| Python | 3 | 构建与校验脚本 |
| make | 可用 | 统一开发入口 |
| C/C++ 编译器 | 支持本机 CGO 构建 | SQLite 等原生依赖与竞态检测 |
| uv | 可用，完整检查需要 | 运行固定版本 Ruff 和 ShellCheck，检查构建脚本 |

首次构建需要下载 Go/npm 依赖、公开主题及检查工具。后续构建复用本地缓存。不要将本机运行数据、配置中的密钥或依赖缓存提交到仓库。

## 分支流程

| 分支 | 用途 | 合并方向 |
|---|---|---|
| `master` | 稳定版本 | 接收经过验证的 `dev` |
| `dev` | 功能集成与验证 | 接收 `feat/*` |
| `feat/<名称>` | 单项功能开发 | 从 `dev` 创建，PR 合入 `dev` |

本次骨架开发分支为 `feat/project-skeleton`。后续开发开始前先检查工作树，保留与任务无关的本地修改。创建功能分支时，确保基于需要集成的 `dev` 提交。

## 常用命令

所有命令在仓库根目录执行。

| 命令 | 行为 |
|---|---|
| `make build` | 构建管理前端，准备公开主题和 Swagger 文档，构建 `dist/dashboard` |
| `make run` | 构建并在本机 `127.0.0.1:8008` 启动 Dashboard |
| `make dev-admin` | 启动管理前端开发服务器，支持前端热更新 |
| `make check` | 执行完整本地检查 |
| `make ci` | 执行与 GitHub Actions 相同的完整检查 |

前端开发时，在一个终端运行 `make run`，另一个终端运行 `make dev-admin`。按开发服务器输出的地址打开 `/dashboard`。开发服务器将 API、WebSocket 和 MCP 请求代理到 `127.0.0.1:8008`。

Dashboard 默认将运行数据写入 `data/`，配置路径为 `data/config.yaml`，SQLite 路径为 `data/sqlite.db`。空数据库初始账号和密码均为 `admin`；首次登录后完成初始化并修改密码。运行生成的配置可能包含密钥，不得提交。

## 提交前检查与 CI

提交 CI 前，先在本机运行：

```sh
make ci
```

检查范围包括：

- 使用 npm 锁文件安装管理前端依赖，执行 lint、测试和生产构建。
- 按固定 release 和 SHA-256 获取哪吒原有的五个公开主题，并将管理前端及公开主题嵌入 Dashboard。
- 使用固定版本 `swag v1.16.6` 生成 Swagger 文档。
- 检查 Go 格式，执行 `go vet`、带竞态检测的 Go 测试和后端构建。
- 使用 Ruff 检查 Python 脚本，使用 ShellCheck 检查协议生成脚本，使用 actionlint 检查 GitHub Actions 工作流。

任一步骤失败时，应处理失败原因并重新运行受影响检查；所有检查通过后再提交 CI。GitHub Actions 使用 `ubuntu-26.04` runner，执行同一入口。本阶段 CI 只验证构建和测试，不上传构建产物，不执行发布或部署。

本阶段检查不包含外部 Nezha Agent 双仓库压力测试，也不包含真实云服务商的签发、DNS 修改或证书部署联调。证书和新增 DNS 业务迁入后，需按实际功能补充验证。

当前通过 `make` 构建和运行；容器镜像及统一安装、升级入口尚未接入。

## 生成文件与构建产物

`dist/dashboard` 是本机可执行文件，版本信息使用当前功能版本和提交信息。前端依赖、构建目录、公开主题下载缓存及生成资源由构建入口管理，不手工编辑生成结果。

修改后端 API 注释后，通过统一构建入口重新生成 Swagger。修改前端依赖时同时更新 `web/admin/package.json` 和 `web/admin/package-lock.json`，继续使用 npm，不引入并行锁文件。

不要直接使用本地 `upstream/` 路径作为 Go replace、前端依赖或脚本运行依赖。从干净克隆开始的构建必须仅依赖仓库内源码和已固定的外部依赖。

## 后续业务迁移

后续按业务职责直接扩展哪吒：

| 目标位置 | 职责 |
|---|---|
| `internal/certificate` | Certimate 证书资产、工作流、签发、续签、部署、通知和运行记录 |
| `internal/dns` | 集中 DNS 与 DDNS 协作 |
| `internal/credential` | 统一凭据与用途解析 |
| `internal/authz` | 哪吒用户与资源授权 |
| `internal/deployment` | 部署目标与 Agent 调用协作 |

资源引用、凭据解析、授权、生命周期、错误与审计的基础接口已定义，见 [公共契约](CONTRACTS.md)。具体业务模块按该契约实现，不在各模块内另建密钥存储或独立授权入口。证书页面直接迁入 `web/admin`，复用哪吒路由、登录会话和 API。不得新增独立 Certimate 应用、PocketBase 登录入口或第二套管理前端。
