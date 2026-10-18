# 哪吒统一管理平台

本项目以 Nezha Dashboard 为基础，将 Certimate 的完整证书功能迁入哪吒，并按 [完整集成方案](docs/DESIGN.md) 扩展集中 DNS、统一凭据、部署目标和资源授权。最终使用一个 Dashboard 进程、一个管理前端和一套哪吒账号。

当前完成范围为项目骨架：哪吒后端和管理前端已纳入同一仓库，提供统一构建、本地检查和 GitHub Actions CI。Certimate 证书业务及新增 DNS、凭据、授权、部署模块尚未迁入。

## 代码结构

```text
.
├── cmd/dashboard/       # Dashboard 入口、HTTP/RPC 控制层和生成资源
├── model/               # 哪吒现有数据模型
├── service/             # 哪吒现有业务服务
├── pkg/                 # 公共工具与基础组件
├── proto/               # Dashboard 与 Agent 的通信协议
├── integration/         # 集成验证工具与用例
├── web/admin/           # 唯一管理前端
├── script/              # 构建、生成与检查脚本
├── docs/                # 中文项目文档和上游来源说明
├── go.mod               # 仓库唯一 Go 模块
├── Makefile             # 统一开发入口
└── upstreams.lock.json  # 上游源码与公开主题版本基线
```

Go 模块暂沿用 `github.com/nezhahq/nezha`，以保留现有导入路径。后续业务实现分别放入 `internal/certificate`、`internal/dns`、`internal/credential`、`internal/authz` 和 `internal/deployment`；实现前不创建空目录。

证书业务直接迁入哪吒，不设置独立 `certimate` 目录、Go 模块、进程或登录入口。哪吒原有公开监控页面与主题继续保留。

## 本地构建

准备 Go 1.26.6、Node.js 26.12.0、npm、Python 3、make 和 C/C++ 编译器；完整检查另需 uv。工具版本与检查说明见 [开发指南](docs/DEVELOPMENT.md)。

```sh
make build
make run
```

`make build` 构建管理前端、获取并校验公开主题、生成 Swagger 文档，再将前端资源内嵌到 `dist/dashboard`。首次构建需要网络访问；无需本地 `upstream/` 目录。

`make run` 在本机启动 Dashboard，访问地址为 `http://127.0.0.1:8008/dashboard`。空数据库沿用哪吒初始账号 `admin` 和密码 `admin`，首次登录后应完成初始化并更改密码。

提交前运行完整本地检查：

```sh
make ci
```

CI 使用 `ubuntu-26.04` runner，运行与本地相同的检查入口，只检查和构建，不上传构建产物，不执行发布或部署。

## 开发与来源

- [开发指南](docs/DEVELOPMENT.md)：分支规范、命令和检查范围。
- [完整集成方案](docs/DESIGN.md)：最终集成目标与实施约束。
- [上游来源](docs/UPSTREAM.md)：固定版本、源码位置和许可证。

分支采用 `master` → `dev` → `feat/*`：功能分支从 `dev` 创建，合入 `dev` 验证后再合入 `master`。

根目录 [LICENSE](LICENSE) 保留哪吒许可证；管理前端许可证位于 [web/admin/LICENSE](web/admin/LICENSE)。
