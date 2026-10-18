# Certimate 上游盘点与迁移表

本文以 `upstreams.lock.json` 锁定的 Certimate `v0.4.35`（`884b353c7e2a5331ca24ff61bc18dea291cd8d91`）为盘点基线。源码参考克隆位于被忽略的 `upstream/certimate/`，不参与项目构建。表中的目标位置遵循 [`DEVELOPMENT.md`](DEVELOPMENT.md) 和 [`DESIGN.md`](DESIGN.md)；实际迁移时应维持现有 Nezha 模块结构，不复制上游独立应用边界。

## 当前实现状态（验收口径）

- 证书基础资产已接入：支持证书材料的加密存储、元数据查询、下载/私钥揭示授权和审计；这部分不包含 ACME 签发、续签、部署或通知 provider。
- 工作流已接入 `internal/workflow` 的最小持久化纵切面：工作流、版本和运行记录使用 GORM 存储，提供草稿/发布、启停、运行快照、状态转换和 Dashboard HTTP API。该能力是版本与运行历史基础，不是完整 Certimate workflow engine。
- DNS 作为独立资源已接入 Cloudflare 纵切面：Zone binding GORM store、授权 DNS 服务、记录读取和记录 CRUD API，以及 `/dashboard/dns` 页面已接入统一数据库、授权器、凭据存储和审计记录器。DNSPod、EdgeOne、现有 DDNS worker、DNS-01 challenge 和调度器尚未接入。
- 尚未完成 Certimate 全量迁移：没有迁移全部节点、ACME 签发、部署和通知 provider、运行节点输出/日志、持久调度、崩溃恢复、离线补发或旧 PocketBase 数据。
- 尚未进行真实 Cloudflare、DNSPod 或 EdgeOne 账号联调；真实部署副作用也未验证。platform key 的备份、恢复和轮换演练尚未完成。

以下章节中的节点、provider、页面和数据清单是上游迁移基线与目标验收范围，不能据此推断对应能力已经实现。

## 迁移原则

- 保留 Certimate 证书业务的可观察行为、工作流图格式、节点语义、提供商能力、运行结果、证书与日志数据，以及上游许可证和版权声明。
- 将 PocketBase 替换为哪吒内部存储/API/认证。不能把 PocketBase 超级用户、访问规则、HTTP API、请求钩子或独立登录状态带入运行时。
- `access` 中的密钥配置迁入统一凭据中心；业务配置改为稳定凭据引用。对旧工作流内嵌配置提供显式迁移与兼容读取，完成数据迁移后再移除兼容层。
- 统一用户和资源授权、审计、Dashboard 生命周期及后台任务调度。每次工作流执行固定运行身份、工作流版本、凭据版本和授权上下文。
- 保留全部上游证书功能与提供商。新增哪吒 Agent 部署能力作为额外提供商，不以它替代上游 SSH、面板或云平台部署方式。

## 后端功能与数据映射

| 能力/数据 | Certimate 来源 | 建议目标 | 迁移处理与依赖 |
|---|---|---|---|
| 证书领域类型、校验、PEM/X.509 解析、密钥算法 | `internal/domain/certificate.go`、`internal/domain/meta.go` | `internal/certificate/domain` | 保留证书来源、SAN、颁发者、有效期、撤销/续签状态；与 Nezha 资源 ID 显式区分或映射。下载、上传、吊销和删除均走统一授权。 |
| 证书记录 `certificate` | `internal/domain/certificate.go`；`internal/repository/certificate.go` | `internal/certificate` 存储层 | SQLite/PocketBase 查询改为项目选定的内部存储。证书 PEM 和私钥属于敏感资产，需加密/访问审计；上传时校验证书与私钥匹配及 SAN。 |
| ACME 账户 `acme_accounts` | `internal/domain/acme_account.go`；`internal/repository/acme_account.go` | `internal/certificate/acme` | 保留 CA、邮箱、账户 URL、目录 URL 与账户私钥/资源对象；私钥应作为受保护证书资产存储，不得经普通列表 API 返回。 |
| 外部凭据 `access` | `internal/domain/access.go`；`internal/repository/access.go`；`internal/domain/provider.go` | `internal/credential` + 证书/提供商绑定 | 上游配置结构可用于类型和表单盘点；密钥迁入统一凭据记录，执行时按作用域解析。DNS 验证、CA、部署、通知的凭据用途必须分别授权。 |
| 工作流定义 `workflow` | `internal/domain/workflow.go`；`internal/repository/workflow.go` | `internal/workflow` | 当前已接入最小持久化、版本保存/发布、启停和 Dashboard API；完整图编辑器、触发器、Cron、调度更新和全部节点语义仍待迁移。 |
| 工作流运行 `workflow_run` | `internal/domain/workflow_run.go`；`internal/repository/workflow_run.go` | `internal/workflow` | 当前已接入运行时定义快照、触发身份、状态、错误和状态转换；节点输出/日志、持久队列、恢复、重试和取消副作用仍待迁移。 |
| 节点输出 `workflow_output`、节点日志 `workflow_logs` | `internal/domain/workflow_output.go`、`workflow_log.go` 及对应 repository | `internal/certificate/run` | 保留可查询的节点输出、变量作用域、日志顺序与敏感字段脱敏；授权筛选需在分页/统计前完成。 |
| 设置 `settings` | `internal/domain/settings.go`；`internal/repository/settings.go`；`internal/settings` | `internal/certificate/settings`，平台通用项进入 Nezha 配置 | 区分证书模块业务设置与独立应用外观/账户/持久化设置。设置缓存刷新由内部服务显式完成，不依赖请求钩子。 |
| 仪表盘统计 | `internal/statistics`、`internal/repository/statistics.go` | 证书服务查询 + Nezha 原生页面 | 迁移到授权后的内部查询，覆盖证书总量/即将过期/已过期与工作流总量/启用数；复用哪吒统一导航和仪表盘。 |
| 预设与通知/脚本模板 | `ui/src/pages/presets/`、`ui/src/components/preset/` 及相关本地化资源 | `web/admin` 证书预设页面/API | 迁移模板内容和导入导出行为；默认模板不应作为可写全局用户数据重复保存。脚本模板导入和导出需审计。 |
| 初始化、迁移和持久化 | `migrations/`、`internal/app/`、`internal/settings/` | `internal/certificate/migrations` + Dashboard 初始化生命周期 | 审计全部 PocketBase schema upgrade/initialize 迁移；制定旧库导入工具、版本检查、备份恢复和可重试策略。不能只迁最后 schema 而遗漏历史数据转换。 |

### 设置键

键常量定义于 `internal/domain/settings.go`。迁移时需逐键决定保留、映射或由平台公共能力替代：

| 上游键 | 内容/来源 | 迁移去向 |
|---|---|---|
| `emails` | 联系邮箱设置 | 证书模块设置；与 Nezha 用户/通知接收人区分。 |
| `notifyTemplate` | 通知模板 | 证书预设/通知模板服务。 |
| `scriptTemplate` | 部署脚本模板 | 证书预设；导入/导出和执行权限单独审计。 |
| `sslProvider` | 默认 CA、CA 配置、超时 | 证书模块设置；其中 secret 字段迁入统一凭据。 |
| `persistence` | 证书过期预警天数、证书保留天数、运行记录保留天数 | 证书模块保留策略；与统一任务/审计保留策略明确边界。 |

`Account`、`Appearance`、`Diagnostics`、`About` 等上游设置页面并非以上设置 collection 键，分别由 Nezha 统一账号、主题、诊断和版本信息替代；PocketBase 数据库/备份的 `Persistence` 页面也不能直接照搬为 Nezha 数据库配置。

上游核心集合名以领域常量为准：`access`、`acme_accounts`、`certificate`、`workflow`、`workflow_run`、`workflow_output`、`workflow_logs`、`settings`。PocketBase 自带 superusers/auth 表属于独立身份体系，不迁入；如需导入旧安装数据，只迁与证书业务相关的记录，并将所有者映射到哪吒用户或平台服务身份。

## 工作流节点与执行器（迁移目标，当前未全部实现）

节点类型定义于 `internal/domain/workflow.go`，画布和表单位于 `ui/src/components/workflow/designer/`。以下是需要兼容的 13 种节点类型及嵌套 `Blocks` 结构，属于迁移目标清单：

| 节点类型 | 上游行为/来源 | 迁移关注点 |
|---|---|---|
| `start`、`end` | 图的入口/终点 | 保留图校验、导入导出与旧图兼容。 |
| `condition`、`branchBlock` | 条件表达式和分支容器 | 保留表达式语法、变量作用域和分支顺序；禁止以权限不足读取到的资源参与条件运算。 |
| `tryCatch`、`tryBlock`、`catchBlock` | 异常边界及嵌套块 | 保留错误传播、捕获范围、取消和运行历史展示。 |
| `delay` | 定时等待 | 等待状态应持久化或可恢复，不能只依赖进程内 sleep。 |
| `bizApply` | 申请/续签证书及 ACME 验证 | 保留 HTTP-01、DNS-01、TLS-ALPN 等上游挑战行为、CA 配置、密钥算法、域名/IP、联系人、有效期与优选链；解析最终域名集合后检查授权。 |
| `bizUpload` | 上传已有证书 | 校验证书链、私钥匹配、SAN 和目标权限；私钥日志/输出必须脱敏。 |
| `bizMonitor` | 检查证书有效性并输出证书变量 | 保留有效期、域名、SAN 等输出变量；对其引用的证书资源实施统一授权。 |
| `bizDeploy` | 部署到上游部署提供商 | 凭据引用、域名和目标范围授权；增加 Nezha Agent 持久部署任务适配器，区分“签发成功”和“已部署”。 |
| `bizNotify` | 调用通知提供商 | 保留模板和通知语义；秘密字段解析与日志脱敏交给统一凭据服务。 |

证书来源值为 `request` 和 `upload`；工作流触发器为 `manual` 和 `scheduled`。运行状态枚举必须原样兼容旧记录：

| 运行状态 | 含义 | 迁移关注点 |
|---|---|---|
| `pending` | 已创建、等待执行 | 持久队列恢复时防止重复创建副作用。 |
| `processing` | 执行中 | Dashboard 非正常退出后要核对节点/外部操作，再决定恢复、失败或人工核验。 |
| `succeeded` | 执行成功 | 保留结束时间、输出和生成证书引用。 |
| `failed` | 执行失败 | 保留错误分类与节点日志，敏感字段脱敏。 |
| `canceled` | 已取消 | 取消意图和停止后续副作用需持久化；已提交的外部操作不能假定回滚。 |

上游运行引擎与分发器主要位于 `internal/workflow/engine/`、`internal/workflow/dispatcher/` 和 `internal/workflow/`。当前仓库只完成 `internal/workflow` 的持久化、版本、发布和运行历史基础；节点执行器、调度、统一取消/超时、并发限制、持久队列/恢复、事件审计以及 Dashboard 优雅停止后的任务收敛仍待实现，不能把当前 API 基础表述为完整执行引擎。

## 提供商与适配器盘点

Certimate 的注册式适配器应按能力完整迁移。下列数字是锁定提交中对应目录的 `sp_*.go` 文件数，表示注册适配器源文件数，不等同于 UI 项数或最终支持的 API 操作数。全量逐项 ID 与配置字段应以各 `sp_*.go`、`internal/domain/provider.go` 和对应 `ui/src/components/access/forms/` / `workflow/designer/forms/` 为准。下表是迁移目标；当前仅完成统一凭据边界和 DNS Cloudflare 纵切面，不能据此宣称表中 provider 已可用。

| 提供商类别 | 来源目录 | 基线数量 | 迁移处理 |
|---|---|---:|---|
| DNS-01 验证 | `internal/certacme/certifiers/` 中 DNS challenge 实现 | 需按 `ACMEDns01Registries` 注册项清点；目录总计 77 个 `sp_*.go`，其中也包含 HTTP-01 实现 | 全量保留，配置引用统一凭据；与集中 DNS Zone 资源授权协作，但不把 DNS-01 provider 等同于完整 DNS 记录管理 API。 |
| HTTP-01 验证 | 同上，`ACMEHttp01Registries` 注册项 | 包含在上述 77 个文件内 | 保留 FTP/SSH/本地目录等验证方式及其文件/主机安全边界；长远可复用 Agent 执行能力。 |
| CA / ACME 服务 | `internal/certacme/certifiers/` 与 `internal/certacme/account.go` | 从 CA provider registry 单独生成精确清单 | 保留 CA、EAB、账户注册/复用、目录端点和账户生命周期；不混用 CA 账户凭据与 DNS 验证凭据。 |
| 证书部署 | `internal/certmgmt/deployers/` | 161 个 `sp_*.go` 文件 | 全量保留上游适配；凭据转统一引用。追加 `Nezha Agent` 部署器，持久化任务并报告主机侧核验状态。 |
| 通知 | `internal/notify/notifiers/` | 10 个 `sp_*.go` 文件 | 全量保留提供商、模板变量和发送结果；通知只允许使用授权的通知凭据。 |
| 凭据配置表单/选择器 | `ui/src/components/access/`、`ui/src/components/provider/` | 每种 provider 对应一个或多个表单/选择组件 | 保留类型字段和高级参数；改为读写统一凭据 API，并按用途过滤可选项。 |

**数量口径待自动化**：DNS/HTTP/CA 必须按 `ACMEDns01Registries`、`ACMEHttp01Registries`、CA registry 中的 `MustRegister` 调用去重统计，不能以文件数直接声称提供商数量。实现阶段应生成并提交 registry ID 清单或测试断言，以防只迁目录遗漏注册实现。

## 前端页面与接口

上游路由定义于 `ui/src/routers/index.tsx`；认证、导航和所有 PocketBase repository 均是替换边界。迁入唯一管理前端 `web/admin`，使用 Nezha 登录会话、路由、导航、权限、主题、API 客户端、错误处理和国际化。工作流设计器应保留上游画布行为，不引入第二套应用壳。

| 上游路由/页面 | 主要业务 | 哪吒目标 |
|---|---|---|
| `/` | Dashboard 统计 | 合并到哪吒原生仪表盘或证书概览区。 |
| `/accesses`、`/accesses/new` | 凭据列表/新增 | 凭据中心中的证书提供商凭据视图；不保留单独 Access 数据库。 |
| `/certificates` | 证书列表、详情、下载、上传、吊销/删除 | 证书管理列表与详情；下载/私钥操作单独授权并审计。 |
| `/workflows`、`/workflows/new` | 工作流列表/新建 | 证书工作流列表和创建页。 |
| `/workflows/:id/design` | 图形化工作流设计 | 工作流设计器原生路由，保留图 JSON 与完整节点表单。 |
| `/workflows/:id/runs` | 运行历史、日志、输出、取消 | 原生运行记录/详情，授权过滤并脱敏。 |
| `/presets` | 工作流、通知和脚本模板 | 证书预设页面。 |
| `/settings/*` | Account、Appearance、SSL Provider、Persistence、Diagnostics、About | SSL/证书业务设置并入系统设置；Account/Auth、主题、持久化、诊断和 About 改由 Nezha 实现或由平台公共能力替代。 |
| `/login` | PocketBase 登录 | 删除并复用 Nezha 登录；不保留独立超级用户会话。 |

前端 API 需要覆盖证书、ACME 账户、凭据引用、工作流草稿/发布/启停/运行/取消、运行记录/日志/输出、预设和证书设置。上游当前直接使用 PocketBase collection、批量操作和实时订阅；改造时明确 REST API 的分页、排序、筛选、错误结构和事件刷新契约，不能让浏览器持有 PocketBase admin token。

## 统一平台替换边界

| 上游耦合 | 替换为 | 接入阶段 |
|---|---|---|
| PocketBase app、collections、repository 与 migrations | Nezha 模块内部存储/API；旧库导入迁移器独立执行 | 先确定数据迁移和 ID 映射，再迁领域服务。 |
| PocketBase superuser 登录、访问规则和自动 owner 字段 | Nezha 用户会话 + `internal/authz` | 任何 API、列表、下载、后台运行入口都使用同一策略。 |
| PocketBase record hooks | 应用服务事务、显式事件/outbox、调度器更新 | 工作流/设置写入后可靠更新任务，支持失败重试和状态核对。 |
| PocketBase cron 与进程内 workflow scheduler | Dashboard 模块生命周期及持久调度/任务服务 | 统一启动、重载、停止、取消和崩溃恢复。 |
| `access` 内联密钥 | `internal/credential` 加密存储与运行时解析 | 凭据引用和用途授权先于真实副作用迁移。 |
| Certimate 独立账户和资源权限 | Nezha user、资源授权与审计 | 旧 owner 按映射表转换，未映射数据必须报告，不得静默提升为管理员可执行任务。 |
| SSH/远程执行器 | 仍保留上游提供商；新增 Nezha Agent 内部部署适配器 | Agent 路径走持久部署任务和目标授权，不伪装 SSH 凭据。 |
| PocketBase 实时订阅 | Nezha API 轮询/事件通道 | 先定义前端刷新与任务状态契约，再替换界面数据源。 |

## 建议实施次序与验收

1. 冻结资源 ID、凭据引用、授权上下文、错误/审计结构和模块生命周期接口。
2. 生成锁定提交的实体/collections、节点类型、provider registry ID、设置键、路由/API 清单；为旧工作流图和 provider 配置保存 fixtures。
3. 实现证书/ACME 数据模型、PocketBase 导入与 ID/关系映射，先覆盖证书列表、详情和安全下载。
4. 迁移凭据引用与 provider registry；先用 HTTP mock 验证 DNS challenge 和 CA 账户，再逐类覆盖部署、通知提供商。
5. 迁移图模型、全部 13 种节点、执行器、运行日志和取消/恢复；保证旧 graph fixture 可解析并可重新保存。
6. 接入统一授权、工作流持久调度与 Nezha Agent 部署，再迁移完整管理界面和路由。
7. 验证迁移中断重试、备份恢复、撤权后不再触发副作用、密钥/私钥不出现在 API 与日志、列表统计先授权过滤、Dashboard 优雅停止和任务恢复。

范围验收至少包括：锁定版本所有 collection/schema migration；所有 `WorkflowNodeType` 注册值；所有 DNS-01、HTTP-01、CA、部署和通知 registry ID；全部页面与关键操作；工作流旧图 fixture；证书、ACME 账户、凭据、运行和输出的关联迁移；授权、审计、脱敏和真实副作用 mock。此清单是迁移基线，不代表实现已经完成。

## 上游来源定位

| 盘点对象 | 上游位置 |
|---|---|
| 领域模型与 provider ID | `internal/domain/` |
| 存储访问 | `internal/repository/` |
| schema 历史与初始化 | `migrations/`、`migrations/snaps/` |
| ACME 账号和挑战 | `internal/certacme/` |
| 部署/通知提供商 | `internal/certmgmt/deployers/`、`internal/notify/notifiers/` |
| 工作流图、执行器、调度 | `internal/workflow/`、`internal/scheduler/`、`internal/app/scheduler.go` |
| PocketBase hooks | `internal/workflow/pbhook.go`、`internal/settings/pbhook.go` |
| API 路由和 handler | `internal/rest/routes/`、`internal/rest/handlers/` |
| 前端路由和页面 | `ui/src/routers/index.tsx`、`ui/src/pages/` |
| 工作流画布与节点表单 | `ui/src/components/workflow/designer/` |
| 凭据/provider 表单 | `ui/src/components/access/`、`ui/src/components/provider/` |
| 凭据 API repository | `ui/src/repository/` |
