# 公共资源、凭据、授权与生命周期契约

本文面向 DNS、证书、凭据、授权和部署模块的实现者，定义这些模块共用的 Go 类型、调用边界和失败行为。契约以 [完整集成方案](DESIGN.md) 为依据。

当前代码已经实现公共类型、结构校验、授权调用保护、密钥输出脱敏、资源注册、授权策略、凭据加密存储、证书资产服务、DNS Zone binding 与记录服务、版本化工作流运行记录、审计持久化和模块生命周期运行器。`internal/resource`、`internal/authz`、`internal/credential`、`internal/certificate`、`internal/dns`、`internal/workflow` 和 `internal/audit` 均有 GORM/SQLite 适配；Dashboard 已接入证书、DNS 和工作流纵切面的 HTTP API 及生产依赖组装。DNS 运行时目前仅装配 Cloudflare；工作流只完成最小持久化、版本/发布和运行历史基础。DNSPod、EdgeOne、完整 Certimate 迁移、节点执行器及生产部署副作用仍待接入和验证。现有哪吒接口、数据库表、ID 编码及认证行为保持原有契约。

## 包与依赖方向

| 包 | 提供的边界 |
|---|---|
| `internal/resource` | 资源类型、稳定引用、所有权及生命周期元数据 |
| `internal/authz` | 执行身份、动作、解析后的名称范围、授权接口及 `Check` |
| `internal/credential` | 凭据引用、元数据、用途绑定、密钥解析和加密存储接口 |
| `internal/lifecycle` | 模块 `Init/Start/Stop` 接口及有序运行器 |
| `internal/platformerr` | 可安全输出的错误码、错误结构和 HTTP 状态映射 |
| `internal/audit` | 审计记录结构和持久化接口 |

这些包不导入 `model`、`service/singleton`、Gin、GORM 或 PocketBase。Dashboard 组装具体实现，将依赖通过模块构造函数注入；业务模块不反向导入 Dashboard 控制器，也不通过全局变量寻找凭据或授权服务。

## 资源引用与所有权

跨模块引用使用 `resource.Ref`：

```json
{"kind":"server","id":"18446744073709551615"}
```

`kind` 与 `id` 共同确定身份。相同 ID 的证书和凭据是不同资源。当前类型包括用户、主机、API Token、域名、DNS Zone、DNS 记录、DDNS 绑定、证书、工作流、运行、凭据和部署目标。

- 用户、主机和 API Token 保留哪吒非零 `uint64` 主键，以规范十进制字符串传递。使用 `resource.Native` 转换；`0`、前导零、符号和溢出值均被拒绝。跨模块契约不使用 `idcodec` 的展示值。
- 其他资源保留权威存储的不透明 ID，区分大小写，不生成第二套可独立修改的 ID。ID 长度为 1～255 字节，必须是有效 UTF-8，不含空白、控制字符、冒号或路径分隔符。
- 厂商 Zone ID、记录 ID 和云账户标识由业务模块存储映射。授权入口必须通过平台引用查出真实账户、Zone 和记录，不能直接信任客户端提交的厂商 ID。
- `Metadata.OwnerID` 指向现有哪吒用户，JSON 使用字符串。`0` 不表示管理员。所有权和跨模块资源状态由统一资源注册数据维护；业务存储只引用或投影这些数据。
- `Revision` 为资源配置版本；`CreatedAt`、`UpdatedAt`、`DeletedAt` 使用 UTC。具体事务及版本递增由权威存储实现。

资源状态为 `pending`、`active`、`disabled`、`deleted`。跨存储关联和授权建立完成前保持 `pending`；只有 `active` 且未软删除的资源可以进入执行路径。`Metadata.Executable` 只检查结构和状态，不代表已授权。

当前 `internal/resource.GORMStore` 将注册表持久化到 `platform_resources`，保存 owner、状态、revision 和软删除时间。更新和删除使用期望 revision 做乐观并发检查；冲突、缺失资源和非法状态不会被转换成成功。platform bootstrap 已统一组装资源、授权、审计、凭据、证书、DNS binding、DNS service 和工作流存储，共用同一 DB、authorizer、credential store 和 audit recorder；尚未接入的 DNS 厂商、部署等业务模块仍需沿用这一组装边界。

删除采用软删除及引用完整性检查。新模块必须在同一权威服务中检查凭据、工作流、部署目标等活动引用；仍被引用时返回 `conflict`，不得级联删除其他模块资产。清理、恢复和物理删除由对应模块制定明确的数据保留策略；本契约不改变哪吒已有表的删除方式。

## 执行身份与资源授权

`authz.Execution` 必须由可信认证结果或持久任务恢复，不接收浏览器自报的角色、管理员标志或服务身份。

| 字段 | 含义 |
|---|---|
| `subject` | 本次执行的实际用户、平台服务、Agent 或设备身份 |
| `triggered_by` | 本次尝试的触发者，与实际运行身份分别记录 |
| `entry` | `session`、`pat`、`schedule`、`workflow`、`retry`、`recovery`、`agent` 或 `device` |
| `token_id` | 原始 PAT 的哪吒主键；派生任务必须保留，不能因进入后台而丢失限制 |
| `source_grant_id` | 派生任务所依赖的源授权；执行时核对其当前有效性 |
| `operation_id` | 服务端生成的逻辑操作 ID；重试与恢复保留此 ID |

用户身份引用哪吒用户 ID，Agent 身份引用哪吒主机 ID。平台服务与设备身份使用独立注册的不透明 ID；它们不能仅凭名称获得权限。交互式用户的实际身份与触发者一致。PAT 请求必须携带非零 `token_id`，会话请求不携带 PAT。后台任务可以保留用户或正式服务身份；带 PAT 限制的后台任务必须继续使用对应用户身份。

所有新入口调用 `authz.Check(ctx, authorizer, request)`。有效权限为当前主体动作权限、资源授权、PAT 限制、目标约束的交集；凭据解析还要叠加凭据用途和绑定限制。管理员也不能跳过 PAT 的 scope 或主机白名单。

`Check` 拒绝无效请求、缺失授权服务、零值拒绝结果，以及缺少策略版本的允许结果。策略错误和上下文取消均不能转为允许。`Decision.PolicyVersion` 与 `GrantIDs` 用于审计，不是可以缓存后重放的授权票据。

授权实现需要从当前哪吒用户和 Token 记录加载身份状态、角色、过期、撤销、scope 和主机范围；这里不复制第二套认证数据库。现有 `model.APIToken.HasScope` 和 `CanAccessServer` 可由适配器使用。新业务路由的 PAT scope 必须在该业务接入时显式加入现有签发与校验集合；本次契约不提前扩大现有 scope。

当前 `internal/authz.GORMAuthorizer` 将 grant 持久化到 `platform_policy_grants`，每次判定读取现行策略，并与现有 `api_tokens` 的 scope、过期和 server whitelist 求交集。管理员不会跳过 PAT 限制；空值、格式错误、溢出或不完整的 whitelist 采用 fail-closed。DNS 和证书名称范围按标签边界匹配，不能用未分隔的字符串后缀替代。

| 动作 | 授权语义 |
|---|---|
| `view` | 查看安全元数据及获准资源 |
| `edit` | 创建或修改业务配置 |
| `execute` | 执行流程、任务或部署 |
| `export` | 导出数据，单独授权 |
| `download` | 下载证书等资产，私钥范围由业务策略继续约束 |
| `delete` | 删除资源 |
| `use` | 在服务端使用凭据，不授予明文读取能力 |
| `reveal` | 显式读取凭据明文 |
| `rotate` | 轮换凭据 |
| `grant` | 修改授权或移交自动化运行身份 |

`Request.DNS` 携带服务端解析的真实 Zone、名称和记录类型。新增记录携带拟创建记录；修改和改名同时携带原记录与新记录；批量操作逐项授权。授权实现按 IDNA、大小写、末尾根点和 DNS 标签边界判断，分别处理子树根开关、DNS 通配和证书通配权限。不能用字符串后缀匹配代替标签边界。

`Request.CertificateNames` 携带全部最终 SAN，包括表达式解析结果或上传证书的实际 SAN。任一名称越界即拒绝。结构校验不执行 DNS/IDNA 规范化，也不解析证书；业务模块与授权实现必须完成这些检查，不能把非空名称视为获准名称。

列表、分页总数、详情、下载、导出和实时事件必须使用同一资源策略。列表应先授权过滤再分页计数；不能仅对当前页面过滤后返回未过滤总数。当前契约只提供单资源判定，批量查询优化必须保持相同语义。

定时、重试、恢复和每次外部副作用之前，重新加载当前权限及实际资源。源授权或 Token 撤销后，用户派生任务停止新的副作用。正式平台自动化依照明确授予的服务身份权限存续；将用户流程移交给服务身份需要单独授权并审计。已发出的外部操作需要核对结果，不能将本地取消等同于远端回滚。DNS-01 清理只允许删除本运行已创建的确切 TXT 值。

## 凭据引用、解析与存储

业务对象仅保存 `credential_ref`，例如：

```json
{"credential_ref":{"id":"access000000001","version":0}}
```

`version=0` 表示在每次获准使用时解析当前版本；正整数表示固定版本。解析器在一次回调内只解析一次，返回实际 `Resolved.Version` 并写入运行和审计记录。重试不能用旧的允许结果绕过当前状态和权限检查。

`credential.Type` 是认证格式标识，不能仅按厂商名称匹配。DNSPod 独立 Token、腾讯云 SecretId/SecretKey 等不同结构由适配器注册为不同类型。调用方必须提供 `expected_type`，解析器必须精确匹配；同一云身份可以通过不同用途绑定供多个模块使用。

用途为 `dns.manage`、`dns.challenge`、`certificate.issue`、`certificate.deploy` 和 `notification.send`。每个 `Binding` 同时包含用途、消费者资源和实际目标资源；只允许一个用途不能隐含授权该云密钥可访问的全部资源。

`Resolver.WithSecret` 的实现顺序：

1. 校验 `UseRequest`，加载实际消费者、目标及名称范围。
2. 使用同一授权接口检查消费者、目标动作和凭据 `use` 权限，并保留 PAT、源授权和名称限制。
3. 检查当前凭据状态、精确认证类型、用途绑定和版本是否有效。
4. 持久记录使用意图，在服务端解密并调用回调；结束或 panic 时销毁明文缓冲区。
5. 持久记录实际版本及结果，不记录秘密、厂商响应正文或包含密钥的 URL。

`credential.Secret` 在 JSON、文本、常见 `fmt` 输出及 `slog` 中显示 `[REDACTED]`；`Resolved` 的 JSON 不含密钥字段。适配器只能在回调作用域内使用显式的 `Bytes()`。`Destroy()` 清零其持有的缓冲区，但无法清除 SDK 创建的副本；这些保护不能替代日志审查，也不能阻止调用方主动输出 `Bytes()`。

`Protector` 接口要求认证加密，将凭据资源引用与版本作为关联数据，拒绝密文替换和篡改。当前 `AESGCMProtector` 已实现 `AES-GCM` 信封，包含 `key_id`、`algorithm`、`nonce` 和 `ciphertext`，并把凭据 ID、版本和 key ID 纳入 AAD。`Store` 将元数据、绑定、版本和密文分别持久化到 `platform_credentials`、`platform_credential_bindings` 和 `platform_credential_versions`；`WithSecret` 在授权、状态和用途检查后才解密，并在回调返回或 panic 时销毁明文。

生产组装时，AES 密钥必须由独立的 platform key 文件或等价的服务端密钥管理器加载。当前 Dashboard 主进程按数据库路径追加 `.platform.key` 加载密钥，例如 `data/sqlite.db.platform.key`；首次启动会以受限权限创建 32 字节密钥，密钥本身不能写入业务数据库，也不能从 JWT、session secret 或其他用户令牌派生。已有加密材料而密钥缺失或权限过宽时，启动会 fail-closed；密钥轮换仍需由部署方编排并保留旧版本。

轮换产生新的不可变版本，不覆盖旧版本。普通轮换后，已进入回调的操作继续使用本次解析版本；新调用解析新版本。旧固定版本只有在仍被明确保留且未撤销时才可继续解析。停用、删除或撤销版本阻止后续解析；已发送的远端请求需核对结果。删除仍被引用的凭据返回 `conflict`，失效版本返回 `credential_version_invalid`，停用返回 `credential_disabled`。密钥明文导出必须另行检查 `reveal` 或 `export`，不能通过普通解析接口向用户返回。

## 证书资产边界与当前接入状态

`internal/certificate` 已完成上传证书资产的基础纵切面。名称会做空白、大小写、IDNA 和 wildcard 边界校验；`ParsePEM` 只接受一个叶证书 PEM，解析 DNS SAN 和 IP SAN，拒绝无 SAN，并验证证书公钥与私钥匹配。证书元数据投影不含 PEM 或私钥；GORM 元数据保存在 `platform_certificates`，材料保存在独立的 `platform_certificate_materials`，使用 AES-GCM 加密和带资源/角色关联数据的认证信封。

证书服务已经提供创建、列表、详情、证书下载、带额外 `reveal` 授权的私钥下载和删除，并对这些操作重新检查当前授权。敏感操作会记录 requested、succeeded 或 failed 审计事件；下载默认只返回证书，只有显式 `include_private=true`（或兼容的 `private_key=true`）且通过 `download` 与 `reveal` 检查时才追加私钥。Certimate 风格的 legacy certificate 字段有明确导入边界，但尚未完成旧库 fixture 的全量迁移验证。

Dashboard 当前暴露以下证书资产 API：`POST/GET /api/v1/certificates`、`GET /api/v1/certificates/:id`、`GET /api/v1/certificates/:id/download` 和 `DELETE /api/v1/certificates/:id`；工作流 API 覆盖列表、创建、版本保存/发布、启停、运行、运行查询、状态转换和删除；DNS API 覆盖 `GET /api/v1/dns/zones`、Zone 记录列表/详情，以及记录的创建、修改和删除，并提供 `/dashboard/dns` 页面。HTTP 层保留哪吒现有 `model.CommonResponse` 信封，并由服务层生成安全错误；`cmd/dashboard/main.go` 已按数据库路径加载独立 platform key，并注入 GORM store、授权、审计、凭据、证书、DNS 和工作流实现。DNS 运行时当前仅支持 Cloudflare，DNSPod/EdgeOne 和真实厂商账号联调仍待完成；工作流设计器、运行节点输出/日志、预设及完整调度/执行器仍未完成，不能据此宣称完整 Certimate 工作流已迁移。

## Dashboard 模块生命周期

模块通过构造函数接收授权、凭据、审计、存储和 Agent 能力，实现 `lifecycle.Module`。构造函数不启动调度器、监听器或后台 goroutine。

| 阶段 | 模块职责 |
|---|---|
| `Init` | 初始化内部存储与迁移、加载配置、注册节点和提供商；不接收执行任务 |
| `Start` | 启动调度器和有界执行器，快速返回；后台工作使用所传上下文 |
| `Stop` | 拒绝新任务，取消或收敛执行，等待后台工作结束并释放资源 |

`lifecycle.New(cleanupTimeout, modules...)` 接收按依赖排列的固定模块列表。`Runtime.Start` 先依次初始化全部模块，再依次启动；不能重复启动。任一初始化或启动失败，取消工作上下文，并用独立、有超时的清理上下文逆序停止所有已进入初始化的模块，包括失败模块本身。

正常 `Runtime.Stop` 取消工作上下文，再逆序清理模块；并发或重复调用只清理一次，并返回相同清理错误。调用使用互斥锁串行执行，模块不能回调同一个运行器。`Init` 和 `Start` 必须及时返回并遵守取消，否则停止调用会等待正在进行的生命周期调用。`Stop` 必须遵守截止时间；运行器不强制中断不响应上下文的 Go 代码，也不在失败后再次停止半关闭的模块。

业务接入 Dashboard 时，在 `service/singleton` 完成数据库等依赖初始化后构造模块，完成 API 组装并在监听服务之前启动运行器。在 `main` 的优雅退出回调中，使用独立关闭上下文停止模块，随后才关闭它们依赖的 RPC、数据库及 TSDB。初始化失败后必须先完成模块清理，再退出进程。

当前证书、DNS 和工作流服务及 HTTP 控制器已经挂入 `cmd/dashboard/main.go` 的依赖组装，主进程在监听前完成数据库迁移、platform key 加载、服务注册和服务注入，并在优雅退出时先停止 HTTP/HTTPS，再关闭依赖它们的运行时资源。当前 workflow service 只提供最小持久化、版本/发布、运行历史和状态转换，尚无完整节点执行器、scheduler、崩溃恢复或离线补发 runtime；其他业务模块仍应按同一生命周期边界接入，不能在包级 `init()` 中另行启动引擎。

如果模块使用已运行的 `singleton.CronShared`，在 `Start` 中登记任务并记录自己的条目 ID，在 `Stop` 中移除这些条目；不关闭其他模块共用的调度器。事件订阅和重试计时器也由所属模块登记和清理。事件触发、定时触发和重试都进入同一个业务应用服务，携带 `Execution` 并重新授权；不得另开绕过权限检查的内部写入入口。本次不引入共享事件总线、全局队列或重试引擎。

## 错误与审计

新模块边界使用 `platformerr.New` 或 `platformerr.From` 输出稳定错误。错误结构包含 `code`、安全 `message`、`operation_id` 和 `retryable`；原始错误仅供进程内 `errors.Is/As` 分类，不写入 API、审计或普通日志。`From` 会重新生成安全文案，避免将厂商错误正文直接透传。

| 错误码 | HTTP 状态 |
|---|---|
| `invalid_argument` | 400 |
| `unauthenticated` | 401 |
| `forbidden` | 403 |
| `not_found` | 404 |
| `conflict`、`credential_disabled`、`credential_version_invalid` | 409 |
| `canceled` | 408 |
| `provider_failure` | 502 |
| `unavailable` | 503 |
| `timeout` | 504 |
| `internal` 或未知错误 | 500 |

`retryable` 只标记超时和暂时不可用；重试前仍需重新授权、检查操作 ID 和远端实际状态。超时不意味着远端未执行，不能据此盲目重复签发、DNS 修改或部署。厂商限流等细分错误由适配器分类，不能从任意响应文本推断可重试性。

平台错误结构及状态映射不改变现有 `model.CommonResponse` 的字符串 `error`。证书 HTTP 控制器已将安全错误映射到现有响应信封；其他新业务 HTTP 控制器仍需在接入时显式完成映射，并在相应 API 契约中声明。

审计使用 `audit.Recorder.Record`。每条事件有唯一 `id`，使用 `Execution.OperationID` 关联同一逻辑操作的多次尝试。记录主体、触发者、入口、动作、资源、结果、安全错误码、策略及授权来源、凭据版本和资源版本；事件结构不提供任意请求正文或日志文本字段。

凭据使用、明文读取、轮换、停用、删除、授权变更、运行身份移交、DNS 修改、证书下载及执行操作必须审计。敏感操作在暴露秘密或发送副作用前持久记录意图，再记录成功、拒绝、失败或取消；审计写入失败不能静默忽略。`Recorder` 实现按事件 ID 去重；跨存储提交与结果不确定的恢复由具体应用服务负责。

当前 `internal/audit.GORMRecorder` 将事件持久化到 `platform_audit_events`，按事件 ID 对完全相同的重试幂等处理，对同 ID 不同内容返回冲突，并支持按 `operation_id` 查询同一逻辑操作的尝试。审计事件不包含任意请求正文、厂商响应、URL、脚本或证书私钥字段。

## 验证边界

当前 `go test -race ./internal/...` 覆盖 ID 无损往返、无效引用、资源注册和 revision 冲突、拒绝优先的授权调用、PAT scope 与 whitelist 交集、重新授权、取消、凭据 AES-GCM 篡改、密钥格式化与销毁、证书 SAN/私钥匹配和材料分离、证书材料跨重启恢复、稳定 platform key 缺失失败、审计幂等、启动失败清理和并发幂等停止；定向测试还覆盖 DNS provider mock、授权服务、workflow version/run 及 Dashboard DNS/workflow API。Dashboard 侧另有证书 API、路由和前端 fallback 回归测试。

这些测试不等同于完整平台验收。仍需验证完整 Certimate fixture/data migration、全部节点与 ACME、deployment/notification providers、工作流调度/崩溃恢复/离线补发、节点输出/日志、Cloudflare/DNSPod/EdgeOne 真实账号联调、完整前后端线上联调、platform key 备份/恢复/轮换演练，以及真实部署副作用。
