# 集中 DNS Go 接口草案

本文定义 DNS 厂商适配器与应用服务的职责边界，供 DNS、凭据、授权、DDNS 和证书工作协作使用。类型声明位于 [`internal/dns/provider.go`](../internal/dns/provider.go)，只依赖 Go 标准库，可独立编译。Provider contract 仍是扩展草案，但 Zone binding GORM store、DNS 应用服务、Dashboard API 和 `/dashboard/dns` 页面已经接入；当前运行时只装配 Cloudflare 适配器。

厂商依据见 [能力矩阵](DNS_PROVIDER_MATRIX.md)，总体约束沿用 [集成方案第六节](DESIGN.md#六集中-dns-与-ddns)。跨模块资源 ID、凭据存储、授权对象和生命周期类型遵循 [公共契约](CONTRACTS.md)；本文件只保留厂商能力和适配器扩展边界。DNSPod、EdgeOne、现有 DDNS worker、DNS-01 challenge 和调度器尚未接入该运行时。

当前已覆盖的 DNS 纵切面包括：`dns.GORMStore` 持久化本地 Zone binding；DNS 服务在 Zone/记录读取及记录增改删前执行资源授权、PAT scope、凭据用途和能力检查，并对写操作记录审计；Dashboard 提供 `GET /api/v1/dns/zones`、`GET /api/v1/dns/zones/:id/records`、`GET /api/v1/dns/zones/:id/records/:recordID`、`POST /api/v1/dns/zones/:id/records`、`PATCH /api/v1/dns/zones/:id/records/:recordID` 和 `DELETE /api/v1/dns/zones/:id/records/:recordID`。Cloudflare 适配器覆盖 Zone/记录读取和按记录 ID 的创建、更新、删除；真实厂商账号联调尚未完成。

## 边界与依赖方向

```text
页面 / API Token / DDNS / DNS-01 / 后台任务
    → DNS 应用服务：资源过滤、授权、凭据用途、操作协调、审计
    → 账户与凭据版本绑定的 Provider
    → 厂商 API
```

应用服务负责读取本地账户和 Zone 绑定，按有效执行主体验证资源与操作权限，然后解析 `credential_ref`。适配器工厂由该服务调用，接收已经校验的厂商配置与执行凭据；工厂、公共授权及凭据解析接口待平台公共契约确定后再添加。浏览器不能提交厂商密钥或任意远程 Zone ID 来替代本地资源授权。

| 层次 | 本草案确定的职责 | 仍由公共契约或后续实现确定的内容 |
|---|---|---|
| 厂商适配器 | 远程 ID、名称、RDATA、TTL、分页、能力、增改删、错误语义 | SDK/HTTP 实现、传输策略、厂商注册与配置表单 |
| DNS 应用服务 | 授权后调用、同资源协调、逐项授权、审计和状态核验；当前已接入本地 Zone binding 和记录 CRUD | 多厂商账户模型、跨操作事务、持久运行队列与调度 |
| 凭据与授权 | 执行前和重试前重新验证主体、用途、范围及凭据状态 | `credential_ref` 类型、加密存储、版本租约、主体与资源类型 |
| Dashboard 生命周期 | Provider 调用接受 `context.Context` 并响应截止时间和取消 | 初始化顺序、调度启动/停止与后台任务注册 |

远程 `ZoneID` / `RecordID` 是账户作用域内的不透明字符串，不是本地资源主键。即使厂商返回整数，也必须无损转换为十进制字符串，不能先经过浮点数；不得将 DNSPod Domain ID、EdgeOne Zone ID 或 Cloudflare Zone ID 直接混用。

## 最小接口与可选能力

`Provider` 包含 `ListZones`、`GetZone`、`Capabilities`、`ListRecords` 和 `GetRecord`。最小接口用于只读资源发现；有权限读取某个 Zone 不代表有权限列出账户的全部 Zone。`GetZone` 可以通过厂商详情接口或精确过滤实现。

`RecordWriter` 提供 `CreateRecord`、`UpdateRecord` 和 `DeleteRecord`。单个适配器实现该接口，只代表具备写入代码；每次操作仍须同时满足该账户、Zone、记录类型、套餐和当前用户的限制。`LineReader`、`DNSSECReader`、`BatchWriter` 均为可选扩展。

`Capabilities` 由适配器在账户和 Zone 范围内观察，能力值为 `available`、`unavailable`、未知。零值或缺少键均为未知。`Support.Reason` 写明套餐、类型限制或无法确认的原因。能力发现失败应返回错误，不能转换为一份全部可用的结果。前端提示可以读取能力，服务端写入必须重新校验；未知能力不允许写入。

DNSSEC 先只定义读取扩展，不加入启停、密钥轮换或注册商 DS 写入。DS 记录存在不代表父区委派已配置或验证通过。普通 DS/DNSKEY 记录编辑与 Zone 的 DNSSEC 开关也不是同一权限。

## 名称与记录表示

统一名称采用小写 ASCII FQDN，保留末尾点。Unicode 输入先按 IDNA 转换，厂商返回值再规范化。apex 直接使用 `zone.Name`，接口不使用 `@` 或空名称。适配器负责厂商所需的相对名称与 FQDN 转换。验证所属 Zone 必须比较 DNS 标签边界，不能用不带分隔符的字符串后缀比较。

`RecordData.Value` 使用完整的 RFC presentation RDATA，不拆分丢失字段。MX 为 `10 mail.example.com.`，SRV 为 `0 5 443 target.example.com.`，CAA 为 `0 issue "letsencrypt.org"`，TXT 为带引号的一个或多个 character-string。优先级保留在 RDATA 中；适配器对接 DNSPod `MX`、Cloudflare `priority` 或 EdgeOne `Priority` 时负责解析与组合，不能把 `0` 当作未填写。TXT chunk、引号、空格和转义必须使用 DNS 解析器处理，不能通用 `strings.Fields` 分割。

`TTL` 显式区分 `explicit` 和 `automatic`。前者使用正整数秒，后者 `Seconds=0`。Cloudflare 的远程值 `1` 映射为 `automatic`，DNSPod 的 `1` 仍表示一秒；是否允许该值由域名套餐决定。零值 TTL 无效，不默认为 600 秒。`TTLLimits` 的空指针表示未知，不能解释为零下限。

`Line` 保存厂商不透明线路 ID，空值表示选用厂商默认线路，读取时尽量返回明确的默认 ID。Cloudflare `Proxied` 独立于线路；不能为关闭代理修改 `Line`。`Weight=nil` 表示未设置，`Weight=0` 保留各厂商真实含义，不能与 SRV RDATA 的 weight 字段混用。

`Comment=nil` 表示无备注，指向空字符串表示清空。`Disabled` 和 `Proxied` 使用可空布尔值，区分不适用与显式 false。`Extensions` 只容纳已验证的厂商字段，如 Cloudflare tags/settings；按厂商白名单验证其结构和写入权限，不能携带密钥、认证头、端点或任意请求参数。未知记录类型和未知扩展可保留为只读，但必须拒绝不能完整保留字段的修改。

## 精确查询、分页与授权过滤

`RecordFilter` 的非空条件按 AND 进行精确匹配。厂商仅支持模糊查询时，适配器必须再次检查名称、类型和线路；使用 ID 过滤模拟 `GetRecord` 时也必须精确检查 ID。不能把「未找到」转换为空结构后继续更新。

`PageRequest.Cursor` 是适配器拥有的不透明游标，首次为空；游标须绑定账户、Zone 和过滤条件，不允许跨范围复用。`Limit` 必须为正，并在适配器确认的边界内。`Page.NextCursor` 非空就要继续读取，即使当前 `Items` 为空；只有空游标表示遍历完成。游标至少支持表达厂商的页码、offset 或 continuation token，消费者不得自行递增它。

适配器返回的是服务端内部数据，不带本地资源授权。应用服务先确定获准的本地账户和 Zone，再查询远程数据；记录级子域范围仍须过滤。适配器游标不能直接作为面向用户的授权分页游标；用户列表的页大小、总数和下一页必须基于授权后的结果生成，不能泄漏未授权名称或厂商原始总数。

## 写入、冲突与保留字段

`CreateRecord` 是新增一条记录，不能表现为「按名称覆盖已有记录」。`UpdateRecord` 接收最新的 `before Record` 和完整的 `after RecordData`；`DeleteRecord` 接收最新的 `before Record`。`before.ID` 必填。应用服务在获准 Zone 中读取该记录，校验当前名称、类型、线路和用途归属；修改还须分别验证旧名称和新名称，防止将获准子域的记录移动到其他范围。

`after` 是完整目标状态，不是字段补丁。应用服务从当前记录复制，应用获准变更，保留未修改的代理、线路、备注、TTL 和已识别扩展。适配器再次读取或使用厂商前置条件检查 `before`，发现不同则返回 `conflict`；不支持厂商原子 CAS 时，这只能缩小竞态窗口，不能消除控制台或其他客户端的并发写入。写入成功返回厂商规范化后的记录；如果写入已成功、回读失败，应报告 `applied` 并保留已知记录 ID。

停用只能调用真实的厂商状态功能；不允许追加 `_pause`、改成其他名称、删除后备份等模拟行为。备注或状态若需要第二次请求，出现部分成功时不能报告「未修改」，应返回 `applied` 或 `unknown` 并由业务层核验。所有外部调用使用有截止时间的上下文。

本草案面向首批按记录 ID 操作的厂商，禁止在适配器内用整组 RRset 替换来模拟单条操作。后续接入 Route 53、PowerDNS 等厂商时，应增加明确的 RRset 读取、集合保留、冲突检测和协调契约，再开放写入能力；不能先给出假记录 ID 让上层误以为可以安全删除一条值。

## 批量执行与错误语义

普通业务批量可以由应用服务逐条调用 `RecordWriter`，逐条授权、协调、执行和审计。`BatchWriter` 专门表示厂商原生批量能力，`BatchCapabilities` 说明操作类型、已确认的数量上限与配置事务性；未知上限不能解释为无限制。

每条 `Change` 必须符合其类型：create 只有 After，update 有 Before 与 After，delete 只有 Before。批量限制在同一账户和 Zone，禁止未经依赖分析的同记录重复操作或依赖厂商生成 ID 的后续操作。适配器可按厂商规则重排，结果通过输入 `Index` 对应，必须覆盖每个输入，分别返回 `not_applied`、`applied` 或 `unknown`。请求级错误不能掩盖已知成功项；未尝试的项目应明确为 `not_applied`。

Cloudflare 原生混合批量可以声明配置事务性，不能声明解析传播原子性。DNSPod 的异步批量任务不能直接冒充同步 `ApplyBatch`；需另行定义任务查询契约或先不实现此扩展。EdgeOne 的原生修改可以只声明 update，不能因接口名带复数就宣告混合事务。

所有厂商错误通过 `ProviderError` 暴露统一分类，调用方通过 `errors.As` 读取厂商码、请求标识、重试提示、写入结果及已知记录 ID。`Error()` 必须脱敏，不拼接认证头、请求体、未过滤的响应或完整 RDATA。权限错误不能按未找到处理，厂商故障不能变成空列表。

| 错误分类 | 恢复规则 |
|---|---|
| `invalid_argument` / `unsupported` | 修正输入或能力选择；不得原样重试 |
| `unauthenticated` / `permission_denied` | 验证凭据状态、用途、云权限与本地授权；不得转用更高权限凭据 |
| `not_found` / `conflict` | 重新读取资源并校验授权；修改和删除不自动变成新增 |
| `rate_limited` | 在预算内遵守厂商提示和退避；`RetryAfter=0` 表示无提示 |
| `unavailable` / `provider_error` | 只读调用可按明确规则重试；未知厂商错误不默认可重试 |
| `canceled` / `deadline_exceeded` | 保持可解包到 Go context 错误；请求已发送时写入结果可能未知 |

错误分类和写入结果相互独立。例如超时可以是 `not_applied`（未发送）、`unknown`（已发送但无响应）或 `applied`（已确认写入但回读超时）。对 `unknown` 先核验，新增和批量不允许盲目重放。读取错误的 Outcome 使用 `not_applied`，不表示查询结果可信。

## DDNS 与 DNS-01 的调用约束

后续 DDNS 绑定应引用本地账户、Zone 和具体远程记录 ID，只更新获准的 A/AAAA。IP 为空时是否删除由绑定策略决定，不能因为目标名称相同就删除全部 A/AAAA。迁移前继续使用现有路径；本次不修改其行为、配置键和数据。

DNS-01 创建 TXT 时，应用服务保存运行/订单、账户、Zone、名称、完整 TXT 值及返回记录 ID。清理前重新验证授权和远程内容，只删除本任务创建且内容仍匹配的记录。如果复用了已存在的同值记录，必须标记非本任务创建，不能清理。不同任务共享一个创建记录时，还需业务层引用或协调机制，不能提前删除。

用户修改、DDNS 和证书验证经同一个应用服务协调。按账户、Zone、名称、类型和必要线路等范围限制并发；授权和凭据状态在执行、重试、清理时重新校验。只有具备明确的后台执行主体和持久授权来源，才能执行计划任务，不能借用请求结束时缓存的管理员权限。

## 后续接入与验证顺序

1. 在现有公共契约、Zone binding 和凭据工厂上补充账户级配置与能力探测，避免让远程 Zone ID 取代本地资源引用。
2. 完成 Cloudflare 真实测试账户联调，验证分页、自动 TTL、权限、错误脱敏和不确定写入结果；当前 HTTP mock 只覆盖适配器行为。
3. 接入 DNSPod 线路、套餐 TTL 和备注；接入 EdgeOne NS 模式、当前批量修改 Action、零权重与优先级范围。
4. 将 DDNS、DNS-01 和调度任务接入同一应用服务，验证子域授权、旧名称与新名称检查、批量部分成功、同名多 TXT，以及并发和清理。
5. 真实测试账户联调后才声明对应厂商能力可用；DNSSEC、其他厂商及异步批量按证据补充扩展。

Provider contract 的编译和 mock 测试只验证 Go 类型、字段保留、错误分类及适配器行为，不等于真实厂商账号、授权、传播一致性或部署兼容性已经通过测试。
