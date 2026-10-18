# DNS 厂商能力矩阵

本文用于选择集中 DNS 的首批适配器，并为 [Go 接口草案](DNS_PROVIDER_CONTRACT.md) 提供依据。核对日期为 2026-10-18。矩阵描述参考源码和厂商接口的能力，不表示统一平台已经实现这些能力，也不替代真实账户、套餐和权限验证。

## 来源与证据范围

- 彩虹 DNS 使用 [`upstreams.lock.json`](../upstreams.lock.json) 固定的提交 `78e77a608fe37c3f7bbbfe35f732bfdf1de43bdd`，共 22 个 DNS 适配器。
- [DnsInterface.php](https://github.com/netcccyun/dnsmgr/blob/78e77a608fe37c3f7bbbfe35f732bfdf1de43bdd/app/lib/DnsInterface.php) 定义区域发现、记录查询、增改删、备注、状态、线路和最低 TTL 等接口；方法存在不代表其实现有效，部分实现直接返回 `false`。
- [DnsHelper.php](https://github.com/netcccyun/dnsmgr/blob/78e77a608fe37c3f7bbbfe35f732bfdf1de43bdd/app/lib/DnsHelper.php) 提供厂商配置。下表的备注、权重、分页声明来自此文件，并结合各适配器方法体核对。适配器源码路径统一为该固定提交下的 `app/lib/dns/<适配器 ID>.php`。
- 首批 Cloudflare、DNSPod、EdgeOne 另核对官方文档。腾讯云参数补充核对[官方 Go SDK 固定快照](https://github.com/TencentCloud/tencentcloud-sdk-go/tree/043228750f05b99e7be4bba973c8560857bead8f/tencentcloud)，仅作为资料，不为项目新增 SDK 依赖。
- 本轮未使用真实云凭据、未修改远程解析记录。其他厂商的当前官方 API、限流值和错误码保留为待核验项。

## 固定基线全量清单

「有」表示参考源码包含区域列表、记录列表及新增、修改、删除的实际调用；不保证每种记录类型都正确。「无」表示基线未提供该项，不能据此断言厂商本身不支持。「未知」表示基线未能给出限制。TTL 数值单位为秒，仅代表基线实现的最低值；「动态」表示向厂商查询；这些数值不能作为所有账户的统一校验规则。

| 厂商 / 适配器 ID | 区域、记录列表、增改删 | TTL 最低值 | 线路或代理 | MX 优先级写入 | 备注 | 记录权重 | 记录分页处理 |
|---|---|---|---|---|---|---|---|
| 阿里云 DNS / `aliyun` | 有 | 动态 | 按域名查询线路 | `Priority` | 单独设置 | 无 | 服务端 |
| DNSPod / `dnspod` | 有 | 动态 | 线路分类及套餐线路 | `MX` | 单独设置 | 有 | 服务端 |
| 华为云 / `huawei` | 有，RRset 修改 | 未知 | 本地线路表 | 透传 RDATA；未使用 `$MX` | 随记录写入 | 有 | 服务端 |
| 百度云 / `baidu` | 有 | 未知 | 固定线路表 | `priority` | 随记录写入 | 无 | 客户端 |
| 西部数码 / `west` | 有 | 未知 | 固定线路表 | `level` | 无 | 无 | 服务端 |
| 火山引擎 / `huoshan` | 有 | 动态 | 线路及套餐过滤 | RDATA | 随记录写入 | 有 | 服务端 |
| 京东云 / `jdcloud` | 有 | 未知 | 套餐线路树 | `mxPriority` | 无 | 有 | 服务端 |
| DNSLA / `dnsla` | 有 | 动态 | 可用线路接口 | `preference` | 无 | 有 | 服务端 |
| 青云 / `qingcloud` | 有 | 60 | Zone view | RDATA | 无 | 有 | 服务端 |
| 宝塔域名 / `bt` | 有 | 300 | view 查询 | `mx` | 随记录写入 | 有 | 服务端 |
| Cloudflare / `cloudflare` | 有 | 未知；自动值见后文 | 基线将代理状态当作线路 | `priority` | 随记录写入 | 无 | 服务端 |
| AWS Route 53 / `aws` | 有 | 60 | 仅默认值 | RDATA | 无 | 无 | 客户端汇总 |
| NameSilo / `namesilo` | 有 | 未知 | 仅默认值 | `rrdistance` | 无 | 无 | 客户端 |
| HE DNS / `henet` | 有，网页会话适配 | 300 | 仅默认值 | `Priority` | 无 | 无 | 客户端 |
| Spaceship / `spaceship` | 有 | 未知 | 仅默认值 | 类型转换后写入 | 无 | 无 | 服务端声明 |
| PowerDNS / `powerdns` | 有，RRset 修改 | 未知 | 仅默认值 | RDATA | 随记录写入 | 无 | 客户端 |
| Technitium / `technitium` | 有 | 未知 | 仅默认值 | 类型转换后写入 | 随记录写入 | 无 | 客户端 |
| 阿里云 ESA / `aliyunesa` | 有，仅 NS 接入 | 1 | 基线将代理状态当作线路 | `Data.Priority` | 随记录写入 | 无 | 服务端 |
| 腾讯 EdgeOne / `tencenteo` | 有，仅 NS 接入 | 60 | 基线仅返回 `Default` | `Priority` | 无 | 有 | 服务端 |
| 彩虹 DNS 互联 / `dnsmgr` | 有，调用对端 API | 动态 | 对端域名信息 | `mx` | 随记录写入 | 有 | 服务端 |
| GoEdge 智能 DNS / `goedge` | 有 | 1 | 地区、ISP、自定义线路 | `mxPriority` | 随记录写入 | 有 | 服务端声明 |
| dynv6 / `dynv6` | 有 | API 未暴露；基线展示 600 | 仅默认值 | `priority` | 无 | 无 | 全量获取后过滤 |

分页列描述基线的处理方式，不是 Go 接口对外的分页协议。尤其不能把基线 `page=false` 解读为厂商不支持分页；该配置表示“不由通用控制层做客户端分页”。GoEdge、Spaceship 和 dynv6 的遍历终止与分页完整性仍需分别验证。

DNSSEC 不在基线公共接口内，不能从普通记录增改删推断其支持。华为云、Route 53、PowerDNS 等以 RRset 为操作单位；Go 适配时必须保留同集合内其他值，不能直接套用首批三个厂商的记录 ID 实现。华为云基线将 Value 拆分后直接写入 `records`，未将独立 `$MX` 参数组合到 RDATA，不能据此宣告优先级字段已正确映射。HE 的网页会话凭据也不等同于现有 Nezha HE DDNS 的 API Key。

## 首批三个厂商的接口映射

| 能力 | Cloudflare | DNSPod（腾讯云 API 3.0） | 腾讯 EdgeOne |
|---|---|---|---|
| 认证 | API Token；Zone 发现需相应 Zone 读取权限，记录读取/写入需 DNS 权限 | 腾讯云 `SecretId` / `SecretKey`，可由统一凭据服务处理临时令牌 | 腾讯云身份，产品为 `teo`；中国站与国际站端点需明确 |
| 区域列表 / 详情 | `GET /zones`、`GET /zones/{zone_id}` | `DescribeDomainList`、`DescribeDomain` | `DescribeZones`，按 `zone-type=full` 筛选；详情可按 Zone ID 筛选后精确匹配 |
| 记录列表 / 详情 | `GET /zones/{zone_id}/dns_records`、`GET .../{record_id}` | `DescribeRecordList`、`DescribeRecord`；复杂过滤另有接口 | `DescribeDnsRecords`，详情按 `id` 查询后精确匹配 |
| 新增 | `POST .../dns_records` | `CreateRecord` | `CreateDnsRecord` |
| 修改 | `PATCH .../dns_records/{record_id}`；全量替换另有 `PUT` | `ModifyRecord`；基线备注需另调 `ModifyRecordRemark` | 当前官方 SDK 为 `ModifyDnsRecords`，单条修改可提交一个元素 |
| 删除 | `DELETE .../dns_records/{record_id}` | `DeleteRecord` | `DeleteDnsRecords`，参数为 `RecordIds` |
| 原生批量 | `POST .../dns_records/batch`，包含 deletes / patches / puts / posts | 有独立批量任务接口；本草案不将异步任务等同同步批量结果 | `ModifyDnsRecords` 最多修改 100 条；另有批量删除、状态接口；混合新增/修改/删除的原子性未确认 |
| TTL | `1` 表示自动；显式范围 60–86400，Enterprise 最低可为 30；代理记录的自动 TTL 需单独校验 | 官方参数范围 1–604800；套餐决定实际下限，应查询域名权限 | 官方参数范围 60–86400，创建默认 300 |
| 线路 | 没有 DNSPod 式线路字段；`proxied` 是独立布尔值 | `RecordLine` / `RecordLineId`，按域名、套餐查询，优先保留线路 ID | `Location`，默认 `Default`；A/AAAA/CNAME 支持，标准版、企业版等条件以厂商文档为准 |
| 优先级 | MX 的 `priority`；SRV 等按对应 RDATA 结构处理 | `MX` 参数也用于 HTTPS/SVCB 优先级，范围 0–65535 | MX `Priority` 范围 0–50，不能套用 DNSPod 范围 |
| 权重 | 普通 DNS 记录无通用权重；SRV 的 RDATA weight 不属于流量线路权重 | `Weight` 范围 0–100；`0` 表示关闭权重功能，受套餐与类型约束 | `Weight=-1` 表示不设置，`0` 表示不解析，1–100 为权重；仅 A/AAAA/CNAME，且同线路同名记录需一致配置 |
| 备注 | `comment`，另有 `tags`；基线独立备注方法返回 `false`，但记录写入支持 comment | 当前官方 Create/Modify 参数有 `Remark`；基线使用单独备注接口，存在多请求部分成功的风险 | 基线和核对的 DNS 记录结构均未提供备注字段，不宣告远程备注支持 |
| 原生停用 | 本草案不宣告支持；基线通过改名模拟停用，不能迁入 | `ModifyRecordStatus` | `ModifyDnsRecordsStatus`；`DnsRecord.Status` 在批量修改输入中被忽略 |
| 分页 | `page` / `per_page`，按响应分页信息终止；上限实施时再次核对 | `Offset` / `Limit`；记录列表当前最大 3000，默认 100 | `Offset` / `Limit`；记录列表默认 20、上限 1000；Zone 列表默认 20、上限 100 |
| DNSSEC | 独立 `/zones/{zone_id}/dnssec` API；仅作为可选读取扩展，权限需单独核验 | 不在基线接口中；当前 API 与套餐能力待进一步核验 | 官方产品文档有 DNSSEC 控制台配置；本轮未确认可用于适配的读取 API，保持未知 |
| 特殊记录 | 官方记录 API 含 CAA、SRV、HTTPS、SVCB、TLSA、DS 等；可读不等于本草案已支持写入 | 通过 `DescribeRecordType` 查询实际类型；URL 转发是厂商能力，不能统一转换为 URI | 核对的当前结构列出 A、AAAA、CNAME、MX、TXT、NS、CAA、SRV；根域名不能添加 NS |

Cloudflare 批量操作在单个数据库事务内执行，但解析传播不保证原子性，且执行顺序固定为删除、局部修改、替换、新增。不能承诺按输入顺序执行，也不能把一次 API 成功视为所有递归解析器都已刷新。

### 基线移植时必须修正的语义

1. **EdgeOne 修改接口名不同。** 基线 [`tencenteo.php`](https://github.com/netcccyun/dnsmgr/blob/78e77a608fe37c3f7bbbfe35f732bfdf1de43bdd/app/lib/dns/tencenteo.php) 调用 `ModifyDnsRecord`，当前核对的官方 SDK 只有 `ModifyDnsRecords`。以官方接口为实现候选，再用 HTTP mock 和真实测试账户确认，不直接复制旧 Action。
2. **EdgeOne 的零权重被基线丢失。** 基线 `empty($Weight) ? -1 : intval($Weight)` 会把 `0` 转为 `-1`。Go 中使用可空数值，保留「不设置」与「不解析」的区别。
3. **Cloudflare 代理不能复用线路。** 基线 [`cloudflare.php`](https://github.com/netcccyun/dnsmgr/blob/78e77a608fe37c3f7bbbfe35f732bfdf1de43bdd/app/lib/dns/cloudflare.php) 把 `proxied` 放入 `Line`，并通过追加 `_pause` 改名模拟停用。Go 中分别表示线路和代理，对不支持的停用返回 `unsupported`，避免改变授权名称。
4. **DNSPod 身份不能按产品名称猜测。** 基线 [`dnspod.php`](https://github.com/netcccyun/dnsmgr/blob/78e77a608fe37c3f7bbbfe35f732bfdf1de43bdd/app/lib/dns/dnspod.php) 使用腾讯云 API `2021-03-23`，不是旧版 DNSPod Token ID/Token 认证格式。
5. **TXT 和 RRset 不能按名称覆盖或删除。** 证书 DNS-01 和用户记录可能共享名称。首批适配器必须按记录 ID 和预期内容操作；同名不同值保留。以 RRset 操作的后续厂商需另行验证读改写与并发协调。

## 限流、错误与写入结果

| 来源 | 可确认的信息 | Go 适配要求 |
|---|---|---|
| Cloudflare | API 会通过 HTTP 状态及 `errors[].code` 报告错误；批量记录文档列出 429 | 429 映射 `rate_limited`，读取存在的 `Retry-After`；保留脱敏厂商码和请求标识；本轮未确认账户与端点的具体配额数值 |
| 腾讯云 API 共性 | `AuthFailure.*`、`UnauthorizedOperation`、`InvalidParameter*`、`ResourceNotFound`、`RequestLimitExceeded*`、`InternalError` 等；响应可含 `RequestId` | 同时检查响应体中的 `Response.Error`，不能只判断 HTTP 200；区分认证失败、无权限、参数错误和限流 |
| DNSPod / EdgeOne 端点差异 | 频率、套餐和业务错误随 Action、账户变化 | 每个 Action 单独核验文档；不能把某一产品的限流常量或业务错误规则复用于另一产品 |
| 其余 19 个适配器 | 固定基线有各自传输和错误处理，尚未核对当前官方配额与错误码 | 实现前补充认证、端点、限流、可重试错误和空列表语义，未知值不写成「无限制」或「自动重试」 |

对请求已发送后发生的断连、超时、取消，写入结果可能为 `unknown`。新增、批量和多请求修改必须先核验远程状态，再决定是否重试；只读查询才可在预算内直接退避重试。配额耗尽（`LimitExceeded`）与请求频率限制（`RequestLimitExceeded`）不能混为同一恢复策略。

## 与现有 Nezha DDNS 的对应

当前 [`service/singleton/ddns.go`](../service/singleton/ddns.go) 注册 `dummy`、`webhook`、`cloudflare`、`tencentcloud`、`he`。其中 `tencentcloud` 使用腾讯云 Secret ID/Key；`he` 使用 API Key。它们是现有 DDNS 配置标识，不在本次变更中重命名或迁移。

[`pkg/ddns/ddns.go`](../pkg/ddns/ddns.go) 通过 SOA 查找 Zone，调用 `libdns.RecordSetter` 写入 A/AAAA，TTL 固定为一分钟；IP 为空时按名称和类型请求删除。该路径没有完整 DNS 管理所需的本地 Zone 绑定、单条记录身份和厂商字段。因此不能把现有 Setter 直接当作新 Provider，也不能把 dummy/webhook 宣告为区域管理提供商。后续迁移必须保留现有 worker 的 owner 检查，再接入按记录 ID 的授权与协调入口。

## 实施入口与验证缺口

首批按「Cloudflare → DNSPod → EdgeOne」实现读取与单条记录写入。每家先确认目标账户的区域发现权限，再确认记录权限；只有记录权限的凭据可通过已知 Zone 导入，不应强制用账户级区域列表验证所有凭据。

实施前尚需确认：Cloudflare 分页和限流配额；DNSPod 各记录类型、套餐及异步批量任务契约；EdgeOne 中国站/国际站差异、线路枚举、批量删除上限和批量失败语义；DNSSEC 读取权限与接口。未确认的能力保持未知，写入入口不得据此放行。

适配器的验证用例应覆盖分页完整性、精确名称与 ID 匹配、自动 TTL、零优先级、零权重、备注清空、不支持字段拒绝、部分成功、写入超时、TXT 同名多值和凭据失效。业务服务还需覆盖子域授权、停权后后台执行、DDNS 与 DNS-01 并发修改。这些为后续实现的验收要求，本次草案不包含已实现的 mock 或真实厂商测试。

## 官方参考资料

- [Cloudflare 记录创建与字段定义](https://developers.cloudflare.com/api/resources/dns/subresources/records/methods/create/)
- [Cloudflare 批量记录 API](https://developers.cloudflare.com/api/resources/dns/subresources/records/methods/batch/)
- [Cloudflare DNSSEC API](https://developers.cloudflare.com/api/resources/dns/subresources/dnssec/)
- [DNSPod 修改记录](https://cloud.tencent.com/document/api/1427/56157)
- [DNSPod 记录列表](https://cloud.tencent.com/document/api/1427/56166)
- [DNSPod 官方 SDK 参数快照](https://github.com/TencentCloud/tencentcloud-sdk-go/blob/043228750f05b99e7be4bba973c8560857bead8f/tencentcloud/dnspod/v20210323/models.go)
- [EdgeOne DNS 记录接入条件](https://edgeone.ai/zh/document/54764)
- [EdgeOne DNSSEC 产品配置](https://edgeone.ai/zh/document/58235)
- [EdgeOne 官方 SDK 参数快照](https://github.com/TencentCloud/tencentcloud-sdk-go/blob/043228750f05b99e7be4bba973c8560857bead8f/tencentcloud/teo/v20220901/models.go)
- [EdgeOne 官方 SDK Action 与业务错误快照](https://github.com/TencentCloud/tencentcloud-sdk-go/blob/043228750f05b99e7be4bba973c8560857bead8f/tencentcloud/teo/v20220901/client.go)
