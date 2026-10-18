# 上游来源与版本基线

项目以哪吒为主体，直接维护纳入仓库的后端和管理前端源码。上游基线记录在 [`upstreams.lock.json`](../upstreams.lock.json)，用于核对功能范围、来源和后续更新差异。

## 固定源码版本

| 上游 | 版本 | 提交 | 当前用途 |
|---|---|---|---|
| [Nezha Dashboard](https://github.com/nezhahq/nezha) | `v2.3.18` | `9881c47f0cc92256ba203919da5a25fab79a6bad` | 已纳入根目录，作为后端主体 |
| [哪吒管理前端](https://github.com/nezhahq/admin-frontend) | `v2.3.8` | `346574968cf4ecec605a74fe503814138a927b3d` | 已纳入 `web/admin`，作为唯一管理前端 |
| [Certimate](https://github.com/certimate-go/certimate) | `v0.4.35` | `884b353c7e2a5331ca24ff61bc18dea291cd8d91` | 后续完整证书业务与界面的迁移基线 |
| [彩虹 DNS](https://github.com/netcccyun/dnsmgr) | 提交基线 | `78e77a608fe37c3f7bbbfe35f732bfdf1de43bdd` | 后续集中 DNS 功能与服务商适配的移植参考 |

彩虹 DNS 基线位于 `2.21` 之后的第 3 个提交，不将该提交标记为正式发布版本。

本次骨架尚未迁入 Certimate 和新增 DNS 业务。后续迁移直接进入哪吒单一 Go 模块，不保留独立 Certimate 目录、进程、账号体系或管理前端。Certimate 的功能范围以固定基线为准，包括证书资产、工作流设计器、签发与续签、提供商、部署、通知、预设、运行历史和设置。

## 源码与参考材料

| 位置 | 内容 |
|---|---|
| 根目录 `cmd`、`model`、`service`、`pkg`、`proto`、`integration` | 纳入并持续维护的哪吒源码 |
| `web/admin` | 纳入并持续维护的哪吒管理前端源码 |
| `docs/upstream/nezha-README.md` | 哪吒上游原始 README |
| `docs/upstream/admin-README.md` | 管理前端上游原始 README |
| `upstream/` | 本地参考克隆，已忽略，不参与构建或运行 |

根目录 Go 模块暂沿用 `github.com/nezhahq/nezha`。保留模块路径是为了保持现有源码导入关系，不代表本项目由哪吒上游发布。

骨架沿用哪吒业务源码，构建和 CI 改用根目录统一入口。原上游工作流及其固定任务结构断言已替换，保留 Agent 协议业务测试和通用策略验证。协议生成脚本只写入当前仓库；旧容器发布配置尚未纳入，统一安装和升级入口在后续接入。

## 公开监控主题

哪吒原有公开监控页面保留以下五个主题。管理前端从 `web/admin` 本地构建，公开主题按锁定的 release 下载；每份主题制品使用 `upstreams.lock.json` 中的 SHA-256 校验后再参与内嵌。

| 主题 | 上游 | 版本 | 内嵌目录 |
|---|---|---|---|
| Official | [nezha-dash-v2](https://github.com/hamster1963/nezha-dash-v2) | `v2.4.3` | `user-dist` |
| Nezha-Pixel | [nezha-pixel](https://github.com/karllao/nezha-pixel) | `v1.6.0` | `nezha-pixel-dist` |
| Nazhua | [nazhua](https://github.com/hi2shark/nazhua) | `v1.2.0` | `nazhua-dist` |
| Aobobo | [aobobo](https://github.com/hi2shark/aobobo) | `v1.5.1` | `aobobo-dist` |
| Nezha-ASCII | [nezha-ascii](https://github.com/hamster1963/nezha-ascii) | `v1.1.0` | `nezha-ascii-dist` |

更新主题时，同时更新版本、下载地址、摘要和哪吒主题元数据，再运行 `make ci` 验证。构建过程不得使用不固定版本的 latest 地址。

## 许可证与后续更新

根目录 [`LICENSE`](../LICENSE) 保留哪吒源码许可证，管理前端许可证保留于 [`web/admin/LICENSE`](../web/admin/LICENSE)。迁移其他上游代码时，应保留对应许可证、版权声明和来源信息。

上游更新先核对锁定基线与目标提交的差异，再将需要的修改迁入现有业务位置。更新源码、来源记录和锁文件应属于同一次可审查变更；本地完整检查通过后再提交 GitHub Actions CI。
