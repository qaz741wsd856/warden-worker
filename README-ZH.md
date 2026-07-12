# Warden：适用于 Cloudflare Workers 的 Bitwarden 兼容服务器

该项目提供了一个自托管的、与 Bitwarden 兼容的服务器，可以**免费**部署到 Cloudflare Workers 上。它旨在实现低维护成本，让你能够“即布即忘（deploy and forget）”，无需担心服务器管理或持续的续费成本。

## 为什么需要另一个 Bitwarden 服务器？

虽然像 [Vaultwarden](https://github.com/dani-garcia/vaultwarden) 这样的项目提供了非常优秀的自托管解决方案，但它们仍然需要你来管理服务器或 VPS。这可能会很麻烦，而且如果你忘记为服务器续费，你可能会失去对密码库的访问权限。

Warden 旨在通过利用 Cloudflare Workers 生态系统来解决这个问题。通过将 Warden 部署到 Cloudflare Worker 并使用 Cloudflare D1 作为存储，你可以拥有一个完全免费、Serverless（无服务器）且低维护成本的 Bitwarden 服务器。

## 功能特性

* **核心密码库功能：** 创建、读取、更新和删除密码凭据（ciphers）和文件夹。
* **文件附件：** 可选使用 Cloudflare KV 或 R2 存储来支持附件。
* **Bitwarden Send：** 通过链接共享加密的文本或文件。
* **设备管理：** 查看并注销活跃的会话。
* **实时同步与推送通知：** 通过 WebSocket 实现实时密码库更新，并支持移动端推送信标。
* **TOTP 支持：** 存储并生成基于时间的一次性密码（两步验证码）。
* **Bitwarden 兼容：** 完美适配官方的 Bitwarden 客户端。
* **免费托管：** 运行在 Cloudflare 的免费层（Free tier）上。
* **低维护：** 一次部署，终身无忧。
* **安全：** 你的加密数据全部存放在你自己的 Cloudflare D1 数据库中。
* **易于部署：** 使用 Wrangler CLI，几分钟内即可完成部署并运行。

### 附件支持

Warden 支持使用 **Cloudflare KV** 或 **Cloudflare R2** 作为存储后端来实现文件附件功能：

| 功能 | KV | R2 |
| --- | --- | --- |
| **最大文件限制** | **25 MB**（硬性限制） | 100 MB（受 Workers 请求体大小限制） |
| **需要绑定信用卡** | **不需要** | 需要 |
| **流式 I/O** | 支持 | 支持 |

**后端选择逻辑：** R2 具有更高优先级 —— 如果配置了 R2，将默认使用 R2；否则，将使用 KV。

具体配置步骤请参阅 [部署指南](https://www.google.com/search?q=docs/deployment.md)。使用 R2 可能会产生额外费用，请参考 [Cloudflare R2 价格标准](https://developers.cloudflare.com/r2/pricing/)。

### Bitwarden Send

* **文本 Send：** 默认开启，无需额外配置。
* **文件 Send：** 需要配置存储后端（KV 或 R2），限制与 [附件支持](https://www.google.com/search?q=%23%E9%99%84%E4%BB%B6%E6%94%AF%E6%8C%81) 相同。

> [!NOTE]
> 由于 D1 数据库单行大小限制为 2 MB，因此最大的文本 Send 大小约为 **1.8 MiB**。此外，`/api/sync` 接口会将当前用户所有的 Send 数据序列化到响应中。大量的 Send 或极大的文本 Send 会显著增加 CPU 时间和响应体积。

## 当前状态

**该项目尚未完全实现所有功能**，~~而且可能永远不会~~。它目前支持个人密码库的核心功能（包括 TOTP）。但是，它**不支持**以下功能：

* 组织与共享
* 2FA 登录（TOTP 凭据生成除外）
* 紧急访问
* 管理员操作（Admin 页面）
* 组织机构管理
* 其他 Bitwarden 高级企业功能

目前没有实施这些功能的紧迫计划。该项目的主要目标是提供一个简单、免费且低维护的个人密码管理器。

## 兼容性

* **浏览器扩展：** Chrome, Firefox, Safari 等（已在 Chrome 上测试过 2026.3.0 版本）
* **Android 应用：** 官方 Bitwarden 安卓客户端（已测试 2026.4.0 版本）
* **iOS 应用：** 官方 Bitwarden iOS 客户端（已测试 2026.4.0 版本）

## 演示 Demo

演示实例地址：[warden.qqnt.de](https://warden.qqnt.de)

你可以使用以 `@warden-worker.demo` 结尾的邮箱注册新账号（该邮箱不需要接收验证码验证）。

如果你决定停止使用演示实例，请删除你的账号以给他人留出空间。

**强烈建议部署你自己的实例**，因为演示实例可能会触及速率限制而被 Cloudflare 临时禁用。

## 快速入门

1. 选择一种部署途径：[CLI 部署](https://www.google.com/search?q=docs/deployment.md%23cli-deployment) 或 [通过 GitHub Actions 进行 CI/CD 部署](https://www.google.com/search?q=docs/deployment.md%23cicd-deployment-with-github-actions)。
2. 根据部署文档配置 Secrets 密钥和可选的附件存储。
3. 配置你的 Bitwarden 客户端，将自定服务器 URL 指向你的 Worker 网址。

## 前端 (Web Vault)

前端使用 [Cloudflare Workers Static Assets](https://developers.cloudflare.com/workers/static-assets/) 直接打包在 Worker 中。GitHub Actions 工作流会自动下载**指定版本**的 [bw_web_builds](https://github.com/dani-garcia/bw_web_builds)（即 Vaultwarden 的 Web 密码库）发行版（默认：`v2026.4.1`），并将其与后端一同部署。你可以通过 GitHub Actions 变量进行覆盖（生产环境为 `BW_WEB_VERSION`，开发环境为 `BW_WEB_VERSION_DEV`），或将其设为 `latest` 以跟随上游更新。

**工作原理：**

* 静态文件（HTML、CSS、JS）直接由 Cloudflare 的边缘网络（Edge Network）分发响应。
* API 请求（如 `/api/*`、`/identity/*`）会被路由转发给基于 Rust 的 Worker 后端。
* 无需单独部署 Cloudflare Pages 或配置额外的域名。

**UI 覆盖（可选）：**

* 该项目在 `public/css/` 中提供了一套精简的“轻量级自托管”UI 微调样式。
* 在 CI/CD（以及本地可选）过程中，解压 `bw_web_builds` 后会应用这些样式：
`mkdir -p public/web-vault/css/ && cp public/css/vaultwarden.css public/web-vault/css/`

> [!NOTE]
> **正在从旧版独立前端部署迁移？** 如果你之前将前端单独部署到了 Cloudflare Pages，现在可以放心地删除 `warden-frontend` Pages 项目，并为 Worker 重新配置路由。前端现已直接内嵌到 Worker 中，不再需要单独部署。

> [!WARNING]
> Web 密码库前端来源于 Vaultwarden，因此它会展示很多高级 UI 功能，但其中绝大多数在本项目中是**无法使用**的。详情请参见 [当前状态](https://www.google.com/search?q=%23%E5%BD%93%E5%89%8D%E7%8A%B6%E6%80%81)。

## 配置自定义域名（可选）

默认的 `*.workers.dev` 域名在本项目中是默认禁用的，因为它可能会抛出 1101 错误。你可以通过在 `wrangler.toml` 中设置 `workers_dev = true` 来启用它。

如果你想使用自己的自定义域名而不是默认的 `*.workers.dev` 域名，请按照以下步骤操作：

### 步骤 1：添加 DNS 记录

1. 登录 [Cloudflare 控制面板](https://dash.cloudflare.com/)。
2. 选择你的域名（例如 `example.com`）。
3. 前往 **DNS** → **记录 (Records)**。
4. 点击 **添加记录 (Add record)**：
* **类型：** `A`（如果是 IPv6 则选择 `AAAA`）
* **名称：** 你的子域名（例如，想使用 `vault.example.com` 则填 `vault`）
* **IPv4 地址：** `192.0.2.1`（这只是个占位符，实际路由会由 Worker 接管）
* **代理状态：** **已代理 (Proxied)**（必须是橙色云朵图标！）
* **TTL：** 自动


5. 点击 **保存**。

> [!IMPORTANT]
> **代理状态必须为“已代理”（橙色云朵）**。如果显示为“仅限 DNS”（灰色云朵），Worker 路由规则将无法生效。

### 步骤 2：添加 Worker 路由

1. 前往 **Workers & Pages** → 选择你的 `warden-worker`。
2. 点击 **设置 (Settings)** → **域名与路由 (Domains & Routes)**。
3. 点击 **添加 (Add)** → **路由 (Route)**。
4. 配置路由信息：
* **路由：** `vault.example.com/*`（替换为你的实际域名）
* **区域 (Zone)：** 选择你的域名所在的区域
* **Worker：** 选择 `warden-worker`


5. 点击 **添加路由**。

## 内置速率限制 (Rate Limiting)

该项目集成了由 [Cloudflare Rate Limiting API](https://developers.cloudflare.com/workers/runtime-apis/bindings/rate-limit/) 驱动的速率限制功能，对敏感接口进行了严格保护：

| 接口端点 | 速率限制 | 统计 Key 类型 | 目的 |
| --- | --- | --- | --- |
| `/identity/connect/token` | 5 次请求 / 分钟 | 电子邮箱地址 | 防止密码暴力破解 |
| `/api/accounts/register` | 5 次请求 / 分钟 | IP 地址 | 防止恶意批量注册及邮箱枚举 |
| `/api/accounts/prelogin` | 5 次请求 / 分钟 | IP 地址 | 防止邮箱枚举探测 |

你可以在 `wrangler.toml` 中调整频率限制设置：

```toml
[[ratelimits]]
name = "LOGIN_RATE_LIMITER"
namespace_id = "1001"
# 调整限制额度（请求数）和周期（可设为 10 或 60 秒）
simple = { limit = 5, period = 60 }

```

> [!NOTE]
> 这里的 `period` 周期必须是 `10` 秒或 `60` 秒。详情请查阅 [Cloudflare 官方文档](https://developers.cloudflare.com/workers/runtime-apis/bindings/rate-limit/)。

如果未绑定速率限制器，请求将直接放行（平稳退化，不影响核心业务）。

## 高级配置

### CPU 算力分流（通过 Durable Objects）

Cloudflare Workers 免费版计划的单次请求 CPU 时间预算（CPU budget）非常有限。有两种接口操作极其消耗 CPU 资源：

* **数据导入（Import）：** 庞大的 JSON 载荷（通常为 500kB–1MB） + 解析过程 + 批量数据库插入。
* **注册、登录及密码验证：** 服务器端为了验证密码需要运行高强度的 PBKDF2 哈希算法。

为了保证主 Worker 的轻快响应，同时顺利支持这些重度操作，Warden 可以**将特定的高能耗接口分流至 Durable Objects (DO) 中运行**：

* **Heavy DO (`HEAVY_DO`)：** 在 Rust 中实现为 `HeavyDo`（复用了现有的 axum 路由），使得高 CPU 消耗的接口可以在更高的 CPU 预算下平稳运行。

**如何启用/禁用：**

高能耗接口是否分流，取决于你是否在 `wrangler.toml` 中配置了 `HEAVY_DO` Durable Object 绑定。

> [!NOTE]
> 在免费计划中，Durable Objects 拥有高达单次请求 30 秒的 CPU 预算（参见 [Cloudflare Durable Objects 限制说明](https://developers.cloudflare.com/durable-objects/platform/limits/)），因此非常适合用来承载消耗 CPU 的重度接口。
> Durable Objects 可能会产生两类计费：计算和存储。本项目**没有使用** DO 存储，且免费计划每天允许 100,000 次请求和 13,000 GB-秒的持续时间，这对于绝大多数个人用户而言绰绰有余。详情请参见 [Cloudflare Durable Objects 计费标准](https://developers.cloudflare.com/durable-objects/platform/pricing/)。
> 如果你选择禁用 Durable Objects，你可能需要订阅 Cloudflare Paid 付费计划，以免因超支而被 Cloudflare 强制熔断。

### 实时同步与推送通知

Warden 支持两种机制的密码库数据实时同步：WebSocket 推送（适用于桌面端应用和浏览器扩展）以及移动端推送通知（适用于官方手机 App）。

**WebSocket 推送（桌面端与扩展）**

该功能由 Durable Objects 驱动。当在 `wrangler.toml` 中配置了 `NOTIFY_DO` Durable Object 绑定时，该功能默认开启。移除此绑定（及相关迁移）将会优雅地关闭 WebSocket 通知功能。

**移动端推送通知**

Warden 支持通过 Bitwarden 官方的推送中继服务（Push Relay Service）向官方移动端应用发送通知。

**设置步骤：**

1. 前往 [https://bitwarden.com/host/](https://bitwarden.com/host/) 获取属于你的 `Installation ID` 和 `Key`。
2. 通过 Cloudflare 控制面板或 `wrangler` CLI 将凭据保存为环境变量密钥（`PUSH_INSTALLATION_ID` 和 `PUSH_INSTALLATION_KEY`）。
3. 在 `wrangler.toml` 的 `[vars]` 中将 `PUSH_ENABLED` 设置为 `true`（或直接在 Cloudflare 控制面板中设置）来启用推送。

（可选）你可以通过设置 `PUSH_RELAY_URI` 和 `PUSH_IDENTITY_URI` 来覆盖默认的中继服务器地址（默认分别为 `https://push.bitwarden.com` 和 `https://identity.bitwarden.com`）。

如需了解详细的配置说明和故障排查，请参阅 [Vaultwarden 维基关于推送通知的说明](https://github.com/dani-garcia/vaultwarden/wiki/Enabling-Mobile-Client-push-notification)。

### 其他环境变量

在 `wrangler.toml` 的 `[vars]` 下配置这些环境变量，或者直接在 Cloudflare 控制面板中进行设置：

* **`BASE_URL`**（可选）：
* 覆盖自动提取的用于文件上传/下载的基准 URL。
* 格式：包含 HTTPS 协议、域名和端口（如果使用了非 443 的反向代理）。末尾不要加斜杠 `/`。
* 示例：`https://vault.example.com` 或 `https://vault.example.com:8443`
* 若未设置，将默认从传入的 HTTP 请求头中动态提取。


* **`PASSWORD_ITERATIONS`**（可选，默认：`600000`）：
* 用于服务器端密码哈希的 PBKDF2 迭代次数。
* 最小值必须为 600000。


* **`TRASH_AUTO_DELETE_DAYS`**（可选，默认：`30`）：
* 软删除（移入回收站）的项目在被彻底清空前保留的天数。
* 设置为 `0` 或负数将关闭自动清空功能。


* **`IMPORT_BATCH_SIZE`**（可选，默认：`30`）：
* 导入/删除操作的批处理大小。
* 设置为 `0` 将禁用批处理。


* **`DISABLE_USER_REGISTRATION`**（可选，默认：`true`）：
* 控制是否在客户端 UI 中显示注册按钮（仅影响 UI 展示，后端实际注册行为不受此限制）。


* **`AUTHENTICATOR_DISABLE_TIME_DRIFT`**（可选，默认：`false`）：
* 设置为 `true` 将禁用 TOTP 验证时 ±1 个步长的容错时间偏移。


* **`ATTACHMENT_MAX_BYTES`**（可选）：
* 单个附件文件的最大体积限制。
* 示例：`104857600` 代表 100MB。


* **`ATTACHMENT_TOTAL_LIMIT_KB`**（可选）：
* 每个用户可使用的总附件存储额度（单位：KB）。
* 示例：`1048576` 代表 1GB。


* **`ATTACHMENT_TTL_SECS`**（可选，默认：`300`，最小值：`60`）：
* 附件上传/下载预签名 URL 的有效寿命（TTL）。


* **`SEND_TEXT_MAX_BYTES`**（可选，默认：`1887436` ≈ 1.8 MiB）：
* 文本类型 Send 内容的最大体积。受限于 D1 数据库单行 2 MB 的物理限制。


* **`SEND_MAX_BYTES`**（可选，默认：`104857600` = 100 MiB）：
* 文件类型 Send 的最大文件体积。受限于与附件相同的 KV/R2 存储后端限制。


* **`USER_SEND_LIMIT_KB`**（可选）：
* 每个用户可用于 Send 文件的最大总存储额度（单位：KB）。


* **`SEND_TTL_SECS`**（可选，默认：`300`）：
* Send 文件上传/下载 URL 的有效寿命（TTL）。



### 定时任务 (Cron Triggers)

Worker 会运行一个定时任务来自动清理回收站中过期的软删除项目。默认情况下，它在每天的 UTC 时间 03:00 运行（即 `wrangler.toml` 中 `[triggers]` 定义的 cron `"0 3 * * *"`）。你可以根据需要调整它；语法请参考 [Cloudflare Cron Triggers 官方文档](https://developers.cloudflare.com/workers/configuration/cron-triggers/)。

## 数据库操作

* **备份与恢复：** 参考 [数据库备份与恢复指南](docs/db-backup-recovery.md%23github-actions-backups) 了解如何设置 GitHub Actions 自动备份以及手动还原数据库的步骤。
* **时空穿梭（Time Travel）：** 参阅 [D1 Time Travel](docs/db-backup-recovery.md%23d1-time-travel-point-in-time-recovery) 将数据库一键回滚还原到过去的某一个历史时间点。
* **预填充全球等效域名（可选）：** 参阅 [docs/deployment.md](docs/deployment.md) 了解如何在 CLI 部署和 CI/CD 中预填充等效域名数据（用于密码自动填充匹配）。
* **利用 D1 进行本地开发：**
* 快速启动：`wrangler dev --persist`
* 全栈开发（带 Web 密码库）：按照部署文档下载前端静态资源，然后运行 `wrangler dev --persist`
* 在本地导入备份：`wrangler d1 execute vault1 --file=backup.sql`
* 检查本地数据库：SQLite 文件存放在 `.wrangler/state/v3/d1/` 路径下



## 本地开发与 D1 调试

使用 Wrangler 在本地运行包含 D1 数据库支持的 Worker。

**快速启动（仅限 API 后端）：**

```bash
wrangler dev --persist

```

**全栈开发（包含 Web 密码库前端）：**

1. 下载前端静态资产（参见 [部署文档 - 下载前端 Web Vault](docs/deployment.md%23download-the-frontend-web-vault)）。
2. 在本地启动服务：
```bash
wrangler dev --persist

```


3. 通过浏览器访问 `http://localhost:8787` 打开密码库。

**临时使用生产环境数据：**

1. 下载并解密你的线上备份（参见 [备份文档 - 恢复数据库至 Cloudflare D1](docs/db-backup-recovery.md%23restoring-database-to-cloudflare-d1)）。
2. 在本地导入数据（**切勿**加 `--remote` 参数）：
```bash
wrangler d1 execute vault1 --file=backup.sql

```


3. 启动 `wrangler dev --persist` 并将你的客户端服务器地址指向 `http://localhost:8787`。

**查看本地 SQLite 数据库：**

```bash
ls .wrangler/state/v3/d1/
sqlite3 .wrangler/state/v3/d1/miniflare-D1DatabaseObject/*.sqlite

```

> [!NOTE]
> 本地开发需要环境中安装了 Node.js 和 Wrangler。Worker 会在基于 [workerd](https://github.com/cloudflare/workerd) 的模拟环境中运行。

## 更新你的 Fork 分支

如果你是通过 GitHub Fork 仓库进行部署的，保持代码与上游同步非常简单：

1. **关注新版本发布：** 在 [本仓库](https://github.com/betanightly/warden-worker) 页面上，点击 **Watch** → **Custom** → 勾选 **Releases**。每当有新版本发布时，你都会收到通知。
2. **同步你的 Fork：** 前往你自己 Fork 的 GitHub 仓库页面，点击 **Sync fork** → **Update branch**。这会将最新的上游代码合并到你 Fork 仓库的默认分支中。
3. **自动触发部署：** 如果你通过 GitHub Actions 设置了 CI/CD，推送到 `main` 分支的操作将自动触发构建并部署新版本到你的 Cloudflare Worker 中。整个过程无需任何人工干预。

> [!TIP]
> 强烈建议在上游发布新版本时及时同步你的 Fork 仓库，以确保你的实例始终拥有最新的功能特性和安全补丁。

## 贡献指南

欢迎提交 Issues 和 Pull Requests。在提交 PR 之前，请务必在本地运行 `cargo fmt` 和 `cargo clippy --target wasm32-unknown-unknown --no-deps` 进行代码格式化与规范检查。

## 开源协议

本项目基于 MIT 开源协议授权。详情请参阅 `LICENSE` 文件。
