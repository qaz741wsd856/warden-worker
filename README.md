# Warden: A Bitwarden-compatible server for Cloudflare Workers

[![Powered by Cloudflare](https://img.shields.io/badge/Powered%20by-Cloudflare-F38020?logo=cloudflare&logoColor=white)](https://www.cloudflare.com/)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Deploy to Cloudflare Workers](https://img.shields.io/badge/Deploy%20to-Cloudflare%20Workers-orange?logo=cloudflare&logoColor=white)](https://workers.cloudflare.com/)

This project provides a self-hosted, Bitwarden-compatible server that can be deployed to Cloudflare Workers for free. It's designed to be low-maintenance, allowing you to "deploy and forget" without worrying about server management or recurring costs.

## Why another Bitwarden server?

While projects like [Vaultwarden](https://github.com/dani-garcia/vaultwarden) provide excellent self-hosted solutions, they still require you to manage a server or VPS. This can be a hassle, and if you forget to pay for your server, you could lose access to your passwords.

Warden aims to solve this problem by leveraging the Cloudflare Workers ecosystem. By deploying Warden to a Cloudflare Worker and using Cloudflare D1 for storage, you can have a completely free, serverless, and low-maintenance Bitwarden server.

## Features

* **Core Vault Functionality:** Create, read, update, and delete ciphers and folders.
* **File Attachments:** Optional Cloudflare KV or R2 storage for attachments.
* **TOTP Support:** Store and generate Time-based One-Time Passwords.
* **Bitwarden Compatible:** Works with official Bitwarden clients.
* **Free to Host:** Runs on Cloudflare's free tier.
* **Low Maintenance:** Deploy it once and forget about it.
* **Secure:** Your encrypted data lives in your Cloudflare D1 database.
* **Easy to Deploy:** Get up and running in minutes with the Wrangler CLI.

### Attachments Support

Warden supports file attachments using either **Cloudflare KV** or **Cloudflare R2** as the storage backend:

| Feature | KV | R2 |
|---------|----|----|  
| Max file size | **25 MB** (hard limit) | 100 MB (By request body size limit of Workers) |
| Credit card required | **No** | Yes |
| Streaming I/O | Yes | Yes |

**Backend selection:** R2 takes priority — if R2 is configured, it will be used. Otherwise, KV is used.

See the [deployment guide](docs/deployment.md) for setup details. R2 may incur additional costs; see [Cloudflare R2 pricing](https://developers.cloudflare.com/r2/pricing/).

## Current Status

**This project is not yet feature-complete**, ~~and it may never be~~. It currently supports the core functionality of a personal vault, including TOTP. However, it does **not** support the following features:

* Sharing
* 2FA login (except TOTP)
* Bitwarden Send
* Device and session management
* Emergency access
* Admin operations
* Organizations
* Other Bitwarden advanced features

There are no immediate plans to implement these features. The primary goal of this project is to provide a simple, free, and low-maintenance personal password manager.

## Compatibility

* **Browser Extensions:** Chrome, Firefox, Safari, etc. (Tested 2025.11.1 on Chrome)
* **Android App:** The official Bitwarden Android app. (Tested 2025.11.0)
* **iOS App:** The official Bitwarden iOS app. (Tested 2025.11.0)

## Demo

A demo instance is available at [warden.qqnt.de](https://warden.qqnt.de).

You can register a new account using an email ending with `@warden-worker.demo` (The email does not need verification).

If you decide to stop using the demo instance, please delete your account to make space for others.

It's highly recommended to deploy your own instance since the demo can hit the rate limit and be disabled by Cloudflare.

## Getting Started

- Choose a deployment path: [CLI Deployment](docs/deployment.md#cli-deployment) or [Github Actions Deployment](docs/deployment.md#cicd-deployment-with-github-actions).
- Set secrets and optional attachments per the deployment doc.
- Configure Bitwarden clients to point at your worker URL.

## Frontend (Web Vault)

The frontend is bundled with the Worker using [Cloudflare Workers Static Assets](https://developers.cloudflare.com/workers/static-assets/). The GitHub Actions workflows download a **pinned** [bw_web_builds](https://github.com/dani-garcia/bw_web_builds) (Vaultwarden web vault) release (default: `v2025.12.0`) and deploy it together with the backend. You can override it via GitHub Actions Variables (`BW_WEB_VERSION` for prod, `BW_WEB_VERSION_DEV` for dev), or set it to `latest` to follow upstream.

**How it works:**
- Static files (HTML, CSS, JS) are served directly by Cloudflare's edge network.
- API requests (`/api/*`, `/identity/*`) are routed to the Rust Worker.
- No separate Pages deployment or domain configuration needed.

**UI overrides (optional):**
- This project ships a small set of "lightweight self-host" UI tweaks in `public/css/`.
- In CI/CD (and optionally locally), we apply them after extracting `bw_web_builds`:
  - `bash scripts/apply-web-vault-overrides.sh public/web-vault`

> [!NOTE]
> Migrating from separate frontend deployment? If you previously deployed the frontend separately to Cloudflare Pages, you can delete the `warden-frontend` Pages project and re-setup the router for the worker. The frontend is now bundled with the Worker and no longer requires a separate deployment.

> [!WARNING]
> The web vault frontend comes from Vaultwarden and therefore exposes many advanced UI features, but most of them are non-functional. See [Current Status](#current-status).

## Configure Custom Domain (Optional)

The default `*.workers.dev` domain is disabled by default, since it may throw 1101 error. You can enable it by setting `workers_dev = true` in `wrangler.toml`.

If you want to use a custom domain instead of the default `*.workers.dev` domain, follow these steps:

### Step 1: Add DNS Record

1. Log in to [Cloudflare Dashboard](https://dash.cloudflare.com/)
2. Select your domain (e.g., `example.com`)
3. Go to **DNS** → **Records**
4. Click **Add record**:
   - **Type:** `A` (or `AAAA` for IPv6)
   - **Name:** your subdomain (e.g., `vault` for `vault.example.com`)
   - **IPv4 address:** `192.0.2.1` (this is a placeholder, the actual routing is handled by Worker)
   - **Proxy status:** **Proxied** (orange cloud icon - this is required!)
   - **TTL:** Auto
5. Click **Save**

> [!IMPORTANT]
> The **Proxy status must be "Proxied"** (orange cloud). If it shows "DNS only" (gray cloud), Worker routes will not work.

### Step 2: Add Worker Route

1. Go to **Workers & Pages** → Select your `warden-worker`
2. Click **Settings** → **Domains & Routes**
3. Click **Add** → **Route**
4. Configure the route:
   - **Route:** `vault.example.com/*` (replace with your domain)
   - **Zone:** Select your domain zone
   - **Worker:** `warden-worker`
5. Click **Add route**

## Built-in Rate Limiting

This project includes rate limiting powered by [Cloudflare's Rate Limiting API](https://developers.cloudflare.com/workers/runtime-apis/bindings/rate-limit/). Sensitive endpoints are protected:

| Endpoint | Rate Limit | Key Type | Purpose |
|----------|------------|----------|---------|
| `/identity/connect/token` | 5 req/min | Email address | Prevent password brute force |
| `/api/accounts/register` | 5 req/min | IP address | Prevent mass registration & email enumeration |
| `/api/accounts/prelogin` | 5 req/min | IP address | Prevent email enumeration |

You can adjust the rate limit settings in `wrangler.toml`:

```toml
[[ratelimits]]
name = "LOGIN_RATE_LIMITER"
namespace_id = "1001"
# Adjust limit (requests) and period (10 or 60 seconds)
simple = { limit = 5, period = 60 }
```

> [!NOTE]
> The `period` must be either `10` or `60` seconds. See [Cloudflare documentation](https://developers.cloudflare.com/workers/runtime-apis/bindings/rate-limit/) for details.

If the binding is missing, requests proceed without rate limiting (graceful degradation).

## Configuration

### Durable Objects (CPU Offloading)

Cloudflare Workers Free plan has a very small per-request CPU budget. Two kinds of endpoints are particularly CPU-heavy:

- import endpoint: large JSON payload (typically 500kB–1MB) + parsing + batch inserts.
- registration, login and password verification endpoint: server-side PBKDF2 for password verification.

To keep the main Worker fast while still supporting these operations, Warden can **offload selected endpoints to Durable Objects (DO)**:

- **Heavy DO (`HEAVY_DO`)**: implemented in Rust as `HeavyDo` (reuses the existing axum router) so CPU-heavy endpoints can run with a higher CPU budget.

**How to enable/disable**

Whether CPU-heavy endpoints are offloaded is determined by whether the `HEAVY_DO` Durable Object binding is configured in `wrangler.toml`.

> [!NOTE]
> Durable Objects have much higher CPU budget of 30 seconds per request in free plan(see [Cloudflare Durable Objects limits](https://developers.cloudflare.com/durable-objects/platform/limits/)), so we can use it to offload the CPU-heavy endpoints.
>
> Durable Objects can incur two types of billing: compute and storage. Storage is not used in this project, and the free plan allows 100,000 requests and 13,000 GB-s duration per day, which should be more than enough for most users. See [Cloudflare Durable Objects pricing](https://developers.cloudflare.com/durable-objects/platform/pricing/) for details.
>
> If you choose to disable Durable Objects, you may need subscribe to a paid plan to avoid being throttled by Cloudflare.

### Environment Variables

Configure environment variables in `wrangler.toml` under `[vars]`, or set them via Cloudflare Dashboard:

* **`PASSWORD_ITERATIONS`** (Optional, Default: `600000`):
  - PBKDF2 iterations for server-side password hashing.
  - Minimum is 600000.
* **`TRASH_AUTO_DELETE_DAYS`** (Optional, Default: `30`): 
  - Days to keep soft-deleted items before purge. 
  - Set to `0` or negative to disable.
* **`IMPORT_BATCH_SIZE`** (Optional, Default: `30`): 
  - Batch size for import/delete operations. 
  - `0` disables batching.
* **`DISABLE_USER_REGISTRATION`** (Optional, Default: `true`): 
  - Controls showing the registration button in the client UI (server behavior unchanged).
* **`AUTHENTICATOR_DISABLE_TIME_DRIFT`** (Optional, Default: `false`): 
  - Set to `true` to disable ±1 time step drift for TOTP validation.
* **`ATTACHMENT_MAX_BYTES`** (Optional): 
  - Max size for individual attachment files. 
  - Example: `104857600` for 100MB.
* **`ATTACHMENT_TOTAL_LIMIT_KB`** (Optional): 
  - Max total attachment storage per user in KB. 
  - Example: `1048576` for 1GB.
* **`ATTACHMENT_TTL_SECS`** (Optional, Default: `300`, Minimum: `60`): 
  - TTL for attachment upload/download URLs.

### Scheduled Tasks (Cron)

The worker runs a scheduled task to clean up soft-deleted items. By default, it runs daily at 03:00 UTC (`wrangler.toml` `[triggers]` cron `"0 3 * * *"`). Adjust as needed; see [Cloudflare Cron Triggers documentation](https://developers.cloudflare.com/workers/configuration/cron-triggers/) for cron expression syntax.

## Database Operations

- **Backup & restore:** See [Database Backup & Restore](docs/db-backup-recovery.md#github-actions-backups) for automated backups and manual restoration steps.
- **Time Travel:** See [D1 Time Travel](docs/db-backup-recovery.md#d1-time-travel-point-in-time-recovery) to restore to a point in time.
- **Seeding Global Equivalent Domains (optional):** See [docs/deployment.md](docs/deployment.md) for seeding in CLI deploy and CI/CD.
- **Local dev with D1:**
  - Quick start: `wrangler dev --persist`
  - Full stack (with web vault): download frontend assets as in deployment doc, then `wrangler dev --persist`
  - Import a backup locally: `wrangler d1 execute vault1 --file=backup.sql`
  - Inspect local DB: SQLite file under `.wrangler/state/v3/d1/`

## Local Development with D1

Run the Worker locally with D1 support using Wrangler.

**Quick start (API-only):**

```bash
wrangler dev --persist
```

**Full stack (with Web Vault):**

1. Download the frontend assets (see [deployment doc](docs/deployment.md#download-the-frontend-web-vault)).
2. Start locally:

   ```bash
   wrangler dev --persist
   ```

3. Access the vault at `http://localhost:8787`.

**Using production data temporarily:**

1. Download and decrypt a backup (see [backup doc](docs/db-backup-recovery.md#restoring-database-to-cloudflare-d1)).
2. Import locally without `--remote`:

   ```bash
   wrangler d1 execute vault1 --file=backup.sql
   ```

3. Start `wrangler dev --persist` and point clients to `http://localhost:8787`.

**Inspect local SQLite:**

```bash
ls .wrangler/state/v3/d1/
sqlite3 .wrangler/state/v3/d1/miniflare-D1DatabaseObject/*.sqlite
```

> [!NOTE]
> Local dev requires Node.js and Wrangler. The Worker runs in a simulated environment via [workerd](https://github.com/cloudflare/workerd).

## Contributing

Issues and PRs are welcome. Please run `cargo fmt` and `cargo clippy --target wasm32-unknown-unknown --no-deps` before submitting.

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.
