# Deployment

This page covers the available deployment paths. Pick the one that fits your workflow and infrastructure.

- **CLI** — build and `wrangler deploy` from your machine.
- **Cloudflare Workers Builds** — connect the repo in the Cloudflare dashboard; `git push` builds and deploys on Cloudflare. No GitHub Actions needed.
- **GitHub Actions** — build and deploy from CI (kept as a manual fallback).

## CLI Deployment

1. **Clone the repository:**

   ```bash
   git clone https://github.com/your-username/warden-worker.git
   cd warden-worker
   ```

2. **Create a D1 Database:**

   ```bash
   wrangler d1 create warden-db
   ```

3. **(Optional) Enable R2 Bucket for Attachments:**

   Warden uses KV for attachments storage by default. If you want to use R2 as storage backend:

   ```bash
   # Create the production bucket
   wrangler r2 bucket create warden-attachments
   ```

   Then enable the R2 binding in `wrangler.toml` by uncommenting the R2 bucket configuration sections.

   **Note:** Attachments are optional. If you remove both KV and R2 bindings, attachment functionality will be disabled but all other features will work normally.

4. **Configure your Database ID:**

   When you create a D1 database, Wrangler will output the `database_id`. To avoid committing this secret to your repository, this project uses an environment variable to configure the database ID.

   You have two options:

   **Option 1: (Recommended) Use a `.env` file:**

   Create a file named `.env` in the root of the project and add the following line, replacing the placeholder with your actual `database_id`:

   ```
   D1_DATABASE_ID="your-database-id-goes-here"
   ```

   Make sure to add the `.env` file to your `.gitignore` file to prevent it from being committed to git.

   **Option 2: Set an environment variable in your shell:**

   You can set the environment variable in your shell before deploying:

   ```bash
   export D1_DATABASE_ID="your-database-id-goes-here"
   wrangler deploy
   ```

5. **Download the frontend (Web Vault):**

   ```bash
   # Default pinned version (override by exporting BW_WEB_VERSION)
   BW_WEB_VERSION="${BW_WEB_VERSION:-v2026.4.1}"
   if [ "${BW_WEB_VERSION}" = "latest" ]; then
     BW_WEB_VERSION="$(curl -s https://api.github.com/repos/dani-garcia/bw_web_builds/releases/latest | jq -r .tag_name)"
   fi

   # Download and extract
   wget "https://github.com/dani-garcia/bw_web_builds/releases/download/${BW_WEB_VERSION}/bw_web_${BW_WEB_VERSION}.tar.gz"
   tar -xzf "bw_web_${BW_WEB_VERSION}.tar.gz" -C public/
   rm "bw_web_${BW_WEB_VERSION}.tar.gz"

   # Remove large source maps to satisfy Cloudflare static asset per-file limits
   find public/web-vault -type f -name '*.map' -delete
   ```

   **Optional:** Apply lightweight UI overrides to generate `public/web-vault/css/vaultwarden.css`:

   ```bash
   mkdir -p public/web-vault/css/ && cp public/css/vaultwarden.css public/web-vault/css/
   ```

6. **Set up database and deploy the worker:**

   ```bash
   # Only run once before first deployment
   wrangler d1 execute vault1 --file sql/schema.sql --remote
   # For migrations
   wrangler d1 migrations apply vault1 --remote

   # (Optional) Seed global equivalent domains into D1
   # This downloads Vaultwarden's global_domains.json by default.
   bash scripts/seed-global-domains.sh --db vault1 --remote
   
   wrangler deploy
   ```

   This will deploy the worker and set up the necessary database tables.

7. **Set environment variables** as `Secret`

- `ALLOWED_EMAILS` your-email@example.com (supports glob patterns like `*@example.com`)
- `JWT_SECRET` a long random string
- `JWT_REFRESH_SECRET` a long random string

   **Optional mobile push relay settings:**  
     `PUSH_ENABLED=true`, `PUSH_RELAY_URI`, `PUSH_IDENTITY_URI` as text variables;  
     `PUSH_INSTALLATION_ID`, `PUSH_INSTALLATION_KEY` as secret variables.  
     See [Mobile Push Notifications](../README.md#mobile-push-notifications-optional) for more details.

8. **Configure your Bitwarden client:**

   In your Bitwarden client, go to the self-hosted login screen and enter the URL of your deployed worker.

   By default, the `*.workers.dev` domain is disabled, since it may throw 1101 error. It's highly recommended to use a custom domain instead; see [Configure Custom Domain](../README.md#configure-custom-domain-optional) for more details.

## Cloudflare Workers Builds (Dashboard)

[Workers Builds](https://developers.cloudflare.com/workers/ci-cd/builds/) is Cloudflare's native Git integration: connect the repository once in the dashboard and every push builds and deploys the Worker on Cloudflare — no GitHub Actions, no API token stored in GitHub.

Because this is a Rust→WASM Worker (the Workers Builds image does not ship Rust) and the frontend, database id, and migrations are all resolved at build time, the whole pipeline is encapsulated in [`scripts/cf-build.sh`](../scripts/cf-build.sh). It installs the Rust toolchain, downloads the Web Vault frontend, substitutes the D1 database id, bootstraps/migrates D1, optionally seeds global domains, and compiles the Worker.

### Setup

1. In the Cloudflare dashboard, go to **Workers & Pages → `warden-worker` → Settings → Build**, then **Connect** your GitHub/GitLab repository (production branch: `main`).

2. Set the build commands:

   | Field | Value |
   |-------|-------|
   | **Build command** | `bash scripts/cf-build.sh` |
   | **Deploy command** | `export PATH="$HOME/.cargo/bin:$PATH" && npx --yes wrangler@4.82.1 deploy` |

   > The Deploy command prepends `$HOME/.cargo/bin` to `PATH` so that `wrangler deploy` can find `cargo`/`worker-build` (installed during the build phase) when it re-runs `wrangler.toml`'s `[build]` step. Keep the pinned `wrangler` version in sync with `WRANGLER_VERSION`.

3. Add **Build variables and secrets** (Settings → Build → *Variables and Secrets*):

   | Name | Type | Required | Description |
   |------|------|----------|-------------|
   | `D1_DATABASE_ID` | variable | yes | Production D1 database id (substituted into `wrangler.toml`) |
   | `CLOUDFLARE_ACCOUNT_ID` | variable | yes | Your Cloudflare account id |
   | `CLOUDFLARE_API_TOKEN` | secret | yes | Token with **Workers** + **D1** (+ **KV**) edit permissions — used for migrations/seed and deploy |
   | `BW_WEB_VERSION` | variable | no | `bw_web_builds` tag (default `v2026.4.1`); set `latest` to track upstream |
   | `WRANGLER_VERSION` | variable | no | Pinned wrangler (default `4.82.1`; match the Deploy command) |
   | `WORKER_BUILD_VERSION` | variable | no | Pinned worker-build (default `0.8.3`; match the `worker` dep in `Cargo.toml`) |
   | `R2_NAME` | variable | no | R2 bucket name; enables the `ATTACHMENTS_BUCKET` binding |
   | `SEED_GLOBAL_DOMAINS` | variable | no | `false` to skip seeding global equivalent domains |
   | `GLOBAL_DOMAINS_URL` | variable | no | Pin a specific `global_domains.json` source |
   | `SKIP_D1` | variable | no | `1` to skip all D1 bootstrap/migrate/seed steps |

   See [Required Secrets](#required-secrets) below for how to obtain the account id and API token (the permissions are identical to the GitHub Actions path).

4. Set the runtime **Worker** secrets (these are *not* build variables — set them under the Worker's **Settings → Variables and Secrets**, not the build config): `ALLOWED_EMAILS`, `JWT_SECRET`, `JWT_REFRESH_SECRET`, plus any optional push settings. See step 7 of [CLI Deployment](#cli-deployment).

5. **Push to `main`.** Cloudflare runs `scripts/cf-build.sh` then `wrangler deploy`. Watch progress under the Worker's **Builds** tab.

> [!NOTE]
> The first build is slow (it compiles the Rust toolchain dependencies and `worker-build` from scratch). Subsequent builds reuse the build cache and are faster.

> [!IMPORTANT]
> Once Workers Builds is connected, the `Build` GitHub Actions workflow no longer deploys on push (its `push` trigger is disabled) to avoid double-deploying `main`. You can still run it manually from the Actions tab.

## CI/CD Deployment with GitHub Actions

This project includes GitHub Actions workflows for automated deployment. This is an alternative to Workers Builds; it ensures consistent builds and deployments from CI.

> [!NOTE]
> The production `Build` workflow's `push` trigger is disabled in favor of Workers Builds (above). To use GitHub Actions for production instead, either run it manually (Actions → *Build* → *Run workflow*) or re-enable the `push` trigger in `.github/workflows/push-cloudflare.yaml` and disconnect Workers Builds to avoid double-deploys.

### Required Secrets

Add the following secrets to your GitHub repository (`Settings > Secrets and variables > Actions`):

| Secret | Required | Description |
|--------|----------|-------------|
| `CLOUDFLARE_API_TOKEN` | yes | Your Cloudflare API token |
| `CLOUDFLARE_ACCOUNT_ID` | yes | Your Cloudflare account ID |
| `D1_DATABASE_ID` | yes | Your production D1 database ID |
| `D1_DATABASE_ID_DEV` | no | Dev D1 database ID (required only if you use the `Deploy Dev` workflow on the `dev` branch) |

#### How to Get Your Cloudflare Account ID

1. Log in to the [Cloudflare Dashboard](https://dash.cloudflare.com/)
2. Select your account
3. Your Account ID is displayed in the right sidebar of the Overview page, or in the URL: `https://dash.cloudflare.com/<account-id>`

#### How to Get Your Cloudflare API Token

The `CLOUDFLARE_API_TOKEN` requires the following permissions:
- **Edit Cloudflare Workers**: Required for deploying the Worker
- **Edit D1**: Required for database migrations and backups
- **Edit KV**: Required for attachments storage (if using KV)

1. Visit [https://dash.cloudflare.com/profile/api-tokens](https://dash.cloudflare.com/profile/api-tokens)
2. Click **Create Token**
3. Use the **Edit Cloudflare Workers** template
4. Add **Account** → **D1** under `Permissions`
5. Select `Account Resources` and `Zone Resources`
6. Click **Continue to Summary** and then **Create Token**

### Optional Variables

#### Web Vault frontend version

You can pin/override the bundled Web Vault (bw_web_builds) version via GitHub Actions Variables:

| Variable | Applies to | Default | Example | Notes |
|----------|------------|---------|---------|-------|
| `BW_WEB_VERSION` | prod (`main/uat/release*`) | `v2026.4.1` | `v2026.4.1` | Set to `latest` to follow upstream latest release |
| `BW_WEB_VERSION_DEV` | dev (`dev`) | `v2026.4.1` | `v2026.4.1` | Set to `latest` to follow upstream latest release |

#### Global Equivalent Domains

Bitwarden clients use `globalEquivalentDomains` for URI matching across well-known domain groups.

To avoid bundling a large JSON file into the Worker, the dataset can be stored in D1 and seeded during deploy.

| Variable | Applies to | Default | Example | Notes |
|----------|------------|---------|---------|-------|
| `SEED_GLOBAL_DOMAINS` | prod + dev | `true` | `false` | Set to `false` to skip seeding (API returns empty list) |
| `GLOBAL_DOMAINS_URL` | prod | (empty) | raw GitHub URL | Optional: pin a specific Vaultwarden tag/commit for reproducible deploys |
| `GLOBAL_DOMAINS_URL_DEV` | dev | (empty) | raw GitHub URL | Same as prod, but for dev workflow |

If you skip seeding, `/api/settings/domains` and `/api/sync` will return `globalEquivalentDomains: []`.

### Usage

1. **Fork or clone the repository** to your GitHub account

2. **Configure the required secrets** in your repository settings

3. **(Optional) Enable R2 bucket for attachments:**

   Warden uses KV for attachments storage by default. If you want to use R2 as storage backend:

   1. **Create R2 buckets in Cloudflare Dashboard before running the action:**
      - Go to **Storage & databases** → **R2** → **Create bucket**
      - Create a production bucket (e.g., `warden-attachments`)

   2. **Add the bucket names as GitHub Action secrets:**
      - `R2_NAME` → production bucket name

   The workflows will auto-append the `ATTACHMENTS_BUCKET` binding into `wrangler.toml` when these secrets are present - no manual binding in the Cloudflare console is required.

4. **Manually trigger the `Build` Action** from the GitHub Actions tab in your repository

5. **Monitor the deployment** in the Actions tab of your repository

6. **Set environment variables** as `secret` in the Cloudflare dashboard (following the command line deployment steps):
   - `ALLOWED_EMAILS` your-email@example.com (supports glob patterns like `*@example.com`, comma separated)
   - `JWT_SECRET` a long random string
   - `JWT_REFRESH_SECRET` a long random string
   - Optional mobile push settings:
     `PUSH_ENABLED=true`, `PUSH_RELAY_URI`, `PUSH_IDENTITY_URI`, `PUSH_INSTALLATION_ID`, `PUSH_INSTALLATION_KEY`.  
     See [Mobile Push Notifications](../README.md#mobile-push-notifications-optional) for more details.


> [!IMPORTANT]
> The server can't work without these three environment variables. If you forget to set them, the server will crash.

If you want to show a 'Create account' button in frontend, you can add `DISABLE_USER_REGISTRATION` as `text` and set it to `false`. Check [Environment Variables](../README.md#environment-variables) for more details.

By default, the `*.workers.dev` domain is disabled, since it may throw 1101 error. It's highly recommended to use a custom domain instead; see [Configure Custom Domain](../README.md#configure-custom-domain-optional) for more details.
