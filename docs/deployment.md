# Deployment

This page covers the two deployment paths. Pick the one that fits your workflow and infrastructure.

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
   BW_WEB_VERSION="${BW_WEB_VERSION:-v2025.12.0}"
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
   bash scripts/apply-web-vault-overrides.sh public/web-vault
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

8. **Configure your Bitwarden client:**

   In your Bitwarden client, go to the self-hosted login screen and enter the URL of your deployed worker.

   By default, the `*.workers.dev` domain is disabled, since it may throw 1101 error. It's highly recommended to use a custom domain instead; see [Configure Custom Domain](../README.md#configure-custom-domain-optional) for more details.

## CI/CD Deployment with GitHub Actions

This project includes GitHub Actions workflows for automated deployment. This is the recommended approach for production environments as it ensures consistent builds and deployments.

### Required Secrets

Add the following secrets to your GitHub repository (`Settings > Secrets and variables > Actions`):

| Secret | Required | Description |
|--------|----------|-------------|
| `CLOUDFLARE_API_TOKEN` | yes | Your Cloudflare API token |
| `CLOUDFLARE_ACCOUNT_ID` | yes | Your Cloudflare account ID |
| `D1_DATABASE_ID` | yes | Your production D1 database ID |
| `D1_DATABASE_ID_DEV` | no | Dev D1 database ID (required only if you use the `Deploy Dev` workflow on the `dev` branch) |

### Optional Variables

#### Web Vault frontend version

You can pin/override the bundled Web Vault (bw_web_builds) version via GitHub Actions Variables:

| Variable | Applies to | Default | Example | Notes |
|----------|------------|---------|---------|-------|
| `BW_WEB_VERSION` | prod (`main/uat/release*`) | `v2025.12.0` | `v2025.12.0` | Set to `latest` to follow upstream latest release |
| `BW_WEB_VERSION_DEV` | dev (`dev`) | `v2025.12.0` | `v2025.12.0` | Set to `latest` to follow upstream latest release |

#### Global Equivalent Domains

Bitwarden clients use `globalEquivalentDomains` for URI matching across well-known domain groups.

To avoid bundling a large JSON file into the Worker, the dataset can be stored in D1 and seeded during deploy.

| Variable | Applies to | Default | Example | Notes |
|----------|------------|---------|---------|-------|
| `SEED_GLOBAL_DOMAINS` | prod + dev | `true` | `false` | Set to `false` to skip seeding (API returns empty list) |
| `GLOBAL_DOMAINS_URL` | prod | (empty) | raw GitHub URL | Optional: pin a specific Vaultwarden tag/commit for reproducible deploys |
| `GLOBAL_DOMAINS_URL_DEV` | dev | (empty) | raw GitHub URL | Same as prod, but for dev workflow |

If you skip seeding, `/api/settings/domains` and `/api/sync` will return `globalEquivalentDomains: []`.

> [!NOTE]
> The `CLOUDFLARE_API_TOKEN` must have **both** Worker and D1 permissions:
> - **Edit Cloudflare Workers** - Required for deploying the Worker
> - **Edit D1** - Required for database migrations and backups
> - **Edit KV** - Required for attachments storage (if using KV)
> 
> When creating the API token in Cloudflare Dashboard, make sure to add both permissions under "Account" → "Cloudflare Workers" and "Account" → "D1".

### How to Get Your Cloudflare Account ID

1. Log in to the [Cloudflare Dashboard](https://dash.cloudflare.com/)
2. Select your account
3. Your Account ID is displayed in the right sidebar of the Overview page, or in the URL: `https://dash.cloudflare.com/<account-id>`

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

6. **Set up tables in database manually** in the Cloudflare dashboard

7. **Set environment variables** as `secret` in the Cloudflare dashboard (following the command line deployment steps):
   - `ALLOWED_EMAILS` your-email@example.com (supports glob patterns like `*@example.com`)
   - `JWT_SECRET` a long random string
   - `JWT_REFRESH_SECRET` a long random string

By default, the `*.workers.dev` domain is disabled, since it may throw 1101 error. It's highly recommended to use a custom domain instead; see [Configure Custom Domain](../README.md#configure-custom-domain-optional) for more details.
