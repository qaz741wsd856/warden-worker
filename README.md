# Warden: A Bitwarden-compatible server for Cloudflare Workers

This project provides a self-hosted, Bitwarden-compatible server that can be deployed to Cloudflare Workers for free. It's designed to be low-maintenance, allowing you to "deploy and forget" without worrying about server management or recurring costs.

## Why another Bitwarden server?

While projects like [Vaultwarden](https://github.com/dani-garcia/vaultwarden) provide excellent self-hosted solutions, they still require you to manage a server or VPS. This can be a hassle, and if you forget to pay for your server, you could lose access to your passwords.

Warden aims to solve this problem by leveraging the Cloudflare Workers ecosystem. By deploying Warden to a Cloudflare Worker and using Cloudflare D1 for storage, you can have a completely free, serverless, and low-maintenance Bitwarden server.

## Features

*   **Core Vault Functionality:** All your basic vault operations are supported, including creating, reading, updating, and deleting ciphers and folders.
*   **TOTP Support:** Store and generate Time-based One-Time Passwords for your accounts.
*   **Bitwarden Compatible:** Works with the official Bitwarden browser extensions and Android app (iOS is untested).
*   **Free to Host:** Runs on Cloudflare's free tier.
*   **Low Maintenance:** Deploy it once and forget about it.
*   **Secure:** Your data is stored in your own Cloudflare D1 database.
*   **Easy to Deploy:** Get up and running in minutes with the Wrangler CLI.

## Current Status

**This project is not yet feature-complete.** It currently supports the core functionality of a personal vault, including TOTP. However, it does **not** support the following features:

*   Sharing
*   Bitwarden Send
*   Organizations
*   Other Bitwarden advanced features

There are no immediate plans to implement these features. The primary goal of this project is to provide a simple, free, and low-maintenance personal password manager.

## Compatibility

*   **Browser Extensions:** Chrome, Firefox, Safari, etc.
*   **Android App:** The official Bitwarden Android app.
*   **iOS App:** Untested. If you have an iOS device, please test and report your findings!

## Getting Started

### Prerequisites

*   A Cloudflare account.
*   The [Wrangler CLI](https://developers.cloudflare.com/workers/wrangler/get-started/) installed and configured.

### Deployment

1.  **Clone the repository:**

    ```bash
    git clone https://github.com/your-username/warden-worker.git
    cd warden-worker
    ```

2.  **Create a D1 Database:**

    ```bash
    wrangler d1 create warden-db
    ```

3.  **Configure your Database ID:**

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

4.  **Download the frontend (Web Vault):**

    ```bash
    # Get latest version tag
    LATEST_TAG=$(curl -s https://api.github.com/repos/dani-garcia/bw_web_builds/releases/latest | jq -r .tag_name)

    # Download and extract
    wget "https://github.com/dani-garcia/bw_web_builds/releases/download/$LATEST_TAG/bw_web_${LATEST_TAG}.tar.gz"
    mkdir -p public
    tar -xzf bw_web_${LATEST_TAG}.tar.gz -C public/

    # Move files from web-vault subfolder
    shopt -s dotglob
    mv public/web-vault/* public/
    shopt -u dotglob
    rmdir public/web-vault
    rm bw_web_${LATEST_TAG}.tar.gz
    ```

5.  **Deploy the worker:**

    ```bash
    wrangler deploy
    ```

    This will deploy the worker and set up the necessary database tables.

6. **Set environment variables** as `Secret`

- `ALLOWED_EMAILS` (Optional) Comma-separated list of allowed emails (e.g., `your-email@example.com`). If not set, any email can register.
- `JWT_SECRET` a long random string
- `JWT_REFRESH_SECRET` a long random string

7.  **Configure your Bitwarden client:**

    In your Bitwarden client, go to the self-hosted login screen and enter the URL of your deployed worker (e.g., `https://warden-worker.your-username.workers.dev`).

### CI/CD Deployment with GitHub Actions

This project includes GitHub Actions workflows for automated deployment. This is the recommended approach for production environments as it ensures consistent builds and deployments.

#### Required Secrets

Add the following secrets to your GitHub repository (`Settings > Secrets and variables > Actions`):

| Secret | Required | Description |
|--------|----------|-------------|
| `CLOUDFLARE_API_TOKEN` | yes | Your Cloudflare API token |
| `CLOUDFLARE_ACCOUNT_ID` | yes | Your Cloudflare account ID |
| `D1_DATABASE_ID` | yes | Your production D1 database ID |

> ⚠️ **Important:** The `CLOUDFLARE_API_TOKEN` must have **both** Worker and D1 permissions:
> - **Edit Cloudflare Workers** - Required for deploying the Worker
> - **Edit D1** - Required for database migrations and backups
> 
> When creating the API token in Cloudflare Dashboard, make sure to add both permissions under "Account" → "Cloudflare Workers" and "Account" → "D1".

#### How to Get Your Cloudflare Account ID

1. Log in to the [Cloudflare Dashboard](https://dash.cloudflare.com/)
2. Select your account
3. Your Account ID is displayed in the right sidebar of the Overview page, or in the URL: `https://dash.cloudflare.com/<account-id>`

#### Usage

1.  **Fork or clone the repository** to your GitHub account

2.  **Configure the required secrets** in your repository settings

3.  **Manually trigger the `Build` Action** from the GitHub Actions tab in your repository

4.  **Monitor the deployment** in the Actions tab of your repository

5.  **Set environment variables** in the Cloudflare console (following the command line deployment steps):
    - `ALLOWED_EMAILS` (Optional) Comma-separated list of allowed emails (e.g., `your-email@example.com`). If not set, any email can register.
    - `JWT_SECRET` a long random string
    - `JWT_REFRESH_SECRET` a long random string

### Frontend (Web Vault)

The frontend is automatically bundled with the Worker deployment using [Cloudflare Workers Static Assets](https://developers.cloudflare.com/workers/static-assets/). The GitHub Actions workflow automatically downloads the latest [bw_web_builds](https://github.com/dani-garcia/bw_web_builds) (Vaultwarden web vault) and deploys it together with the backend.

**How it works:**
- Static files (HTML, CSS, JS) are served directly by Cloudflare's edge network
- API requests (`/api/*`, `/identity/*`) are routed to the Rust Worker
- No separate Pages deployment or domain configuration needed

> [!NOTE]
> **Migrating from separate frontend deployment?** If you previously deployed the frontend separately to Cloudflare Pages (using the old `deploy-frontend.yml` workflow), you can now delete the `warden-frontend` Pages project from your Cloudflare Dashboard and re-setup the router for worker. The frontend is now bundled with the Worker and no longer requires a separate deployment.

> ⚠️ **Important:** The web vault frontend comes from Vaultwarden and therefore **exposes many advanced UI features**, but most of them are **non-functional** because Warden Worker's backend intentionally does **NOT** implement the corresponding APIs. In practice, it mainly provides bulk management capabilities that aren't available in browser extensions. The following features (among others) are not supported:
> - Sharing vaults
> - Device management
> - Organizations
> - Send functionality
> - Emergency access
> - Admin console features
> - And many other advanced Bitwarden features

### Configure Custom Domain (Optional)

If you want to use a custom domain instead of the default `*.workers.dev` domain, follow these steps:

#### Step 1: Add DNS Record

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

> ⚠️ **Important:** The **Proxy status must be "Proxied"** (orange cloud). If it shows "DNS only" (gray cloud), Worker routes will not work.

#### Step 2: Add Worker Route

1. Go to **Workers & Pages** → Select your `warden-worker`
2. Click **Settings** → **Domains & Routes**
3. Click **Add** → **Route**
4. Configure the route:
   - **Route:** `vault.example.com/*` (replace with your domain)
   - **Zone:** Select your domain zone
   - **Worker:** `warden-worker`
5. Click **Add route**

### Configure Rate Limiting (Recommended)

To protect your authentication endpoints from brute force attacks, it's highly recommended to configure rate limiting rules:

1. **Navigate to Security Settings:**
   - In Cloudflare Dashboard, select your domain (e.g., `example.com`)
   - Go to **Security** → **WAF** → **Rate limiting rules**

2. **Create a rate limiting rule:**
   - Click **Create rule**
   - **Rule name:** `Limit Identity API`
   - **If incoming requests match...** 
     - Field: `URI Path`
     - Operator: `starts with`
     - Value: `/identity/`
   - **Then take action:**
     - Choose action: `Block` or `Managed Challenge`
     - **Rate limit:** Set requests per period (e.g., `10 requests per 1 minute`)
   - Click **Deploy**

   > **Tip:** You can also use the expression builder with: `(starts_with(http.request.uri.path, "/identity/"))`

3. **Optional - Additional security rules:**
   - Consider adding similar rules for `/api/accounts/` endpoints
   - You may also enable **Bot Fight Mode** under Security → Bots for additional protection

## Configuration

This project requires minimal configuration. The main configuration is done in the `wrangler.toml` file, where you specify your D1 database binding.

### Other Environment Variables

You can configure the following environment variables in `wrangler.toml` under the `[vars]` section, or set them via Cloudflare Dashboard:

*   **`TRASH_AUTO_DELETE_DAYS`** (Optional, Default: `30`)
    
    Number of days to keep soft-deleted items before automatically purging them. When a cipher is deleted, it's marked with a `deleted_at` timestamp (soft delete). After the specified number of days, the item will be permanently removed from the database.
    
    *   Set to `0` or a negative value to disable automatic purging
    *   Defaults to `30` days if not specified
    *   Example: `TRASH_AUTO_DELETE_DAYS = "7"` to keep deleted items for 7 days

*   **`IMPORT_BATCH_SIZE`** (Optional, Default: `30`)
    
    Number of records to process in each batch when importing and deleting data. This helps manage memory usage and processing time for large imports.
    
    *   Set to `0` to disable batching (all records imported in a single batch)
    *   Defaults to `30` records per batch if not specified
    *   Example: `IMPORT_BATCH_SIZE = "50"` to process 50 records per batch

*   **`DISABLE_USER_REGISTRATION`** (Optional, Default: `true`)
    
    Controls whether the "Create Account" / registration button is displayed in the Bitwarden client UI.
    
    *   Set to `false` to show the registration button
    *   Defaults to `true` (hide registration button)
    *   **Note:** This setting only affects the client UI display. It does NOT affect the actual registration functionality on the server side.

### Scheduled Tasks (Cron)

The worker includes a scheduled task that runs automatically to clean up soft-deleted items. By default, this task runs daily at 03:00 UTC.

*   **Automatic Cleanup:** The scheduled task automatically purges ciphers that have been soft-deleted for longer than the `TRASH_AUTO_DELETE_DAYS` period
*   **Schedule:** Configured in `wrangler.toml` under `[triggers]` section with cron expression `"0 3 * * *"` (daily at 03:00 UTC)

You can modify the cron schedule in `wrangler.toml` if you want to run the cleanup task at a different time or frequency. See [Cloudflare Cron Triggers documentation](https://developers.cloudflare.com/workers/configuration/cron-triggers/) for cron expression syntax.

### Database Backup (GitHub Actions)

> ⚠️ **Note:** To use this backup feature, you must fork this repository and configure the same three required secrets as described in the [CI/CD Deployment ](#cicd-deployment-with-github-actions) section in advance: `CLOUDFLARE_API_TOKEN`, `CLOUDFLARE_ACCOUNT_ID`, and `D1_DATABASE_ID`.

This project includes a GitHub Action workflow that automatically backs up your D1 database to S3-compatible storage daily. The backup runs at 04:00 UTC (1 hour after the cleanup task).

> ⚠️ **Important Notes:** 
> - **Manual trigger required for first run:** You must manually trigger the Action once (GitHub Actions → Backup D1 Database to S3 → Run workflow) before scheduled backups will run automatically.
> - **Ensure your S3 bucket is set to private access** to prevent data leaks and avoid unnecessary public traffic costs.
> - **⚠️ CRITICAL: Do NOT use R2 from the same Cloudflare account as your Worker** for backups. If your Cloudflare account gets suspended or banned, you will lose access to both your Worker and your backup storage, resulting in complete data loss. Always use a separate Cloudflare account or a different S3-compatible storage provider (AWS S3, Backblaze B2, MinIO, etc.) for backups to ensure redundancy and disaster recovery.

#### Required Secrets for Backup

Add the following secrets to your GitHub repository (`Settings > Secrets and variables > Actions`):

| Secret | Required | Description |
|--------|----------|-------------|
| `S3_ACCESS_KEY_ID` | yes | Your S3 access key ID |
| `S3_SECRET_ACCESS_KEY` | yes | Your S3 secret access key |
| `S3_BUCKET` | yes | The S3 bucket name for storing backups |
| `S3_REGION` | yes | The S3 region (e.g., `us-east-1`). If unsure, use `auto` |
| `S3_ENDPOINT` | no | Custom S3 endpoint URL. Defaults to AWS S3 if not set. Required for S3-compatible services (MinIO, Cloudflare R2, Backblaze B2, etc.) |
| `BACKUP_ENCRYPTION_KEY` | no | Optional encryption passphrase. If set, backups will be encrypted with AES-256. **Strongly recommended** since the database contains unencrypted user metadata (emails, item counts) |

#### Backup Features

*   **Automatic Daily Backups:** Production database is backed up daily at 04:00 UTC
*   **Manual Trigger:** You can manually trigger a backup from the GitHub Actions tab
*   **Environment Selection:** When triggering manually, you can choose to backup either `production` or `dev` database
*   **Compression:** Backups are compressed using gzip to save storage space
*   **Optional Encryption:** If `BACKUP_ENCRYPTION_KEY` is set, backups are encrypted with AES-256-CBC (PBKDF2 key derivation, 100k iterations)
*   **Automatic Cleanup:** Old backups older than 30 days are automatically deleted
*   **S3-Compatible:** Works with AWS S3, Cloudflare R2, MinIO, Backblaze B2, and any S3-compatible storage

#### Backup File Location

Backups are stored in your S3 bucket with the following structure:

```
# Unencrypted backups
s3://your-bucket/warden-worker/production/vault1_prod_YYYY-MM-DD_HH-MM-SS.sql.gz

# Encrypted backups (when BACKUP_ENCRYPTION_KEY is set)
s3://your-bucket/warden-worker/production/vault1_prod_YYYY-MM-DD_HH-MM-SS.sql.gz.enc
```

#### Decrypting Backups

If you enabled encryption, use the following command to decrypt a backup:

```bash
openssl enc -aes-256-cbc -d -pbkdf2 -iter 100000 \
  -in vault1_prod_YYYY-MM-DD_HH-MM-SS.sql.gz.enc \
  -out backup.sql.gz \
  -pass pass:"YOUR_ENCRYPTION_KEY"

# Then decompress
gunzip backup.sql.gz
```

#### Restoring Database to Cloudflare D1

To restore your D1 database from a backup:

1.  **Download the backup from S3:**

    ```bash
    # Using AWS CLI
    aws s3 cp s3://your-bucket/warden-worker/production/vault1_prod_YYYY-MM-DD_HH-MM-SS.sql.gz.enc ./
    
    # Or with custom endpoint (e.g., R2, MinIO)
    aws s3 cp s3://your-bucket/warden-worker/production/vault1_prod_YYYY-MM-DD_HH-MM-SS.sql.gz.enc ./ \
      --endpoint-url https://your-s3-endpoint.com
    ```

2.  **Decrypt the backup (if encrypted):**

    ```bash
    openssl enc -aes-256-cbc -d -pbkdf2 -iter 100000 \
      -in vault1_prod_YYYY-MM-DD_HH-MM-SS.sql.gz.enc \
      -out backup.sql.gz \
      -pass pass:"YOUR_ENCRYPTION_KEY"
    ```

3.  **Decompress the backup:**

    ```bash
    gunzip backup.sql.gz
    ```

4.  **Restore to Cloudflare D1:**

    First, find your database name using wrangler:

    ```bash
    wrangler d1 list
    ```

    This will show a table with your databases. Look for the `name` column (e.g., `warden-db` for production or `warden-dev` for dev).

    Then restore the backup:

    ```bash
    # Replace DATABASE_NAME with your actual database name (e.g., warden-db)
    
    # First, you may want to clear the existing database (optional, use with caution!)
    # wrangler d1 execute DATABASE_NAME --remote --command "DELETE FROM ciphers; DELETE FROM folders; DELETE FROM users;"
    
    # Import the backup
    wrangler d1 execute DATABASE_NAME --remote --file=backup.sql
    ```

    > **Note:** The `--remote` flag is required to execute against your production D1 database. Without it, the command will run against the local development database. 

    > ⚠️ **Troubleshooting: `no such table: main.users` error**
    > 
    > If you encounter this error when importing, it's because `wrangler d1 export` may output tables in an order that doesn't respect foreign key dependencies (e.g., `folders` table is created before `users` table, but `folders` has a foreign key referencing `users`).
    > 
    > **Solution:** Add `PRAGMA foreign_keys=OFF;` at the beginning of your backup.sql file to disable foreign key checks during import:
    > 
    > ```bash
    > # Prepend the PRAGMA statement to your backup file
    > echo -e "PRAGMA foreign_keys=OFF;\n$(cat backup.sql)" > backup.sql
    > 
    > # Then import as usual
    > wrangler d1 execute DATABASE_NAME --remote --file=backup.sql
    > ```
    > 
    > Alternatively, you can manually reorder the SQL statements in the backup file to ensure parent tables (`users`) are created before child tables (`folders`, `ciphers`).

#### D1 Time Travel (Point-in-Time Recovery)

Cloudflare D1 provides a built-in Time Travel feature that allows you to restore your database to any point within the last 30 days. This is useful for undoing accidental data modifications or deletions without needing a backup.

To use Time Travel:

1.  **Check current restore bookmark:**

    ```bash
    # Replace DATABASE_NAME with your actual database name (e.g., warden-db)
    wrangler d1 time-travel info DATABASE_NAME
    ```

2.  **Restore to a specific timestamp:**

    ```bash
    # Restore to a specific point in time (ISO 8601 format)
    wrangler d1 time-travel restore DATABASE_NAME --timestamp=2024-01-15T12:00:00Z
    
    # Or restore to a specific bookmark
    wrangler d1 time-travel restore DATABASE_NAME --bookmark=<bookmark_id>
    ```

> **Note:** Time Travel retains data for 30 days on the free tier. See [Cloudflare D1 Time Travel documentation](https://developers.cloudflare.com/d1/reference/time-travel/) for more details.

### Local Development with D1

You can run this Worker locally with full D1 database support using Wrangler. This is useful for development, testing, or as a temporary fallback when Cloudflare services are unavailable.

#### Quick Start (API-only, no frontend)

```bash
wrangler dev --persist
```

This starts the backend API at `http://localhost:8787`. You can use Bitwarden browser extensions or mobile apps directly.

#### Full Stack Development (with Web Vault frontend)

1.  **Download the frontend:**

    ```bash
    # Get latest version tag
    LATEST_TAG=$(curl -s https://api.github.com/repos/dani-garcia/bw_web_builds/releases/latest | jq -r .tag_name)
    
    # Download and extract
    wget "https://github.com/dani-garcia/bw_web_builds/releases/download/$LATEST_TAG/bw_web_${LATEST_TAG}.tar.gz"
    mkdir -p public
    tar -xzf bw_web_${LATEST_TAG}.tar.gz -C public/
    
    # Move files from web-vault subfolder
    shopt -s dotglob
    mv public/web-vault/* public/
    shopt -u dotglob
    rmdir public/web-vault
    rm bw_web_${LATEST_TAG}.tar.gz
    ```

2.  **Start the local server:**

    ```bash
    wrangler dev --persist
    ```

3.  **Access the Web Vault** at `http://localhost:8787`

#### Running with Production Data (Emergency Fallback)

1.  **Download and decrypt your backup** (follow the backup restore steps above)

2.  **Import the backup to local D1:**

    ```bash
    # Without --remote flag, this imports to local database
    wrangler d1 execute vault1 --file=backup.sql
    ```

3.  **Start the local server with persistence:**

    ```bash
    wrangler dev --persist
    ```

4.  **Configure your Bitwarden client** to use `http://localhost:8787` (or your local network IP for mobile devices)

#### Accessing Local SQLite Database Directly

The local D1 database is stored as a SQLite file. You can access it directly:

```bash
# Find the database file
ls .wrangler/state/v3/d1/

# Open with SQLite CLI
sqlite3 .wrangler/state/v3/d1/miniflare-D1DatabaseObject/*.sqlite

# Example: List all users
sqlite> SELECT email FROM users;
```

> **Note:** The local development environment requires Node.js and Wrangler installed. The Worker runs in a simulated environment using [workerd](https://github.com/cloudflare/workerd), Cloudflare's open-source Workers runtime.

## Contributing

Contributions are welcome! If you find a bug, have a feature request, or want to improve the code, please open an issue or submit a pull request.

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.
