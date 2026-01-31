# Database Backup, Restore, and Time Travel

Centralize your D1 operational playbooks here: backup automation, restore flows, and point-in-time recovery.

## GitHub Actions Backups

> [!NOTE]
> To use this backup feature, you must fork this repository and configure the required Cloudflare secrets as described in the [CI/CD deployment](deployment.md#cicd-deployment-with-github-actions) section in advance: `CLOUDFLARE_API_TOKEN`, `CLOUDFLARE_ACCOUNT_ID`, and `D1_DATABASE_ID` (and `D1_DATABASE_ID_DEV` if you want to backup `dev`).

This project includes a GitHub Action workflow that automatically exports your D1 database and uploads the backup to one or more destinations (S3-compatible storage and/or WebDAV) daily. The backup runs at 04:00 UTC (1 hour after the cleanup task).

> [!NOTE]
> - **Manual trigger required for first run:** You must manually trigger the Action once (GitHub Actions → Backup D1 Database (S3/WebDAV) → Run workflow) before scheduled backups will run automatically.
> - **Ensure your S3 bucket is set to private access** to prevent data leaks and avoid unnecessary public traffic costs.
> - **⚠️ CRITICAL: Do NOT use R2 from the same Cloudflare account as your Worker** for backups. If your Cloudflare account gets suspended or banned, you will lose access to both your Worker and your backup storage, resulting in complete data loss. Always use a separate Cloudflare account or a different S3-compatible storage provider (AWS S3, Backblaze B2, MinIO, etc.) for backups to ensure redundancy and disaster recovery.
> - **Destinations are opt-in:** Upload steps run only when the corresponding secrets are configured. If you configure neither S3 nor WebDAV, the workflow will still export/compress/encrypt the backup but will not upload it anywhere.

### Backup Destination Secrets

Add the following secrets to your GitHub repository (`Settings > Secrets and variables > Actions`):

#### S3-compatible storage (optional)

| Secret | Required | Description |
|--------|----------|-------------|
| `S3_ACCESS_KEY_ID` | yes (for S3) | Your S3 access key ID |
| `S3_SECRET_ACCESS_KEY` | yes (for S3) | Your S3 secret access key |
| `S3_BUCKET` | yes (for S3) | The S3 bucket name for storing backups |
| `S3_REGION` | yes (for S3) | The S3 region (e.g., `us-east-1`). If unsure, use `auto` |
| `S3_ENDPOINT` | no | Custom S3 endpoint URL. Defaults to AWS S3 if not set. Required for S3-compatible services (MinIO, Cloudflare R2, Backblaze B2, etc.) |

#### WebDAV (optional)

| Secret | Required | Description |
|--------|----------|-------------|
| `WEBDAV_URL` | yes (for WebDAV) | WebDAV endpoint URL (e.g., Nextcloud: `https://example.com/remote.php/dav/files/<user>/`) |
| `WEBDAV_USER` | yes (for WebDAV) | WebDAV username |
| `WEBDAV_PASSWORD` | yes (for WebDAV) | WebDAV password |
| `WEBDAV_VENDOR` | no | WebDAV vendor for rclone (`nextcloud`, `owncloud`, or `other`). Defaults to `other` |
| `WEBDAV_BASE_PATH` | no | Base path for backups on the remote. Defaults to `warden-worker` |

#### Common (optional)

| Secret | Required | Description |
|--------|----------|-------------|
| `BACKUP_ENCRYPTION_KEY` | no | Optional encryption passphrase. If set, backups will be encrypted with AES-256. **Strongly recommended** since the database contains unencrypted user metadata (emails, item counts) |
| `BACKUP_RETENTION_DAYS` | no | Number of days to keep backups. Defaults to 30 |

### Backup Features

* **Automatic Daily Backups:** Production database is backed up daily at 04:00 UTC
* **Manual Trigger:** You can manually trigger a backup from the GitHub Actions tab
* **Environment Selection:** When triggering manually, you can choose to backup either `production` or `dev` database
* **Compression:** Backups are compressed using gzip to save storage space
* **Optional Encryption:** If `BACKUP_ENCRYPTION_KEY` is set, backups are encrypted with AES-256-CBC (PBKDF2 key derivation, 100k iterations)
* **Automatic Cleanup:** Old backups older than 30 days are automatically deleted
* **Destination-based uploads:** Upload steps run only when destination secrets are configured
* **S3-Compatible:** Works with AWS S3, Cloudflare R2, MinIO, Backblaze B2, and any S3-compatible storage
* **WebDAV:** Works with most WebDAV servers (including Nextcloud/ownCloud)

### Backup File Location

Backups are stored with the following structure:

```
# Unencrypted backups
s3://your-bucket/warden-worker/production/vault1_prod_YYYY-MM-DD_HH-MM-SS.sql.gz

# Encrypted backups (when BACKUP_ENCRYPTION_KEY is set)
s3://your-bucket/warden-worker/production/vault1_prod_YYYY-MM-DD_HH-MM-SS.sql.gz.enc

# WebDAV backups (WEBDAV_BASE_PATH defaults to warden-worker)
<WEBDAV_BASE_PATH>/production/vault1_prod_YYYY-MM-DD_HH-MM-SS.sql.gz
<WEBDAV_BASE_PATH>/production/vault1_prod_YYYY-MM-DD_HH-MM-SS.sql.gz.enc
```

### Decrypting Backups

If you enabled encryption, use the following command to decrypt a backup:

```bash
openssl enc -aes-256-cbc -d -pbkdf2 -iter 100000 \
  -in vault1_prod_YYYY-MM-DD_HH-MM-SS.sql.gz.enc \
  -out backup.sql.gz \
  -pass pass:"YOUR_ENCRYPTION_KEY"

# Then decompress
gunzip backup.sql.gz
```

### Restoring Database to Cloudflare D1

1. **Download the backup from S3:**

    ```bash
    # Using AWS CLI
    aws s3 cp s3://your-bucket/warden-worker/production/vault1_prod_YYYY-MM-DD_HH-MM-SS.sql.gz.enc ./
    
    # Or with custom endpoint (e.g., R2, MinIO)
    aws s3 cp s3://your-bucket/warden-worker/production/vault1_prod_YYYY-MM-DD_HH-MM-SS.sql.gz.enc ./ \
      --endpoint-url https://your-s3-endpoint.com
    ```

    Or from WebDAV (using rclone):

    ```bash
    rclone copy webdav:warden-worker/production/vault1_prod_YYYY-MM-DD_HH-MM-SS.sql.gz.enc ./
    ```

2. **Decrypt the backup (if encrypted):**

    ```bash
    openssl enc -aes-256-cbc -d -pbkdf2 -iter 100000 \
      -in vault1_prod_YYYY-MM-DD_HH-MM-SS.sql.gz.enc \
      -out backup.sql.gz \
      -pass pass:"YOUR_ENCRYPTION_KEY"
    ```

3. **Decompress the backup:**

    ```bash
    gunzip backup.sql.gz
    ```

4. **Restore to Cloudflare D1:**

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

    > [!NOTE]
    > The `--remote` flag is required to execute against your production D1 database. Without it, the command will run against the local development database. 

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

## D1 Time Travel (Point-in-Time Recovery)

Cloudflare D1 provides a built-in Time Travel feature that allows you to restore your database to any point within the last 30 days. This is useful for undoing accidental data modifications or deletions without needing a backup.

To use Time Travel:

1. **Check current restore bookmark:**

    ```bash
    # Replace DATABASE_NAME with your actual database name (e.g., warden-db)
    wrangler d1 time-travel info DATABASE_NAME
    ```

2. **Restore to a specific timestamp:**

    ```bash
    # Restore to a specific point in time (ISO 8601 format)
    wrangler d1 time-travel restore DATABASE_NAME --timestamp=2024-01-15T12:00:00Z
    
    # Or restore to a specific bookmark
    wrangler d1 time-travel restore DATABASE_NAME --bookmark=<bookmark_id>
    ```

> [!NOTE]
> Time Travel retains data for 30 days on the free tier. See [Cloudflare D1 Time Travel documentation](https://developers.cloudflare.com/d1/reference/time-travel/) for more details.
