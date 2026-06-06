#!/usr/bin/env bash
#
# scripts/cf-build.sh
#
# Self-contained build for Cloudflare Workers Builds (the dashboard Git
# integration). With this in place a plain `git push` makes Cloudflare build
# and deploy the Worker, with no GitHub Actions required.
#
# Configure it in the dashboard under:
#   Workers & Pages > warden-worker > Settings > Build
#
#   Build command:   bash scripts/cf-build.sh
#   Deploy command:  export PATH="$HOME/.cargo/bin:$PATH" && npx --yes wrangler@4.82.1 deploy
#
# Why the Deploy command tweaks PATH: this is a Rust->WASM Worker, but the
# Workers Builds image does not ship Rust. This script installs the toolchain
# into $HOME/.cargo during the build phase; `wrangler deploy` then re-runs
# worker-build (via wrangler.toml's [build] command) during the deploy phase,
# so cargo must be on PATH there too. Build and deploy share the same
# filesystem, so the toolchain installed here is still present at deploy time.
#
# This mirrors .github/workflows/push-cloudflare.yaml, minus the final deploy.
#
# Build variables / secrets (Settings > Build > "Variables and Secrets"):
#   D1_DATABASE_ID        (required)  production D1 database id
#   CLOUDFLARE_ACCOUNT_ID (required)  your Cloudflare account id
#   CLOUDFLARE_API_TOKEN  (secret)    token with Workers + D1 (+ KV) edit perms;
#                                     required to run migrations/seed (and used by deploy)
#   BW_WEB_VERSION        (optional)  bw_web_builds tag (default below); "latest" to track upstream
#   WRANGLER_VERSION      (optional)  pinned wrangler (default below; match the Deploy command)
#   WORKER_BUILD_VERSION  (optional)  pinned worker-build (default below; match the `worker` dep in Cargo.toml)
#   R2_NAME               (optional)  R2 bucket name; enables the ATTACHMENTS_BUCKET binding
#   SEED_GLOBAL_DOMAINS   (optional)  "false" to skip seeding global equivalent domains
#   GLOBAL_DOMAINS_URL    (optional)  pin a specific global_domains.json source
#   SKIP_D1               (optional)  "1" to skip all D1 bootstrap/migrate/seed steps
#
set -euo pipefail

# Run from the repository root regardless of where the script is invoked.
cd "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"

WORKER_BUILD_VERSION="${WORKER_BUILD_VERSION:-0.8.3}"
WRANGLER_VERSION="${WRANGLER_VERSION:-4.82.1}"
BW_WEB_VERSION="${BW_WEB_VERSION:-v2026.4.1}"
D1_NAME="${D1_NAME:-vault1}"
SEED_GLOBAL_DOMAINS="${SEED_GLOBAL_DOMAINS:-true}"
SKIP_D1="${SKIP_D1:-0}"

WRANGLER="npx --yes wrangler@${WRANGLER_VERSION}"

step() { printf '\n\033[1m=== %s ===\033[0m\n' "$1"; }

# ---------------------------------------------------------------------------
step "Rust toolchain (pinned by rust-toolchain.toml)"
# The Workers Builds image ships Node/Python/Go/etc. but NOT Rust, and this is
# a Rust->WASM Worker. Install rustup, then the channel pinned in
# rust-toolchain.toml along with the wasm32-unknown-unknown target.
if ! command -v rustup >/dev/null 2>&1; then
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
    | sh -s -- -y --profile minimal --default-toolchain none
fi
# shellcheck source=/dev/null
. "$HOME/.cargo/env"

TOOLCHAIN="$(sed -n 's/^[[:space:]]*channel[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' rust-toolchain.toml | head -n 1)"
if [ -z "${TOOLCHAIN}" ]; then
  echo "ERROR: could not read [toolchain].channel from rust-toolchain.toml" >&2
  exit 1
fi
echo "Installing Rust ${TOOLCHAIN} + wasm32-unknown-unknown"
rustup toolchain install "${TOOLCHAIN}" --profile minimal --target wasm32-unknown-unknown

step "worker-build ${WORKER_BUILD_VERSION}"
if ! command -v worker-build >/dev/null 2>&1; then
  cargo install --locked -q worker-build --version "${WORKER_BUILD_VERSION}"
fi

# ---------------------------------------------------------------------------
step "Web Vault frontend (bw_web_builds ${BW_WEB_VERSION})"
# The frontend is not committed (see .gitignore); download it at build time.
TAG="${BW_WEB_VERSION}"
if [ "${TAG}" = "latest" ]; then
  TAG="$(curl -fsSL https://api.github.com/repos/dani-garcia/bw_web_builds/releases/latest \
    | grep -oP '"tag_name":\s*"\K[^"]+')"
  echo "Resolved latest tag: ${TAG}"
fi
curl -fsSL -o "bw_web_${TAG}.tar.gz" \
  "https://github.com/dani-garcia/bw_web_builds/releases/download/${TAG}/bw_web_${TAG}.tar.gz"
tar -xzf "bw_web_${TAG}.tar.gz" -C public/
rm -f "bw_web_${TAG}.tar.gz"
if [ ! -d public/web-vault ]; then
  echo "ERROR: public/web-vault not found after extracting bw_web_builds" >&2
  exit 1
fi
# Drop source maps to satisfy Cloudflare's per-file static asset size limit.
find public/web-vault -type f -name '*.map' -delete
# Apply the lightweight UI override.
mkdir -p public/web-vault/css/
cp public/css/vaultwarden.css public/web-vault/css/
echo "Frontend ready in public/web-vault"

# ---------------------------------------------------------------------------
step "Configure wrangler.toml"
if [ -z "${D1_DATABASE_ID:-}" ]; then
  echo "ERROR: D1_DATABASE_ID build variable is not set" >&2
  exit 1
fi
# wrangler does not expand \${VAR} in wrangler.toml, so substitute it here.
sed -i "s|\${D1_DATABASE_ID}|${D1_DATABASE_ID}|g" wrangler.toml
echo "Substituted \${D1_DATABASE_ID} in wrangler.toml"

if [ -n "${R2_NAME:-}" ]; then
  echo "Enabling R2 bucket binding -> ${R2_NAME}"
  {
    echo ''
    echo '[[r2_buckets]]'
    echo 'binding = "ATTACHMENTS_BUCKET"'
    echo "bucket_name = \"${R2_NAME}\""
  } >> wrangler.toml
fi

# ---------------------------------------------------------------------------
if [ "${SKIP_D1}" = "1" ]; then
  step "D1 bootstrap/migrate/seed -- SKIPPED (SKIP_D1=1)"
elif [ -z "${CLOUDFLARE_API_TOKEN:-}" ]; then
  step "D1 bootstrap/migrate/seed -- SKIPPED (no CLOUDFLARE_API_TOKEN)"
  echo "Set the CLOUDFLARE_API_TOKEN (+ CLOUDFLARE_ACCOUNT_ID) build secret to run migrations." >&2
else
  step "D1: bootstrap base schema if the database is empty"
  D1_OUT="$($WRANGLER d1 execute "${D1_NAME}" --remote --json --command \
    "SELECT COUNT(*) AS cnt FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' AND name NOT LIKE '_cf_%' AND name NOT IN ('d1_migrations');")"
  # Parse with node (always present in the build image) to avoid a jq dependency.
  TABLE_COUNT="$(printf '%s' "$D1_OUT" | node -e '
    let s = ""; process.stdin.on("data", d => s += d).on("end", () => {
      try {
        const j = JSON.parse(s);
        const r = Array.isArray(j) ? j[0] : j;
        process.stdout.write(String(r.results[0].cnt));
      } catch (e) { process.exit(3); }
    });')"
  echo "Existing application table count: ${TABLE_COUNT}"
  if [ "${TABLE_COUNT}" = "0" ]; then
    echo "Empty database -> applying sql/schema.sql"
    $WRANGLER d1 execute "${D1_NAME}" --remote --file sql/schema.sql

    echo "Marking bundled migrations as already applied (schema.sql includes them)"
    BOOTSTRAP_SQL="$(mktemp)"
    cat >"${BOOTSTRAP_SQL}" <<'SQL'
CREATE TABLE IF NOT EXISTS d1_migrations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT UNIQUE NOT NULL,
  applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL
);
SQL
    for f in migrations/*.sql; do
      [ -e "$f" ] || continue
      echo "INSERT OR IGNORE INTO d1_migrations (name) VALUES ('$(basename "$f")');" >>"${BOOTSTRAP_SQL}"
    done
    $WRANGLER d1 execute "${D1_NAME}" --remote --file "${BOOTSTRAP_SQL}"
    rm -f "${BOOTSTRAP_SQL}"
  else
    echo "Database already has tables; skipping base schema bootstrap"
  fi

  step "D1: apply migrations"
  # Retry loop tolerates "duplicate column" errors left by legacy ensure_schema:
  # mark the offending migration as applied, then continue.
  MAX_RETRIES=15
  RETRY_COUNT=0
  while [ "${RETRY_COUNT}" -lt "${MAX_RETRIES}" ]; do
    echo "Applying migrations (attempt $((RETRY_COUNT + 1))/${MAX_RETRIES})..."
    if $WRANGLER d1 migrations apply "${D1_NAME}" --remote 2>&1 | tee migration_output.txt; then
      echo "All migrations applied"
      break
    fi
    if grep -q "duplicate column name" migration_output.txt; then
      FAILED_MIGRATION="$(grep -oP "Migration \K[0-9]+_[a-zA-Z0-9_]+\.sql(?= failed)" migration_output.txt || true)"
      if [ -z "${FAILED_MIGRATION}" ]; then
        echo "ERROR: duplicate-column error, but could not parse the migration name" >&2
        cat migration_output.txt >&2
        exit 1
      fi
      echo "Migration '${FAILED_MIGRATION}' already present via legacy schema; marking as applied"
      $WRANGLER d1 execute "${D1_NAME}" --remote --command "
        CREATE TABLE IF NOT EXISTS d1_migrations (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          name TEXT UNIQUE NOT NULL,
          applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL
        );
        INSERT OR IGNORE INTO d1_migrations (name) VALUES ('${FAILED_MIGRATION}');"
      RETRY_COUNT=$((RETRY_COUNT + 1))
    else
      echo "ERROR: migration failed with an unexpected error" >&2
      cat migration_output.txt >&2
      exit 1
    fi
  done
  rm -f migration_output.txt
  if [ "${RETRY_COUNT}" -ge "${MAX_RETRIES}" ]; then
    echo "ERROR: exceeded ${MAX_RETRIES} migration retries" >&2
    exit 1
  fi

  if [ "${SEED_GLOBAL_DOMAINS}" = "false" ]; then
    step "Seed global domains -- SKIPPED (SEED_GLOBAL_DOMAINS=false)"
  else
    step "Seed global equivalent domains"
    if [ -n "${GLOBAL_DOMAINS_URL:-}" ]; then
      bash scripts/seed-global-domains.sh --db "${D1_NAME}" --remote \
        --wrangler-version "${WRANGLER_VERSION}" --url "${GLOBAL_DOMAINS_URL}"
    else
      bash scripts/seed-global-domains.sh --db "${D1_NAME}" --remote \
        --wrangler-version "${WRANGLER_VERSION}"
    fi
  fi
fi

# ---------------------------------------------------------------------------
step "Compile Worker (worker-build --release)"
# Compile here so Rust errors fail the build phase. `wrangler deploy` re-runs
# this incrementally during the deploy phase, then uploads the Worker.
worker-build --release --locked

step "Build complete"
echo "Next, the Deploy command runs: wrangler deploy"
