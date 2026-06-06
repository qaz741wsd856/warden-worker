#!/usr/bin/env bash
#
# scripts/cf-build.sh  --  BUILD phase for Cloudflare Workers Builds.
#
# Paired with scripts/cf-deploy.sh (the Deploy phase). Together they let a plain
# `git push` build and deploy the Worker from Cloudflare's dashboard Git
# integration, with no GitHub Actions required.
#
# Configure both in the dashboard under:
#   Workers & Pages > warden-worker > Settings > Build
#
#   Build command:   bash scripts/cf-build.sh
#   Deploy command:  bash scripts/cf-deploy.sh
#
# This phase installs the Rust/WASM toolchain (the Workers Builds image does not
# ship Rust), downloads the Web Vault frontend, configures wrangler.toml, and
# compiles the Worker. D1 migrations run in the Deploy phase (cf-deploy.sh),
# where the auto-generated build token is the active credential -- so no extra
# API token is needed here; just grant that build token D1:Edit once (see
# cf-deploy.sh / docs/deployment.md).
#
# Build variables (Settings > Build > "Variables and Secrets"):
#   D1_DATABASE_ID        (required)  production D1 database id (substituted into wrangler.toml)
#   BW_WEB_VERSION        (optional)  bw_web_builds tag (default below); "latest" to track upstream
#   WORKER_BUILD_VERSION  (optional)  pinned worker-build (default below; match the `worker` dep in Cargo.toml)
#   R2_NAME               (optional)  R2 bucket name; enables the ATTACHMENTS_BUCKET binding
#
set -euo pipefail

# Run from the repository root regardless of where the script is invoked.
cd "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"

WORKER_BUILD_VERSION="${WORKER_BUILD_VERSION:-0.8.3}"
BW_WEB_VERSION="${BW_WEB_VERSION:-v2026.4.1}"

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
# Pin to this toolchain explicitly so rustup uses it directly and IGNORES
# rust-toolchain.toml. That file lists `components = ["rustfmt", "clippy"]`,
# which rustup would otherwise lazily download on the first in-repo cargo
# command -- slow (clippy is large) and unnecessary for a release build.
# We install the wasm32 target explicitly below, so nothing is lost.
export RUSTUP_TOOLCHAIN="${TOOLCHAIN}"
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
# This edit persists to the Deploy phase (build and deploy share the workspace).
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
step "Compile Worker (worker-build --release)"
# Compile here so Rust errors fail the build phase. `wrangler deploy` re-runs
# this incrementally during the deploy phase, then uploads the Worker.
worker-build --release --locked

step "Build complete"
echo "Next, the Deploy command runs: bash scripts/cf-deploy.sh"
