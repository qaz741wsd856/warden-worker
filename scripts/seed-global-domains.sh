#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Seed Vaultwarden/Bitwarden global equivalent domains into Cloudflare D1.

This:
1) Downloads (or reads local) global_domains.json
2) Generates sql/global_domains_seed.sql
3) Executes it against a D1 database via wrangler

Usage:
  ./scripts/seed-global-domains.sh --db <d1_name> [--env <wrangler_env>] [--remote] [--url <raw_json_url>] [--wrangler-version <ver>]

Examples:
  ./scripts/seed-global-domains.sh --db vault1 --remote
  ./scripts/seed-global-domains.sh --db vault1 --env dev --remote
  ./scripts/seed-global-domains.sh --db vault1 --remote \
    --url https://raw.githubusercontent.com/dani-garcia/vaultwarden/<tag-or-commit>/src/static/global_domains.json

  # Use a pinned Wrangler version via npx (recommended for CI)
  ./scripts/seed-global-domains.sh --db vault1 --remote --wrangler-version 4.82.1
EOF
}

DB_NAME=""
ENV_NAME=""
REMOTE=0
URL=""
INPUT=""
OUTPUT="sql/global_domains_seed.sql"
WRANGLER_VERSION=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --db)
      DB_NAME="${2:-}"; shift 2;;
    --env)
      ENV_NAME="${2:-}"; shift 2;;
    --remote)
      REMOTE=1; shift;;
    --url)
      URL="${2:-}"; shift 2;;
    --input)
      INPUT="${2:-}"; shift 2;;
    --output)
      OUTPUT="${2:-}"; shift 2;;
    --wrangler-version)
      WRANGLER_VERSION="${2:-}"; shift 2;;
    -h|--help)
      usage; exit 0;;
    *)
      echo "Unknown arg: $1" >&2
      usage
      exit 2;;
  esac
done

if [[ -z "$DB_NAME" ]]; then
  echo "Missing required --db <d1_name>" >&2
  usage
  exit 2
fi

GEN_ARGS=(--output "$OUTPUT")
if [[ -n "$INPUT" ]]; then
  GEN_ARGS+=(--input "$INPUT")
elif [[ -n "$URL" ]]; then
  GEN_ARGS+=(--url "$URL")
fi

python3 scripts/generate-global-domains-seed.py "${GEN_ARGS[@]}"

WRANGLER_ARGS=(d1 execute "$DB_NAME" --file "$OUTPUT")
if [[ -n "$ENV_NAME" ]]; then
  WRANGLER_ARGS+=(--env "$ENV_NAME")
fi
if [[ "$REMOTE" -eq 1 ]]; then
  WRANGLER_ARGS+=(--remote)
fi

WRANGLER=(wrangler)
if [[ -n "$WRANGLER_VERSION" ]]; then
  WRANGLER=(npx --yes "wrangler@${WRANGLER_VERSION}")
elif ! command -v wrangler >/dev/null 2>&1; then
  WRANGLER=(npx --yes wrangler)
fi

"${WRANGLER[@]}" "${WRANGLER_ARGS[@]}"

