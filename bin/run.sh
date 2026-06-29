#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT"

if [[ -f .env ]]; then
  set -a
  source .env
  set +a
fi

if [[ -z "${GITHUB_ACCESS_TOKEN:-}" ]]; then
  echo "Error: GITHUB_ACCESS_TOKEN is not set."
  echo "Either:"
  echo "  export GITHUB_ACCESS_TOKEN='ghp_...'"
  echo "  or create a .env file in this directory with your token."
  exit 1
fi

DB_PATH="${GITSCOUT_DB:-$PROJECT_ROOT/findings.duckdb}"
LOGFILE="${GITSCOUT_LOGFILE:-}"

echo "Starting GitScout (runs until you press Ctrl+C)..."
echo "DuckDB: $DB_PATH"
echo "Query:  python3 query_findings.py --db $DB_PATH interesting"
echo

if [[ -n "$LOGFILE" ]]; then
  exec python3 gitscout.py --db "$DB_PATH" --logfile "$LOGFILE"
else
  exec python3 gitscout.py --db "$DB_PATH"
fi
