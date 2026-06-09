#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
PROJECT_DIR="$ROOT_DIR/v7"

if command -v uv >/dev/null 2>&1; then
    RUNNER=(uv run --project "$PROJECT_DIR" python)
else
    RUNNER=(python)
fi

PYTHONPATH="$PROJECT_DIR" "${RUNNER[@]}" "$SCRIPT_DIR/run_all_tests.py" "$SCRIPT_DIR" "$@"
