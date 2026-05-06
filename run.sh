#!/bin/bash
# CF_AI CLI launcher
# Usage: bash run.sh [-m gpt-4o] [-e "agent pentest https://example.com"]

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Load .env if present
if [ -f "$SCRIPT_DIR/.env" ]; then
    set -a
    source "$SCRIPT_DIR/.env"
    set +a
fi

# Prefer venv python, fall back to system python3
PYTHON="$SCRIPT_DIR/venv/bin/python3"
[ -f "$PYTHON" ] || PYTHON="$(command -v python3)"

if [ -z "$PYTHON" ]; then
    echo "Error: python3 not found"
    exit 1
fi

exec "$PYTHON" "$SCRIPT_DIR/cli.py" "$@"
