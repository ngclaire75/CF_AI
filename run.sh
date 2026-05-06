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

# Always use system python3 (venv may have old openai 0.28.x)
PYTHON="$(command -v python3)"

if [ -z "$PYTHON" ]; then
    echo "Error: python3 not found"
    exit 1
fi

exec "$PYTHON" "$SCRIPT_DIR/cli.py" "$@"
