#!/bin/bash

VENV_DIR="$(dirname "$0")/venv"
PYTHON="$VENV_DIR/bin/python3"

echo "Starting CF_AI Server..."
echo "========================"

if [ ! -f .env ]; then
    echo "Warning: .env file not found. Using default settings."
    echo "Copy .env.example to .env and configure as needed."
fi

if [ -f .env ]; then
    export $(grep -v '^#' .env | xargs)
fi

# Use venv if available, fall back to system python3
if [ -f "$PYTHON" ]; then
    PY="$PYTHON"
else
    if ! command -v python3 &>/dev/null; then
        echo "Error: Python3 is not installed"
        exit 1
    fi
    PY="python3"
fi

# Quick import check
$PY -c "import flask" 2>/dev/null
if [ $? -ne 0 ]; then
    echo "Error: Flask not installed. Run: sudo ./setup.sh"
    exit 1
fi

echo "Starting server on ${CFAI_HOST:-0.0.0.0}:${CFAI_PORT:-8888}"
echo "Press Ctrl+C to stop"
echo ""

$PY cfai_server.py