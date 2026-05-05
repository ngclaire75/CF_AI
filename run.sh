#!/bin/bash

# CF_AI Run Script
# This script starts the CF_AI server

echo "Starting CF_AI Server..."
echo "========================"

# Check if .env file exists
if [ ! -f .env ]; then
    echo "Warning: .env file not found. Using default settings."
    echo "Copy .env.example to .env and configure as needed."
fi

# Load environment variables
if [ -f .env ]; then
    export $(grep -v '^#' .env | xargs)
fi

# Check if Python is available
if ! command -v python3 &> /dev/null; then
    echo "Error: Python3 is not installed or not in PATH"
    exit 1
fi

# Check if required packages are installed
python3 -c "import flask, psutil, requests, beautifulsoup4" 2>/dev/null
if [ $? -ne 0 ]; then
    echo "Error: Required Python packages not installed."
    echo "Run: pip3 install -r requirements.txt"
    exit 1
fi

# Start the server
echo "Starting server on ${CFAI_HOST:-0.0.0.0}:${CFAI_PORT:-8888}"
echo "Press Ctrl+C to stop"
echo ""

python3 cfai_server.py