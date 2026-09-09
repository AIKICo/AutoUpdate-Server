#!/usr/bin/env bash
set -e

# Change to the directory of this script
cd "$(dirname "$0")"

# Ensure binary is executable
if [ -f "./autoupdate-server" ]; then
    chmod +x ./autoupdate-server
else
    echo "Error: autoupdate-server binary not found in $(pwd)"
    echo "Run ./build_linux.sh first if building from source."
    exit 1
fi

echo "=========================================="
echo " Starting AutoUpdate-Server (Linux x64)"
echo " Listening on: http://0.0.0.0:8000"
echo " Web Admin UI: http://0.0.0.0:8000/admin/"
echo " Default user: admin / admin123"
echo "=========================================="

exec ./autoupdate-server -c config.ini
