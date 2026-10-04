#!/usr/bin/env bash
set -e

cd "$(dirname "$0")"

echo "==> Building AutoUpdate-Server on Linux x64..."

if ! command -v gcc &> /dev/null; then
    echo "gcc not found. Attempting package installation..."
    if command -v apt-get &> /dev/null; then
        sudo apt-get update && sudo apt-get install -y gcc make unixodbc-dev
    elif command -v yum &> /dev/null; then
        sudo yum install -y gcc make unixODBC-devel
    elif command -v apk &> /dev/null; then
        sudo apk add gcc make musl-dev unixodbc-dev
    fi
fi

mkdir -p bin
gcc -O3 -Wall -pthread -D_GNU_SOURCE -Isrc src/main.c src/server.c src/http.c src/admin.c src/utils.c src/sha256.c src/md5.c src/db.c src/puff.c src/zip_reader.c -lodbc -lpthread -ldl -lm -o autoupdate-server
cp autoupdate-server bin/autoupdate-server 2>/dev/null || true
chmod +x autoupdate-server bin/autoupdate-server 2>/dev/null || true

echo "==> Build Successful: $(pwd)/autoupdate-server"
echo "    Start the server with: ./run_linux.sh"
