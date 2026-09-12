#!/usr/bin/env bash
set -e

cd "$(dirname "$0")"

echo "==> Building AutoUpdate-Server on Linux x64..."

if ! command -v gcc &> /dev/null; then
    echo "gcc not found. Attempting package installation..."
    if command -v apt-get &> /dev/null; then
        sudo apt-get update && sudo apt-get install -y gcc make libsqlite3-dev
    elif command -v yum &> /dev/null; then
        sudo yum install -y gcc make sqlite-devel
    elif command -v apk &> /dev/null; then
        sudo apk add gcc make musl-dev sqlite-dev
    fi
fi

mkdir -p bin
if [ -f "src/sqlite3.c" ]; then
    gcc -O3 -Wall -pthread -D_GNU_SOURCE -Isrc -DSQLITE_THREADSAFE=1 src/main.c src/server.c src/http.c src/admin.c src/utils.c src/sha256.c src/md5.c src/db.c src/sqlite3.c src/puff.c src/zip_reader.c -lpthread -ldl -lm -o autoupdate-server
else
    gcc -O3 -Wall -pthread -D_GNU_SOURCE src/main.c src/server.c src/http.c src/admin.c src/utils.c src/sha256.c src/md5.c src/db.c src/puff.c src/zip_reader.c -lsqlite3 -lpthread -ldl -lm -o autoupdate-server
fi
cp autoupdate-server bin/autoupdate-server 2>/dev/null || true
chmod +x autoupdate-server bin/autoupdate-server 2>/dev/null || true

echo "==> Build Successful: $(pwd)/autoupdate-server"
echo "    Start the server with: ./run_linux.sh"
