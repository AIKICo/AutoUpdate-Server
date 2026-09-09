#!/bin/bash
# ==============================================================================
# اسکریپت وضعیت Nginx
# ==============================================================================

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
cd "$DIR"

if [ -f "logs/nginx.pid" ]; then
    PID=$(cat logs/nginx.pid)
    if kill -0 "$PID" 2>/dev/null; then
        echo "Nginx با شناسه (PID) $PID در حال اجرا است."
        exit 0
    fi
fi

echo "Nginx فعال نیست."
