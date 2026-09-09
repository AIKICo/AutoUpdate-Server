#!/bin/bash
# ==============================================================================
# اسکریپت توقف Nginx پرتابل
# ==============================================================================

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
cd "$DIR"

if [ ! -f "logs/nginx.pid" ]; then
    echo "Nginx در حال اجرا نیست (فایل logs/nginx.pid یافت نشد)."
    exit 0
fi

echo "در حال متوقف کردن Nginx..."
./sbin/nginx -p "$DIR" -c conf/nginx.conf -s stop

if [ $? -eq 0 ]; then
    echo "Nginx متوقف گردید."
else
    # روش جایگزین با ارسال مستقیم سیگنال
    PID=$(cat logs/nginx.pid)
    kill "$PID" 2>/dev/null && echo "Nginx با ارسال سیگنال متوقف شد."
fi
rm -f logs/nginx.pid
