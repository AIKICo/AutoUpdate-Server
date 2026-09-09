#!/bin/bash
# ==============================================================================
# اسکریپت راه‌اندازی Nginx پرتابل در پس‌زمینه (بدون نیاز به نصب)
# ==============================================================================

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
cd "$DIR"

chmod +x ./sbin/nginx

mkdir -p logs temp updates

if [ -f "logs/nginx.pid" ]; then
    PID=$(cat logs/nginx.pid)
    if kill -0 "$PID" 2>/dev/null; then
        echo "Nginx در حال حاضر با شناسه فرآیند (PID) $PID در حال اجرا است."
        exit 0
    fi
fi

echo "در حال راه‌اندازی Nginx در پس‌زمینه..."
./sbin/nginx -p "$DIR" -c conf/nginx.conf

if [ $? -eq 0 ]; then
    echo "Nginx با موفقیت در پس‌زمینه فعال شد."
    echo "پورت شنود: 8080 (قابل تغییر در conf/nginx.conf)"
    echo "آدرس دسترسی: http://localhost:8080/"
else
    echo "خطا در راه‌اندازی Nginx. لاگ‌های خطا در logs/error.log را بررسی فرمایید."
fi
