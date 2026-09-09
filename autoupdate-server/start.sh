#!/bin/bash
# ==============================================================================
# اسکریپت راه‌اندازی وب‌سرور در پس‌زمینه (Background Daemon)
# ==============================================================================

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
cd "$DIR"

chmod +x ./bin/autoupdate-server

# بررسی وضعیت قبلی
if [ -f "autoupdate.pid" ]; then
    PID=$(cat autoupdate.pid)
    if kill -0 "$PID" 2>/dev/null; then
        echo "سرور در حال حاضر با شناسه فرآیند (PID) $PID در حال اجرا است."
        exit 0
    fi
fi

echo "در حال راه‌اندازی AutoUpdate-Server در پس‌زمینه..."
./bin/autoupdate-server -d -p 8080 -w ./updates -r ./webroot -u admin -a admin123 -l autoupdate.log

if [ $? -eq 0 ]; then
    echo "سرور با موفقیت راه‌اندازی گردید."
    echo "پنل مدیریت: http://localhost:8080/admin/"
    echo "فایل‌های به‌روزرسانی: http://localhost:8080/AutoUpdater.xml"
else
    echo "خطا در راه‌اندازی سرور. فایل autoupdate.log را بررسی فرمایید."
fi
