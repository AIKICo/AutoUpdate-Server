@echo off
chcp 65001 >nul
title AutoUpdate-Server v2.0
cd /d "%~dp0"

echo ==============================================================================
echo   وب‌سرور پرسرعت AutoUpdate-Server (مخصوص AutoUpdater.NET)
echo ==============================================================================
echo.
echo در حال اجرای سرور روی پورت 8000...
echo پنل مدیریت تحت وب: http://localhost:8000/admin/
echo نام کاربری ورود: admin
echo کلمه عبور ورود: admin123
echo.
echo برای بستن سرور، این پنجره را ببندید یا کلیدهای Ctrl+C را فشار دهید.
echo ==============================================================================
echo.

start http://localhost:8000/admin/

.\bin\autoupdate-server.exe -p 8000 -w .\updates -r .\webroot
pause
