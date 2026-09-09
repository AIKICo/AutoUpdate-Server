@echo off
setlocal enabledelayedexpansion

echo ========================================================
echo  AutoUpdate-Server - Linux x64 Distribution Packager
echo ========================================================

set SCRIPT_DIR=%~dp0
set SRC_DIR=%SCRIPT_DIR%autoupdate-server
set OUT_DIR=%SCRIPT_DIR%publish\linux-x64
set OUT_ZIP=%SCRIPT_DIR%publish\autoupdate-server-linux-x64-bundle.zip

if not exist "%SCRIPT_DIR%publish" mkdir "%SCRIPT_DIR%publish"
if exist "%OUT_DIR%" rd /s /q "%OUT_DIR%"
mkdir "%OUT_DIR%"
mkdir "%OUT_DIR%\src"
mkdir "%OUT_DIR%\updates"
mkdir "%OUT_DIR%\webroot"

echo [1/4] Copying source files and headers...
xcopy /y /q "%SRC_DIR%\src\*.*" "%OUT_DIR%\src\"
copy /y "%SRC_DIR%\Makefile" "%OUT_DIR%\" >nul

echo [2/4] Copying Web UI assets...
xcopy /s /e /y /q "%SRC_DIR%\webroot\*" "%OUT_DIR%\webroot\"

echo [3/4] Copying Linux control scripts and configs...
copy /y "%SRC_DIR%\run_linux.sh" "%OUT_DIR%\" >nul
copy /y "%SRC_DIR%\build_linux.sh" "%OUT_DIR%\" >nul
copy /y "%SRC_DIR%\install_service.sh" "%OUT_DIR%\" >nul
copy /y "%SRC_DIR%\autoupdater.service" "%OUT_DIR%\" >nul
copy /y "%SRC_DIR%\Dockerfile.linux-x64" "%OUT_DIR%\Dockerfile" >nul

(
  echo [server]
  echo port = 8000
  echo updates_dir = ./updates
  echo webroot_dir = ./webroot
) > "%OUT_DIR%\config.ini"

echo [4/4] Creating distribution archive...
powershell -NoProfile -Command "Compress-Archive -Path '%OUT_DIR%\*' -DestinationPath '%OUT_ZIP%' -Force"

echo.
echo ========================================================
echo  SUCCESS: Linux x64 Distribution Bundle Created!
echo  Directory: %OUT_DIR%
echo  Zip:       %OUT_ZIP%
echo.
echo  Quick Deploy on Linux:
echo    1. Copy %OUT_ZIP% to target Linux server
echo    2. unzip autoupdate-server-linux-x64-bundle.zip
echo    3. ./build_linux.sh
echo    4. ./run_linux.sh  (or: sudo ./install_service.sh)
echo ========================================================
