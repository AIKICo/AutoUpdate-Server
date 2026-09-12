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
mkdir "%OUT_DIR%\bin"
mkdir "%OUT_DIR%\src"
mkdir "%OUT_DIR%\updates"
mkdir "%OUT_DIR%\webroot"

echo [1/5] Building static Linux x64 executable...
set ZIG_EXE=C:\Users\Milad.nisoc\AppData\Local\Temp\zig_extracted\zig-x86_64-windows-0.14.1\zig.exe
if exist "%ZIG_EXE%" (
    "%ZIG_EXE%" cc -target x86_64-linux-musl -O3 -static -pthread -I"%SRC_DIR%\src" -DSQLITE_THREADSAFE=1 "%SRC_DIR%\src\main.c" "%SRC_DIR%\src\server.c" "%SRC_DIR%\src\http.c" "%SRC_DIR%\src\admin.c" "%SRC_DIR%\src\utils.c" "%SRC_DIR%\src\sha256.c" "%SRC_DIR%\src\md5.c" "%SRC_DIR%\src\db.c" "%SRC_DIR%\src\sqlite3.c" -o "%SRC_DIR%\bin\autoupdate-server"
)

if exist "%SRC_DIR%\bin\autoupdate-server" (
    copy /y "%SRC_DIR%\bin\autoupdate-server" "%OUT_DIR%\autoupdate-server" >nul
    copy /y "%SRC_DIR%\bin\autoupdate-server" "%OUT_DIR%\bin\autoupdate-server" >nul
    echo  - Pre-compiled static Linux binary copied successfully.
) else (
    echo  - WARNING: Pre-compiled binary not found, user will need to run ./build_linux.sh on server.
)

echo [2/5] Copying source files and headers...
xcopy /y /q "%SRC_DIR%\src\*.*" "%OUT_DIR%\src\"
copy /y "%SRC_DIR%\Makefile" "%OUT_DIR%\" >nul

echo [3/5] Copying Web UI assets and updates repository...
xcopy /s /e /y /q "%SRC_DIR%\webroot\*" "%OUT_DIR%\webroot\"
if exist "%SRC_DIR%\updates" xcopy /s /e /y /q "%SRC_DIR%\updates\*" "%OUT_DIR%\updates\"

echo [4/5] Copying Linux control scripts and configs...
copy /y "%SRC_DIR%\run_linux.sh" "%OUT_DIR%\" >nul
copy /y "%SRC_DIR%\build_linux.sh" "%OUT_DIR%\" >nul
copy /y "%SRC_DIR%\install_service.sh" "%OUT_DIR%\" >nul
copy /y "%SRC_DIR%\autoupdater.service" "%OUT_DIR%\" >nul
copy /y "%SRC_DIR%\Dockerfile.linux-x64" "%OUT_DIR%\Dockerfile" >nul

copy /y "%SRC_DIR%\config.ini" "%OUT_DIR%\" >nul

echo [5/6] Ensuring all scripts and text files use pure UNIX (LF) line endings...
powershell -NoProfile -Command "$files = Get-ChildItem -Path '%OUT_DIR%' -Recurse -File | Where-Object { $_.Extension -notin @('.exe', '.dll', '.so', '.a', '.gz', '.zip', '.png', '.jpg', '.ico', '.db') -and $_.Name -ne 'autoupdate-server' }; foreach ($f in $files) { $bytes = [System.IO.File]::ReadAllBytes($f.FullName); $hasCR = $false; for ($i = 0; $i -lt $bytes.Length; $i++) { if ($bytes[$i] -eq 13) { $hasCR = $true; break } }; if ($hasCR) { $text = [System.IO.File]::ReadAllText($f.FullName, [System.Text.Encoding]::UTF8); $fixed = $text.Replace(\"`r`n\", \"`n\").Replace(\"`r\", \"`n\"); [System.IO.File]::WriteAllText($f.FullName, $fixed, (New-Object System.Text.UTF8Encoding($false))) } }"

echo [6/6] Creating distribution archives (.zip and .tar.gz)...
powershell -NoProfile -Command "Compress-Archive -Path '%OUT_DIR%\*' -DestinationPath '%OUT_ZIP%' -Force"
powershell -NoProfile -Command "Set-Location '%SCRIPT_DIR%publish'; tar -czf '%SCRIPT_DIR%publish\autoupdate-server-linux-x64.tar.gz' -C '%SCRIPT_DIR%publish' linux-x64"
copy /y "%SCRIPT_DIR%publish\autoupdate-server-linux-x64.tar.gz" "%SCRIPT_DIR%autoupdate-server-linux-x64.tar.gz" >nul
copy /y "%OUT_ZIP%" "%SCRIPT_DIR%autoupdate-server-linux-x64.zip" >nul

echo.
echo ========================================================
echo  SUCCESS: Linux x64 Distribution Bundle Created!
echo  Directory: %OUT_DIR%
echo  Zip:       %OUT_ZIP%
echo  Tar.gz:    %SCRIPT_DIR%publish\autoupdate-server-linux-x64.tar.gz
echo.
echo  Quick Deploy on Offline Linux Server:
echo    1. Copy autoupdate-server-linux-x64.tar.gz to server
echo    2. tar -xzf autoupdate-server-linux-x64.tar.gz
echo    3. cd linux-x64
echo    4. chmod +x autoupdate-server *.sh
echo    5. ./run_linux.sh  (or: sudo ./install_service.sh)
echo ========================================================
