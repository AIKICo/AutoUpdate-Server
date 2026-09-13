@echo off
setlocal enabledelayedexpansion

echo ========================================================
echo  AutoUpdate-Server - Windows x64 Distribution Packager
echo ========================================================

set SCRIPT_DIR=%~dp0
set SRC_DIR=%SCRIPT_DIR%autoupdate-server
set OUT_DIR=%SCRIPT_DIR%publish\win-x64
set OUT_ZIP=%SCRIPT_DIR%publish\autoupdate-server-win-x64.zip

if not exist "%SCRIPT_DIR%publish" mkdir "%SCRIPT_DIR%publish"
if exist "%OUT_DIR%" rd /s /q "%OUT_DIR%"
mkdir "%OUT_DIR%"
mkdir "%OUT_DIR%\updates"
mkdir "%OUT_DIR%\webroot"

echo [1/4] Building optimized Windows x64 Release binary with MSBuild...
set MSBUILD="C:\Program Files\Microsoft Visual Studio\18\Enterprise\MSBuild\Current\Bin\MSBuild.exe"
if not exist %MSBUILD% (
    for /f "usebackq tokens=*" %%i in (`"%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" -latest -requires Microsoft.Component.MSBuild -find MSBuild\**\Bin\MSBuild.exe`) do (
        set MSBUILD="%%i"
    )
)

if exist %MSBUILD% (
    %MSBUILD% "%SCRIPT_DIR%AutoUpdate-Server.sln" /p:Configuration=Release /p:Platform=x64 /t:Rebuild /verbosity:minimal
) else (
    echo WARNING: MSBuild not found, checking pre-built binary...
)

if exist "%SRC_DIR%\bin\autoupdate-server.exe" (
    copy /y "%SRC_DIR%\bin\autoupdate-server.exe" "%OUT_DIR%\autoupdate-server.exe" >nul
    echo  - Windows x64 executable copied successfully.
) else (
    echo  - ERROR: autoupdate-server.exe not found!
    exit /b 1
)

echo [2/4] Copying Web UI assets...
xcopy /s /e /y /q "%SRC_DIR%\webroot\*" "%OUT_DIR%\webroot\"

echo [3/4] Copying Windows launcher and configs...
copy /y "%SRC_DIR%\config.ini" "%OUT_DIR%\" >nul

(
echo @echo off
echo chcp 65001 ^>nul
echo title AutoUpdate-Server v2.0
echo cd /d "%%~dp0"
echo.
echo ==============================================================================
echo   AutoUpdate-Server ^(High-Performance C Server for AutoUpdater.NET^)
echo ==============================================================================
echo.
echo Starting web server on port 8000...
echo Web Admin Console: http://localhost:8000/admin/
echo Default Username:  admin
echo Default Password:  admin123
echo.
echo Press Ctrl+C to stop the server.
echo ==============================================================================
echo.
echo start http://localhost:8000/admin/
echo autoupdate-server.exe -p 8000 -w .\updates -r .\webroot
echo pause
) > "%OUT_DIR%\run_server.bat"

echo [4/4] Creating distribution archive (.zip)...
powershell -NoProfile -Command "Compress-Archive -Path '%OUT_DIR%\*' -DestinationPath '%OUT_ZIP%' -Force"
copy /y "%OUT_ZIP%" "%SCRIPT_DIR%autoupdate-server-win-x64.zip" >nul

echo.
echo ========================================================
echo  SUCCESS: Windows x64 Distribution Bundle Created!
echo  Directory: %OUT_DIR%
echo  Zip:       %OUT_ZIP%
echo  Root Zip:  %SCRIPT_DIR%autoupdate-server-win-x64.zip
echo ========================================================
