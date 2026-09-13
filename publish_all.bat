@echo off
setlocal enabledelayedexpansion

echo ===================================================================
echo   AutoUpdate-Server - Dual Platform Packager (Windows + Linux)
echo ===================================================================
echo.

set SCRIPT_DIR=%~dp0

echo STEP 1/2: Publishing Windows x64 Distribution...
call "%SCRIPT_DIR%publish_win_x64.bat"
if %ERRORLEVEL% neq 0 (
    echo ERROR: Windows publish failed!
    exit /b %ERRORLEVEL%
)

echo.
echo STEP 2/2: Publishing Linux x64 Distribution...
call "%SCRIPT_DIR%publish_linux_x64.bat"
if %ERRORLEVEL% neq 0 (
    echo ERROR: Linux publish failed!
    exit /b %ERRORLEVEL%
)

echo.
echo ===================================================================
echo   ALL DISTRIBUTIONS CREATED SUCCESSFULLY!
echo ===================================================================
echo  Windows x64 Package:
echo    - Folder:  %SCRIPT_DIR%publish\win-x64
echo    - Zip:     %SCRIPT_DIR%autoupdate-server-win-x64.zip
echo.
echo  Linux x64 Package:
echo    - Folder:  %SCRIPT_DIR%publish\linux-x64
echo    - Tar.gz:  %SCRIPT_DIR%autoupdate-server-linux-x64.tar.gz
echo    - Zip:     %SCRIPT_DIR%autoupdate-server-linux-x64.zip
echo ===================================================================
