@echo off
chcp 65001 >nul
title AutoUpdate-Server Launcher
cd /d "%~dp0autoupdate-server"
call run_windows.bat
