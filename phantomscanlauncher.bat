@echo off
setlocal
title PhantomScan Launcher
cd /d "%~dp0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0PhantomScan-Launcher.ps1"
if errorlevel 1 (
    echo.
    echo [error] PhantomScan Launcher exited with an error.
    pause
)
