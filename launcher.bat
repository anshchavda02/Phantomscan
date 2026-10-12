@echo off
setlocal
title PhantomScan Launcher
cd /d "%~dp0"
chcp 65001 >nul 2>&1
where powershell.exe >nul 2>&1
if errorlevel 1 (
    if exist "%~dp0.venv\Scripts\python.exe" (
        "%~dp0.venv\Scripts\python.exe" "%~dp0phantomscan.py" %*
    ) else (
        python "%~dp0phantomscan.py" %*
    )
    echo.
    pause
    exit /b %errorlevel%
)
if "%~1"=="" (
    powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0PhantomScan-Launcher.ps1"
) else (
    if exist "%~dp0.venv\Scripts\python.exe" (
        "%~dp0.venv\Scripts\python.exe" "%~dp0phantomscan.py" %*
    ) else (
        python "%~dp0phantomscan.py" %*
    )
    echo.
    pause
)
if errorlevel 1 pause
exit /b %errorlevel%
