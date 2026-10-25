@echo off
setlocal
title PhantomScan Launcher
cd /d "%~dp0"
chcp 65001 >nul 2>&1
set "PYTHONPATH=%~dp0;%~dp0modules;%PYTHONPATH%"
if not exist "%~dp0.venv\Scripts\python.exe" (
    echo ============================================================
    echo [warning] PhantomScan virtual environment [.venv] was not found!
    echo Running install.bat to set up dependencies...
    echo ============================================================
    if exist "%~dp0install.bat" call "%~dp0install.bat"
)
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
