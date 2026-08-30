@echo off
setlocal
title PhantomScan CLI
cd /d "%~dp0"
chcp 65001 >nul 2>&1

if exist "%~dp0.venv\Scripts\python.exe" (
    "%~dp0.venv\Scripts\python.exe" "%~dp0phantomscan.py" %*
) else (
    python "%~dp0phantomscan.py" %*
)
exit /b %errorlevel%

