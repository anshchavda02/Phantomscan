@echo off
setlocal
title PhantomScan CLI
if exist "%~dp0.venv\Scripts\python.exe" (
    "%~dp0.venv\Scripts\python.exe" "%~dp0phantomscan.py" %*
) else (
    python "%~dp0phantomscan.py" %*
)
