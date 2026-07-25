@echo off
setlocal
title PhantomScan Launcher
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0PhantomScan-Launcher.ps1"
if errorlevel 1 pause
pause
