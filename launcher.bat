@echo off
setlocal enabledelayedexpansion
title PhantomScan v2.0 - Security Assessment Launcher
cd /d "%~dp0"

:: Check if PowerShell is available
where powershell >nul 2>nul
if %errorlevel% neq 0 (
    echo [ERROR] PowerShell is required to run PhantomScan Launcher.
    echo Please install or enable PowerShell and try again.
    pause
    exit /b 1
)

:: Run PowerShell interactive launcher with bypass policy
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0PhantomScan-Launcher.ps1"
if %errorlevel% neq 0 (
    echo.
    echo [ERROR] PhantomScan Launcher terminated with an error code %errorlevel%.
    pause
)
