@echo off
setlocal EnableDelayedExpansion
title PhantomScan 2.2.0 - Security Assessment Launcher
cd /d "%~dp0"
chcp 65001 >nul 2>&1

:: 1. Resolve Python Interpreter
set "PYTHON_EXE="
if exist "%~dp0.venv\Scripts\python.exe" (
    set "PYTHON_EXE=%~dp0.venv\Scripts\python.exe"
) else if exist "%~dp0venv\Scripts\python.exe" (
    set "PYTHON_EXE=%~dp0venv\Scripts\python.exe"
) else (
    where python.exe >nul 2>&1
    if not errorlevel 1 set "PYTHON_EXE=python.exe"
)

:: 2. Auto-repair if virtualenv or Python is missing
if not defined PYTHON_EXE (
    echo ============================================================
    echo  PhantomScan 2.2.0 - Setup Required
    echo ============================================================
    echo.
    echo  [!] Python virtual environment was not found in .venv.
    echo.
    if exist "%~dp0install.bat" (
        echo  Would you like to run install.bat now to set up PhantomScan?
        set /p "RUN_INSTALL=[Y/n]: "
        if /i "!RUN_INSTALL!"=="n" (
            echo Setup cancelled. Run install.bat manually when ready.
            pause
            exit /b 1
        )
        echo.
        call "%~dp0install.bat"
        if exist "%~dp0.venv\Scripts\python.exe" (
            set "PYTHON_EXE=%~dp0.venv\Scripts\python.exe"
        ) else (
            echo [!] Setup did not complete successfully.
            pause
            exit /b 1
        )
    ) else (
        echo  Please install Python 3.10+ from https://python.org
        pause
        exit /b 1
    )
)

:: 3. Forward CLI arguments if provided directly
if not "%~1"=="" (
    "%PYTHON_EXE%" "%~dp0phantomscan.py" %*
    set "EXIT_CODE=%errorlevel%"
    if !EXIT_CODE! neq 0 (
        echo.
        echo [!] PhantomScan exited with error code !EXIT_CODE!.
        pause
    )
    exit /b !EXIT_CODE!
)

:: 4. Resolve Preferred PowerShell Engine (PowerShell 7 pwsh.exe or Windows PowerShell)
set "PS_EXE="
where pwsh.exe >nul 2>&1
if not errorlevel 1 (
    set "PS_EXE=pwsh.exe"
) else (
    where powershell.exe >nul 2>&1
    if not errorlevel 1 (
        set "PS_EXE=powershell.exe"
    )
)

:: 5. Fallback if PowerShell is absent
if not defined PS_EXE (
    echo [*] PowerShell not found. Launching Python CLI directly...
    "%PYTHON_EXE%" "%~dp0phantomscan.py" --help
    echo.
    pause
    exit /b %errorlevel%
)

:: 6. Launch the Interactive PowerShell TUI Launcher
"%PS_EXE%" -NoLogo -NoProfile -ExecutionPolicy Bypass -WindowStyle Normal -File "%~dp0PhantomScan-Launcher.ps1"
set "EXIT_CODE=%errorlevel%"

if %EXIT_CODE% neq 0 (
    echo.
    echo [!] Launcher exited with error code %EXIT_CODE%.
    pause
)

exit /b %EXIT_CODE%
