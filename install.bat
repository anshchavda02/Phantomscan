@echo off
setlocal
title PhantomScan Windows Installer

set "ROOT=%~dp0"
set "VENV=%ROOT%.venv"
set "DESKTOP=%USERPROFILE%\Desktop"
if exist "%USERPROFILE%\OneDrive\Desktop" set "DESKTOP=%USERPROFILE%\OneDrive\Desktop"

echo ============================================================
echo PhantomScan Windows Installer
echo Authorized security assessment use only.
echo ============================================================
echo.

where python >nul 2>nul
if errorlevel 1 (
  echo [error] Python 3.10+ was not found on PATH.
  echo Install Python from https://www.python.org/downloads/windows/
  pause
  exit /b 1
)

python -m venv "%VENV%"
if errorlevel 1 (
  echo [error] Could not create virtual environment.
  pause
  exit /b 1
)

"%VENV%\Scripts\python.exe" -m pip install --upgrade pip
if exist "%ROOT%requirements.txt" (
  "%VENV%\Scripts\python.exe" -m pip install -r "%ROOT%requirements.txt"
)

(
  echo @echo off
  echo setlocal
  echo title PhantomScan Launcher
  echo powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%%~dp0PhantomScan-Launcher.ps1"
  echo if errorlevel 1 pause
) > "%ROOT%PhantomScan Launcher.bat"

(
  echo @echo off
  echo setlocal
  echo title PhantomScan
  echo "%VENV%\Scripts\python.exe" "%ROOT%phantomscan.py" %%*
) > "%ROOT%phantomscan-cli.bat"

copy /Y "%ROOT%PhantomScan Launcher.bat" "%DESKTOP%\PhantomScan Launcher.bat" >nul

echo.
echo [ok] PhantomScan installed.
echo [ok] Desktop launcher: %DESKTOP%\PhantomScan Launcher.bat
echo.
echo CLI examples:
echo   "%ROOT%phantomscan-cli.bat" --target example.com --profile passive
echo   "%ROOT%phantomscan-cli.bat" --target example.com --profile full --debug
echo.
pause
