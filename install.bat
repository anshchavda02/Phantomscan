@echo off
setlocal
title PhantomScan Windows Installer

set "ROOT=%~dp0"
set "VENV=%ROOT%.venv"
set "DESKTOP=%USERPROFILE%\Desktop"
if exist "%USERPROFILE%\OneDrive\Desktop" set "DESKTOP=%USERPROFILE%\OneDrive\Desktop"

echo ============================================================
echo PhantomScan 2.2.0 Windows Installer
echo Authorized security assessment use only.
echo ============================================================
echo.

where python >nul 2>nul
if errorlevel 1 (
  echo [error] Python 3.10+ was not found on PATH.
  echo Install Python from https://www.python.org/downloads/windows/
  echo Make sure to check "Add Python to PATH" during installation.
  pause
  exit /b 1
)

echo [1/5] Setting up Python virtual environment...
if not exist "%VENV%" (
  python -m venv "%VENV%"
  if errorlevel 1 (
    echo [error] Could not create virtual environment.
    pause
    exit /b 1
  )
)

echo [2/5] Upgrading pip and installing dependencies...
"%VENV%\Scripts\python.exe" -m pip install --upgrade pip --quiet
if exist "%ROOT%requirements.txt" (
  "%VENV%\Scripts\python.exe" -m pip install -r "%ROOT%requirements.txt" --quiet
)

echo.
echo [3/5] Setting up native polyglot engines...
where go >nul 2>nul
if not errorlevel 1 (
  echo [+] Compiling Go Port Scanner...
  cd /d "%ROOT%engines\go"
  if not exist "bin" mkdir "bin"
  go build -o bin\phantomscan-go.exe main.go 2>nul
  cd /d "%ROOT%"
) else (
  echo [info] Go compiler not found on PATH. Python native port scanner will be used.
)

where cargo >nul 2>nul
if not errorlevel 1 (
  echo [+] Compiling Rust TLS Inspector...
  cd /d "%ROOT%engines\rust"
  cargo build --release 2>nul
  cd /d "%ROOT%"
) else (
  echo [info] Rust/Cargo not found on PATH. Python native TLS inspector will be used.
)

where npm >nul 2>nul
if not errorlevel 1 (
  if exist "%ROOT%engines\node" (
    echo [+] Setting up Node Headless Browser Engine ^(Playwright/Chromium^)...
    cd /d "%ROOT%engines\node"
    call npm install --no-audit --no-fund 2>nul
    call npx playwright install chromium 2>nul
    cd /d "%ROOT%"
  )
) else (
  echo [info] Node/NPM not found on PATH. Optional headless browser engine skipped.
)

echo.
echo [4/5] Creating launcher scripts...
(
  echo @echo off
  echo setlocal
  echo title PhantomScan Launcher
  echo cd /d "%%~dp0"
  echo chcp 65001 ^>nul 2^>^&1
  echo where powershell.exe ^>nul 2^>^&1
  echo if errorlevel 1 ^(
  echo     if exist "%%~dp0.venv\Scripts\python.exe" ^(
  echo         "%%~dp0.venv\Scripts\python.exe" "%%~dp0phantomscan.py" %%*
  echo     ^) else ^(
  echo         python "%%~dp0phantomscan.py" %%*
  echo     ^)
  echo     if errorlevel 1 pause
  echo     exit /b %%errorlevel%%
  echo ^)
  echo if "%%~1"=="" ^(
  echo     powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%%~dp0PhantomScan-Launcher.ps1"
  echo ^) else ^(
  echo     if exist "%%~dp0.venv\Scripts\python.exe" ^(
  echo         "%%~dp0.venv\Scripts\python.exe" "%%~dp0phantomscan.py" %%*
  echo     ^) else ^(
  echo         python "%%~dp0phantomscan.py" %%*
  echo     ^)
  echo ^)
  echo if errorlevel 1 pause
  echo exit /b %%errorlevel%%
) > "%ROOT%PhantomScan Launcher.bat"
copy /y "%ROOT%PhantomScan Launcher.bat" "%ROOT%launcher.bat" >nul

(
  echo @echo off
  echo setlocal
  echo title PhantomScan CLI
  echo cd /d "%%~dp0"
  echo chcp 65001 ^>nul 2^>^&1
  echo if exist "%%~dp0.venv\Scripts\python.exe" ^(
  echo     "%%~dp0.venv\Scripts\python.exe" "%%~dp0phantomscan.py" %%*
  echo ^) else ^(
  echo     python "%%~dp0phantomscan.py" %%*
  echo ^)
  echo exit /b %%errorlevel%%
) > "%ROOT%phantomscan-cli.bat"

if exist "%DESKTOP%" (
  copy /y "%ROOT%PhantomScan Launcher.bat" "%DESKTOP%\PhantomScan Launcher.bat" >nul 2>nul
)

echo.
echo [5/5] Running engine health diagnostics...
"%VENV%\Scripts\python.exe" "%ROOT%phantomscan.py" --check-engines

echo.
echo ============================================================
echo [ok] PhantomScan 2.2.0 installation complete!
echo ============================================================
if exist "%DESKTOP%\PhantomScan Launcher.bat" (
  echo [ok] Desktop launcher created: %DESKTOP%\PhantomScan Launcher.bat
)
echo [ok] Local launcher: "%ROOT%PhantomScan Launcher.bat"
echo.
echo CLI usage examples:
echo   "%ROOT%phantomscan-cli.bat" --target example.com --profile passive
echo   "%ROOT%phantomscan-cli.bat" --target example.com --profile quick
echo   "%ROOT%phantomscan-cli.bat" --target example.com --profile full --debug
echo   "%ROOT%phantomscan-cli.bat" --target http://localhost:3000 --app-profile juiceshop
echo.
pause
