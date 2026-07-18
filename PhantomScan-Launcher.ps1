param()

$ErrorActionPreference = "Stop"
$Host.UI.RawUI.WindowTitle = "PhantomScan Launcher"

$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$BundledPython = "C:\Users\anshc\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe"
$Python = if (Test-Path -LiteralPath $BundledPython) { $BundledPython } else { "python" }
$Cli = Join-Path $Root "phantomscan.py"
$Reports = Join-Path $Root "reports"
$Logs = Join-Path $Root "logs"

function Write-AsciiLogo {
    Write-Host "  ____  _                 _                  ____                  " -ForegroundColor Cyan
    Write-Host " |  _ \| |__   __ _ _ __ | |_ ___  _ __ ___ / ___|  ___ __ _ _ __  " -ForegroundColor Cyan
    Write-Host " | |_) | '_ \ / _` | '_ \| __/ _ \| '_ ` _ \\___ \ / __/ _` | '_ \ " -ForegroundColor Cyan
    Write-Host " |  __/| | | | (_| | | | | || (_) | | | | | |___) | (_| (_| | | | |" -ForegroundColor Cyan
    Write-Host " |_|   |_| |_|\__,_|_| |_|\__\___/|_| |_| |_|____/ \___\__,_|_| |_|" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "                    Scan Smart. Stay Secure." -ForegroundColor DarkCyan
    Write-Host ""
}

function Write-Title {
    Clear-Host
    Write-AsciiLogo
    Write-Host "============================================================" -ForegroundColor DarkCyan
    Write-Host " PhantomScan 2.0.0 - Authorized Security Assessment" -ForegroundColor White
    Write-Host "============================================================" -ForegroundColor DarkCyan
    Write-Host "Use only on systems you own or have written authorization to test." -ForegroundColor Yellow
    Write-Host ""
}

function Read-Choice {
    param(
        [string]$Prompt,
        [string[]]$Allowed,
        [string]$Default
    )
    while ($true) {
        $value = Read-Host "$Prompt [$Default]"
        if ([string]::IsNullOrWhiteSpace($value)) {
            return $Default
        }
        if ($Allowed -contains $value) {
            return $value
        }
        Write-Host "Choose one of: $($Allowed -join ', ')" -ForegroundColor Yellow
    }
}

function Read-YesNo {
    param(
        [string]$Prompt,
        [bool]$Default = $true
    )
    $suffix = if ($Default) { "Y/n" } else { "y/N" }
    while ($true) {
        $value = Read-Host "$Prompt [$suffix]"
        if ([string]::IsNullOrWhiteSpace($value)) {
            return $Default
        }
        switch ($value.ToLowerInvariant()) {
            "y" { return $true }
            "yes" { return $true }
            "n" { return $false }
            "no" { return $false }
            default { Write-Host "Please enter y or n." -ForegroundColor Yellow }
        }
    }
}

function Get-NewestHtmlReport {
    param([datetime]$StartedAt)
    if (-not (Test-Path -LiteralPath $Reports)) {
        return $null
    }
    return Get-ChildItem -LiteralPath $Reports -Filter "*.html" |
        Where-Object { $_.LastWriteTime -ge $StartedAt } |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1
}

function Get-NewestLogFile {
    param([datetime]$StartedAt)
    if (-not (Test-Path -LiteralPath $Logs)) {
        return $null
    }
    return Get-ChildItem -LiteralPath $Logs -Filter "*.log" |
        Where-Object { $_.LastWriteTime -ge $StartedAt } |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1
}

while ($true) {
    Write-Title
    Write-Host "Scan options:" -ForegroundColor White
    Write-Host "-------------" -ForegroundColor DarkGray
    Write-Host "  1. Passive scan      Safe HTTP/DNS/email checks only"
    Write-Host "  2. Quick scan        Real HTTP/DNS + TCP/TLS fallback checks"
    Write-Host "  3. Full scan         Real TCP port scan + TLS inspection"
    Write-Host "  4. API scan          API-focused profile"
    Write-Host "  5. Network scan      Network-focused profile"
    Write-Host "  6. Custom profile"
    Write-Host "  7. Help"
    Write-Host "  0. Exit"
    Write-Host ""

    $mode = Read-Choice "Select an option" @("0", "1", "2", "3", "4", "5", "6", "7") "1"
    if ($mode -eq "0") {
        break
    }
    if ($mode -eq "7") {
        & $Python $Cli --help
        Write-Host ""
        Read-Host "Press Enter to return to the menu"
        continue
    }

    $profile = switch ($mode) {
        "1" { "passive" }
        "2" { "quick" }
        "3" { "full" }
        "4" { "api" }
        "5" { "network" }
        "6" { Read-Choice "Profile" @("quick", "full", "passive", "owasp", "bug-bounty", "api", "network") "quick" }
    }

    $target = Read-Host "Target domain, IP, CIDR, or URL"
    if ([string]::IsNullOrWhiteSpace($target)) {
        Write-Host "No target entered." -ForegroundColor Yellow
        Start-Sleep -Seconds 1
        continue
    }

    $ports = Read-Choice "Ports" @("top100", "top1000", "custom") "top100"
    if ($ports -eq "custom") {
        $ports = Read-Host "Enter ports, for example 80,443,8080 or 1-1000"
        if ([string]::IsNullOrWhiteSpace($ports)) {
            $ports = "top100"
        }
    }

    $showJsonInWindow = Read-YesNo "Print JSON in this window" $false
    $openHtml = Read-YesNo "Open HTML report in browser after scan" $true
    $saveJson = Read-YesNo "Save JSON report" $true
    $requestPdf = Read-YesNo "Request PDF flag (experimental in this build)" $false
    $debugLogging = Read-YesNo "Show debug log output in this window" $false

    $scanArgs = @("--target", $target, "--profile", $profile, "--ports", $ports)
    if ($showJsonInWindow) {
        $scanArgs += "--json"
    }
    if ($requestPdf) {
        $scanArgs += "--pdf"
    }
    if ($debugLogging) {
        $scanArgs += "--debug"
    }
    if (-not $saveJson) {
        Write-Host "JSON report will not be saved." -ForegroundColor Yellow
    }

    Write-Host ""
    Write-Host "Starting PhantomScan..." -ForegroundColor Green
    if ($profile -ne "passive") {
        Write-Host "Real network scanning is enabled. Full/network scans can take 20-60 seconds depending on target and ports." -ForegroundColor Yellow
    }
    Write-Host "& `"$Python`" `"$Cli`" $($scanArgs -join ' ')" -ForegroundColor DarkGray
    Write-Host ""

    $startedAt = Get-Date
    try {
        & $Python $Cli @scanArgs
        $exitCode = $LASTEXITCODE
    } catch {
        Write-Host "Scan failed: $($_.Exception.Message)" -ForegroundColor Red
        $exitCode = 1
    }

    if ($exitCode -eq 0 -and $openHtml) {
        $html = Get-NewestHtmlReport -StartedAt $startedAt
        if ($null -ne $html) {
            Write-Host "Opening HTML report: $($html.FullName)" -ForegroundColor Green
            Start-Process -FilePath $html.FullName
        } else {
            Write-Host "No new HTML report was found." -ForegroundColor Yellow
        }
    }

    $logFile = Get-NewestLogFile -StartedAt $startedAt
    if ($null -ne $logFile) {
        Write-Host "Log file: $($logFile.FullName)" -ForegroundColor DarkCyan
    }

    Write-Host ""
    Write-Host "Reports folder: $Reports" -ForegroundColor Cyan
    Write-Host "Logs folder:    $Logs" -ForegroundColor Cyan
    Write-Host ""
    $again = Read-YesNo "Run another scan" $false
    if (-not $again) {
        break
    }
}
