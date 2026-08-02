param()

$ErrorActionPreference = "Stop"
$Host.UI.RawUI.WindowTitle = "PhantomScan Launcher"

$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$VenvPython = Join-Path $Root ".venv\Scripts\python.exe"
$Python = if (Test-Path -LiteralPath $VenvPython) { $VenvPython } else { "python" }
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
    Write-Host "  1. Passive scan        Safe DNS/email checks & Deep Web Analysis"
    Write-Host "  2. Quick scan          Fast HTTP checks + Top 100 Port Scan + Basic TLS"
    Write-Host "  3. Full scan           Deep Web + Concurrent Go Portscan + Rust TLS Inspection"
    Write-Host "  4. API scan            API-focused HTTP analysis without web crawling"
    Write-Host "  5. Network scan        Intensive Go Portscanner focused profile"
    Write-Host "  6. Advanced scan       Run 35 advanced security modules (Logic, IDOR, AI Security, Takeover, PII, etc.)"
    Write-Host "  7. Deep scan           Full scan + Advanced scan modules combined"
    Write-Host "  8. AI App Security     Target AI-generated / vibe-coded web app vulns (Keys, RLS, Prompts, CRUD, .env)"
    Write-Host "  9. Differential scan   Compare Staging vs Production security posture (--diff-env)"
    Write-Host " 10. Mobile API scan     Extract & test backend APIs from APK or IPA binaries"
    Write-Host " 11. Dependency check    Check project for Dependency Confusion risks (--check-deps)"
    Write-Host " 12. Merge scan reports  Deduplicate and merge multiple scan JSON files (--merge)"
    Write-Host " 13. Verification server Start local one-click remediation verification server (--serve-verify)"
    Write-Host " 14. Custom profile"
    Write-Host " 15. Proxy mode          Intercept traffic and feed to YAML Rules Engine"
    Write-Host " 16. Help"
    Write-Host "  0. Exit"
    Write-Host ""

    $mode = Read-Choice "Select an option" @("0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13", "14", "15", "16") "1"
    if ($mode -eq "0") {
        break
    }
    if ($mode -eq "16") {
        & $Python $Cli --help
        Write-Host ""
        Read-Host "Press Enter to return to the menu"
        continue
    }

    if ($mode -eq "8") {
        $target = Read-Host "Target domain or URL (e.g. https://myvibeapp.lovable.app)"
        if (-not [string]::IsNullOrWhiteSpace($target)) {
            & $Python $Cli --target $target --modules ai_app_security
        } else {
            Write-Host "No target entered." -ForegroundColor Yellow
        }
        Write-Host ""
        Read-Host "Press Enter to return to the menu"
        continue
    }

    if ($mode -eq "9") {
        $staging = Read-Host "Staging target URL/domain (e.g. staging.example.com)"
        $production = Read-Host "Production target URL/domain (e.g. example.com)"
        & $Python $Cli --diff-env --staging $staging --production $production
        Write-Host ""
        Read-Host "Press Enter to return to the menu"
        continue
    }

    if ($mode -eq "10") {
        $path = Read-Host "Path to app.apk or app.ipa"
        if ($path.EndsWith(".apk")) {
            & $Python $Cli --mobile-apk $path --extract-apis
        } else {
            & $Python $Cli --mobile-ipa $path --extract-apis
        }
        Write-Host ""
        Read-Host "Press Enter to return to the menu"
        continue
    }

    if ($mode -eq "11") {
        $dir = Read-Host "Path to project directory [.]"
        if ([string]::IsNullOrWhiteSpace($dir)) { $dir = "." }
        & $Python $Cli --check-deps $dir
        Write-Host ""
        Read-Host "Press Enter to return to the menu"
        continue
    }

    if ($mode -eq "12") {
        $files = Read-Host "Enter space-separated JSON report file paths"
        & $Python $Cli --merge $files.Split(' ')
        Write-Host ""
        Read-Host "Press Enter to return to the menu"
        continue
    }

    if ($mode -eq "13") {
        $port = Read-Host "Port for verification server [8420]"
        if ([string]::IsNullOrWhiteSpace($port)) { $port = "8420" }
        Write-Host "Starting remediation verification server on http://localhost:$port..." -ForegroundColor Green
        & $Python $Cli --serve-verify --verify-port $port
        continue
    }

    $profile = switch ($mode) {
        "1" { "passive" }
        "2" { "quick" }
        "3" { "full" }
        "4" { "api" }
        "5" { "network" }
        "6" { "advanced" }
        "7" { "deep" }
        "14" { Read-Choice "Profile" @("quick", "full", "passive", "owasp", "bug-bounty", "api", "network", "advanced", "deep", "monitor") "quick" }
        "15" { "proxy" }
    }

    $target = Read-Host "Target domain, IP, CIDR, or URL"
    if ([string]::IsNullOrWhiteSpace($target)) {
        Write-Host "No target entered." -ForegroundColor Yellow
        Start-Sleep -Seconds 1
        continue
    }

    $ports = "top100"
    if ($profile -ne "proxy") {
        $ports = Read-Choice "Ports" @("top100", "top1000", "custom") "top100"
        if ($ports -eq "custom") {
            $ports = Read-Host "Enter ports, for example 80,443,8080 or 1-1000"
            if ([string]::IsNullOrWhiteSpace($ports)) {
                $ports = "top100"
            }
        }
    }

    $showJsonInWindow = Read-YesNo "Print JSON in this window" $false
    $openHtml = Read-YesNo "Open HTML report in browser after scan" $true
    $saveJson = Read-YesNo "Save JSON report" $true
    $requestPdf = Read-YesNo "Request PDF flag (experimental in this build)" $false
    $debugLogging = Read-YesNo "Show debug log output in this window" $false

    $scanArgs = @("--target", $target)
    
    if ($profile -eq "proxy") {
        $proxyPort = Read-Host "Enter local port for proxy [8080]"
        if ([string]::IsNullOrWhiteSpace($proxyPort)) {
            $proxyPort = "8080"
        }
        $scanArgs += "--proxy"
        $scanArgs += "127.0.0.1:$proxyPort"
    } else {
        $scanArgs += "--profile"
        $scanArgs += $profile
        $scanArgs += "--ports"
        $scanArgs += $ports
        
        # Options specific to advanced/deep profiles
        if ($profile -eq "advanced" -or $profile -eq "deep" -or $profile -eq "monitor") {
            $runAllAdvanced = Read-YesNo "Run all 35 advanced modules (y) or select specific ones (n)" $true
            if ($runAllAdvanced) {
                $scanArgs += "--advanced"
            } else {
                $modules = Read-Host "Enter comma-separated modules (e.g. business_logic,idor,graphql)"
                if (-not [string]::IsNullOrWhiteSpace($modules)) {
                    $scanArgs += "--modules"
                    $scanArgs += $modules
                }
            }
            
            $provideAuth = Read-YesNo "Provide authentication for stateful/authenticated scanning" $false
            if ($provideAuth) {
                $authCookie = Read-Host "Enter Auth Cookie (e.g. session=abc123...)"
                if (-not [string]::IsNullOrWhiteSpace($authCookie)) {
                    $scanArgs += "--auth-cookie"
                    $scanArgs += "`"$authCookie`""
                }
                $authToken = Read-Host "Enter Auth Token (e.g. eyJhbGci...)"
                if (-not [string]::IsNullOrWhiteSpace($authToken)) {
                    $scanArgs += "--auth-token"
                    $scanArgs += "`"$authToken`""
                }
            }
        }
    }
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
    if ($profile -eq "full") {
        Write-Host "[*] Full Scan Activated:" -ForegroundColor Cyan
        Write-Host "    - Deep Web Analysis (Headers, Cookies, CORS, Sensitive Paths)" -ForegroundColor Cyan
        Write-Host "    - Rust Native TLS Inspection (Certificates, SANs, Grading)" -ForegroundColor Cyan
        Write-Host "    - Go Concurrent TCP Port Scanner" -ForegroundColor Cyan
        Write-Host "    - Email Security (SPF/DMARC) & DNS Brute-forcing" -ForegroundColor Cyan
        Write-Host "    Note: Full scans may take 1-5 minutes depending on the target." -ForegroundColor Yellow
    } elseif ($profile -eq "advanced" -or $profile -eq "deep") {
        Write-Host "[*] Advanced Scan Activated:" -ForegroundColor Cyan
        Write-Host "    - Will execute advanced modules (Logic, IDOR, Injection, Chain Engine, etc.)" -ForegroundColor Cyan
        Write-Host "    - Deep testing may take additional time to complete." -ForegroundColor Yellow
    } elseif ($profile -ne "passive") {
        Write-Host "Real network scanning is enabled. Scans can take 1-3 minutes depending on target and ports." -ForegroundColor Yellow
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
