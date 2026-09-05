              # PhantomScan Installation and Usage Guide

PhantomScan is for authorized security assessment only. Run it only against systems you own or have explicit written permission to test.

---

## Quick Start by Operating System

### 1. Linux CLI

#### Automated Install (Recommended)
```bash
git clone https://github.com/anshchavda02/Phantomscan.git phantomscan
cd phantomscan
bash scripts/install.sh
```

If `~/.local/bin` is not already in your PATH, add it to your shell configuration (`~/.bashrc` or `~/.zshrc`):
```bash
export PATH="$HOME/.local/bin:$PATH"
```

#### Manual / Virtual Environment Install
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

# Optional: Build fast native engines (if Go, Rust, and Node are installed)
bash scripts/build.sh
```

#### Run CLI on Linux
```bash
phantomscan --target example.com --profile passive
phantomscan --target example.com --profile full --debug
phantomscan --target 127.0.0.1 --profile network --ports top100
phantomscan --target example.com --advanced
```

---

### 2. macOS CLI

#### Automated Install (Recommended)
```bash
# 1. Install prerequisites with Homebrew (if needed)
brew install python

# Optional native engines:
brew install go rust node

# 2. Clone and install
git clone https://github.com/anshchavda02/Phantomscan.git phantomscan
cd phantomscan
bash scripts/install_macos.sh
```

Ensure `~/.local/bin` is in your shell PATH (`~/.zshrc`):
```bash
export PATH="$HOME/.local/bin:$PATH"
```

#### Run CLI on macOS
```bash
phantomscan --target example.com --profile passive
phantomscan --target example.com --profile quick
phantomscan --target example.com --profile full --debug
```

---

### 3. Windows

1. Install Python 3.10 or newer from <https://www.python.org/downloads/windows/> (ensure *"Add Python to PATH"* is checked).
2. Download or clone this repository:
   ```cmd
   git clone https://github.com/anshchavda02/Phantomscan.git
   cd Phantomscan
   ```
3. Run `install.bat` (or double-click it in Windows Explorer):
   ```cmd
   install.bat
   ```
4. The installer creates a virtual environment, installs dependencies, sets up the Node/Playwright engine, and compiles Go/Rust binaries if present.

#### Run on Windows
- **Interactive Menu**: Double-click `PhantomScan Launcher.bat` or run:
  ```cmd
  "PhantomScan Launcher.bat"
  ```
- **CLI Direct**:
  ```cmd
  phantomscan-cli.bat --target example.com --profile passive
  phantomscan-cli.bat --target example.com --profile full --debug
  ```

---

## Multi-Engine Architecture & Tooling

PhantomScan operates with a hybrid polyglot architecture:
- **Python (Core & Modules)**: Runs the scanner orchestrator, 35+ vulnerability modules, pattern analysis, and HTML report generator.
- **Go Engine (`engines/go`)**: High-speed, concurrent TCP port scanner (`bin/phantomscan-go`).
- **Rust Engine (`engines/rust`)**: Low-level TLS/SSL cryptographic inspector (`phantomscan-rust`).
- **Node Engine (`engines/node`)**: Headless browser engine with Playwright & Chromium for SPA / DOM inspection and visual screenshot capture.

*Note: If Go, Rust, or Node are not installed on your system, PhantomScan automatically falls back to native Python sockets and HTTP inspection gracefully.*

---

## CLI Reference & Common Commands

### Basic Scans
```bash
# Passive Recon (HTTP, DNS, Whois, Headers, Secrets)
phantomscan --target example.com --profile passive

# Quick Scan
phantomscan --target example.com --profile quick

# Full Deep Security Scan
phantomscan --target example.com --profile full

# Run all 35 Advanced Modules (including Vibe App Security Suite)
phantomscan --target example.com --advanced
```

### Port Specification
```bash
phantomscan --target example.com --ports top100
phantomscan --target example.com --ports top1000
phantomscan --target example.com --ports 80,443,8080,8443
phantomscan --target example.com --ports 1-1000
```

### Reporting & Formats
```bash
# JSON Output to stdout
phantomscan --target example.com --json

# Export JSON to File
phantomscan --target example.com --json-out reports/scan_result.json

# OWASP Compliance View
phantomscan --target example.com --compliance owasp

# Security Checklist View
phantomscan --target example.com --checklist
```

### Authenticated & Hybrid Scans
```bash
# Authenticated Scan with Cookie
phantomscan --target example.com --auth-cookie "session_id=abcdef123456"

# Authenticated Scan with Bearer Token
phantomscan --target example.com --auth-token "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."

# Hybrid Scan (Correlate live endpoints with local source code)
phantomscan --target example.com --advanced --source-path ./my-app --check-slopsquatting
```

### Local & Vulnerable Application Testing
```bash
# Tailored scan for OWASP Juice Shop
phantomscan --target http://localhost:3000 --app-profile juiceshop

# Tailored scan for DVWA (Damn Vulnerable Web App)
phantomscan --target http://localhost:8080 --app-profile dvwa

# Auto-detect vulnerable target profile
phantomscan --target http://testphp.vulnweb.com --app-profile auto
```

### Diagnostics & Benchmark Harness
```bash
# Verify status of all polyglot engines and dependencies
phantomscan --check-engines

# Run automated detection and false-positive benchmark harness
python scripts/benchmark.py --suite clean
```

---

## Testing & Verification

Run the comprehensive test suite across all modules:
```bash
# Python test suite (330+ passing tests across unit, integration, and contract tests)
python -m pytest

# Run false-positive regression suite (120+ regression tests)
python -m pytest tests/false_positive_regression/

# Run multi-language engine tests
make test
```

---

## Optional Packages

```bash
# PDF Report Generation (requires system cairo/pango)
pip install -r requirements-optional.txt
```
