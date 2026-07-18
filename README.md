<div align="center">
  <h1>🛡️ PhantomScan v2.0.0</h1>
  <p><strong>Scan Smart. Stay Secure.</strong></p>
  <p>An advanced, high-performance Authorized Security Assessment Platform.</p>
</div>

---

## 📖 What is PhantomScan?

PhantomScan is a modern, modular, and highly concurrent security assessment tool designed for penetration testers, security engineers, and system administrators. It performs deep reconnaissance and vulnerability analysis on web applications, domains, and network infrastructure.

PhantomScan is built with a hybrid architecture for maximum performance and reliability:
- **Python (Orchestrator)**: Handles the asynchronous event loop, deep web analysis (HTTP headers, path fuzzing, cookies), email security (SPF/DMARC), and DNS/WHOIS lookups.
- **Go (Port Scanner)**: A highly concurrent TCP port scanning engine utilizing goroutines for lightning-fast network probing.
- **Rust (TLS Inspector)**: A native, high-performance TLS/SSL analysis engine utilizing `rustls` and `ring` to extract certificate metadata and dynamically grade connection security.

### ⚠️ Ethical Use Policy
**AUTHORIZED USE ONLY.** PhantomScan must only be run against systems you own or have explicit, written authorization to assess. The tool automatically enforces scope constraints based on the provided target.

---

## ✨ Features

- **Deep Web Analysis**: Automatically probes for missing security headers (HSTS, CSP, X-Frame-Options), insecure cookies (missing HttpOnly/Secure flags), wildcard CORS policies, and exposed sensitive paths (e.g., `.git/HEAD`, `.env`, `robots.txt`).
- **Concurrent TCP Port Scanning**: Leverages Go for blazing-fast SYN/TCP port checks on the most common ports.
- **TLS/SSL Inspection**: Uses Rust to evaluate certificate transparency, validity periods, Subject Alternative Names (SANs), and issues TLS grades (A-F) based on configuration strength.
- **Email Security Auditing**: Verifies the presence and strictness of SPF, DMARC, and MX records.
- **Subdomain Enumeration**: Queries `crt.sh` and performs asynchronous DNS brute-forcing.
- **Rich Reporting**: Outputs highly detailed JSON, CSV, and aesthetic HTML reports containing specific evidence (e.g., exact missing headers) for every vulnerability found.

---

## 🚀 Installation & Requirements

### Prerequisites
- **Python 3.10+** (for the orchestrator)
- **Go 1.21+** (for the port scanning engine)
- **Rust 2021 Toolchain** (for the TLS engine)

### Setup (Windows / Linux / macOS)

Clone the repository and build the native engines:

```bash
git clone https://github.com/anshchavda02/Phantomscan.git
cd Phantomscan

# 1. Install Python Dependencies
pip install -r requirements.txt

# 2. Build the Go Engine
cd engines/go
go build -o phantomscan-go.exe .
cd ../..

# 3. Build the Rust Engine
cd engines/rust
cargo build --release
cp target/release/phantomscan-rust.exe ../../engines/rust/
cd ../..
```
*(Note: On Linux/macOS, the executable extensions will just be `phantomscan-go` and `phantomscan-rust`)*

---

## 💻 How to Run

### Option 1: The Interactive Launcher (Windows)
For the easiest experience on Windows, simply double-click the `PhantomScan Launcher.bat` file in the root directory. This will open a user-friendly PowerShell interface allowing you to select your scan profile, target, and reporting options without needing the CLI.

### Option 2: Command Line Interface
You can run PhantomScan directly via Python for automation or advanced usage:

```bash
# Quick Scan (Web + DNS + TLS)
python phantomscan.py --target example.com --profile quick

# Full Scan (Includes full TCP port scan)
python phantomscan.py --target example.com --profile full

# Save output to JSON directly in the terminal
python phantomscan.py --target example.com --profile passive --json
```

**Profiles:**
- `passive`: Safe HTTP/DNS/email checks only.
- `quick`: Real HTTP/DNS + TCP/TLS checks on common ports.
- `full`: Complete TCP port scan + deep TLS inspection.

---

## 📊 Output & Reports
Upon completion, PhantomScan generates reports in the `reports/` directory:
- **HTML Report**: A beautiful, easily readable summary of the score, grade, and evidence for each finding.
- **JSON Report**: Machine-readable data perfect for integrating into CI/CD pipelines or SIEMs.
- **CSV Report**: Tabular data for quick spreadsheet analysis.

All scan findings include an `evidence` field detailing the exact HTTP response, missing header, or configuration flaw that triggered the alert.
