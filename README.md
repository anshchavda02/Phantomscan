<div align="center">
<pre>
  ____  _                 _                  ____                  
 |  _ \| |__   __ _ _ __ | |_ ___  _ __ ___ / ___|  ___ __ _ _ __  
 | |_) | '_ \ / _` | '_ \| __/ _ \| '_ ` _ \\___ \ / __/ _` | '_ \ 
 |  __/| | | | (_| | | | | || (_) | | | | | |___) | (_| (_| | | | |
 |_|   |_| |_|\__,_|_| |_|\__\___/|_| |_| |_|____/ \___\__,_|_| |_|
</pre>
  <h3>Scan Smart. Stay Secure.</h3>
  <p>An advanced, high-performance Authorized Security Assessment Platform.</p>
</div>

---

## What is PhantomScan?

PhantomScan is a modern, modular, and highly concurrent security assessment tool designed for penetration testers, security engineers, and system administrators. It performs deep reconnaissance and vulnerability analysis on web applications, domains, and network infrastructure.

PhantomScan is built with a hybrid architecture for maximum performance and reliability:
- **Python (Orchestrator)**: Handles the asynchronous event loop, deep web analysis (HTTP headers, path fuzzing, cookies), email security (SPF/DMARC), and DNS/WHOIS lookups.
- **Go (Port Scanner)**: A highly concurrent TCP port scanning engine utilizing goroutines for lightning-fast network probing.
- **Rust (TLS Inspector)**: A native, high-performance TLS/SSL analysis engine utilizing `rustls` and `ring` to extract certificate metadata and dynamically grade connection security.

### Ethical Use Policy
**AUTHORIZED USE ONLY.** PhantomScan must only be run against systems you own or have explicit, written authorization to assess. The tool automatically enforces scope constraints based on the provided target.

---

## Features

<details>
<summary><strong>Advanced Vulnerability Modules</strong></summary>
<br>
Includes 20 specialized modules for detecting complex vulnerabilities like Business Logic Flaws, IDOR/BOLA, JWT bypasses, Blind/OOB vulnerabilities, Race Conditions, HTTP Request Smuggling, and Server-Side Request Forgery (SSRF).
</details>

<details>
<summary><strong>Vulnerability Chain Engine & Attack Paths</strong></summary>
<br>
Automatically correlates isolated findings (e.g., CORS + XSS) into high-impact exploit chains, generating visual Mermaid.js attack path diagrams.
</details>

<details>
<summary><strong>Deep Web Analysis</strong></summary>
<br>
Automatically probes for missing security headers, insecure cookies, wildcard CORS policies, and exposed sensitive paths (e.g., <code>.git/HEAD</code>, <code>.env</code>, <code>robots.txt</code>).
</details>

<details>
<summary><strong>Concurrent TCP Port Scanning</strong></summary>
<br>
Leverages Go for blazing-fast SYN/TCP port checks on the most common ports.
</details>

<details>
<summary><strong>TLS/SSL Inspection</strong></summary>
<br>
Uses Rust to evaluate certificate transparency, validity periods, Subject Alternative Names (SANs), and issues TLS grades (A-F) based on configuration strength.
</details>

<details>
<summary><strong>Email Security Auditing</strong></summary>
<br>
Verifies the presence and strictness of SPF, DMARC, and MX records.
</details>

<details>
<summary><strong>Subdomain Enumeration</strong></summary>
<br>
Queries <code>crt.sh</code> and performs asynchronous DNS brute-forcing.
</details>

<details>
<summary><strong>Compliance Mapping</strong></summary>
<br>
Automatically maps findings to OWASP Top 10 (2021), PCI DSS v4.0, and NIST 800-53 controls.
</details>

<details>
<summary><strong>Rich Reporting & AI Narratives</strong></summary>
<br>
Outputs highly detailed JSON, CSV, and aesthetic HTML reports. Uses rule-based Natural Language Generation (NLG) to create executive summaries and remediation narratives without requiring external API keys.
</details>

---

## Installation & Requirements

For comprehensive, step-by-step instructions for all platforms, please refer to the detailed installation guide:

**[View Detailed Installation Guide (Windows, macOS, Linux)](INSTALL.md)**

### Prerequisites Summary
- **Python 3.10+** (for the orchestrator)
- **Go 1.21+** (for the port scanning engine)
- **Rust 2021 Toolchain** (for the TLS engine)

---

## How to Run

### Option 1: The Interactive Launcher (Windows)
For the easiest experience on Windows, simply double-click the `PhantomScan Launcher.bat` file in the root directory. This will open a user-friendly PowerShell interface allowing you to select your scan profile, target, and reporting options without needing the CLI.

### Option 2: Command Line Interface
You can run PhantomScan directly via Python for automation or advanced usage:

```bash
# Quick Scan (Web + DNS + TLS)
python phantomscan.py --target example.com --profile quick

# Full Scan (Includes full TCP port scan)
python phantomscan.py --target example.com --profile full

# Advanced Scan (Includes all 20 advanced modules like IDOR, SSRF, Logic Flaws)
python phantomscan.py --target example.com --advanced

# Stateful Authenticated Scan
python phantomscan.py --target example.com --advanced --auth-cookie "session=abc123"

# Save output to JSON directly in the terminal
python phantomscan.py --target example.com --profile passive --json
```

**Profiles & Flags:**
- `passive`: Safe HTTP/DNS/email checks only.
- `quick`: Real HTTP/DNS + TCP/TLS checks on common ports.
- `full`: Complete TCP port scan + deep TLS inspection.
- `--advanced`: Runs the 20 advanced vulnerability modules.
- `--modules`: Comma-separated list of specific advanced modules to run (e.g., `business_logic,idor`).

---

## Output & Reports
Upon completion, PhantomScan generates reports in the `reports/` directory:
- **HTML Report**: A beautiful, easily readable summary of the score, grade, and evidence for each finding.
- **JSON Report**: Machine-readable data perfect for integrating into CI/CD pipelines or SIEMs.
- **CSV Report**: Tabular data for quick spreadsheet analysis.

All scan findings include an `evidence` field detailing the exact HTTP response, missing header, or configuration flaw that triggered the alert.
