<div align="center">
<pre>
  ____  _                 _                  ____                  
 |  _ \| |__   __ _ _ __ | |_ ___  _ __ ___ / ___|  ___ __ _ _ __  
 | |_) | '_ \ / _` | '_ \| __/ _ \| '_ ` _ \\___ \ / __/ _` | '_ \ 
 |  __/| | | | (_| | | | | || (_) | | | | | |___) | (_| (_| | | | |
 |_|   |_| |_|\__,_|_| |_|\__\___/|_| |_| |_|____/ \___\__,_|_| |_|
</pre>
  <h3>Scan Smart. Stay Secure.</h3>
  <p><strong>The ultimate polyglot, enterprise-grade Vulnerability Scanner for Web Apps and Networks.</strong></p>
</div>

---

## What is PhantomScan?

PhantomScan is an advanced, automated security assessment platform built for penetration testers, security engineers, and system administrators. 

Unlike traditional scanners that only check for outdated software or simple injection flaws, **PhantomScan understands business logic, multi-step workflows, and complex exploit chains.** It simulates how a modern attacker thinks—finding deep logical flaws, bypassing state machines, and identifying misconfigurations across your web applications, cloud environments, and raw network infrastructure.

Whether you are securing a simple blog or a complex API-driven microservice architecture, PhantomScan provides actionable, compliance-ready intelligence to secure your perimeter.

---

## The Hybrid Architecture

PhantomScan leverages the strengths of three different programming languages to achieve maximum speed, concurrency, and deep analysis without compromise:

- **Python (The Brain)**: Orchestrates the scan, runs the 20 advanced vulnerability modules, handles asynchronous web fuzzing, and generates AI-driven reports.
- **Go (The Muscle)**: Powers a blazing-fast, concurrent TCP SYN port scanner using goroutines to map network boundaries in seconds.
- **Rust (The Inspector)**: Handles low-level, high-performance TLS/SSL cryptographic analysis, extracting certificate metadata and grading connection security safely and natively.

---

## Features Breakdown

### Advanced Vulnerability Detection (20 Specialized Modules)
PhantomScan goes beyond the basics. It includes 20 bespoke security modules that actively test for complex, modern vulnerabilities:

<details>
<summary><strong>1. Business Logic & Authentication Flaws</strong></summary>
<br>
<ul>
  <li><strong>Business Logic Analyzer:</strong> Detects mass assignment, negative price manipulation, and logic limits.</li>
  <li><strong>IDOR / BOLA Detector:</strong> Automatically swaps object IDs cross-session to find Insecure Direct Object References.</li>
  <li><strong>JWT / OAuth Tester:</strong> Cracks weak HMACs, tests 'none' alg bypass, and key confusion attacks.</li>
  <li><strong>Auth & Session Manager:</strong> Tests for session fixation and improper token invalidation after logout.</li>
  <li><strong>Stateful Workflow Scanner:</strong> Learns multi-step flows (Cart -> Checkout) and attempts state machine bypasses.</li>
</ul>
</details>

<details>
<summary><strong>2. Injection & Memory Corruption</strong></summary>
<br>
<ul>
  <li><strong>Prototype Pollution:</strong> Injects <code>__proto__</code> payloads to detect client/server-side JS pollution.</li>
  <li><strong>Second-Order Injection:</strong> Stores XSS/SQLi in profiles/settings and checks if they trigger on admin dashboards.</li>
  <li><strong>HTTP Request Smuggling:</strong> Exploits CL.TE, TE.CL ambiguities using raw TCP sockets to bypass WAFs.</li>
</ul>
</details>

<details>
<summary><strong>3. Advanced Web & Cloud Attacks</strong></summary>
<br>
<ul>
  <li><strong>Blind / OOB Detector:</strong> Uses Out-Of-Band callbacks to catch asynchronous vulnerabilities like Log4Shell or Blind SSRF.</li>
  <li><strong>Race Condition Detector:</strong> Floods endpoints concurrently to exploit Time-of-Check to Time-of-Use (TOCTOU) flaws.</li>
  <li><strong>SSRF Detector:</strong> Probes for internal network access and cloud metadata evasion.</li>
  <li><strong>GraphQL Tester:</strong> Enables introspection, discovers hidden queries, and attempts batching DoS attacks.</li>
  <li><strong>WebSocket Tester:</strong> Tests for Cross-Site WebSocket Hijacking (CSWSH) and unauthenticated channels.</li>
  <li><strong>Cloud Metadata Exposure:</strong> Detects exposed S3 buckets and probes AWS/GCP/Azure IMDS endpoints.</li>
  <li><strong>Supply Chain Analyzer:</strong> Scans 3rd-party JS for hardcoded AWS/Stripe keys and missing SRI tags.</li>
</ul>
</details>

### Core Infrastructure Reconnaissance
<details>
<summary><strong>Deep Network & Web Recon</strong></summary>
<br>
<ul>
  <li><strong>Concurrent TCP Port Scanning:</strong> Rapidly identifies open services across 1000s of ports.</li>
  <li><strong>TLS/SSL Grading:</strong> Evaluates cipher strength, certificate transparency, and issues an A-F grade.</li>
  <li><strong>Email Security Auditing:</strong> Checks SPF, DMARC, and MX records to prevent domain spoofing.</li>
  <li><strong>Subdomain Enumeration:</strong> Queries <code>crt.sh</code> and brute-forces hidden subdomains.</li>
  <li><strong>Deep Web Analysis:</strong> Finds missing security headers, insecure cookies, wild CORS policies, and sensitive exposed paths (<code>.git</code>, <code>.env</code>).</li>
</ul>
</details>

### Intelligence & Reporting
<details>
<summary><strong>Actionable Insights & Compliance</strong></summary>
<br>
<ul>
  <li><strong>Vulnerability Chain Engine:</strong> Automatically correlates isolated low-risk findings (e.g., CORS + Reflected XSS) into critical exploit chains (Account Takeover).</li>
  <li><strong>Attack Path Builder:</strong> Generates visual <strong>Mermaid.js</strong> diagrams showing how an attacker pivots through your app to achieve business impact.</li>
  <li><strong>Compliance Mapping:</strong> Maps every finding directly to <strong>OWASP Top 10 (2021)</strong>, <strong>PCI DSS v4.0</strong>, and <strong>NIST 800-53</strong> controls.</li>
  <li><strong>AI Narrative Generation:</strong> Uses a local, rule-based Natural Language Generation engine to write executive summaries and custom remediation advice (No API keys required!).</li>
  <li><strong>Continuous Monitoring:</strong> Compares scans against previous baselines and fires webhooks for newly introduced vulnerabilities.</li>
</ul>
</details>

---

## Installation

PhantomScan supports Windows, macOS, and Linux. For detailed, step-by-step setup instructions for the Python, Go, and Rust components, see the Installation Guide:

**[View Detailed Installation Guide](INSTALL.md)**

---

## Getting Started

### Option 1: The Interactive Launcher (Recommended for Windows)
Just double-click **`PhantomScan Launcher.bat`**. 
This launches a beautiful, interactive PowerShell menu where you can configure advanced scans, supply authentication tokens, and choose target profiles without typing a single command.

### Option 2: Command Line Interface
Run PhantomScan directly from your terminal for CI/CD automation or quick ad-hoc testing:

```bash
# 1. Advanced Full Scan (Runs all 20 advanced modules + Network + TLS)
python phantomscan.py --target example.com --advanced

# 2. Stateful Authenticated Scan (Test behind a login)
python phantomscan.py --target example.com --advanced --auth-cookie "session_id=12345abcde"

# 3. Continuous Monitoring (Diff against a baseline)
python phantomscan.py --target example.com --advanced --baseline reports/baseline.json

# 4. Quick Passive Scan (Safe recon only, no active fuzzing)
python phantomscan.py --target example.com --profile passive --json
```

---

## Ethical Use Policy

**AUTHORIZED USE ONLY.** 

PhantomScan is a powerful tool capable of altering application state (via advanced modules like Race Conditions and Business Logic testing). **You must only run this tool against systems you own or systems you have explicit, written authorization to assess.**

The tool strictly enforces scope constraints based on the provided target to prevent accidental out-of-bounds scanning, but the operator bears all responsibility for its use.
