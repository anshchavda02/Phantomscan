<div align="center">

```
  ____  _                 _                  ____                  
 |  _ \| |__   __ _ _ __ | |_ ___  _ __ ___ / ___|  ___ __ _ _ __  
 | |_) | '_ \ / _` | '_ \| __/ _ \| '_ ` _ \\___ \ / __/ _` | '_ \ 
 |  __/| | | | (_| | | | | || (_) | | | | | |___) | (_| (_| | | | |
 |_|   |_| |_|\__,_|_| |_|\__\___/|_| |_| |_|____/ \___\__,_|_| |_|
```

### **Enterprise-Grade Polyglot Vulnerability Scanner**
*Tailored for AI-Generated & Vibe-Coded Web Apps, Cloud Backends, and Modern APIs*

[![Tests](https://img.shields.io/badge/tests-197%20passed-brightgreen.svg?style=flat-square)](tests/)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg?style=flat-square)](https://www.python.org/)
[![Go](https://img.shields.io/badge/engine-Go%20%7C%20Rust%20%7C%20Node%20%7C%20Python-blueviolet.svg?style=flat-square)](engines/)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey.svg?style=flat-square)](INSTALL.md)
[![License](https://img.shields.io/badge/license-MIT-green.svg?style=flat-square)](LICENSE)

[Quick Start](#-quick-start) • [Architecture](#-polyglot-architecture) • [Features](#-core-capabilities) • [CLI Reference](#-cli-command-reference) • [Reporting](#-enterprise-reporting) • [Documentation](INSTALL.md)

</div>

---

## 📌 Executive Summary

**PhantomScan v2.0.0** is an enterprise-grade automated security assessment engine engineered for security engineers, penetration testers, and DevSecOps teams.

Traditional dynamic vulnerability scanners focus almost exclusively on legacy web servers or basic static rule fuzzing. **PhantomScan bridges the modern security gap** by introducing deep analysis engines specifically tuned for **AI-generated applications** (built via tools like Lovable.dev, Bolt.new, v0, Cursor, Windsurf, Replit AI, and Base44), **BaaS architectures** (Supabase, Firebase, Convex), and **modern full-stack web frameworks** (Next.js, Remix, tRPC, GraphQL).

---

## ⚡ Polyglot Architecture

PhantomScan combines four programming ecosystems into a unified scanning pipeline for optimal execution speed, deep cryptographic rigor, and rich DOM rendering:

```
┌───────────────────────────────────────────────────────────────────────────────────┐
│                               PHANTOMSCAN CORE                                    │
│                     Python Orchestrator & FindingGate™                            │
└──────────────┬──────────────────┬──────────────────┬──────────────────┬───────────┘
               │                  │                  │                  │
               ▼                  ▼                  ▼                  ▼
     ┌──────────────────┐┌──────────────────┐┌──────────────────┐┌──────────────────┐
     │    Go Engine     ││   Rust Engine    ││   Node Engine    ││  Python Modules  │
     │  (High-Speed     ││  (Native TLS/SSL ││ (Playwright DOM  ││  (35+ Advanced   │
     │   SYN Scanner)   ││   Cryptographic  ││   SPA & Visual   ││   Security & AI  │
     │                  ││    Inspector)    ││   Screenshots)   ││   Scanners)      │
     └─────────┬────────┘└────────┬─────────┘└────────┬─────────┘└────────┬─────────┘
               │                  │                   │                   │
               └──────────────────┴─────────┬─────────┴───────────────────┘
                                            │
                                            ▼
                          ┌───────────────────────────────────┐
                          │   Vulnerability Chain Engine      │
                          │   & Interactive HTML/JSON Report  │
                          └───────────────────────────────────┘
```

- 🧠 **Python (Orchestrator & Intelligence)**: Manages the execution pipeline, 35+ specialized detection modules, CVSS scoring, and reporting engines.
- ⚡ **Go (Network Muscle)**: High-concurrency TCP SYN port scanner built with goroutines to enumerate network surfaces in seconds.
- 🦀 **Rust (Cryptographic Inspector)**: Low-level TLS/SSL analyzer inspecting cipher suites, handshake negotiation, and certificate chains natively.
- 🌐 **Node.js + Playwright (Browser Engine)**: Headless browser rendering SPA frontends, discovering exposed login endpoints, and capturing high-resolution visual evidence screenshots.

---

## 🛡️ Core Capabilities

### 1. Vibe-Coded & AI App Security Suite
Designed to audit modern AI-assisted web applications and serverless backends:
- **150+ Secret Pattern Engine**: Scans JS bundles, source maps, and local codebases against curated pattern databases (OpenAI, Anthropic, Gemini, AWS, Stripe, Supabase, Firebase) with Shannon entropy scoring and false-positive comment suppression.
- **Supabase Auditor V2**: Audits Row Level Security (RLS) policies across PostgREST endpoints (`/rest/v1/`), open storage buckets, auth configuration weaknesses, and service key disclosures.
- **Firebase Auditor V2**: Probes Realtime Database rules (`/.json`), Firestore security policies, and exposed Admin SDK credentials.
- **Alternative BaaS Auditors**: Audits Convex backend functions, exposed MongoDB connection strings, and unauthenticated PostgreSQL URLs.
- **ORM Misconfiguration Detector**: Identifies Prisma error disclosures, unscoped models missing tenant/user ownership fields, and raw Drizzle `sql``` injection vectors.
- **tRPC & GraphQL Analyzers**: Probes `/api/trpc` routes and GraphQL endpoints for introspections, unauthenticated administrative procedures, and query abuse.
- **Slopsquatting Dependency Checker**: Verifies dependencies against npm/PyPI registries to detect AI-hallucinated packages susceptible to supply-chain takeover.
- **AI Prompt & Serverless Proxy Protection**: Tests `/api/chat` and `/api/generate` routes for missing rate limits and prompt injection leakage.

### 2. Multi-Step Vulnerability Chain Engine
PhantomScan correlates seemingly minor low-severity findings into actionable **Critical Exploit Chains**:
- `Supabase RLS Bypass` ➔ `User Record Enumeration` ➔ `Account Takeover`
- `Firebase Open Database` ➔ `PII Harvesting` ➔ `Full Data Exfiltration`
- `Unauthenticated AI Proxy` ➔ `Prompt Extraction` ➔ `Unlimited LLM Cost Drain`
- `Slopsquatting Hallucination` ➔ `Malicious Dependency Injection` ➔ `Supply Chain RCE`

Each chain includes automated **Mermaid.js attack path diagrams** detailing prerequisite steps, execution vectors, and business impact.

### 3. FindingGate™ False-Positive Elimination
Alert fatigue is eliminated through a multi-tier confirmation gate:
- **Response Body Heuristics**: Validates that flagged endpoints return authentic error/data structures rather than generic SPA catch-alls.
- **CSP Meta-Tag Resolution**: Evaluates both HTTP response headers and `<meta http-equiv="Content-Security-Policy">` tags.
- **Statistical Timing Verification**: Re-tests potential time-based SQLi / SSRF signals against randomized baseline latencies to prevent false alarms on network fluctuations.

---

## 🚀 Quick Start

### Installation

#### Linux CLI
```bash
git clone https://github.com/anshchavda02/Phantomscan.git phantomscan
cd phantomscan
bash scripts/install.sh
```

#### macOS CLI
```bash
git clone https://github.com/anshchavda02/Phantomscan.git phantomscan
cd phantomscan
bash scripts/install_macos.sh
```

#### Windows CLI & Launcher
```cmd
git clone https://github.com/anshchavda02/Phantomscan.git
cd Phantomscan
install.bat
```

*For detailed prerequisite instructions across all platforms, see [INSTALL.md](INSTALL.md).*

---

## 💻 CLI Command Reference

### Basic Scans
```bash
# Passive Recon (HTTP headers, DNS, Whois, Secrets, Technologies)
phantomscan --target example.com --profile passive

# Quick Active Scan
phantomscan --target example.com --profile quick

# Full Deep Security Assessment
phantomscan --target example.com --profile full --debug

# Run All 35 Advanced Modules (including Vibe App Security Suite)
phantomscan --target example.com --advanced
```

### Targeted & Authenticated Scanning
```bash
# Run Specific Security Modules
phantomscan --target example.com --modules ai_app_security,vuln_chain,idor

# Authenticated Scan with Session Cookie
phantomscan --target example.com --advanced --auth-cookie "session_id=abc123xyz"

# Authenticated API Scan with Bearer Token
phantomscan --target api.example.com --profile api --auth-token "Bearer eyJhbGciOi..."

# Hybrid Scan (Correlate live endpoints with local source code)
phantomscan --target example.com --advanced --source-path ./my-app --check-slopsquatting
```

### Scan Profiles

| Profile | Target Scope | Engines Invoked | Typical Duration |
| :--- | :--- | :--- | :--- |
| `passive` | Non-intrusive recon, DNS, WHOIS, header analysis | Python | ~2-5s |
| `quick` | Standard web services + common ports | Python + Go | ~5-15s |
| `full` | Deep web fuzzing, TLS inspection, port discovery | Python + Go + Rust + Node | ~20-45s |
| `api` | REST, GraphQL, tRPC, API keys & JWT evaluation | Python + Node | ~15-30s |
| `network` | Full port enumeration (top 1000) & service discovery | Go + Rust | ~10-30s |
| `advanced` / `deep` | Full 35+ module suite, AI security, vuln chaining | All Engines | ~30-60s |

### CLI Options & Flags

| Flag | Description |
| :--- | :--- |
| `--target` | Target domain, IP address, CIDR block, or URL. |
| `--profile` | Scan profile: `passive`, `quick`, `full`, `api`, `network`, `advanced`, `deep`. |
| `--advanced` | Enables the full 35-module advanced security suite. |
| `--ports` | Port selection: `top100`, `top1000`, `80,443,8080`, or ranges (`1-1000`). |
| `--source-path` | Path to local repository for hybrid black-box + source code analysis. |
| `--check-slopsquatting` | Audits dependencies for AI-hallucinated package names. |
| `--auth-cookie` | Session cookie header for authenticated crawling. |
| `--auth-token` | Authorization token header for authenticated API assessment. |
| `--json` | Stream scan output as structured JSON to stdout. |
| `--json-out` | Write complete scan results to a specified JSON file. |
| `--compliance` | Output compliance matrix (`owasp`, `pci-dss`, `hipaa`, `iso27001`). |
| `--checklist` | Generate actionable pre-flight hardening checklist. |
| `--debug` | Enable verbose diagnostic logging. |

---

## 📊 Enterprise Reporting

PhantomScan generates **Wiz/Snyk-tier interactive HTML reports** along with machine-readable **JSON** and **CSV** artifacts:

- **Executive Summary & Security Score**: Visual grade (`A` through `F`) computed with CVSS v3.1 severity weighting.
- **6-Axis Risk Radar**: Real-time canvas radar mapping category breakdowns (Recon, Web, Auth, Cloud/BaaS, Supply Chain, Cryptography).
- **Interactive Exploit Chains**: Expandable Mermaid.js graphs showing end-to-end attack paths.
- **Visual Evidence & DOM Screenshots**: Embedded headless browser renders illustrating captured vulnerabilities and exposed interfaces.
- **Remediation Playbooks**: Actionable mitigation code snippets and OWASP / CVE references for engineering teams.

```
reports/
├── example.com_20260829_134500.html   # Interactive visual dashboard
├── example.com_20260829_134500.json   # CI/CD machine-readable output
└── fp_log_example.com_20260829.json   # Suppressed findings audit trail
```

---

## 🧪 Testing & Verification

PhantomScan maintains strict quality benchmarks across all engines and modules:

```bash
# Run complete Python test suite (197 Passing Tests)
python -m pytest

# Run multi-language engine unit tests
make test
```

---

## ⚖️ Ethical Use & Legal Disclaimer

> [!IMPORTANT]
> **PhantomScan is intended strictly for authorized security auditing, penetration testing, and educational research.**
> 
> Testing systems without prior explicit written authorization from the system owner is illegal. The developers assume no liability for misuse, unauthorized activities, or damage caused by this software.

---

<div align="center">
  <sub>Built with ❤️ for modern DevSecOps, AppSec Engineers, and Security Researchers.</sub>
</div>
