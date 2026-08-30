<div align="center">

<pre>
  ____  _                 _                  ____                  
 |  _ \| |__   __ _ _ __ | |_ ___  _ __ ___ / ___|  ___ __ _ _ __  
 | |_) | '_ \ / _` | '_ \| __/ _ \| '_ ` _ \\___ \ / __/ _` | '_ \ 
 |  __/| | | | (_| | | | | || (_) | | | | | |___) | (_| (_| | | | |
 |_|   |_| |_|\__,_|_| |_|\__\___/|_| |_| |_|____/ \___\__,_|_| |_|
</pre>

### **Next-Generation Modular Cybersecurity Platform for Automated Vulnerability Assessment**
*Enterprise-Grade DAST Engineered for Modern APIs, AI-Generated / Vibe-Coded Web Apps, Cloud Backends, and Supply Chains*

[![Tests](https://img.shields.io/badge/tests-290%20passed-brightgreen.svg?style=flat-square)](tests/)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg?style=flat-square)](https://www.python.org/)
[![Go](https://img.shields.io/badge/go-1.21%2B-00ADD8.svg?style=flat-square)](engines/go/)
[![Rust](https://img.shields.io/badge/rust-2021%20edition-dea584.svg?style=flat-square)](engines/rust/)
[![Playwright](https://img.shields.io/badge/playwright-v1.40%2B-45ba4b.svg?style=flat-square)](engines/node/)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey.svg?style=flat-square)](INSTALL.md)
[![License](https://img.shields.io/badge/license-MIT-green.svg?style=flat-square)](LICENSE)

[Quick Start](#quick-start) • [Architecture](#polyglot-architecture--pipeline-dag) • [Security Pillars](#core-security-pillars) • [CLI Reference](#cli-command-reference) • [Enterprise Reporting](#enterprise-reporting--telemetry) • [Documentation](INSTALL.md)

</div>

---

## Executive Summary

**PhantomScan v2.0.0** is an evidence-driven, high-concurrency automated vulnerability assessment platform engineered for AppSec teams, DevSecOps pipelines, and modern penetration testers.

Legacy vulnerability scanners focus primarily on monolithic web servers and static pattern fuzzing. **PhantomScan bridges the modern security posture gap** by combining:
1. **AI-Native & Vibe-Coded Application Security**: Auditing applications built with LLM-assisted workflows (*Lovable, Bolt.new, v0, Cursor, Replit, Windsurf*), testing Backend-as-a-Service (BaaS) architectures (*Supabase, Firebase, Convex*), and verifying AI supply chain packages against hallucinated slopsquatting.
2. **Modern Web & API Protocol Scanners**: Native fuzzers for GraphQL introspection, WebSocket Origin/CSWSH, Prototype Pollution, HTTP Request Smuggling (CL.TE / TE.CL), and IDOR/BOLA.
3. **Multi-Stage Statistical Injections**: High-specificity SQL Injection, XSS, Path Traversal, and Second-Order Injection engines using baseline differentials and statistical timing verification to guarantee zero false positives.
4. **Multi-Language Polyglot Performance**: High-speed Go SYN port scanning, Rust native cryptographic TLS inspection, Node.js Playwright SPA DOM crawling, and an async Python DAG orchestrator.

---

## Polyglot Architecture & Pipeline DAG

PhantomScan executes security operations across a **6-stage topological Pipeline DAG** orchestrated with typed **Asset Graph** state management:

```
  ┌────────────────────────────────────────────────────────────────────────────────────────┐
  │                                    PHANTOMSCAN CORE                                    │
  │              Topological Pipeline DAG • Asset Graph Engine • FindingGate™              │
  └───────────────┬──────────────────┬───────────────────┬───────────────────┬─────────────┘
                  │                  │                   │                   │
                  ▼                  ▼                   ▼                   ▼
        ┌──────────────────┐┌──────────────────┐┌──────────────────┐┌──────────────────┐
        │    Go Engine     ││   Rust Engine    ││   Node Engine    ││  Python Modules  │
        │  (High-Speed     ││  (Native TLS/SSL ││ (Playwright DOM  ││  (38 Specialized │
        │   SYN Scanner)   ││   Cryptographic  ││   SPA & Visual   ││   Security & AI  │
        │                  ││    Inspector)    ││   Screenshots)   ││   Scanners)      │
        └─────────┬────────┘└────────┬─────────┘└────────┬─────────┘└────────┬─────────┘
                  │                  │                   │                   │
                  └──────────────────┴─────────┬─────────┴───────────────────┘
                                               │
                                               ▼
                             ┌───────────────────────────────────┐
                             │    Vulnerability Chain Engine     │
                             │  & Compliance Matrix (OWASP/PCI)  │
                             └─────────────────┬─────────────────┘
                                               │
                                               ▼
                             ┌───────────────────────────────────┐
                             │   Interactive HTML/JSON Report    │
                             │  + Tokenized One-Click Verify UI  │
                             └───────────────────────────────────┘
```

### Execution Pipeline Order (PR-A01 Guaranteed)
1. **Reconnaissance & Surface Mapping**: DNS, WHOIS/RDAP, Subdomain Enumeration (crt.sh + DNS brute force), Subdomain Takeover (16+ providers), Email Security (SPF/DMARC/DKIM on root domain).
2. **Discovery & Crawling**: JavaScript AST Route Extractor, OpenAPI/Swagger Ingestion, SPA Playwright Crawler with form baseline payload generation.
3. **Active Security & AI Probes**: Multi-Stage Injection, BaaS RLS audits, tRPC probers, GraphQL analyzers, WebSocket testers, Prototype Pollution, IDOR, Request Smuggling, SSRF.
4. **Correlation & Synthesis**: Vulnerability Chaining (`VulnChainEngine`), Mermaid.js attack graph generation, Regulatory Compliance mapping (OWASP, PCI DSS, NIST).
5. **Post-Processing (`FindingGate`)**: Deterministic SHA-256 fingerprinting, verification method validation, canonical severity ceiling enforcement, secret masking (`SEC-H02`), deduction caps (`PR-S01`).
6. **Scoring & Reporting**: Real-time CVSS scoring, 6-axis risk radar, interactive HTML dashboard, JSON/CSV export, and one-click remediation verification server.

---

## Core Security Pillars

### 1. Modern Web & API Protocol Suite
- **GraphQL Tester**: Discovers `/graphql`, queries schema introspection, checks for batch query amplification, and tests field suggestion vulnerabilities.
- **WebSocket Tester**: Performs CSWSH (Cross-Site WebSocket Hijacking) testing by evaluating origin reflection, token validation, and unencrypted transmission.
- **Prototype Pollution**: Tests `__proto__`, `constructor.prototype` object mutations against JSON endpoints and query parameters.
- **HTTP Request Smuggling**: Tests CL.TE, TE.CL, and TE.TE header obfuscation with socket desync timing verification.
- **IDOR / BOLA Detector**: Evaluates numerical, UUID, and object reference boundaries across REST endpoints with multi-identity differential analysis.
- **Race Condition Limit Overrun**: Executes concurrent parallel bursts against checkout, transfer, coupon, and claim endpoints.

### 2. AI-Native & Vibe-Coded Application Security
- **BaaS RLS Policy Auditor**: Evaluates Supabase (`/rest/v1/`) and Firebase (`/.json`) endpoints for missing or bypassed Row Level Security.
- **150+ Secret Pattern Engine**: High-entropy secret scanner for OpenAI, Anthropic, Gemini, AWS, Stripe, GitHub, Supabase, and database connection strings (masked to first 8 chars + `***`).
- **tRPC Endpoint Prober**: Maps `/api/trpc` routes, inspecting unauthenticated procedure mutations and schema leakages.
- **Package Hallucination & Slopsquatting**: Cross-references package references against registry databases to prevent AI-hallucinated package takeovers.
- **AI Prompt Proxy Protection**: Assesses `/api/chat` and `/api/generate` for missing rate limits and prompt extraction vectors.

### 3. Multi-Stage Injection & Verification Engine
- **SQL Injection**: Multi-dialect signatures (MySQL, MSSQL, PostgreSQL, Oracle, SQLite) with statistical baseline differentials and reversible error detection.
- **Cross-Site Scripting (XSS)**: Tests query parameters and form fields using non-executing reflection markers and CSP meta-tag analysis.
- **Path Traversal & LFI**: Detects directory escapes (`../../etc/passwd`, `..\windows\win.ini`) with response body pattern verification.
- **Second-Order Injection**: Tracks multi-step inputs stored and rendered across distinct application states.

### 4. Enterprise Resilience & Quality Assurance
- **Two-Tier Scan Cache**: Persistent SQLite cache with TTL invalidation to accelerate recurring CI/CD pipelines.
- **Circuit Breakers & Rate Limiting**: Centralized `ScopePolicy` preventing RFC 1918 private IP escapes, loopback probing, and cloud metadata tampering (`SEC-S02`).
- **Resource Governor**: Real-time memory ceiling enforcement and process isolation.
- **One-Click Remediation Verification**: Embedded local server (`--serve-verify`) allowing developers to validate fixes instantly with tokenized verify endpoints.

---

## Quick Start

### Installation

#### Linux CLI
```bash
git clone https://github.com/anshchavda02/Phantomscan.git
cd Phantomscan
bash scripts/install.sh
```

#### macOS CLI
```bash
git clone https://github.com/anshchavda02/Phantomscan.git
cd Phantomscan
bash scripts/install_macos.sh
```

#### Windows CLI & Interactive Launcher
```cmd
git clone https://github.com/anshchavda02/Phantomscan.git
cd Phantomscan
install.bat
```
*(Or double-click `PhantomScan Launcher.bat` / run `PhantomScan-Launcher.ps1`)*

---

## CLI Command Reference

### Common Workflows
```bash
# Passive Assessment (Safe DNS, WHOIS, Security Headers, Technology Stack)
python phantomscan.py --target example.com --profile passive

# Quick Web & API Scan
python phantomscan.py --target example.com --profile quick

# Deep Scan (Executes All 38 Modules + 150 Crawl Pages + Supply Chain Checks)
python phantomscan.py --target example.com --profile deep --ports top100 --advanced

# AI & Vibe-Coded Application Security Scan
python phantomscan.py --target my-app.lovable.app --profile ai --check-slopsquatting

# Authenticated Assessment with Session Cookie or Bearer Token
python phantomscan.py --target app.example.com --profile deep --auth-cookie "session=xyz123"

# Staging vs. Production Differential Posture Scan
python phantomscan.py --target prod.example.com --diff-env staging.example.com

# Start One-Click Remediation Verification Server
python phantomscan.py --serve-verify --port 8787
```

### Scan Profiles

| Profile | Focus Area | Modules & Engines Active |
| :--- | :--- | :--- |
| `passive` | Non-intrusive reconnaissance | DNS, WHOIS, HTTP Headers, Tech Stack, Secrets |
| `quick` | Fast perimeter check | HTTP Checks + Top 100 Port Scan + Basic TLS |
| `full` | Deep infrastructure scan | Full Crawling + Go Port Scanner + Rust TLS Inspector |
| `api` | API & backend audit | REST, GraphQL, tRPC, OpenAPI, JWT, IDOR |
| `network` | Port & service enumeration | High-concurrency Go SYN port scanner |
| `advanced` | Comprehensive application logic | 38 Advanced Detection Modules + FindingGate™ |
| `deep` | Exhaustive All-in-One | Full Recon + 150-Page Crawl + All 38 Modules (`force_all`) |
| `ai` | AI / Vibe-Coded web apps | BaaS RLS, tRPC, Secret Entropy, Slopsquatting, Prompt APIs |
| `diff` | Environment comparison | Differential posture analysis between Staging and Production |

---

## Enterprise Reporting & Telemetry

PhantomScan produces rich, self-contained **interactive HTML dashboards**, machine-readable **JSON**, and **CSV** reports:

- **Executive Posture Dashboard**: CVSS v3.1 score grade (`A` through `F`), category breakdown, and positive defense bonuses.
- **Executed Modules Telemetry**: Real-time log of every executed module displaying execution phase, runtime engine, duration, status, and finding counts.
- **Interactive Finding Cards**: Full remediation playbooks, CVSS vectors, cURL reproduction commands, and raw request/response evidence blocks.
- **Exploit Chain Diagrams**: Mermaid.js attack graphs visualizing multi-step privilege escalation and data exfiltration paths.
- **Compliance Matrix**: Automatic pass/fail mapping against **OWASP Top 10 (2021)**, **PCI DSS v4.0**, **NIST 800-53**, and **HIPAA Security Rule**.

```
reports/
├── example.com_20260830_072649.html   # Interactive visual dashboard
├── example.com_20260830_072649.json   # Machine-readable scan data & telemetry
└── fp_log_example.com_20260830.json   # FindingGate™ suppression audit trail
```

---

## Testing & Verification

PhantomScan enforces rigorous automated test coverage across all subsystems:

```bash
# Run full automated test suite (290 Passing Tests)
pytest -v

# Run false-positive regression tests
pytest tests/false_positive_regression/

# Run polyglot engine integration tests
pytest tests/python/test_engines_polyglot.py
```

---

## Ethical Use & Authorization Warning

> [!IMPORTANT]
> **PhantomScan is engineered strictly for authorized cybersecurity testing, defensive hardening, and academic research.**
> 
> Testing targets without explicit written authorization from the asset owner is illegal. The developers and contributors accept no liability for misuse, unauthorized activities, or damage resulting from the use of this software. Scope enforcement is centrally maintained.

---

<div align="center">
  <sub>Engineered with precision for modern DevSecOps, AppSec Engineers, and Security Researchers.</sub>
</div>


