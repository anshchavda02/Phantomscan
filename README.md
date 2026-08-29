<div align="center">
<pre>
  ____  _                 _                  ____                  
 |  _ \| |__   __ _ _ __ | |_ ___  _ __ ___ / ___|  ___ __ _ _ __  
 | |_) | '_ \ / _` | '_ \| __/ _ \| '_ ` _ \\___ \ / __/ _` | '_ \ 
 |  __/| | | | (_| | | | | || (_) | | | | | |___) | (_| (_| | | | |
 |_|   |_| |_|\__,_|_| |_|\__\___/|_| |_| |_|____/ \___\__,_|_| |_|
</pre>
  <h3>Scan Smart. Stay Secure. — Version 2.0.0</h3>
  <p><strong>The commercial-grade, polyglot vulnerability scanner tailored for AI-generated & Vibe-Coded Web Apps, Cloud Architectures, and Complex APIs.</strong></p>
</div>

---

## What is PhantomScan v2.0.0?

PhantomScan is an enterprise-grade, automated security assessment platform engineered for penetration testers, security auditors, and DevSecOps engineers.

While standard scanners focus solely on static CVE checks or simple web fuzzing, **PhantomScan v2.0.0 features specialized engines for AI-generated ("vibe-coded") applications** built with tools like Lovable.dev, Bolt.new, v0, Cursor, Windsurf, Replit AI, and Base44. It exposes hidden LLM secrets, audits Row Level Security (RLS) policies, checks serverless proxy abuse, detects AI-hallucinated dependency slopsquatting, and correlates low-severity findings into multi-step exploit chains.

---

## The Hybrid Polyglot Architecture

PhantomScan combines three languages for optimal balance between orchestrative intelligence, raw execution speed, and cryptographic rigor:

- **Python (The Brain)**: Powers 35+ specialized security modules, orchestrates scans, manages pattern databases, and builds interactive HTML/JSON reports.
- **Go (The Muscle)**: High-speed, concurrent TCP SYN port scanner built with goroutines to enumerate network attack surfaces in seconds.
- **Rust (The Inspector)**: Low-level TLS/SSL cryptographic analyzer evaluating cipher suites, protocol vulnerabilities, and certificate validity natively.

---

## Complete Feature Suite

### 1. Vibe App Security Module Suite (Mid-2026 Commercial Parity)

PhantomScan v2.0 introduces 9 specialized sub-scanners dedicated to securing AI-generated and full-stack vibe-coded web applications:

- **JSON-Driven Secret Pattern Engine**: Scans client JS bundles, source maps, and local source repositories against **150+ vendor-specific patterns** across 8 categories (LLM/AI, Payment, BaaS, Cloud, Email, Dev/Deploy, Analytics, and Generic). Uses Shannon entropy scoring and line-level comment context awareness.
- **Supabase Auditor V2**: Full CRUD RLS auditing (`SELECT`, `INSERT`, `UPDATE`, `DELETE`) on PostgREST endpoints (`/rest/v1/`), storage bucket visibility tests, auth confirmation settings, and key format detection (`sb_secret_` vs `service_role` JWTs).
- **Firebase Auditor V2**: Probes Realtime Database (`/.json`), Firestore collections, Storage bucket rules, and Admin SDK private key leaks.
- **Alternative Backend Auditor**: Introspects Convex functions (`/api/query`), detects exposed MongoDB connection strings, and flags raw PostgreSQL connection URLs.
- **ORM Misconfiguration Detector**: Identifies Prisma error disclosures, scans `schema.prisma` for models missing ownership fields (`userId`, `owner_id`), and detects raw Drizzle `sql``` string injection risks.
- **tRPC Endpoint Prober**: Discovers `/api/trpc` routes and tests common administrative procedures (`user.getAll`, `admin.deleteUser`) for unauthenticated access.
- **Slopsquatting Dependency Detector**: Cross-references `package.json` and `requirements.txt` against npm and PyPI registries to catch AI-hallucinated package names before attackers hijack them.
- **Hybrid Scan Coordinator**: Source-aware analysis mode via `--source-path`, audits committed `.env` files across Git history, and boosts finding confidence to `confirmed` when findings overlap between live bundles and local source code.
- **Serverless & System Prompt Protection**: Probes unauthenticated AI endpoints (`/api/chat`, `/api/generate`) for missing rate limits and system prompt leakage via prompt injection probes.

---

### 2. Business Logic, Auth & Complex Web Scanners

- **Business Logic Analyzer**: Detects mass assignment, price manipulation, and limit bypasses.
- **IDOR / BOLA Detector**: Automatically swaps user/object IDs cross-session to identify unauthorized access.
- **JWT & OAuth Tester**: Checks for `none` algorithm bypasses, weak HMAC secrets, and key confusion vulnerabilities.
- **Stateful Workflow Scanner**: Maps multi-step operations (Cart -> Checkout -> Payment) to uncover state machine bypasses.
- **Prototype Pollution**: Tests for client-side and server-side `__proto__` pollution.
- **HTTP Request Smuggling**: Uses raw TCP socket techniques to test CL.TE and TE.CL ambiguities.
- **Out-Of-Band (OOB) Detector**: Integrates OOB callbacks to capture asynchronous vulnerabilities like Log4Shell and Blind SSRF.
- **Race Condition Detector**: Concurrent flooding to catch Time-of-Check to Time-of-Use (TOCTOU) race conditions.

---

### 3. Vulnerability Chain Engine & Attack Paths

PhantomScan correlates isolated lower-severity findings into critical multi-step **Exploit Chains**:

- **Supabase RLS Bypass → Full Database Compromise**
- **Firebase Test-Mode → Full Data Dump**
- **AI Proxy Abuse → Unlimited LLM Cost Drain**
- **Slopsquatting → Supply Chain RCE**
- **.env Leak → Cloud Credential Compromise**
- **Prisma Error Leak + IDOR → Schema-Guided Data Theft**
- **tRPC Unauth + Default Creds → Admin Takeover**

Generates interactive **Mermaid.js** diagrams illustrating exact attack trajectories for executive presentation.

---

## Command Line Usage

### Standard Scan Commands

```bash
# 1. Run all 35 Advanced Modules (including Vibe App Security Suite)
python phantomscan.py --target example.com --advanced

# 2. Hybrid Black-Box + Source-Aware Scan with Slopsquatting Check
python phantomscan.py --target example.com --advanced --source-path ./my-app --check-slopsquatting

# 3. Targeted Vibe Security Module Execution
python phantomscan.py --target example.com --modules ai_app_security,vuln_chain

# 4. Stateful Authenticated Scan
python phantomscan.py --target example.com --advanced --auth-cookie "session_id=abc123xyz"

# 5. Quick Passive Recon Scanner
python phantomscan.py --target example.com --profile passive --json
```

### CLI Flag Reference

| Flag | Description |
| :--- | :--- |
| `--target` | Target domain, IP, CIDR, or URL to assess. |
| `--profile` | Scan profile: `quick`, `full`, `passive`, `api`, `network`, `advanced`, `deep`. |
| `--advanced` | Runs all 35 advanced security modules. |
| `--source-path` | Path to local source code for hybrid black-box + white-box analysis. |
| `--check-slopsquatting` | Queries npm/PyPI registries for AI-hallucinated packages (requires `--source-path`). |
| `--modules` | Comma-separated list of specific modules to run (e.g., `ai_app_security,idor`). |
| `--auth-cookie` | Session cookie string for authenticated scans. |
| `--auth-token` | Bearer token string for API authenticated scans. |
| `--json-out` | File path to export JSON report artifact. |

---

## Installation & Setup

For the complete installation guide across Linux, macOS, and Windows, see [INSTALL.md](INSTALL.md).

### Linux & macOS CLI Quickstart
```bash
# Clone Repository
git clone https://github.com/anshchavda02/Phantomscan.git phantomscan
cd phantomscan

# Run automated installer
bash scripts/install.sh       # On Linux
# or: bash scripts/install_macos.sh  # On macOS

# Execute Scan
phantomscan --target example.com --profile passive
```

### Running Tests
```bash
# Verify Full Test Suite (197 Passing Tests)
python -m pytest
```

---

## Ethical Use Policy

**AUTHORIZED TESTING ONLY.** PhantomScan is designed strictly for authorized security assessments against systems you own or have explicit written permission to test.
