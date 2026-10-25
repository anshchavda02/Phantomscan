# Changelog

## 2.3.0

- Added comprehensive **PHP2Shell Detection & Advisory Suite** (`CVE-2026-109618` & `CVE-2026-109619`):
  - Detects core PHP runtime memory corruption during request cleanup under out-of-memory (OOM) conditions (CVE-2026-109618) and stale session/global state reuse across worker processes (CVE-2026-109619).
  - Accurate version boundary checks for PHP 5.4 through 8.5 (unpatched: < 8.2.35, 8.3.0–8.3.35, 8.4.0–8.4.26, 8.5.0–8.5.11, and all legacy EOL branches).
  - Suppression on official patched releases (8.5.12, 8.4.27, 8.3.36, 8.2.35).
- Upgraded **CVE Engine** (`modules/cve_engine.py` & `phantomscan/modules/cve_engine.py`):
  - Integrated offline-ready curated high-impact vulnerability database covering PHP (PHP2Shell, CVE-2024-4577 CGI RCE, CVE-2024-2756, CVE-2023-3824, CVE-2022-31629), Apache HTTP Server (CVE-2021-41773, CVE-2021-42013, CVE-2022-22720, CVE-2023-25690, CVE-2024-38476), Nginx (CVE-2021-23017, CVE-2022-41741, CVE-2024-7347), OpenSSL (CVE-2022-3602, CVE-2022-3786, CVE-2023-0286), Spring Framework (CVE-2022-22965 Spring4Shell, CVE-2024-38816), WordPress (CVE-2023-2745), Atlassian Confluence (CVE-2022-26134, CVE-2023-22527), and Node.js (CVE-2023-30589, CVE-2024-21892).
  - Implemented semver range matching engine (`parse_version_tuple`, `version_in_range`).
  - Added technology canonical normalization (`normalize_tech`).
  - Preserved critical zero-days (relaxed 7-day age cutoff for CVSS >= 7.0 and emergency advisories).
- Expanded **YAML Security Templates** (`rules/cve/`):
  - `rules/cve/php2shell.yaml`: Active version and banner inspection for PHP2Shell.
  - `rules/cve/php-cgi-rce.yaml`: PHP-CGI Windows argument injection RCE (CVE-2024-4577).
  - `rules/cve/spring4shell.yaml`: Spring Framework ClassLoader DataBinder RCE (CVE-2022-22965).
  - `rules/cve/apache-path-traversal.yaml`: Apache 2.4.49/2.4.50 Path Traversal & RCE (CVE-2021-41773 / CVE-2021-42013).
  - `rules/cve/nginx-alias-traversal.yaml`: Nginx insecure alias directory traversal.
  - `rules/cve/confluence-ognl-rce.yaml`: Atlassian Confluence OGNL injection RCE (CVE-2022-26134).
  - `rules/cve/drupalgeddon2.yaml`: Drupal Core Form API AJAX RCE (CVE-2018-7600).
  - `rules/cve/openssl-punycode.yaml`: OpenSSL Punycode buffer overflow (CVE-2022-3602).
- Enhanced **Template Executor** (`modules/template_executor.py`):
  - Native CVE categorization (`category: cve`), metadata binding (`cve-id`, `cvss-score`), and reference propagation.
- Enhanced **Recon & Technology Fingerprinting** (`phantomscan/recon.py`):
  - Extracted compound server banners (e.g. `Apache/2.4.41 (Ubuntu) PHP/8.1.2 OpenSSL/1.1.1f`).
  - Added `X-PHP-Version`, `phpinfo` body, and meta generator version parsing.
- Enhanced **Sensitive Path Scanner** (`modules/sensitive_path_scanner.py`):
  - Added `/info.php`, `/php_info.php`, `/admin/phpinfo.php`, `/pma/`, `/.env.backup`, `/docker-compose.yml`, `/storage/logs/laravel.log` with strict response verification.
- Enhanced **Supply Chain Analyzer** (`phantomscan/modules/supply_chain.py`):
  - Added modern secret detection: Anthropic Claude, OpenAI project keys, Google AI Gemini, Supabase service secrets, Groq, DeepSeek, Resend, HuggingFace.
  - Automated vulnerable JavaScript library detection with CVE mapping for jQuery (< 3.5.0), Lodash (< 4.17.21), AngularJS (1.x), Moment.js (< 2.29.4), and Bootstrap (< 4.3.1).
- Fixed **Windows Installation & GitHub Distribution** (`install.bat`, `PhantomScan Launcher.bat`, `PhantomScan-Launcher.ps1`, `phantomscan-cli.bat`):
  - Fixed Windows batch parser syntax issues caused by unescaped parentheses and pseudo-comments (`. was unexpected at this time`).
  - Fixed `%ROOT%` trailing-backslash quote escaping trap that invalidated pip editable package installation on Windows paths.
  - Added robust Python resolution supporting `py -3`, `python`, and `py` launcher aliases with version >= 3.10 verification.
  - Added editable package self-registration (`pip install -e .`) so `phantomscan` and `modules` are always resolvable from any working directory.
  - Fixed Desktop launcher path bug where direct file copies into `%DESKTOP%` failed to find `.venv` and `PhantomScan-Launcher.ps1`; desktop launchers now use explicit directory anchoring and create a proper Windows `.lnk` shortcut.
  - Fixed missing entrypoint export `from phantomscan import main` in `phantomscan/__init__.py` and added `phantomscan/__main__.py` enabling direct `python -m phantomscan` execution.
  - Added bootstrap `sys.path` injection in `phantomscan.py` for repository root and `modules/`.
- Expanded automated test suite to 493 tests with 100% pass rate.

## 2.2.0

- Added dedicated **AI & Vibe-Coded Web Application Security Scanner** (`ai_app_security`) containing 7 sub-scanners:
  - `AISecretScanner`: Client-side LLM API key regex scanning (OpenAI, Anthropic, Gemini, Groq, Replicate, HuggingFace, Perplexity, xAI, Cohere, Mistral, ElevenLabs, Stripe, Twilio), BaaS configuration (Supabase service_role vs anon JWT decoding, Firebase), source maps, and platform marker detection (Lovable, Bolt.new, v0, Replit, Base44, Create.xyz, Softr, Framer AI, Windsurf).
  - `RLSAuditor`: Supabase PostgREST and Firebase Realtime DB Row Level Security auditing (unauthenticated read/write, sensitive columns).
  - `ServerlessAbuseDetector`: Unauthenticated AI proxy endpoint and cost-abuse risk detection across 18 common path candidates.
  - `SystemPromptLeakDetector`: System prompt & internal business rule leakage detection via prompt injection probes.
  - `CRUDOwnershipChecker`: Auto-generated CRUD endpoint ownership (BOLA/IDOR) validation.
  - `EnvDebugScanner`: Exposed `.env`, `.git`, build artifact, and debug route detection.
  - `DefaultCredChecker`: Default/example admin credential checker.
- Overhauled Windows interactive launcher (`PhantomScan-Launcher.ps1`) to 20 options:
  - Added Option 9: Local / Vulnerable App scanning with automated profiles (`juiceshop`, `dvwa`, `webgoat`, `bwapp`, `vulnweb-php`, `vulnweb-asp`).
  - Added Option 15: Detection Benchmark Harness (`scripts/benchmark.py`) for automated TP/FP accuracy measurement.
  - Added Option 16: Polyglot Engine Health Diagnostics (`--check-engines`).
  - Added Option 17: Multi-tier Test Runner (full suite, FP regressions, polyglot integration, live regression script).
- Updated Windows batch launcher (`install.bat`, `launcher.bat`, `PhantomScan Launcher.bat`, `phantomscan-cli.bat`) with execution policy bypass, automatic virtualenv resolution, and post-install engine health diagnostics.
- Updated Linux and macOS installer scripts (`scripts/install.sh`, `scripts/install_macos.sh`) with post-install health check and v2.2.0 CLI examples.
- Added **Pure-Python Standalone PDF Report Exporter** (`phantomscan/pdf_report.py`) powered by ReportLab:
  - Generates publication-grade, styled executive and technical audit PDFs without external C dependencies (no `cairo` or `pango` required).
  - Features executive summary banners, security scorecards, letter grade badges, severity matrix tables, attack surface summaries, compound exploit chains, syntax-escaped monospace evidence cards, and regulatory compliance matrices.
  - Dynamic two-pass numbered canvas with running headers and confidential audit footers ("Page X of Y").
  - Integrated into CLI via `--pdf` and `--pdf-out <path>`, and auto-detected in the Windows interactive launcher (`PhantomScan-Launcher.ps1`).
- Expanded automated test coverage to 464 tests across unit, contract, and false-positive regression suites.
- Codebase Audit Remediation & Hardening:
  - Fixed infinite loop DoS in SQLi error signature parser on duplicate match boundaries.
  - Hardened remediation verifier with dynamic HMAC secrets, target URL binding, ScopePolicy enforcement, and HTML output escaping.
  - Added safe extraction path validation against Zip Slip for mobile APK decompilation.
  - Calibrated unreachable/offline target scoring (Grade F / Score 20), 100% inconclusive compliance mapping, and unreachable narrative advisories.
  - Differentiated unregistered internal packages from public collisions in dependency confusion detector.
  - Wired `config.yaml` loader into CLI orchestrator, engine selection, timeouts, and cache TTLs.
  - Upgraded deprecated `asyncio.iscoroutinefunction` and `aiohttp.ClientWSTimeout` APIs.
  - Cleaned all unused imports across `phantomscan/` and `modules/` (flake8 0 warnings).
  - Added standard `pyproject.toml` PEP 518/621 packaging specification.

## 2.1.0

- Massive update introducing 20 advanced vulnerability modules (Logic Flaws, IDOR, OOB, Prototype Pollution, Request Smuggling, etc.).
- Added `advanced_scan.py` orchestrator to seamlessly manage advanced active and post-processing modules.
- Introduced Vulnerability Chain Engine for correlating exploit chains.
- Introduced Attack Path Builder with Mermaid.js graph outputs.
- Added Stateful multi-step scanner capabilities and auth token support.
- Updated `PhantomScan-Launcher.ps1` with new Advanced and Deep scan menus.
- Mapped findings to OWASP Top 10, PCI DSS v4, and NIST 800-53 via the new Compliance Reporter.
- Created AI Narrative Reporter using rule-based NLG for executive summaries.

## 2.0.0

- Initial PhantomScan implementation.
- Added scope-enforced Python CLI orchestrator.
- Added SQLite persistence, HTML and JSON reports.
- Added optional Go, Rust, and Node JSON engines.
- Added known platform context, false-positive controls, and safe web checks.

