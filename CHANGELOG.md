# Changelog

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

