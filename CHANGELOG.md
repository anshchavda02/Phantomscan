# Changelog

## 2.2.0

- Added dedicated **AI & Vibe-Coded Web Application Security Scanner** (`ai_app_security`) containing 7 sub-scanners:
  - `AISecretScanner`: Client-side LLM API key regex scanning (OpenAI, Anthropic, Gemini, Groq, Replicate, HuggingFace, Perplexity, xAI, Cohere, Mistral, ElevenLabs, Stripe, Twilio), BaaS configuration (Supabase service_role vs anon JWT decoding, Firebase), source maps, and platform marker detection (Lovable, Bolt.new, v0, Replit, Base44, Create.xyz, Softr, Framer AI, Windsurf).
  - `RLSAuditor`: Supabase PostgREST and Firebase Realtime DB Row Level Security auditing (unauthenticated read/write, sensitive columns).
  - `ServerlessAbuseDetector`: Unauthenticated AI proxy endpoint and cost-abuse risk detection across 18 common path candidates.
  - `SystemPromptLeakDetector`: System prompt & internal business rule leakage detection via prompt injection probes.
  - `CRUDOwnershipChecker`: Auto-generated CRUD endpoint ownership (BOLA/IDOR) validation.
  - `EnvDebugScanner`: Exposed `.env`, `.git`, build artifact, and debug route detection.
  - `DefaultCredChecker`: Default/example admin credential checker.
- Updated `PhantomScan-Launcher.ps1` with dedicated AI App Security scan option (Option 8).
- Updated CLI parser and help options across `phantomscan.py`.
- Added unit test suite in `tests/python/test_ai_app_security.py` (27 test cases).

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

