# PhantomScan Architecture

PhantomScan uses a Python orchestrator with optional JSON-speaking engines. It is built on a modular, multi-engine architecture designed to ensure safety, robustness, and extensibility.

## Core Flow

1. **CLI Orchestrator (`phantomscan.py`)**
   - Parses arguments and targets.
   - Configures the beautiful `rich` terminal output and structured logging.
   - Orchestrates the sequence of reconnaissance, scanning, and postprocessing.

2. **Reconnaissance (`phantomscan/recon.py`)**
   - Retrieves basic target intelligence without active exploitation.
   - Collects DNS records, WHOIS, and passive tech stack information.

3. **Multi-Engine Scanning (`phantomscan/engines.py`)**
   - Executes external engines written in Go and Rust for high-performance tasks like port scanning and TLS inspection.
   - Passes data via JSON over STDOUT to maintain engine isolation.

4. **Data Models (`phantomscan/models.py`)**
   - Enforces strict data consistency.
   - `Finding` objects are strictly typed and validated upon instantiation (must contain valid severities like `critical`, `high`, `medium`, `low`, `info`).

5. **Postprocessing (`phantomscan/postprocess.py`)**
   - Validates findings against environmental context.
   - Filters out known false positives based on hosting and platform knowledge.

6. **Reporting (`phantomscan/reporting.py`)**
   - Generates polished HTML, JSON, and CSV reports.
   - Fully self-contained output, no external network calls required to render HTML.

## Data Flow Diagram

```
User CLI
  |
  v
Target parser -> Scope policy
  |
  +-> Python recon: DNS, HTTP headers, email posture, technology hints
  +-> Go engine: concurrent TCP connect scan
  +-> Rust engine: TLS reachability and grading hook
  +-> Node engine: browser-adjacent page signals
  |
  v
Postprocessor -> SQLite -> HTML/JSON/CSV reports
```

## IPC

All engines read a `phantomscan.request.v1` JSON object from stdin and write a `phantomscan.engine.v1` JSON object to stdout. The orchestrator validates the schema before merging engine output.

## Adding Engines

New engines must accept stdin JSON, enforce the supplied scope, avoid shell expansion, emit schema-versioned JSON, and fail closed with clear warnings.
