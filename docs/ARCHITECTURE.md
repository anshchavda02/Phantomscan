# Architecture

PhantomScan uses a Python orchestrator with optional JSON-speaking engines.

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
Postprocessor -> SQLite -> HTML/JSON reports
```

## IPC

All engines read a `phantomscan.request.v1` JSON object from stdin and write a `phantomscan.engine.v1` JSON object to stdout. The orchestrator validates the schema before merging engine output.

## Adding Engines

New engines must accept stdin JSON, enforce the supplied scope, avoid shell expansion, emit schema-versioned JSON, and fail closed with clear warnings.

