# PhantomScan 2.0.0 Implementation Plan

PhantomScan is implemented as a safe, authorized security assessment platform. It enforces target scope before any network action, prints an authorization warning on every startup, and limits active behavior to discovery and defensive validation. Exploit execution, credential guessing, destructive probing, and out-of-scope crawling are intentionally excluded.

## 1. Phases

1. Project structure and build system
   - Create Python package, Go engine, Rust engine, Node.js engine, data files, scripts, tests, templates, and documentation.
   - Build outputs are optional. The Python CLI skips missing engines with warnings.

2. SQLite schema and data layer
   - Store scans, findings, DNS cache, WHOIS cache, CVE cache, and engine runs.
   - Use parameterized SQL only.

3. Go scanner engine
   - Provide concurrent DNS lookup and TCP connect scanning.
   - Output JSON to stdout with schema version `phantomscan.engine.v1`.

4. Rust TLS engine
   - Inspect TLS certificate metadata and return a conservative SSL grade.
   - Output JSON to stdout with schema version `phantomscan.engine.v1`.

5. Node.js browser engine
   - Fetch and parse rendered-adjacent page signals using safe HTTP requests.
   - Output JSON to stdout with schema version `phantomscan.engine.v1`.

6. Python recon and intelligence modules
   - Target parsing, scope validation, DNS, HTTP headers, email security, technology hints, passive API discovery, and report models.

7. Python vulnerability and CVE modules
   - Defensive checks for security headers, cookies, CORS, API exposure, and known technology/version findings.
   - CVE matching is conservative and suppresses unverified matches by default.

8. False positive post-processor
   - Apply known platform context, cookie downgrades, MFA/login-page gating, CORS confirmation rules, and CVE hard filters.

9. Reporting engine
   - Generate single-file HTML and JSON reports.
   - PDF is prepared as an output option but requires an external renderer in this lightweight distribution.

10. Tests and documentation
   - Python unit tests avoid real external network calls.
   - Go, Rust, and Node tests validate schemas and core classifiers.

## 2. IPC Schemas

### Engine Request

```json
{
  "schema": "phantomscan.request.v1",
  "target": "example.com",
  "target_type": "domain",
  "profile": "quick",
  "ports": "top100",
  "timeout_seconds": 5,
  "scope": {
    "allowed_hosts": ["example.com"],
    "allowed_cidrs": []
  }
}
```

### Engine Response

```json
{
  "schema": "phantomscan.engine.v1",
  "engine": "go-portscan",
  "status": "ok",
  "target": "example.com",
  "started_at": "2026-07-17T00:00:00Z",
  "finished_at": "2026-07-17T00:00:01Z",
  "findings": [],
  "observations": [],
  "warnings": []
}
```

### Finding

```json
{
  "id": "SEC-HEADER-HSTS",
  "title": "HTTP Strict Transport Security is not present",
  "severity": "medium",
  "confidence": "high",
  "category": "web",
  "target": "https://example.com",
  "evidence": "Strict-Transport-Security header missing",
  "recommendation": "Enable HSTS with an appropriate max-age after HTTPS readiness is confirmed.",
  "references": []
}
```

## 3. Assumptions

1. Operators have explicit written authorization for every target.
2. Internet access may be unavailable; all modules degrade gracefully.
3. Optional tools such as nmap, Go, Rust, Node, and Playwright may be absent.
4. Tests must not call the public internet.
5. Known platform intelligence is contextual and never overrides directly observed critical evidence.
6. CVE output requires exact product/version evidence; otherwise the candidate is suppressed.

## 4. Build Steps

1. `bash scripts/check_deps.sh`
2. `bash scripts/build.sh`
3. `python phantomscan.py --target example.com --profile passive --json`
4. Optional: `make test`

