# Scan Engine Audit

This audit records the issues fixed in the real-scanning pass.

## Findings

- `phantomscan.py`: optional Go/Rust engines could be missing, leaving full scans without port or TLS coverage. Fixed by adding Python fallback TCP and TLS scanners.
- `phantomscan.py`: no per-module timing or scan log existed. Fixed with `--debug`, `--log-file`, automatic `logs/` output, and timing observations.
- `phantomscan/recon.py`: HTTP connection failures were observations only, so unreachable services could still score perfectly. Fixed by creating evidence-backed informational findings.
- `phantomscan/recon.py`: cookie parsing split on commas and treated expiry fragments as cookies. Fixed with `http.cookies.SimpleCookie`.
- `phantomscan/postprocess.py`: defensive bonuses could erase real deductions and produce `100/100` despite findings. Fixed with capped bonuses and scan-completeness penalties.
- `phantomscan/scanners.py`: added real TCP connect scanning, banner grabbing, service labeling, and TLS certificate inspection using Python standard library fallbacks.

## Verification

- Local full scan against `127.0.0.1` performed real network attempts, took more than 10 seconds, found open TCP 135, recorded HTTP/TLS failures as evidence-backed findings, and scored `84/100`.
- Unit tests now assert incomplete scans cannot produce a perfect score.

Third-party verification scans must be run only by the operator against systems they own or have explicit written authorization to assess.
