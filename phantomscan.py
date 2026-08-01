#!/usr/bin/env python3
"""PhantomScan CLI orchestrator."""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
from datetime import datetime
from pathlib import Path
import sys
import time
from typing import Any

from phantomscan.db import Database
from phantomscan.email_security import analyze_email
from phantomscan.engines import run_engine
from phantomscan.health import EngineHealthChecker
from phantomscan.models import Observation, utc_now
from phantomscan.postprocess import grade, load_known_platform, post_process, score
from phantomscan.progress import ScanProgressDisplay
from phantomscan.recon import (
    collect_dns_records,
    deep_analyze_web,
    detect_technologies,
    enumerate_subdomains,
    fetch_headers,
    lookup_whois,
    resolve_target,
)
from phantomscan.rules_engine import run_yaml_rules
from phantomscan.reporting import write_html_report, write_json_report, write_csv_report
from phantomscan.scanners import inspect_tls, scan_ports
from phantomscan.scope import parse_target, root_domain
from phantomscan.advanced_scan import run_advanced_modules
from phantomscan.http_client import RobustHTTPClient

WARNING = """
PhantomScan 2.0.0 - Scan Smart. Stay Secure.
Authorized security assessment only. Run this tool only against systems you own
or have explicit written authorization to test. Scope is enforced per target.
"""

from rich.console import Console
from rich.logging import RichHandler

console = Console()


def cprint(text: str, color: str = "cyan") -> None:
    """Print a terminal message using Rich."""
    console.print(text, style=color)


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI parser."""
    parser = argparse.ArgumentParser(
        prog="phantomscan", 
        description="PhantomScan v2.1 - Advanced Extensible Vulnerability Scanner (35 Modules)",
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    # Target Selection
    target_group = parser.add_argument_group("Target Selection")
    target_group.add_argument("--target", help="Single target domain, IP, CIDR, or URL to scan (e.g., example.com)")
    target_group.add_argument("--batch", help="File containing a list of targets (one per line)")
    
    # Scan Profiles & Modules
    scan_group = parser.add_argument_group("Scan Profiles & Modules")
    scan_group.add_argument(
        "--profile",
        default="quick",
        choices=["quick", "full", "passive", "owasp", "bug-bounty", "api", "network", "advanced", "deep"],
        help="Scan profile to execute:\n"
             "  quick      - Fast HTTP checks, top 100 ports, basic TLS\n"
             "  full       - Deep web analysis, full TLS, concurrent port scan, YAML engine\n"
             "  passive    - Safe DNS/email checks & Deep Web without active fuzzing\n"
             "  api        - API-focused HTTP analysis without web crawling\n"
             "  network    - Intensive Go port-scanner focused profile\n"
             "  advanced   - Run 35 advanced security modules (Logic, IDOR, AI/Vibe-Coded, Takeover, PII, etc.)\n"
             "  deep       - Full scan + Advanced scan modules combined"
    )
    scan_group.add_argument("--ports", default="top100", help="Ports to scan (e.g., 'top100', 'top1000', or '80,443,8080')")
    scan_group.add_argument("--proxy", help="Start Passive Proxy Mode on HOST:PORT (e.g., 127.0.0.1:8080) to intercept and feed browser traffic to the YAML engine")
    scan_group.add_argument("--advanced", action="store_true", help="Run all 35 advanced security modules")
    scan_group.add_argument("--modules", help="Comma-separated list of specific advanced modules to run (e.g., 'ai_app_security,idor')")
    scan_group.add_argument("--source-path", help="Path to local source code for hybrid black-box + white-box analysis (enables ORM, Prisma, Drizzle, and .env git-history checks)")
    scan_group.add_argument("--check-slopsquatting", action="store_true", help="Check project dependencies for AI-hallucinated packages (slopsquatting). Requires --source-path.")


    # Authenticated & Multi-Role Scanning (Module 1)
    auth_group = parser.add_argument_group("Authenticated & Multi-Role Scanning")
    auth_group.add_argument("--auth-cookie", help="Authentication cookie string for stateful scanning")
    auth_group.add_argument("--auth-token", help="Bearer token for API authenticated scanning")
    auth_group.add_argument("--auth-profile", action="append", help="Path to encrypted AuthProfile file (can specify multiple)")
    auth_group.add_argument("--multi-role-scan", action="store_true", help="Perform multi-role access control testing across auth profiles")

    # Differential Environment Scanner (Module 2)
    diff_group = parser.add_argument_group("Differential Environment Scanner")
    diff_group.add_argument("--diff-env", action="store_true", help="Run differential environment scanner comparing Staging vs Production")
    diff_group.add_argument("--staging", help="Staging target URL/domain")
    diff_group.add_argument("--production", help="Production target URL/domain")

    # Mobile App & Dependency Security (Modules 3, 4)
    mobile_group = parser.add_argument_group("Mobile & Dependency Security")
    mobile_group.add_argument("--mobile-apk", help="Path to APK binary to decompile and extract backend APIs")
    mobile_group.add_argument("--mobile-ipa", help="Path to IPA binary to extract backend APIs")
    mobile_group.add_argument("--extract-apis", action="store_true", help="Extract and test backend APIs from mobile app binaries")
    mobile_group.add_argument("--check-deps", help="Path to project directory to check for Dependency Confusion risks")

    # Authentication & Protection Testing (Module 7)
    proto_group = parser.add_argument_group("Login Anti-Automation Testing")
    proto_group.add_argument("--test-login-protection", action="store_true", help="Test login page anti-automation / rate limiting protection")

    # Workflow & Ticketing Integrations (Module 9)
    ticket_group = parser.add_argument_group("Ticketing & Alert Integrations")
    ticket_group.add_argument("--ticket-provider", choices=["jira", "slack", "teams"], help="Ticketing integration provider")
    ticket_group.add_argument("--jira-url", help="Jira instance URL (e.g. https://company.atlassian.net)")
    ticket_group.add_argument("--jira-user", help="Jira username/email")
    ticket_group.add_argument("--jira-token", help="Jira API token")
    ticket_group.add_argument("--jira-project", default="SEC", help="Jira project key (default: SEC)")
    ticket_group.add_argument("--slack-webhook", help="Slack Webhook URL for alerting")
    ticket_group.add_argument("--teams-webhook", help="MS Teams Webhook URL for alerting")
    ticket_group.add_argument("--auto-ticket", help="Comma-separated severities to auto-ticket (e.g. 'critical,high')")

    # Reporting & Analytics (Modules 6, 10, 11)
    analytics_group = parser.add_argument_group("Reporting & Analytics")
    analytics_group.add_argument("--expiry-calendar", action="store_true", help="Generate standalone HTML expiry calendar for targets")
    analytics_group.add_argument("--targets-file", help="File with list of targets for expiry calendar")
    analytics_group.add_argument("--video-summary", action="store_true", help="Generate an executive video summary (.mp4) via local TTS")
    analytics_group.add_argument("--baseline", help="Path to previous JSON report for continuous monitoring diff")
    analytics_group.add_argument("--webhook", help="URL to send alerts for new findings (Continuous Monitor)")

    # Team Operations & Verification (Modules 12, 13)
    team_group = parser.add_argument_group("Team Operations & Verification")
    team_group.add_argument("--merge", nargs="+", help="JSON scan report files to merge and deduplicate")
    team_group.add_argument("--serve-verify", action="store_true", help="Start local lightweight remediation verification server")
    team_group.add_argument("--verify-port", type=int, default=8420, help="Port for remediation verification server (default: 8420)")

    # Scan Configuration & Tuning
    config_group = parser.add_argument_group("Scan Configuration & Tuning")
    config_group.add_argument("--threads", type=int, default=1, help="Number of concurrent threads (default: 1)")
    config_group.add_argument("--depth", type=int, default=1, help="Web crawler depth (default: 1)")
    config_group.add_argument("--silent", action="store_true", help="Suppress rich terminal output (useful for piping)")
    config_group.add_argument("--debug", action="store_true", help="Enable verbose debug logging and pre-scan engine health checks")
    config_group.add_argument("--confidence", choices=["high", "medium", "low"], default="high", help="Minimum confidence level to report (default: high)")
    config_group.add_argument("--show-medium", action="store_true", help="Include medium-confidence findings in the main output")
    config_group.add_argument("--show-all", action="store_true", help="Include all findings regardless of confidence")
    config_group.add_argument("--cve", action="store_true", help="Focus exclusively on CVE detection modules")
    config_group.add_argument("--cvss-min", type=float, default=4.0, help="Minimum CVSS score to flag (default: 4.0)")
    
    # Output & Reporting
    report_group = parser.add_argument_group("Output & Reporting")
    report_group.add_argument("--json", action="store_true", help="Print JSON findings to stdout at the end of the scan")
    report_group.add_argument("--json-out", help="Path to save the JSON report")
    report_group.add_argument("--pdf", action="store_true", help="Generate a PDF report (experimental)")
    report_group.add_argument("--pdf-out", help="Path to save the PDF report")
    report_group.add_argument("--log-file", help="Custom path for the debug log file")
    
    # Legacy / Unused in v2 (Kept for compatibility)
    legacy_group = parser.add_argument_group("Legacy / Enterprise Options")
    legacy_group.add_argument("--recon", action="store_true", help=argparse.SUPPRESS)
    legacy_group.add_argument("--recon-only", action="store_true", help=argparse.SUPPRESS)
    legacy_group.add_argument("--crawl", action="store_true", help=argparse.SUPPRESS)
    legacy_group.add_argument("--screenshot", action="store_true", help=argparse.SUPPRESS)
    legacy_group.add_argument("--compliance", help=argparse.SUPPRESS)
    legacy_group.add_argument("--checklist", action="store_true", help=argparse.SUPPRESS)
    legacy_group.add_argument("--output", default="report", help=argparse.SUPPRESS)
    legacy_group.add_argument("--collect-evidence", action="store_true", help=argparse.SUPPRESS)
    legacy_group.add_argument("--narrative", action="store_true", help=argparse.SUPPRESS)
    legacy_group.add_argument("--learning", action="store_true", help=argparse.SUPPRESS)
    legacy_group.add_argument("--client", help=argparse.SUPPRESS)
    legacy_group.add_argument("--assessor", help=argparse.SUPPRESS)
    legacy_group.add_argument("--engagement-type", help=argparse.SUPPRESS)
    legacy_group.add_argument("--ref", help=argparse.SUPPRESS)
    legacy_group.add_argument("--diff", action="store_true", help=argparse.SUPPRESS)
    legacy_group.add_argument("--verify", help=argparse.SUPPRESS)
    legacy_group.add_argument("--watch", help=argparse.SUPPRESS)
    legacy_group.add_argument("--interval", help=argparse.SUPPRESS)
    legacy_group.add_argument("--daemon", choices=["start", "stop", "status"], help=argparse.SUPPRESS)
    legacy_group.add_argument("--annotate", action="store_true", help=argparse.SUPPRESS)
    legacy_group.add_argument("--resume", action="store_true", help=argparse.SUPPRESS)

    return parser


def setup_logger(
    root: Path, target: str, debug: bool, log_file: str | None
) -> logging.Logger:
    """Configure per-scan logging."""
    safe_target = target.replace("/", "_").replace(":", "_")
    logs_dir = root / "logs"
    logs_dir.mkdir(exist_ok=True)
    path = (
        Path(log_file)
        if log_file
        else logs_dir / f"phantomscan_{safe_target}_{int(time.time())}.log"
    )
    logger = logging.getLogger(f"phantomscan.{safe_target}.{int(time.time() * 1000)}")
    logger.setLevel(logging.DEBUG)
    logger.propagate = False
    formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(module)s: %(message)s")
    file_handler = logging.FileHandler(path, encoding="utf-8")
    file_handler.setFormatter(formatter)
    file_handler.setLevel(logging.DEBUG)
    logger.addHandler(file_handler)
    if debug:
        rich_handler = RichHandler(
            console=console, rich_tracebacks=True, show_time=False, show_path=False
        )
        rich_handler.setLevel(logging.DEBUG)
        logger.addHandler(rich_handler)
    logger.info("Log file: %s", path)
    return logger


async def timed_step(
    name: str,
    logger: logging.Logger,
    observations: list[dict[str, Any]],
    silent: bool,
    func: Any,
    *args: Any,
) -> Any:
    """Run and time one scan step, catching recoverable errors."""
    started = time.perf_counter()

    async def _run_func() -> Any:
        try:
            return await func(*args)
        except (OSError, TimeoutError, ValueError, RuntimeError, Exception) as exc:
            logger.exception("%s failed: %s", name, exc)
            observations.append(
                Observation(
                    f"{name.lower().replace(' ', '_')}_error", str(exc), "orchestrator"
                ).to_dict()
            )
            # If the func was supposed to return a tuple, return a tuple of empty lists
            import inspect
            sig = inspect.signature(func)
            if "tuple" in str(sig.return_annotation).lower():
                return ([], [])
            return []

    if not silent:
        with console.status(f"[*] {name}...", spinner="line", spinner_style="cyan"):
            result = await _run_func()
    else:
        result = await _run_func()

    elapsed_ms = int((time.perf_counter() - started) * 1000)
    observations.append(
        Observation(
            f"{name.lower().replace(' ', '_')}_duration_ms", elapsed_ms, "timing"
        ).to_dict()
    )
    if not silent:
        cprint(f"[+] {name} complete ({elapsed_ms} ms)", "green")
    logger.info("%s complete in %dms", name, elapsed_ms)
    return result


async def scan_one(
    args: argparse.Namespace, target_value: str, root: Path
) -> dict[str, Any]:
    """Run one authorised scan and return the full report dict."""
    target = parse_target(target_value)
    logger = setup_logger(root, target.host, args.debug, args.log_file)
    logger.info(
        "Starting authorised scan target=%s profile=%s", target.host, args.profile
    )
    if not args.silent:
        cprint("[*] PhantomScan v2.0.0 — Authorised Use Only", "cyan")
        cprint(f"[*] Target  : {target.host}", "cyan")
        cprint(f"[*] Profile : {args.profile}", "cyan")

    started = utc_now()
    db = Database(root / "phantomscan.sqlite3")
    scan_id = db.create_scan(target.host, args.profile, started)

    observations: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []

    # ── Recon phase ───────────────────────────────────────────────────────────
    dns_obs = await timed_step(
        "Resolving target", logger, observations, args.silent,
        resolve_target, target, logger,
    )
    observations.extend(item.to_dict() for item in dns_obs)

    detail_obs = await timed_step(
        "Fetching DNS records", logger, observations, args.silent,
        collect_dns_records, target, logger,
    )
    observations.extend(item.to_dict() for item in detail_obs)

    whois_obs = await timed_step(
        "Running WHOIS/RDAP lookup", logger, observations, args.silent,
        lookup_whois, target, 15.0, logger,
    )
    observations.extend(item.to_dict() for item in whois_obs)

    subdomain_obs = await timed_step(
        "Enumerating subdomains", logger, observations, args.silent,
        enumerate_subdomains, target, logger,
    )
    observations.extend(item.to_dict() for item in subdomain_obs)

    # ── HTTP analysis ─────────────────────────────────────────────────────────
    http_obs, http_findings = await timed_step(
        "Analyzing HTTP", logger, observations, args.silent,
        fetch_headers, target, 10.0, logger,
    )
    if isinstance(http_obs, (list, tuple)):
        observations.extend(item.to_dict() for item in http_obs)
    if isinstance(http_findings, (list, tuple)):
        findings.extend(item.to_dict() for item in http_findings)

    # Resolve the effective base URL from the HTTP result
    effective_url: str = target.base_url
    for obs in observations:
        if obs.get("name") == "http_url" and obs.get("value"):
            effective_url = str(obs["value"])
            break

    # Deep web analysis (sensitive paths, CORS, disclosures, redirect)
    deep_findings = []
    if args.profile in ("full", "bug-bounty", "owasp"):
        deep_findings = await timed_step(
            "Deep web analysis", logger, observations, args.silent, deep_analyze_web, target, effective_url, logger
        )
    if isinstance(deep_findings, list):
        findings.extend(item.to_dict() for item in deep_findings)

    if args.profile != "network":
        await timed_step(
            "YAML vulnerability rules", logger, observations, args.silent, run_yaml_rules, effective_url, observations
        )

    # Technology fingerprinting
    tech_obs_list = detect_technologies([*dns_obs, *(item for item in http_obs if hasattr(item, "name"))])
    observations.extend(item.to_dict() for item in tech_obs_list)

    # Email security (SPF/DMARC/MX)
    email_obs, email_findings = await timed_step(
        "Checking email security", logger, observations, args.silent,
        analyze_email, target, logger,
    )
    if isinstance(email_obs, (list, tuple)):
        observations.extend(item.to_dict() for item in email_obs)
    if isinstance(email_findings, (list, tuple)):
        findings.extend(item.to_dict() for item in email_findings)

    # Known-platform context
    platform = load_known_platform(root / "data", root_domain(target.host))
    if platform:
        observations.append(Observation("known_platform", platform, "data").to_dict())

    # ── Active scan phase ─────────────────────────────────────────────────────
    request: dict[str, Any] = {
        "schema": "phantomscan.request.v1",
        "target": target.host,
        "target_type": target.target_type,
        "profile": args.profile,
        "ports": args.ports,
        "timeout_seconds": 5,
        "scope": {
            "allowed_hosts": [target.host],
            "allowed_cidrs": [target.host] if target.target_type == "cidr" else [],
        },
    }
    _exe = ".exe" if sys.platform == "win32" else ""
    engine_specs = [
        ("go-portscan",  [str(root / "engines" / "go" / "bin" / f"phantomscan-go{_exe}")]),
        ("rust-tls",     [str(root / "engines" / "rust" / "target" / "release" / f"phantomscan-rust{_exe}")]),
        ("node-browser", ["node", str(root / "engines" / "node" / "browser_engine.js")]),
    ]

    if args.profile != "passive":
        port_obs, port_findings = await timed_step(
            "Scanning TCP ports", logger, observations, args.silent,
            scan_ports, target, args.ports, logger,
        )
        observations.extend(item.to_dict() for item in port_obs)
        findings.extend(port_findings)

        tls_obs, tls_findings = await timed_step(
            "Inspecting TLS", logger, observations, args.silent,
            inspect_tls, target, logger,
        )
        observations.extend(item.to_dict() for item in tls_obs)
        findings.extend(tls_findings)

        for name, command in engine_specs:
            result = await run_engine(command, request, name, target)
            payload = result.to_dict()
            db.save_engine_run(scan_id, name, result.status, payload)
            observations.append(
                Observation(f"engine_{name}", result.status, "engine").to_dict()
            )
            observations.extend(payload.get("observations", []))
            findings.extend(payload.get("findings", []))
            for warning in payload.get("warnings", []):
                observations.append(
                    Observation(f"{name}_warning", warning, "engine").to_dict()
                )
                logger.warning("%s warning: %s", name, warning)
                if not args.silent:
                    cprint(f"[!] {name}: {warning}", "yellow")

    # ── Advanced modules phase ────────────────────────────────────────────────
    if args.advanced or args.modules or args.profile in ("advanced", "deep", "monitor"):
        client = RobustHTTPClient()
        await client.start()
        try:
            adv_profile = args.modules if args.modules else args.profile
            if args.advanced and adv_profile not in ("advanced", "deep", "monitor") and not args.modules:
                adv_profile = "advanced"

            adv_findings, new_obs = await timed_step(
                "Running advanced modules", logger, observations, args.silent,
                run_advanced_modules,
                target.host,
                effective_url,
                client,
                observations,
                findings,
                adv_profile,
                args.auth_cookie,
                args.auth_token,
                args.baseline,
                args.webhook,
                getattr(args, "source_path", None),
                getattr(args, "check_slopsquatting", False),
            )
            seen_keys = {(f.get("id"), f.get("target"), f.get("title")) for f in findings if isinstance(f, dict)}
            for f in adv_findings:
                if isinstance(f, dict):
                    key = (f.get("id"), f.get("target"), f.get("title"))
                    if key not in seen_keys:
                        seen_keys.add(key)
                        findings.append(f)
            observations = new_obs
        finally:
            await client.close()

    # ── Post-processing and scoring ───────────────────────────────────────────
    safe_target = target.host.replace("/", "_").replace(":", "_")
    include_medium = args.show_medium or args.show_all or args.confidence in {"medium", "low"}
    include_low = args.show_all or args.confidence == "low"

    # Parse timestamp for report filenames (YYYYMMDD_HHMMSS)
    try:
        ts_dt = datetime.fromisoformat(started)
        ts_str = ts_dt.strftime("%Y%m%d_%H%M%S")
    except Exception:
        ts_str = str(int(time.time()))

    final_findings, suppressed_findings, observations = post_process(
        findings=findings,
        observations=observations,
        data_dir=root / "data",
        target_host=root_domain(target.host),
        include_medium=include_medium,
        include_low=include_low,
        fp_log_path=root / "reports" / f"fp_log_{safe_target}_{ts_str}.json",
    )
    final_score = score(final_findings, observations)
    final_grade = grade(final_score)
    finished = utc_now()

    # Calculate elapsed scan duration in seconds
    start_dt = datetime.fromisoformat(started)
    finish_dt = datetime.fromisoformat(finished)
    duration_sec = max(0.1, round((finish_dt - start_dt).total_seconds(), 2))

    for item in final_findings:
        db.save_finding(scan_id, item)
    db.finish_scan(scan_id, finished, final_score)
    db.close()

    logger.info(
        "Scan complete: %d findings, %d suppressed, score=%d, duration=%.1fs",
        len(final_findings), len(suppressed_findings), final_score, duration_sec
    )
    if not args.silent:
        color = "green" if final_score >= 80 else "yellow" if final_score >= 60 else "red"
        cprint(
            f"[+] Scan complete: {len(final_findings)} findings, "
            f"score {final_score}/100 ({final_grade}) in {duration_sec}s",
            color,
        )

    return {
        "schema": "phantomscan.report.v1",
        "target": target.host,
        "profile": args.profile,
        "started_at": started,
        "finished_at": finished,
        "duration": duration_sec,
        "score": final_score,
        "grade": final_grade,
        "findings": final_findings,
        "suppressed_findings": suppressed_findings,
        "observations": observations,
        "engagement": {
            "client": args.client,
            "assessor": args.assessor,
            "engagement_type": args.engagement_type,
            "reference": args.ref,
        },
        "options": {
            "learning": args.learning,
            "checklist": args.checklist,
            "screenshot": args.screenshot,
            "compliance": args.compliance,
        },
        "ethical_use": "Authorized assessment only. Scope enforced to the supplied target.",
    }


async def main_async() -> int:
    """CLI async entrypoint."""
    parser = build_parser()
    args = parser.parse_args()
    if not args.silent:
        cprint(WARNING.strip(), "yellow")
    if not args.target and not args.batch:
        parser.error("--target or --batch is required")

    root = Path(__file__).resolve().parent

    # Pre-scan engine health check (when --debug is set)
    if args.debug and not args.silent:
        checker = EngineHealthChecker(root)
        await checker.check_all()
        cprint("")  # blank line

    targets = (
        [args.target]
        if args.target
        else Path(args.batch).read_text(encoding="utf-8").splitlines()
    )
    reports: list[dict[str, Any]] = []

    for target in [t for t in targets if t.strip()]:
        display = ScanProgressDisplay(target, silent=args.silent)
        report = await display.run_with_progress(scan_one(args, target, root))
        reports.append(report)

    output_dir = root / "reports"
    output_dir.mkdir(exist_ok=True)

    def get_unique_path(base_path: Path) -> Path:
        """Ensure file path is unique by appending an incrementing suffix if it already exists."""
        if not base_path.exists():
            return base_path
        stem = base_path.stem
        suffix = base_path.suffix
        counter = 1
        while True:
            candidate = base_path.parent / f"{stem}_{counter}{suffix}"
            if not candidate.exists():
                return candidate
            counter += 1

    for report in reports:
        safe_target = report["target"].replace("/", "_").replace(":", "_")
        try:
            ts_dt = datetime.fromisoformat(report.get("started_at", ""))
            ts_str = ts_dt.strftime("%Y%m%d_%H%M%S")
        except Exception:
            ts_str = str(int(time.time()))

        if args.json_out and len(reports) == 1:
            json_path = Path(args.json_out)
        else:
            json_path = get_unique_path(output_dir / f"{safe_target}_{ts_str}.json")

        html_path = get_unique_path(output_dir / f"{safe_target}_{ts_str}.html")
        csv_path = get_unique_path(output_dir / f"{safe_target}_{ts_str}.csv")
        write_json_report(json_path, report)
        write_csv_report(csv_path, report)
        write_html_report(html_path, report)
        if args.json:
            print(json.dumps(report, indent=2, sort_keys=True))
        elif not args.silent:
            cprint(f"Report written : {html_path}", "green")
            cprint(f"JSON written   : {json_path}", "green")
            cprint(f"CSV written    : {csv_path}", "green")

    return 0


def main() -> int:
    """CLI entrypoint."""
    parser = build_parser()
    args = parser.parse_args()

    if args.daemon == "stop":
        sys.exit(0)
        
    if args.proxy:
        if ":" not in args.proxy:
            print("Proxy argument must be in format HOST:PORT (e.g., 127.0.0.1:8080)")
            sys.exit(1)
        host, port_str = args.proxy.split(":", 1)
        from phantomscan.proxy import start_proxy
        start_proxy(host, int(port_str), target_scope=args.target or "localhost")
        return 0

    return asyncio.run(main_async())


if __name__ == "__main__":
    if sys.platform == "win32":
        sys.stdout.reconfigure(encoding='utf-8')
    raise SystemExit(main())
