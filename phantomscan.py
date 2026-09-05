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

import hashlib

from phantomscan.db import Database
from phantomscan.email_security import analyze_email
from phantomscan.engines import run_engine
from phantomscan.health import EngineHealthChecker
from phantomscan.models import Observation, utc_now
from phantomscan.pipeline import PipelineState, assert_pipeline_order
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
from phantomscan.http_client import RobustHTTPClient, http_client
from phantomscan.js_analyzer import JSRouteExtractor
from phantomscan.openapi_parser import OpenAPIParser
from phantomscan.web_crawler import WebCrawler
from phantomscan.local_app_profiles import (
    detect_app_profile,
    get_profile,
    profile_to_observations,
)
from phantomscan.proxy_detector import auto_resolve_route

# Enterprise modules
from modules.http_pool import SharedHTTPPool
from modules.scan_cache import ScanCache
from modules.circuit_breaker import CircuitBreaker, CircuitOpenError, create_default_breakers
from modules.degradation_matrix import print_degradation_table
from modules.scan_checkpoint import ScanCheckpoint
from modules.resource_governor import ResourceGovernor
from modules.structured_logging import (
    configure_logging,
    ScanLogger,
    build_scan_summary,
)

WARNING = """
PhantomScan 2.2.0 - Scan Smart. Stay Secure.
Authorized security assessment only. Run this tool only against systems you own
or have explicit written authorization to test. Scope is enforced per target.
"""

from rich.console import Console
from rich.logging import RichHandler

console = Console()


def cprint(text: str, color: str = "cyan") -> None:
    """Print a terminal message using Rich."""
    console.print(text, style=color)


def _finding_key(f: dict[str, Any]) -> str:
    parts = [
        str(f.get("title", "")),
        str(f.get("module", "")),
        str(f.get("severity", "")),
        str(f.get("evidence", ""))[:100],
    ]
    return hashlib.sha256(":".join(parts).encode()).hexdigest()


def _parse_dt_naive(iso: str) -> datetime:
    dt = datetime.fromisoformat(iso)
    if dt.tzinfo is not None:
        from datetime import timezone
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


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
        choices=["quick", "full", "passive", "owasp", "bug-bounty", "api", "network", "advanced", "deep", "deepscan"],
        help="Scan profile to execute:\n"
             "  quick      - Fast HTTP checks, top 100 ports, basic TLS\n"
             "  full       - Deep web analysis, full TLS, concurrent port scan, YAML engine\n"
             "  passive    - Safe DNS/email checks & Deep Web without active fuzzing\n"
             "  api        - API-focused HTTP analysis without web crawling\n"
             "  network    - Intensive Go port-scanner focused profile\n"
             "  advanced   - Run 35 advanced security modules (Logic, IDOR, AI/Vibe-Coded, Takeover, PII, etc.)\n"
             "  deep/deepscan - Comprehensive all-in-one scan: Full reconnaissance, deep crawling, port scan, TLS, and all 35+ advanced security modules"
    )
    scan_group.add_argument("--ports", default="top100", help="Ports to scan (e.g., 'top100', 'top1000', or '80,443,8080')")
    scan_group.add_argument("--proxy", help="Start Passive Proxy Mode on HOST:PORT (e.g., 127.0.0.1:8080) to intercept and feed browser traffic to the YAML engine")
    scan_group.add_argument("--advanced", action="store_true", help="Run all 35 advanced security modules")
    scan_group.add_argument("--modules", help="Comma-separated list of specific advanced modules to run (e.g., 'ai_app_security,idor')")
    scan_group.add_argument("--source-path", help="Path to local source code for hybrid black-box + white-box analysis (enables ORM, Prisma, Drizzle, and .env git-history checks)")
    scan_group.add_argument("--check-slopsquatting", action="store_true", help="Check project dependencies for AI-hallucinated packages (slopsquatting). Requires --source-path.")
    scan_group.add_argument(
        "--app-profile", "--local-app",
        choices=["juiceshop", "juice-shop", "dvwa", "webgoat", "bwapp", "vulnweb", "vulnweb-php", "vulnweb-asp", "auto"],
        default="auto",
        help="Optimize scan for a known vulnerable app (auto-detects if 'auto')",
    )
    scan_group.add_argument("--upstream-proxy", "--http-proxy", dest="upstream_proxy", help="Route all outbound scanner HTTP/HTTPS requests through an upstream proxy (e.g. http://127.0.0.1:8080)")
    scan_group.add_argument("--auto-proxy", action="store_true", default=None, help="Automatically detect active local proxies/VPN tunnels (Burp Suite, Clash, V2Ray, Fiddler, Tor) and reroute traffic if direct target connection fails (enabled by default on deep/advanced profiles)")
    scan_group.add_argument("--no-auto-proxy", dest="auto_proxy", action="store_false", help="Disable automatic local proxy/VPN discovery and rerouting")
    scan_group.add_argument("--timeout", type=float, default=10.0, help="Per-request HTTP timeout in seconds (default: 10.0)")
    scan_group.add_argument("--crawl-depth", type=int, default=None,
                           help="Web crawler depth (overrides --depth for crawling)")


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
    legacy_group.add_argument("--resume", help="Resume a previously interrupted scan by scan ID")

    # Enterprise flags
    enterprise_group = parser.add_argument_group("Enterprise Performance & Reliability")
    enterprise_group.add_argument(
        "--time-budget", type=int, default=None,
        help="Maximum total scan time in seconds. Degrades gracefully to partial results."
    )
    enterprise_group.add_argument(
        "--log-format", choices=["json", "text"], default="text",
        help="Log output format: 'json' for structured/machine-parseable, 'text' for human-readable (default: text)"
    )
    enterprise_group.add_argument(
        "--max-memory-mb", type=int, default=2048,
        help="Maximum memory usage ceiling in MB (default: 2048)"
    )
    enterprise_group.add_argument(
        "--max-concurrent-scans", type=int, default=5,
        help="Maximum concurrent batch scans (default: 5)"
    )

    # System Diagnostics & Benchmarking
    diagnostic_group = parser.add_argument_group("System Diagnostics & Benchmarking")
    diagnostic_group.add_argument(
        "--check-engines", "--engine-health",
        action="store_true",
        help="Perform pre-scan health check of optional polyglot engines and exit"
    )
    diagnostic_group.add_argument(
        "--benchmark",
        action="store_true",
        help="Launch the automated benchmark harness against predefined test targets"
    )

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
    returns_tuple: bool = False,
    **kwargs: Any,
) -> Any:
    """Run and time one scan step, catching recoverable errors."""
    started = time.perf_counter()

    async def _run_func() -> Any:
        try:
            return await func(*args, **kwargs)
        except (OSError, TimeoutError, ValueError, RuntimeError, Exception) as exc:
            logger.exception("%s failed: %s", name, exc)
            observations.append(
                Observation(
                    f"{name.lower().replace(' ', '_')}_error", str(exc), "orchestrator"
                ).to_dict()
            )
            return ([], []) if returns_tuple else []

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
    if getattr(args, "profile", "") == "deepscan":
        args.profile = "deep"
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

    if not target.is_local:
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

    # ── Auto-Proxy / Smart Routing Resolution ─────────────────────────────────
    active_proxy = getattr(args, "upstream_proxy", None)
    auto_proxy_enabled = getattr(args, "auto_proxy", None)
    if auto_proxy_enabled is None:
        # Default enabled for deep / advanced / full profiles
        auto_proxy_enabled = args.profile in ("deep", "deepscan", "advanced", "full", "owasp", "bug-bounty")

    if not active_proxy and auto_proxy_enabled:
        resolved_proxy, route_msg = await auto_resolve_route(
            target.base_url, configured_proxy=active_proxy, profile=args.profile, force_auto=False
        )
        if resolved_proxy:
            active_proxy = resolved_proxy
            setattr(args, "upstream_proxy", resolved_proxy)
            if not args.silent:
                cprint(f"[*] [SMART-ROUTING] {route_msg}", "green")
            observations.append(Observation("smart_proxy_routed", resolved_proxy, "routing").to_dict())

    # ── HTTP analysis ─────────────────────────────────────────────────────────
    http_obs, http_findings = await timed_step(
        "Analyzing HTTP", logger, observations, args.silent,
        fetch_headers, target, 10.0, logger, active_proxy,
        returns_tuple=True,
    )
    if isinstance(http_obs, (list, tuple)):
        observations.extend(item.to_dict() for item in http_obs)
    if isinstance(http_findings, (list, tuple)):
        findings.extend(item.to_dict() for item in http_findings)

    # If direct HTTP analysis failed (e.g. timeout / connection drop) and no proxy was active, probe local proxies now!
    has_http_error = any(obs.get("name") == "http_error" for obs in observations)
    if has_http_error and not active_proxy and auto_proxy_enabled:
        if not args.silent:
            cprint("[!] Direct connection to target timed out. Probing local proxies/VPN tunnels (Burp Suite, Clash, Tor, V2Ray)...", "yellow")
        resolved_proxy, route_msg = await auto_resolve_route(target.base_url, profile=args.profile, force_auto=True)
        if resolved_proxy:
            active_proxy = resolved_proxy
            setattr(args, "upstream_proxy", resolved_proxy)
            if not args.silent:
                cprint(f"[*] [SMART-ROUTING] Rerouting scan through {resolved_proxy} ({route_msg})", "green")
            observations.append(Observation("smart_proxy_routed", resolved_proxy, "routing").to_dict())
            # Retry HTTP analysis through the resolved proxy!
            retry_obs, retry_findings = await fetch_headers(target, 10.0, logger, active_proxy)
            observations.extend(item.to_dict() for item in retry_obs)
            findings.extend(item.to_dict() for item in retry_findings)

    # Resolve the effective base URL from the HTTP result
    effective_url: str = target.base_url
    for obs in observations:
        if obs.get("name") in ("effective_url", "http_url") and obs.get("value"):
            effective_url = str(obs["value"])
            break

    # If effective_url starts with https:// but target failed over HTTPS without explicit scheme:
    if effective_url.startswith("https://") and any(obs.get("name") == "http_error" for obs in observations):
        if not target.has_explicit_scheme:
            effective_url = f"http://{target.netloc}"

    # ── OpenAPI / Swagger Discovery ───────────────────────────────────────────
    if args.profile != "passive":
        async def _run_openapi() -> tuple[list[Any], list[Any]]:
            timeout_sec = getattr(args, "timeout", 10.0)
            async with http_client(proxy=active_proxy, timeout_seconds=timeout_sec) as client:
                parser = OpenAPIParser(client)
                _, o_obs, o_findings = await parser.discover_and_parse(effective_url, logger)
                return o_obs, o_findings

        open_obs, open_findings = await timed_step(
            "OpenAPI / Swagger discovery", logger, observations, args.silent,
            _run_openapi,
            returns_tuple=True,
        )
        if isinstance(open_obs, (list, tuple)):
            observations.extend(item.to_dict() if hasattr(item, "to_dict") else item for item in open_obs)
        if isinstance(open_findings, (list, tuple)):
            findings.extend(item.to_dict() if hasattr(item, "to_dict") else item for item in open_findings)

    # ── SPA & JavaScript Route Analysis ───────────────────────────────────────
    DEEP_PROFILES = ("full", "bug-bounty", "owasp", "advanced", "deep", "deepscan")
    if args.profile in DEEP_PROFILES:
        async def _run_js_analyzer() -> tuple[list[Any], list[Any]]:
            timeout_sec = getattr(args, "timeout", 10.0)
            async with http_client(proxy=active_proxy, timeout_seconds=timeout_sec) as client:
                extractor = JSRouteExtractor(client)
                html_body = ""
                try:
                    res = await client.get(effective_url, retries=1)
                    html_body = res.text()
                except Exception:
                    pass
                _, js_obs, js_sec_findings = await extractor.analyze(effective_url, html_body, logger)
                return js_obs, js_sec_findings

        js_obs_res, js_sec_res = await timed_step(
            "JavaScript route & secret extraction", logger, observations, args.silent,
            _run_js_analyzer,
            returns_tuple=True,
        )
        if isinstance(js_obs_res, (list, tuple)):
            observations.extend(item.to_dict() if hasattr(item, "to_dict") else item for item in js_obs_res)
        if isinstance(js_sec_res, (list, tuple)):
            findings.extend(item.to_dict() if hasattr(item, "to_dict") else item for item in js_sec_res)

    # ── Emit is_local_target observation for score calibration ─────────────
    if target.is_local:
        observations.append(
            Observation("is_local_target", True, "scope").to_dict()
        )

    # ── App profile detection + known endpoints & baseline findings ───────
    app_profile_key = getattr(args, "app_profile", None) or getattr(args, "local_app", None)
    if app_profile_key == "auto" or not app_profile_key:
        # Auto-detect by fingerprinting the main page body and host
        body_sample = ""
        for obs in observations:
            if obs.get("name") == "body_sample":
                body_sample = str(obs.get("value", ""))
                break
        detected = detect_app_profile(body_sample, target_host=target.host)
        if detected:
            app_profile_key = detected
            if not args.silent:
                cprint(f"[*] Auto-detected app profile: {get_profile(detected)['name']}", "green")

    if app_profile_key and app_profile_key != "auto":
        profile_obs = profile_to_observations(app_profile_key, effective_url)
        observations.extend(profile_obs)
        logger.info(
            "App profile '%s' provided %d seed observations for crawler/active modules",
            app_profile_key,
            len(profile_obs),
        )

    # ── Web crawling (parameter & form discovery) ─────────────────────────
    CRAWL_PROFILES = ("full", "bug-bounty", "owasp", "advanced", "deep", "deepscan")
    if args.profile in CRAWL_PROFILES or args.profile != "passive":
        crawl_depth = getattr(args, "crawl_depth", None) or args.depth
        if args.profile in ("deep", "deepscan"):
            crawler_pages = 150
            crawler_depth = max(crawl_depth, 3)
        elif args.profile in ("owasp", "advanced"):
            crawler_pages = 60
            crawler_depth = max(crawl_depth, 2)
        else:
            crawler_pages = 50
            crawler_depth = crawl_depth

        seed_urls: list[str] = []
        for o in observations:
            if o.get("name") == "discovered_urls" and isinstance(o.get("value"), list):
                seed_urls.extend(o["value"])

        async def _run_crawler() -> list[Any]:
            proxy_url = getattr(args, "upstream_proxy", None)
            timeout_sec = getattr(args, "timeout", 10.0)
            async with http_client(proxy=proxy_url, timeout_seconds=timeout_sec) as client:
                crawler = WebCrawler(client, max_pages=crawler_pages, max_depth=crawler_depth)
                result = await crawler.crawl(effective_url, seed_urls=seed_urls)
                return crawler.to_observations(result, effective_url)

        crawl_obs = await timed_step(
            "Web crawling (links, forms, APIs)", logger, observations, args.silent,
            _run_crawler,
        )
        if isinstance(crawl_obs, list):
            observations.extend(
                item.to_dict() if hasattr(item, "to_dict") else item
                for item in crawl_obs
            )

    # Deep web analysis (sensitive paths, CORS, disclosures, redirect)
    DEEP_PROFILES = ("full", "bug-bounty", "owasp", "advanced", "deep", "deepscan")
    if args.profile in DEEP_PROFILES:
        timeout_sec = getattr(args, "timeout", 10.0)
        deep_findings = await timed_step(
            "Deep web analysis", logger, observations, args.silent,
            deep_analyze_web, target, effective_url, logger, active_proxy, timeout_sec,
            returns_tuple=False
        )
        if isinstance(deep_findings, list):
            findings.extend(
                f.to_dict() if hasattr(f, 'to_dict')
                else f
                for f in deep_findings
            )

    if args.profile != "network":
        yaml_findings = await timed_step(
            "YAML vulnerability rules", logger, observations, args.silent,
            run_yaml_rules, effective_url, observations
        )
        if isinstance(yaml_findings, list):
            findings.extend(
                f.to_dict() if hasattr(f, 'to_dict')
                else f
                for f in yaml_findings
            )

    # Technology fingerprinting
    tech_obs_input = [
        item if isinstance(item, Observation)
        else Observation(str(item.get("name", "")), item.get("value"), str(item.get("source", "")))
        for item in observations
    ]
    tech_obs_list = detect_technologies(tech_obs_input)
    observations.extend(item.to_dict() for item in tech_obs_list)

    # Email security (SPF/DMARC/MX) — skip for local targets
    if not target.is_local:
        email_obs, email_findings = await timed_step(
            "Checking email security", logger, observations, args.silent,
            analyze_email, target, logger,
            returns_tuple=True,
        )
        if isinstance(email_obs, (list, tuple)):
            observations.extend(item.to_dict() for item in email_obs)
        if isinstance(email_findings, (list, tuple)):
            findings.extend(item.to_dict() for item in email_findings)
    else:
        logger.info("Skipping email security check for local target %s", target.host)

    # Known-platform context — skip for local targets
    if not target.is_local:
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
            returns_tuple=True,
        )
        observations.extend(item.to_dict() for item in port_obs)
        findings.extend(port_findings)

        tls_obs, tls_findings = await timed_step(
            "Inspecting TLS", logger, observations, args.silent,
            inspect_tls, target, logger,
            returns_tuple=True,
        )
        observations.extend(item.to_dict() for item in tls_obs)
        findings.extend(tls_findings)

        async def _run_single_engine(name: str, command: list[str]) -> tuple[str, Any]:
            res = await run_engine(command, request, name, target)
            return name, res

        engine_results = await asyncio.gather(
            *(_run_single_engine(name, cmd) for name, cmd in engine_specs),
            return_exceptions=True,
        )
        for r in engine_results:
            if isinstance(r, tuple):
                name, result = r
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
    if args.advanced or args.modules or args.profile in ("advanced", "deep", "deepscan", "monitor"):
        proxy_url = getattr(args, "upstream_proxy", None)
        timeout_sec = getattr(args, "timeout", 10.0)
        client = RobustHTTPClient(proxy=proxy_url, timeout_seconds=timeout_sec)
        await client.start()
        try:
            adv_profile = args.modules if args.modules else args.profile
            if args.advanced and adv_profile not in ("advanced", "deep", "deepscan", "monitor") and not args.modules:
                adv_profile = "advanced"

            is_deep = adv_profile in ("deep", "deepscan")
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
                getattr(args, "check_slopsquatting", False) or is_deep,
                force_all=is_deep,
                returns_tuple=True,
            )
            seen_keys = {
                _finding_key(f)
                for f in findings
                if isinstance(f, dict)
            }
            for f in adv_findings:
                if isinstance(f, dict):
                    key = _finding_key(f)
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
        ts_dt = _parse_dt_naive(started)
        ts_str = ts_dt.strftime("%Y%m%d_%H%M%S")
    except Exception:
        ts_str = str(int(time.time()))

    pipeline_state = PipelineState()
    pipeline_state.mark_raw_collected()

    final_findings, suppressed_findings, observations = post_process(
        findings=findings,
        observations=observations,
        data_dir=root / "data",
        target_host=root_domain(target.host),
        include_medium=include_medium,
        include_low=include_low,
        fp_log_path=root / "reports" / f"fp_log_{safe_target}_{ts_str}.json",
    )
    pipeline_state.mark_gated()
    pipeline_state.mark_fp_processed()

    # Refresh compliance and AI narrative findings on clean, post-processed final findings
    from phantomscan.modules.compliance import ComplianceReporter
    from phantomscan.modules.ai_narrative import AINarrativeReporter

    final_findings = [
        f for f in final_findings
        if not (
            str(f.get("id", "")).startswith("COMPLIANCE-")
            or str(f.get("id", "")).startswith("AI-NARRATIVE-")
        )
    ]
    comp_rep = ComplianceReporter()
    comp_findings = comp_rep.generate_compliance_report(final_findings, effective_url)
    final_findings.extend(comp_findings)

    narr_rep = AINarrativeReporter()
    narr_text = narr_rep.generate_narrative(final_findings, effective_url)
    final_findings.append({
        "id": "AI-NARRATIVE-SUMMARY",
        "title": "Executive Summary & Remediation Narrative",
        "severity": "info",
        "confidence": "high",
        "category": "reporting",
        "target": effective_url,
        "evidence": narr_text,
        "recommendation": "Distribute this narrative to technical leadership.",
    })

    # ENFORCE ORDER: FindingGate -> FP PostProcessor -> Score Engine
    assert_pipeline_order(pipeline_state)
    pipeline_state.mark_score_calculated()

    platform = load_known_platform(root / "data", root_domain(target.host))
    final_score = score(final_findings, observations, platform=platform)
    final_grade = grade(final_score)
    finished = utc_now()

    # Calculate elapsed scan duration in seconds
    start_dt = _parse_dt_naive(started)
    finish_dt = _parse_dt_naive(finished)
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
        "scan_id": str(scan_id),
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
        "scan_metadata": {
            "modules_failed": getattr(args, "_modules_failed", []),
            "circuit_breakers_opened": getattr(args, "_breakers_opened", []),
            "cache_hit_rate": getattr(args, "_cache_hit_rate", 0.0),
            "degradation_active": getattr(args, "_degradation_msgs", []),
        },
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
    """CLI async entrypoint with enterprise infrastructure."""
    parser = build_parser()
    args = parser.parse_args()
    if not args.silent:
        cprint(WARNING.strip(), "yellow")

    root = Path(__file__).resolve().parent

    # Quick diagnostic: check engines and exit
    if getattr(args, "check_engines", False):
        checker = EngineHealthChecker(root)
        health = await checker.check_all()
        engine_statuses = {k: v.available for k, v in health.engines.items()}
        print_degradation_table(engine_statuses)
        return 0

    # Quick diagnostic: benchmark suite
    if getattr(args, "benchmark", False):
        benchmark_script = root / "scripts" / "benchmark.py"
        if benchmark_script.exists():
            import subprocess
            proc = subprocess.run([sys.executable, str(benchmark_script), "--suite", "clean"])
            return proc.returncode
        else:
            cprint("[!] Benchmark script not found.", "red")
            return 1

    if not args.target and not args.batch:
        parser.error("--target, --batch, --check-engines, or --benchmark is required")

    # Configure structured logging
    configure_logging(
        log_format=getattr(args, "log_format", "text"),
        debug=args.debug,
    )

    # Initialize enterprise infrastructure
    governor = ResourceGovernor(
        max_memory_mb=getattr(args, "max_memory_mb", 2048),
        max_concurrent_scans=getattr(args, "max_concurrent_scans", 5),
    )
    scan_cache = ScanCache(db_path=root / "phantomscan.sqlite3")
    checkpoint = ScanCheckpoint(db_path=root / "phantomscan.sqlite3")
    breakers = create_default_breakers()

    # Pre-scan engine health check with degradation matrix
    if args.debug and not args.silent:
        checker = EngineHealthChecker(root)
        health = await checker.check_all()
        engine_statuses = {
            k: v.available for k, v in health.engines.items()
        }
        degradation_msgs = print_degradation_table(engine_statuses)
        args._degradation_msgs = degradation_msgs
        cprint("")  # blank line
    elif not args.silent:
        # Quick health check without verbose table
        checker = EngineHealthChecker(root)
        health = await checker.check_all()

    # Store breaker reference on args for downstream modules
    args._breakers_opened = []
    args._modules_failed = []
    args._cache_hit_rate = 0.0

    targets = (
        [args.target]
        if args.target
        else Path(args.batch).read_text(encoding="utf-8").splitlines()
    )
    reports: list[dict[str, Any]] = []

    try:
        for target in [t for t in targets if t.strip()]:
            async with governor.acquire_scan_slot():
                governor.check_memory()
                display = ScanProgressDisplay(target, silent=args.silent)
                report = await display.run_with_progress(scan_one(args, target, root))
                if report.get("duration", 0) < 5.0:
                    logging.warning(
                        "Scan completed in under 5 seconds — "
                        "this may indicate modules are returning "
                        "mock/cached data rather than performing "
                        "real network operations. Use --debug "
                        "to investigate."
                    )
                    if not args.silent:
                        cprint(
                            "[!] Warning: Scan completed very "
                            "quickly. Verify real scanning occurred.",
                            "yellow"
                        )
                reports.append(report)

        # Update cache hit rate on args for report metadata
        args._cache_hit_rate = scan_cache.hit_rate

    finally:
        # Always close shared resources to prevent connection leaks
        await SharedHTTPPool.shutdown()
        scan_cache.close()
        checkpoint.close()

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
            ts_dt = _parse_dt_naive(report.get("started_at", ""))
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
        if not args.target:
            print(
                "[!] --proxy mode requires --target "
                "to define the authorized scope. "
                "Refusing to start an unrestricted proxy."
            )
            sys.exit(1)
        if ":" not in args.proxy:
            print("Proxy argument must be in format HOST:PORT (e.g., 127.0.0.1:8080)")
            sys.exit(1)
        host, port_str = args.proxy.split(":", 1)
        if host in ("0.0.0.0", "::"):
            print(
                "[!] Warning: Proxy is binding to all "
                "interfaces. This exposes an open proxy "
                "on your network. Use 127.0.0.1 unless "
                "you specifically need network-wide access."
            )
        try:
            from phantomscan.proxy import start_proxy
        except ImportError:
            print(
                "Proxy mode requires mitmproxy: "
                "pip install mitmproxy>=10.0"
            )
            sys.exit(1)
        start_proxy(host, int(port_str), target_scope=args.target or "localhost")
        return 0

    return asyncio.run(main_async())


if __name__ == "__main__":
    if sys.platform == "win32":
        sys.stdout.reconfigure(encoding='utf-8')
    raise SystemExit(main())
