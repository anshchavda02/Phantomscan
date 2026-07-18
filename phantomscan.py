#!/usr/bin/env python3
"""PhantomScan CLI orchestrator."""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
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
from phantomscan.reporting import write_html_report, write_json_report, write_csv_report
from phantomscan.scanners import inspect_tls, scan_ports
from phantomscan.scope import parse_target, root_domain

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
    parser = argparse.ArgumentParser(prog="phantomscan")
    parser.add_argument("--target", required=False)
    parser.add_argument("--batch")
    parser.add_argument("--threads", type=int, default=1)
    parser.add_argument(
        "--profile",
        default="quick",
        choices=["quick", "full", "passive", "owasp", "bug-bounty", "api", "network"],
    )
    parser.add_argument("--ports", default="top100")
    parser.add_argument("--recon", action="store_true")
    parser.add_argument("--recon-only", action="store_true")
    parser.add_argument("--crawl", action="store_true")
    parser.add_argument("--depth", type=int, default=1)
    parser.add_argument("--screenshot", action="store_true")
    parser.add_argument("--cve", action="store_true")
    parser.add_argument("--cvss-min", type=float, default=4.0)
    parser.add_argument("--compliance")
    parser.add_argument("--checklist", action="store_true")
    parser.add_argument("--output", default="report")
    parser.add_argument("--pdf", action="store_true")
    parser.add_argument("--pdf-out")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--json-out")
    parser.add_argument("--collect-evidence", action="store_true")
    parser.add_argument("--silent", action="store_true")
    parser.add_argument("--narrative", action="store_true")
    parser.add_argument("--learning", action="store_true")
    parser.add_argument("--client")
    parser.add_argument("--assessor")
    parser.add_argument("--engagement-type")
    parser.add_argument("--ref")
    parser.add_argument("--confidence", choices=["high", "medium", "low"], default="medium")
    parser.add_argument("--show-medium", action="store_true")
    parser.add_argument("--show-all", action="store_true")
    parser.add_argument("--proxy")
    parser.add_argument("--diff", action="store_true")
    parser.add_argument("--verify")
    parser.add_argument("--watch")
    parser.add_argument("--interval")
    parser.add_argument("--daemon", choices=["start", "stop", "status"])
    parser.add_argument("--annotate", action="store_true")
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--debug", action="store_true")
    parser.add_argument("--log-file")
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
    deep_findings = await timed_step(
        "Deep web analysis", logger, observations, args.silent,
        deep_analyze_web, target, effective_url, logger,
    )
    if isinstance(deep_findings, list):
        findings.extend(item.to_dict() for item in deep_findings)

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

    # ── Post-processing and scoring ───────────────────────────────────────────
    safe_target = target.host.replace("/", "_").replace(":", "_")
    include_medium = args.show_medium or args.show_all or args.confidence in {"medium", "low"}
    include_low = args.show_all or args.confidence == "low"

    final_findings, suppressed_findings, observations = post_process(
        findings=findings,
        observations=observations,
        data_dir=root / "data",
        target_host=root_domain(target.host),
        include_medium=include_medium,
        include_low=include_low,
        fp_log_path=root / "reports" / f"fp_log_{safe_target}.json",
    )
    final_score = score(final_findings, observations)
    final_grade = grade(final_score)
    finished = utc_now()

    for item in final_findings:
        db.save_finding(scan_id, item)
    db.finish_scan(scan_id, finished, final_score)
    db.close()

    logger.info(
        "Scan complete: %d findings, %d suppressed, score=%d",
        len(final_findings), len(suppressed_findings), final_score,
    )
    if not args.silent:
        color = "green" if final_score >= 80 else "yellow" if final_score >= 60 else "red"
        cprint(
            f"[+] Scan complete: {len(final_findings)} findings, "
            f"score {final_score}/100 ({final_grade})",
            color,
        )

    return {
        "schema": "phantomscan.report.v1",
        "target": target.host,
        "profile": args.profile,
        "started_at": started,
        "finished_at": finished,
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

    for report in reports:
        safe_target = report["target"].replace("/", "_").replace(":", "_")
        json_path = (
            Path(args.json_out)
            if args.json_out and len(reports) == 1
            else output_dir / f"{safe_target}.json"
        )
        html_path = output_dir / f"{safe_target}.html"
        csv_path = output_dir / f"{safe_target}.csv"
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
    return asyncio.run(main_async())


if __name__ == "__main__":
    raise SystemExit(main())
