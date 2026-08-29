#!/usr/bin/env python3
"""PhantomScan Detection & Performance Benchmark Harness.

Measures scanner accuracy (True Positives and False Positives) and performance
metrics against predefined known clean and known vulnerable targets.

Usage:
    # Run known clean targets (example.com, httpbin.org)
    python scripts/benchmark.py --suite clean

    # Run known vulnerable test sites (requires --confirm-authorized)
    python scripts/benchmark.py --suite vulnerable --confirm-authorized

    # Run against a single target (e.g., local Juice Shop)
    python scripts/benchmark.py --target http://localhost:3000

    # Compare current benchmark results with a baseline JSON file
    python scripts/benchmark.py --target https://example.com --baseline benchmark_baseline.json
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

# Predefined target suites
CLEAN_TARGETS = [
    "https://example.com",
    "https://httpbin.org",
]

VULNERABLE_TARGETS = [
    "http://testphp.vulnweb.com",
    "http://testaspnet.vulnweb.com",
]

LOCAL_TARGETS = [
    "http://localhost:3000",
]


def run_scanner_subprocess(
    target: str,
    profile: str = "quick",
    timeout_sec: int = 600,
) -> tuple[int, dict[str, Any], float]:
    """Execute phantomscan.py in a subprocess and parse JSON output.
    
    Returns (returncode, report_dict, duration_seconds).
    """
    t0 = time.perf_counter()
    import tempfile
    
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        tmp_json_path = tmp.name

    try:
        cmd = [
            sys.executable,
            str(REPO_ROOT / "phantomscan.py"),
            "--target",
            target,
            "--profile",
            profile,
            "--silent",
            "--json-out",
            tmp_json_path,
        ]

        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_sec,
            cwd=str(REPO_ROOT),
        )
        elapsed = time.perf_counter() - t0

        report: dict[str, Any] = {}
        if os.path.exists(tmp_json_path) and os.path.getsize(tmp_json_path) > 0:
            try:
                with open(tmp_json_path, "r", encoding="utf-8") as f:
                    report = json.load(f)
            except Exception as e:
                report = {"error": f"Failed to parse report JSON: {e}"}
        elif proc.stdout.strip():
            # Fallback to parsing stdout if present
            try:
                for line in reversed(proc.stdout.strip().split("\n")):
                    line = line.strip()
                    if line.startswith("{"):
                        report = json.loads(line)
                        break
            except Exception:
                pass

        return proc.returncode, report, elapsed

    finally:
        if os.path.exists(tmp_json_path):
            try:
                os.remove(tmp_json_path)
            except OSError:
                pass


def benchmark_target(
    target: str,
    profile: str = "quick",
) -> dict[str, Any]:
    """Scan a target and collect benchmark metrics."""
    print(f"[*] Benchmarking target: {target} (profile: {profile})...")
    
    returncode, report, elapsed = run_scanner_subprocess(target, profile=profile)

    findings = report.get("findings", [])
    scan_meta = report.get("scan_metadata", {}) or report.get("scan_meta", {})
    modules_executed = (
        report.get("modules_executed")
        or scan_meta.get("modules_executed")
        or []
    )

    sev_counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }

    for f in findings:
        sev = str(f.get("severity", "info")).lower()
        if sev in sev_counts:
            sev_counts[sev] += 1
        else:
            sev_counts["info"] += 1

    result = {
        "target": target,
        "scan_duration_seconds": round(elapsed, 2),
        "total_findings": len(findings),
        "findings_by_severity": sev_counts,
        "score": report.get("score", 0),
        "grade": report.get("grade", "N/A"),
        "modules_executed": modules_executed,
        "false_positive_flags": "",
        "status": "success" if returncode == 0 else f"failed (code {returncode})",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    print(
        f"    Duration: {result['scan_duration_seconds']}s | "
        f"Findings: {result['total_findings']} "
        f"(Crit: {sev_counts['critical']}, High: {sev_counts['high']}, "
        f"Med: {sev_counts['medium']}, Low: {sev_counts['low']}, Info: {sev_counts['info']}) | "
        f"Score: {result['score']}/100"
    )

    return result


def compare_against_baseline(
    current_results: list[dict[str, Any]],
    baseline_path: Path,
) -> dict[str, Any]:
    """Compare current benchmark results against a baseline JSON file."""
    if not baseline_path.exists():
        print(f"[!] Baseline file not found: {baseline_path}")
        return {}

    try:
        with open(baseline_path, "r", encoding="utf-8") as f:
            baseline_data = json.load(f)
    except Exception as e:
        print(f"[!] Failed to read baseline JSON: {e}")
        return {}

    baseline_by_target = {}
    if isinstance(baseline_data, list):
        for entry in baseline_data:
            baseline_by_target[entry.get("target")] = entry
    elif isinstance(baseline_data, dict) and "results" in baseline_data:
        for entry in baseline_data["results"]:
            baseline_by_target[entry.get("target")] = entry

    comparison: dict[str, Any] = {"targets": {}}

    print("\n" + "=" * 80)
    print("  BASELINE COMPARISON MATRIX")
    print("=" * 80)
    print(f"{'Target':<32} | {'Findings (Cur vs Base)':<24} | {'Score Delta':<12} | {'Status'}")
    print("-" * 80)

    for cur in current_results:
        target = cur["target"]
        base = baseline_by_target.get(target)

        if not base:
            print(f"{target:<32} | {cur['total_findings']:>3} vs {'N/A':<3}               | {'N/A':<12} | NEW TARGET")
            comparison["targets"][target] = {"status": "new", "current": cur}
            continue

        cur_total = cur["total_findings"]
        base_total = base.get("total_findings", 0)
        diff_total = cur_total - base_total
        diff_str = f"{cur_total} vs {base_total} ({'+' if diff_total > 0 else ''}{diff_total})"

        cur_score = cur.get("score", 0)
        base_score = base.get("score", 0)
        score_diff = cur_score - base_score
        score_str = f"{cur_score} vs {base_score} ({'+' if score_diff > 0 else ''}{score_diff})"

        status = "SAME"
        if diff_total < 0:
            status = "FEWER FINDINGS"
        elif diff_total > 0:
            status = "MORE FINDINGS"

        print(f"{target:<32} | {diff_str:<24} | {score_str:<12} | {status}")

        comparison["targets"][target] = {
            "status": status,
            "current_findings": cur_total,
            "baseline_findings": base_total,
            "findings_delta": diff_total,
            "current_score": cur_score,
            "baseline_score": base_score,
            "score_delta": score_diff,
            "severity_diff": {
                sev: cur["findings_by_severity"].get(sev, 0)
                - base.get("findings_by_severity", {}).get(sev, 0)
                for sev in ["critical", "high", "medium", "low", "info"]
            },
        }

    print("=" * 80 + "\n")
    return comparison


def print_summary_table(results: list[dict[str, Any]]) -> None:
    """Print results formatted as markdown and console table."""
    print("\n" + "=" * 90)
    print("  BENCHMARK RESULTS TABLE")
    print("=" * 90)
    print(
        f"{'Target':<30} | {'Crit':<5} | {'High':<5} | {'Med':<5} | {'Low':<5} | "
        f"{'Info':<5} | {'Score':<5} | {'Duration':<8} | {'Status'}"
    )
    print("-" * 90)

    for r in results:
        sev = r.get("findings_by_severity", {})
        print(
            f"{r['target']:<30} | "
            f"{sev.get('critical', 0):<5} | "
            f"{sev.get('high', 0):<5} | "
            f"{sev.get('medium', 0):<5} | "
            f"{sev.get('low', 0):<5} | "
            f"{sev.get('info', 0):<5} | "
            f"{r.get('score', 0):<5} | "
            f"{r.get('scan_duration_seconds', 0):<7.2f}s | "
            f"{r.get('status', 'OK')}"
        )
    print("=" * 90 + "\n")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="PhantomScan Accuracy and Performance Benchmark Harness",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Authorized Use Notice:
  Run benchmark only against targets you own or have explicit written
  authorization to scan. Public test sites (e.g. vulnweb.com) are intended
  for scanner testing.
        """,
    )
    parser.add_argument(
        "--target",
        help="Scan a specific target URL (e.g. http://localhost:3000)",
    )
    parser.add_argument(
        "--suite",
        choices=["clean", "vulnerable", "local", "all"],
        default="clean",
        help="Target suite to benchmark (default: clean)",
    )
    parser.add_argument(
        "--profile",
        default="quick",
        choices=["quick", "full", "advanced", "deepscan", "passive", "api"],
        help="Scan profile to use (default: quick)",
    )
    parser.add_argument(
        "--baseline",
        type=Path,
        help="Path to baseline JSON file for differential comparison",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Custom output file for benchmark JSON results",
    )
    parser.add_argument(
        "--confirm-authorized",
        action="store_true",
        help="Explicit confirmation that you are authorized to test the targets",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    targets_to_scan: list[str] = []
    if args.target:
        targets_to_scan = [args.target]
    else:
        if args.suite == "clean":
            targets_to_scan = CLEAN_TARGETS
        elif args.suite == "vulnerable":
            if not args.confirm_authorized:
                print(
                    "[!] ERROR: Benchmarking vulnerable targets requires explicit confirmation.\n"
                    "    Please pass --confirm-authorized to proceed."
                )
                return 1
            targets_to_scan = VULNERABLE_TARGETS
        elif args.suite == "local":
            targets_to_scan = LOCAL_TARGETS
        elif args.suite == "all":
            if not args.confirm_authorized:
                print(
                    "[!] ERROR: Benchmarking all targets requires explicit confirmation.\n"
                    "    Please pass --confirm-authorized to proceed."
                )
                return 1
            targets_to_scan = CLEAN_TARGETS + VULNERABLE_TARGETS + LOCAL_TARGETS

    print(f"\n============================================================")
    print(f"  PhantomScan Detection & Performance Benchmark")
    print(f"  Targets: {len(targets_to_scan)} | Profile: {args.profile}")
    print(f"============================================================\n")

    results: list[dict[str, Any]] = []
    for target in targets_to_scan:
        res = benchmark_target(target, profile=args.profile)
        results.append(res)

    print_summary_table(results)

    # Save output JSON
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_path = args.output or Path(f"benchmark_results_{ts}.json")
    output_payload = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "profile": args.profile,
        "total_targets": len(results),
        "results": results,
    }

    try:
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(output_payload, f, indent=2)
        print(f"[+] Benchmark results written to: {output_path.resolve()}")
    except Exception as e:
        print(f"[!] Failed to write benchmark results JSON: {e}")

    # Baseline comparison if requested
    if args.baseline:
        compare_against_baseline(results, args.baseline)

    return 0


if __name__ == "__main__":
    sys.exit(main())
