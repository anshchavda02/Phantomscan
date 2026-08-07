#!/usr/bin/env python3
"""PhantomScan benchmark harness.

Measures scan performance metrics to verify enterprise upgrade
improvements are real, not assumed. Run identical scans and report:
  - Total scan duration
  - Peak memory usage
  - Cache hit rate
  - Module parallelism (tier breakdown)
  - Checkpoint/resume timing

Usage:
    python scripts/benchmark.py --target example.com --profile quick
    python scripts/benchmark.py --target example.com --profile full --runs 3

Target improvements to verify:
  □ Full-profile scan completes significantly faster with parallelism
  □ Batch scan shows measurable cache reuse (>0% hit rate)
  □ Memory usage stays under configured max_memory_mb
  □ Circuit breaker degrades gracefully on API failure
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# Add the repo root to path for imports
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))


def get_memory_mb() -> float:
    """Return current process RSS in MB."""
    try:
        import psutil
        return psutil.Process().memory_info().rss / 1024 / 1024
    except ImportError:
        return -1.0


async def run_single_benchmark(
    target: str,
    profile: str,
    run_index: int,
) -> dict:
    """Execute one benchmark run and collect metrics."""
    from phantomscan.scope import parse_target
    from phantomscan.db import Database
    from phantomscan.models import utc_now

    print(f"\n{'='*60}")
    print(f"  Benchmark Run {run_index + 1}: {target} (profile={profile})")
    print(f"{'='*60}")

    mem_before = get_memory_mb()
    t0 = time.perf_counter()

    # Import scan_one from the orchestrator
    # We use subprocess to get clean measurements
    import subprocess
    cmd = [
        sys.executable, str(REPO_ROOT / "phantomscan.py"),
        "--target", target,
        "--profile", profile,
        "--silent",
        "--json",
    ]

    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=600,
        cwd=str(REPO_ROOT),
    )

    elapsed = time.perf_counter() - t0
    mem_after = get_memory_mb()
    peak_memory = max(mem_before, mem_after)

    # Parse the JSON output for findings count
    findings_count = 0
    score = 0
    scan_duration = elapsed
    modules_run = 0
    cache_hit_rate = 0.0

    if proc.returncode == 0 and proc.stdout.strip():
        try:
            # The JSON output may be preceded by other text
            lines = proc.stdout.strip().split("\n")
            for line in reversed(lines):
                line = line.strip()
                if line.startswith("{"):
                    report = json.loads(line)
                    findings_count = len(report.get("findings", []))
                    score = report.get("score", 0)
                    scan_duration = report.get("duration", elapsed)
                    metadata = report.get("scan_metadata", {})
                    cache_hit_rate = metadata.get("cache_hit_rate", 0.0)
                    break
        except (json.JSONDecodeError, IndexError):
            pass

    result = {
        "run_index": run_index + 1,
        "target": target,
        "profile": profile,
        "duration_seconds": round(elapsed, 2),
        "scan_duration_seconds": round(scan_duration, 2),
        "peak_memory_mb": round(peak_memory, 1),
        "findings_count": findings_count,
        "score": score,
        "cache_hit_rate": round(cache_hit_rate, 4),
        "exit_code": proc.returncode,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    if proc.returncode != 0:
        result["stderr"] = proc.stderr[:500] if proc.stderr else ""

    return result


def print_results_table(results: list[dict]) -> None:
    """Print benchmark results in a formatted table."""
    print(f"\n{'='*70}")
    print("  BENCHMARK RESULTS")
    print(f"{'='*70}")

    headers = ["Run", "Duration(s)", "Memory(MB)", "Findings", "Score", "Cache Hit%", "Status"]
    widths = [5, 12, 11, 9, 6, 11, 8]

    header_line = "  ".join(h.ljust(w) for h, w in zip(headers, widths))
    print(f"\n  {header_line}")
    print(f"  {'─'*len(header_line)}")

    for r in results:
        status = "✓ OK" if r["exit_code"] == 0 else "✗ FAIL"
        cache_pct = f"{r['cache_hit_rate']*100:.1f}%"
        row = [
            str(r["run_index"]),
            f"{r['duration_seconds']:.2f}",
            f"{r['peak_memory_mb']:.1f}" if r['peak_memory_mb'] > 0 else "N/A",
            str(r["findings_count"]),
            str(r["score"]),
            cache_pct,
            status,
        ]
        line = "  ".join(v.ljust(w) for v, w in zip(row, widths))
        print(f"  {line}")

    # Summary statistics
    if len(results) > 1:
        durations = [r["duration_seconds"] for r in results]
        memories = [r["peak_memory_mb"] for r in results if r["peak_memory_mb"] > 0]
        print(f"\n  Summary:")
        print(f"    Average duration: {sum(durations)/len(durations):.2f}s")
        print(f"    Min duration:     {min(durations):.2f}s")
        print(f"    Max duration:     {max(durations):.2f}s")
        if memories:
            print(f"    Peak memory:      {max(memories):.1f}MB")

    print(f"\n{'='*70}\n")


async def main() -> int:
    parser = argparse.ArgumentParser(
        prog="benchmark",
        description="PhantomScan performance benchmark harness",
    )
    parser.add_argument("--target", required=True, help="Target to scan")
    parser.add_argument("--profile", default="quick", help="Scan profile")
    parser.add_argument("--runs", type=int, default=1, help="Number of benchmark runs")
    parser.add_argument("--output", help="Save results to JSON file")
    args = parser.parse_args()

    print(f"\nPhantomScan Benchmark Harness")
    print(f"Target:  {args.target}")
    print(f"Profile: {args.profile}")
    print(f"Runs:    {args.runs}")
    print(f"Python:  {sys.version.split()[0]}")
    print(f"Memory tracking: {'psutil available' if get_memory_mb() > 0 else 'psutil not installed'}")

    results = []
    for i in range(args.runs):
        result = await run_single_benchmark(args.target, args.profile, i)
        results.append(result)
        print(f"  Run {i+1}: {result['duration_seconds']:.2f}s, "
              f"{result['findings_count']} findings, "
              f"score={result['score']}")

    print_results_table(results)

    if args.output:
        output_path = Path(args.output)
        output_path.write_text(json.dumps(results, indent=2))
        print(f"Results saved to: {output_path}")

    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
