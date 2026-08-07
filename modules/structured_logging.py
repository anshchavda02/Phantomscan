"""Structured, machine-parseable logging for enterprise log aggregation.

Supports both JSON (``--log-format json``) and human-readable text
(``--log-format text``, default) output modes. Every log line includes
scan_id, module, duration_ms, and status fields for ELK/Datadog/Splunk.
"""

from __future__ import annotations

import json
import logging
import sys
import time
from typing import Any, Optional

logger = logging.getLogger(__name__)


class StructuredFormatter(logging.Formatter):
    """JSON-lines log formatter that emits structured fields."""

    def format(self, record: logging.LogRecord) -> str:
        log_entry: dict[str, Any] = {
            "timestamp": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "module": record.module,
            "message": record.getMessage(),
        }
        # Attach extra structured fields if present
        for key in ("scan_id", "scan_module", "duration_ms", "status",
                     "target", "tier", "error"):
            value = getattr(record, key, None)
            if value is not None:
                log_entry[key] = value
        if record.exc_info and record.exc_info[1]:
            log_entry["exception"] = str(record.exc_info[1])
        return json.dumps(log_entry, default=str)


class HumanFormatter(logging.Formatter):
    """Rich-compatible human-readable formatter preserving structured extras."""

    _FORMAT = "%(asctime)s [%(levelname)s] %(module)s: %(message)s"

    def __init__(self) -> None:
        super().__init__(self._FORMAT)

    def format(self, record: logging.LogRecord) -> str:
        base = super().format(record)
        extras = []
        for key in ("scan_id", "scan_module", "duration_ms", "status"):
            value = getattr(record, key, None)
            if value is not None:
                extras.append(f"{key}={value}")
        if extras:
            return f"{base} [{', '.join(extras)}]"
        return base


def configure_logging(
    log_format: str = "text",
    debug: bool = False,
    log_file: Optional[str] = None,
) -> None:
    """Configure the root logger for structured or text output.

    Args:
        log_format: ``"json"`` for structured or ``"text"`` for human-readable.
        debug: Enable DEBUG level output.
        log_file: Optional file path to write logs to.
    """
    root = logging.getLogger()
    root.setLevel(logging.DEBUG if debug else logging.INFO)

    # Remove existing handlers to avoid duplicates
    for handler in root.handlers[:]:
        root.removeHandler(handler)

    formatter: logging.Formatter
    if log_format == "json":
        formatter = StructuredFormatter()
    else:
        formatter = HumanFormatter()

    # Console handler
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setFormatter(formatter)
    console_handler.setLevel(logging.DEBUG if debug else logging.INFO)
    root.addHandler(console_handler)

    # Optional file handler
    if log_file:
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setFormatter(formatter)
        file_handler.setLevel(logging.DEBUG)
        root.addHandler(file_handler)


class ScanLogger:
    """Convenience wrapper that injects scan context into every log call."""

    def __init__(self, scan_id: str, base_logger: Optional[logging.Logger] = None) -> None:
        self._logger = base_logger or logging.getLogger("phantomscan")
        self.scan_id = scan_id

    def _log(self, level: int, msg: str, **kwargs: Any) -> None:
        extra = {"scan_id": self.scan_id}
        extra.update(kwargs)
        self._logger.log(level, msg, extra=extra)

    def info(self, msg: str, **kwargs: Any) -> None:
        self._log(logging.INFO, msg, **kwargs)

    def warning(self, msg: str, **kwargs: Any) -> None:
        self._log(logging.WARNING, msg, **kwargs)

    def error(self, msg: str, **kwargs: Any) -> None:
        self._log(logging.ERROR, msg, **kwargs)

    def debug(self, msg: str, **kwargs: Any) -> None:
        self._log(logging.DEBUG, msg, **kwargs)

    def module_start(self, module: str) -> float:
        """Log module start and return the start timestamp."""
        self.info(
            f"Module {module} started",
            scan_module=module,
            status="started",
        )
        return time.perf_counter()

    def module_complete(
        self,
        module: str,
        start_time: float,
        status: str = "success",
    ) -> float:
        """Log module completion with duration. Returns elapsed ms."""
        elapsed_ms = round((time.perf_counter() - start_time) * 1000, 1)
        self.info(
            f"Module {module} {status}",
            scan_module=module,
            duration_ms=elapsed_ms,
            status=status,
        )
        return elapsed_ms

    def scan_summary(self, summary: dict[str, Any]) -> None:
        """Emit the final structured scan summary object."""
        self.info(
            "Scan complete",
            **{k: v for k, v in summary.items() if k != "message"},
        )
        # Also emit as a standalone JSON line for machine parsing
        self._logger.info(json.dumps(summary, default=str))


def build_scan_summary(
    scan_id: str,
    target: str,
    started_at: str,
    duration_seconds: float,
    modules_run: int,
    modules_failed: int,
    modules_degraded: int,
    findings_total: int,
    findings_by_severity: dict[str, int],
    score: int,
    circuit_breakers_opened: list[str],
    cache_hit_rate: float,
) -> dict[str, Any]:
    """Build the structured scan summary dict."""
    return {
        "scan_id": scan_id,
        "target": target,
        "started_at": started_at,
        "duration_seconds": round(duration_seconds, 1),
        "modules_run": modules_run,
        "modules_failed": modules_failed,
        "modules_degraded": modules_degraded,
        "findings_total": findings_total,
        "findings_by_severity": findings_by_severity,
        "score": score,
        "circuit_breakers_opened": circuit_breakers_opened,
        "cache_hit_rate": round(cache_hit_rate, 3),
    }
