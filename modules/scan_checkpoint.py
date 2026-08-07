"""Scan checkpointing and resume support.

Persists scan progress to SQLite after every tier completes so a
crashed or interrupted scan (Ctrl+C, OOM kill, network drop) can
resume from the last completed tier instead of restarting from zero.
"""

from __future__ import annotations

import hashlib
import json
import logging
import signal
import sqlite3
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)


_CHECKPOINT_TABLE_DDL = """
CREATE TABLE IF NOT EXISTS checkpoints (
    scan_id         TEXT PRIMARY KEY,
    target          TEXT NOT NULL,
    profile         TEXT NOT NULL,
    completed_tiers TEXT NOT NULL,
    findings_json   TEXT NOT NULL,
    context_json    TEXT NOT NULL,
    updated_at      TEXT NOT NULL,
    checksum        TEXT NOT NULL
);
"""


@dataclass
class CheckpointData:
    """Deserialized checkpoint state."""

    scan_id: str
    target: str
    profile: str
    completed_tiers: list[int]
    findings: list[dict[str, Any]]
    context_state: dict[str, Any]
    updated_at: str = ""
    checksum: str = ""


class ScanCheckpoint:
    """Persist and restore scan state to/from SQLite.

    Wire into the scheduler — call :meth:`save` after every tier
    completes. Register :meth:`install_signal_handlers` at scan start
    for graceful Ctrl+C handling.
    """

    def __init__(self, db_path: Path) -> None:
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(db_path))
        self._conn.row_factory = sqlite3.Row
        self._conn.execute(_CHECKPOINT_TABLE_DDL)
        self._conn.commit()
        self._pending_save: Optional[dict[str, Any]] = None

    @staticmethod
    def generate_scan_id(target: str, profile: str) -> str:
        """Generate a deterministic scan ID for resume matching."""
        raw = f"{target}:{profile}:{datetime.now(timezone.utc).strftime('%Y%m%d')}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def _compute_checksum(self, data: str) -> str:
        return hashlib.sha256(data.encode()).hexdigest()[:32]

    def save(
        self,
        scan_id: str,
        target: str,
        profile: str,
        completed_tiers: list[int],
        findings: list[dict[str, Any]],
        context_state: dict[str, Any],
    ) -> None:
        """Save a checkpoint synchronously (safe for signal handlers)."""
        now = datetime.now(timezone.utc).isoformat()
        findings_json = json.dumps(findings, default=str)
        context_json = json.dumps(context_state, default=str)
        combined = findings_json + context_json
        checksum = self._compute_checksum(combined)

        self._conn.execute(
            """INSERT OR REPLACE INTO checkpoints
               (scan_id, target, profile, completed_tiers, findings_json,
                context_json, updated_at, checksum)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                scan_id,
                target,
                profile,
                json.dumps(completed_tiers),
                findings_json,
                context_json,
                now,
                checksum,
            ),
        )
        self._conn.commit()
        logger.debug(
            "Checkpoint saved: scan_id=%s, tiers=%s",
            scan_id,
            completed_tiers,
        )

    def load(self, scan_id: str) -> Optional[CheckpointData]:
        """Load a checkpoint, returning None if not found or corrupted."""
        row = self._conn.execute(
            "SELECT * FROM checkpoints WHERE scan_id = ?", (scan_id,)
        ).fetchone()
        if not row:
            return None

        # Validate integrity
        findings_json = row["findings_json"]
        context_json = row["context_json"]
        stored_checksum = row["checksum"]
        computed = self._compute_checksum(findings_json + context_json)

        if computed != stored_checksum:
            logger.warning(
                "Checkpoint %s failed integrity check — discarding",
                scan_id,
            )
            self.delete(scan_id)
            return None

        try:
            return CheckpointData(
                scan_id=row["scan_id"],
                target=row["target"],
                profile=row["profile"],
                completed_tiers=json.loads(row["completed_tiers"]),
                findings=json.loads(findings_json),
                context_state=json.loads(context_json),
                updated_at=row["updated_at"],
                checksum=stored_checksum,
            )
        except (json.JSONDecodeError, KeyError) as exc:
            logger.warning(
                "Checkpoint %s is corrupted: %s — discarding",
                scan_id,
                exc,
            )
            self.delete(scan_id)
            return None

    def delete(self, scan_id: str) -> None:
        """Remove a checkpoint after successful scan completion."""
        self._conn.execute(
            "DELETE FROM checkpoints WHERE scan_id = ?", (scan_id,)
        )
        self._conn.commit()

    def list_checkpoints(self) -> list[dict[str, Any]]:
        """Return metadata for all stored checkpoints."""
        rows = self._conn.execute(
            "SELECT scan_id, target, profile, completed_tiers, updated_at "
            "FROM checkpoints ORDER BY updated_at DESC"
        ).fetchall()
        return [dict(r) for r in rows]

    def install_signal_handlers(
        self,
        scan_id: str,
        target: str,
        profile: str,
        get_state_fn: Any,
    ) -> None:
        """Register SIGINT/SIGTERM handlers for emergency checkpoint save.

        ``get_state_fn`` must return ``(completed_tiers, findings, context)``
        when called.
        """

        def _handler(signum: int, frame: Any) -> None:
            sig_name = signal.Signals(signum).name
            logger.info(
                "Received %s — saving emergency checkpoint for %s",
                sig_name,
                scan_id,
            )
            try:
                tiers, findings, ctx = get_state_fn()
                self.save(scan_id, target, profile, tiers, findings, ctx)
                logger.info("Emergency checkpoint saved successfully")
            except Exception as exc:
                logger.error("Emergency checkpoint save failed: %s", exc)
            raise SystemExit(128 + signum)

        signal.signal(signal.SIGINT, _handler)
        if hasattr(signal, "SIGTERM"):
            signal.signal(signal.SIGTERM, _handler)

    def close(self) -> None:
        """Close the SQLite connection."""
        self._conn.close()
