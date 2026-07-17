"""SQLite persistence layer."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any


SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL,
    profile TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    score INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    finding_id TEXT NOT NULL,
    severity TEXT NOT NULL,
    payload TEXT NOT NULL,
    FOREIGN KEY(scan_id) REFERENCES scans(id)
);
CREATE TABLE IF NOT EXISTS cache (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    expires_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS engine_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    engine TEXT NOT NULL,
    status TEXT NOT NULL,
    payload TEXT NOT NULL,
    FOREIGN KEY(scan_id) REFERENCES scans(id)
);
"""


class Database:
    """Small SQLite wrapper using parameterized statements."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path)
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    def create_scan(self, target: str, profile: str, started_at: str) -> int:
        """Create a scan row and return its id."""
        cur = self.conn.execute(
            "INSERT INTO scans(target, profile, started_at) VALUES (?, ?, ?)",
            (target, profile, started_at),
        )
        self.conn.commit()
        return int(cur.lastrowid)

    def save_finding(self, scan_id: int, finding: dict[str, Any]) -> None:
        """Persist one finding."""
        self.conn.execute(
            "INSERT INTO findings(scan_id, finding_id, severity, payload) VALUES (?, ?, ?, ?)",
            (scan_id, finding["id"], finding["severity"], json.dumps(finding, sort_keys=True)),
        )
        self.conn.commit()

    def save_engine_run(self, scan_id: int, engine: str, status: str, payload: dict[str, Any]) -> None:
        """Persist one engine result."""
        self.conn.execute(
            "INSERT INTO engine_runs(scan_id, engine, status, payload) VALUES (?, ?, ?, ?)",
            (scan_id, engine, status, json.dumps(payload, sort_keys=True)),
        )
        self.conn.commit()

    def finish_scan(self, scan_id: int, finished_at: str, score: int) -> None:
        """Mark a scan complete."""
        self.conn.execute(
            "UPDATE scans SET finished_at = ?, score = ? WHERE id = ?",
            (finished_at, score, scan_id),
        )
        self.conn.commit()

    def close(self) -> None:
        """Close the SQLite connection."""
        self.conn.close()
