"""Two-tier scan cache: in-memory L1 + SQLite-backed L2.

Shared across all modules within a single scan AND across scans
within a TTL window.  Useful for ``--batch`` and daemon modes
scanning overlapping infrastructure (e.g. app.example.com and
api.example.com reuse the same root-domain WHOIS/DNS results).
"""

from __future__ import annotations

import json
import logging
import sqlite3
import time
from pathlib import Path
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)

# ── Default TTLs (seconds) ────────────────────────────────────────────────────

DEFAULT_TTLS: dict[str, int] = {
    "dns":        300,      # 5 min — DNS records change infrequently
    "ip_intel":   3600,     # 1 hr — IP geo changes rarely
    "whois":      86400,    # 24 hr — registration data changes very rarely
    "crtsh":      3600,     # 1 hr — CT log updates periodically
    "cve":        86400,    # 24 hr — NVD publishes daily
    "platform":   0,        # Never expires within a single process
}


class ScanCache:
    """Two-tier cache: L1 in-memory dict + L2 SQLite for cross-scan reuse.

    Args:
        db_path: Path to the SQLite database (created if missing).
        ttl_overrides: Per-category TTL overrides from config.yaml.
    """

    _CACHE_TABLE_DDL = """
    CREATE TABLE IF NOT EXISTS scan_cache (
        cache_key   TEXT PRIMARY KEY,
        value_json  TEXT NOT NULL,
        expires_at  REAL NOT NULL
    );
    """

    def __init__(
        self,
        db_path: Path,
        ttl_overrides: Optional[dict[str, int]] = None,
    ) -> None:
        self._memory: dict[str, Any] = {}
        self._ttls = {**DEFAULT_TTLS, **(ttl_overrides or {})}
        self._db_path = db_path
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(db_path))
        self._conn.execute(self._CACHE_TABLE_DDL)
        self._conn.commit()
        # Statistics
        self.hits: int = 0
        self.misses: int = 0

    @property
    def hit_rate(self) -> float:
        total = self.hits + self.misses
        return self.hits / total if total else 0.0

    def ttl_for(self, category: str) -> int:
        """Return the configured TTL for *category*, defaulting to 300s."""
        return self._ttls.get(category, 300)

    async def get_or_fetch(
        self,
        key: str,
        fetch_fn: Callable[..., Any],
        ttl_seconds: Optional[int] = None,
        category: str = "dns",
    ) -> Any:
        """Return cached value or invoke *fetch_fn* and cache the result.

        Lookup order:
          1. L1 — in-memory dict (same scan, zero latency)
          2. L2 — SQLite (cross-scan, avoids re-querying within TTL)
          3. Actually call *fetch_fn* and store at both tiers
        """
        # L1: in-memory
        if key in self._memory:
            self.hits += 1
            return self._memory[key]

        effective_ttl = ttl_seconds if ttl_seconds is not None else self.ttl_for(category)

        # L2: SQLite
        row = self._conn.execute(
            "SELECT value_json, expires_at FROM scan_cache WHERE cache_key = ?",
            (key,),
        ).fetchone()
        if row is not None:
            value_json, expires_at = row
            if expires_at == 0 or time.time() < expires_at:
                value = json.loads(value_json)
                self._memory[key] = value
                self.hits += 1
                return value
            else:
                # Expired — evict
                self._conn.execute(
                    "DELETE FROM scan_cache WHERE cache_key = ?", (key,)
                )
                self._conn.commit()

        # L3: actually fetch
        self.misses += 1
        value = await fetch_fn()

        # Store in both tiers
        self._memory[key] = value
        expires = 0.0 if effective_ttl == 0 else time.time() + effective_ttl
        try:
            self._conn.execute(
                "INSERT OR REPLACE INTO scan_cache (cache_key, value_json, expires_at) "
                "VALUES (?, ?, ?)",
                (key, json.dumps(value, default=str), expires),
            )
            self._conn.commit()
        except (sqlite3.OperationalError, TypeError) as exc:
            logger.debug("Cache write failed for key=%s: %s", key, exc)

        return value

    def put(self, key: str, value: Any, ttl_seconds: int = 300) -> None:
        """Directly insert a value into both cache tiers."""
        self._memory[key] = value
        expires = 0.0 if ttl_seconds == 0 else time.time() + ttl_seconds
        try:
            self._conn.execute(
                "INSERT OR REPLACE INTO scan_cache (cache_key, value_json, expires_at) "
                "VALUES (?, ?, ?)",
                (key, json.dumps(value, default=str), expires),
            )
            self._conn.commit()
        except (sqlite3.OperationalError, TypeError) as exc:
            logger.debug("Cache write failed for key=%s: %s", key, exc)

    def invalidate(self, key: str) -> None:
        """Remove *key* from both tiers."""
        self._memory.pop(key, None)
        self._conn.execute("DELETE FROM scan_cache WHERE cache_key = ?", (key,))
        self._conn.commit()

    def clear_expired(self) -> int:
        """Evict expired entries from SQLite and return count removed."""
        now = time.time()
        cursor = self._conn.execute(
            "DELETE FROM scan_cache WHERE expires_at > 0 AND expires_at < ?",
            (now,),
        )
        self._conn.commit()
        removed = cursor.rowcount
        # Also purge L1 (best-effort; L1 is checked lazily)
        stale_keys = [
            k for k in list(self._memory)
            if k not in {r[0] for r in self._conn.execute(
                "SELECT cache_key FROM scan_cache"
            ).fetchall()}
        ]
        for k in stale_keys:
            self._memory.pop(k, None)
        return removed

    def close(self) -> None:
        """Close the SQLite connection."""
        self._conn.close()
