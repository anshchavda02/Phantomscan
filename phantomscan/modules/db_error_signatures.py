"""Curated vendor-exact database error signature patterns.

Every pattern here is specific enough that it could only reasonably appear in
an actual database error message — never generic words like "sql" or "database"
alone.  Used by :class:`SQLiDetector` to confirm error-based SQL injection.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class ErrorMatch:
    """A confirmed database error signature match."""

    db_type: str
    signature: str          # the regex pattern that matched
    matched_text: str       # the actual text fragment found


# ── Vendor-exact error signatures ─────────────────────────────────────────────
# Each pattern MUST be highly specific to its database engine.  Generic
# substrings like "sql", "error", "database", "syntax error" are FORBIDDEN
# because they appear in WAF block pages, blog posts, and framework debug
# pages that are unrelated to real injection.

SIGNATURES: list[dict[str, object]] = [
    {
        "db_type": "MySQL",
        "patterns": [
            r"SQL syntax.*?MySQL",
            r"Warning.*?\Wmysqli?_",
            r"MySQLSyntaxErrorException",
            r"valid MySQL result",
            r"check the manual that corresponds to your (MySQL|MariaDB) server version",
        ],
    },
    {
        "db_type": "PostgreSQL",
        "patterns": [
            r"PostgreSQL.*?ERROR",
            r"Warning.*?\Wpg_",
            r"valid PostgreSQL result",
            r"Npgsql\.",
            r"PG::SyntaxError",
            r"org\.postgresql\.util\.PSQLException",
        ],
    },
    {
        "db_type": "MSSQL",
        "patterns": [
            r"Driver.*? SQL[\-\_\ ]*Server",
            r"OLE DB.*? SQL Server",
            r"\bSQL Server[^&]+Driver",
            r"Warning.*?\Wmssql_",
            r"System\.Data\.SqlClient\.SqlException",
            r"Unclosed quotation mark after the character string",
            r"Microsoft OLE DB Provider for ODBC Drivers",
        ],
    },
    {
        "db_type": "Oracle",
        "patterns": [
            r"\bORA-[0-9]{4,5}",
            r"Oracle error",
            r"Oracle.*?Driver",
            r"Warning.*?\Woci_",
            r"quoted string not properly terminated",
        ],
    },
    {
        "db_type": "SQLite",
        "patterns": [
            r"SQLite/JDBCDriver",
            r"SQLite\.Exception",
            r"System\.Data\.SQLite\.SQLiteException",
            r"Warning.*?\Wsqlite_",
            r"\[SQLITE_ERROR\]",
            r"sqlite3\.OperationalError",
            r"SequelizeDatabaseError",
            r"SQLITE_ERROR: unrecognized token",
            r"SQLITE_ERROR: near \".*?\": syntax error",
        ],
    },
    {
        "db_type": "MongoDB",
        "patterns": [
            r"MongoError",
            r"MongoServerError",
            r"CastError: Cast to ObjectId failed",
        ],
    },
]

# Pre-compile for performance
_COMPILED: list[tuple[str, re.Pattern[str]]] = []
for _db in SIGNATURES:
    _db_type = str(_db["db_type"])
    for _raw in _db["patterns"]:  # type: ignore[union-attr]
        _COMPILED.append((_db_type, re.compile(str(_raw), re.IGNORECASE)))


def find_signature(body: str) -> Optional[ErrorMatch]:
    """Scan *body* for a vendor-exact database error signature.

    Returns the first :class:`ErrorMatch` found, or ``None`` if no
    vendor-specific error pattern is present.
    """
    for db_type, pattern in _COMPILED:
        match = pattern.search(body)
        if match:
            return ErrorMatch(
                db_type=db_type,
                signature=pattern.pattern,
                matched_text=match.group(0),
            )
    return None
