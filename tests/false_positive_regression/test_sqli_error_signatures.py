"""Regression: DB error signatures must be vendor-exact, not generic."""

from __future__ import annotations

import pytest

from phantomscan.modules.db_error_signatures import find_signature


def test_generic_sql_word_not_matched():
    """The word 'sql' alone must NEVER match as a DB error signature."""
    assert find_signature("This page explains SQL basics") is None


def test_generic_error_not_matched():
    """Generic 'error' or 'syntax error' alone must not match."""
    assert find_signature("There was an error processing your request") is None
    assert find_signature("Syntax error in configuration file") is None


def test_generic_database_error_not_matched():
    """The phrase 'database error' alone must not match."""
    assert find_signature("A database error has occurred") is None


def test_mysql_vendor_exact_matches():
    """MySQL vendor-specific patterns must match correctly."""
    match = find_signature(
        "You have an error in your SQL syntax; check the manual that "
        "corresponds to your MySQL server version"
    )
    assert match is not None
    assert match.db_type == "MySQL"


def test_postgresql_vendor_exact_matches():
    """PostgreSQL vendor-specific patterns must match."""
    match = find_signature("PostgreSQL query failed: ERROR: syntax error at or near")
    assert match is not None
    assert match.db_type == "PostgreSQL"


def test_mssql_vendor_exact_matches():
    """MSSQL vendor-specific patterns must match."""
    match = find_signature(
        "Unclosed quotation mark after the character string 'test"
    )
    assert match is not None
    assert match.db_type == "MSSQL"


def test_oracle_vendor_exact_matches():
    """Oracle vendor-specific patterns must match."""
    match = find_signature("ORA-01756: quoted string not properly terminated")
    assert match is not None
    assert match.db_type == "Oracle"


def test_sqlite_vendor_exact_matches():
    """SQLite vendor-specific patterns must match."""
    match = find_signature("sqlite3.OperationalError: near \"'\": syntax error")
    assert match is not None
    assert match.db_type == "SQLite"


def test_waf_block_mentioning_sql_not_matched():
    """A WAF block page that mentions 'SQL' defensively must not match any
    DB error signature — it uses generic phrasing, not vendor-exact."""
    body = (
        "Access Denied - Malicious SQL pattern detected by security policy. "
        "Your request has been blocked."
    )
    assert find_signature(body) is None


def test_error_in_your_query_not_matched():
    """'error in your query' alone is too generic and must not match."""
    assert find_signature("There was an error in your query parameters") is None
