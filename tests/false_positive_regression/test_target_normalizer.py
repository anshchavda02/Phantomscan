"""Tests for target normalization and local target detection."""
from __future__ import annotations

from phantomscan.scope import normalize_target, parse_target


def test_localhost_web_root():
    target = normalize_target("localhost:3000")
    assert target.web_root == "http://localhost:3000"
    assert target.host == "localhost"
    assert target.port == 3000
    assert target.scheme == "http"


def test_localhost_3000_web_root():
    target = normalize_target("http://localhost:3000")
    assert target.web_root == "http://localhost:3000"
    assert target.host == "localhost"
    assert target.port == 3000
    assert target.scheme == "http"


def test_localhost_is_local():
    assert normalize_target("localhost:3000").is_local is True
    assert normalize_target("127.0.0.1:8080").is_local is True
    assert normalize_target("http://127.0.0.1").is_local is True
    assert normalize_target("localhost").is_local is True


def test_google_not_local():
    target = normalize_target("google.com")
    assert target.is_local is False
    assert target.web_root == "https://google.com"
    assert target.port == 443
    assert target.scheme == "https"


def test_private_ips_are_local():
    assert normalize_target("10.0.0.1").is_local is True
    assert normalize_target("192.168.1.50:8080").is_local is True
    assert normalize_target("172.16.0.5").is_local is True
    assert normalize_target("172.31.255.254").is_local is True
    assert normalize_target("app.local:5000").is_local is True
    assert normalize_target("service.internal").is_local is True
    assert normalize_target("8.8.8.8").is_local is False
