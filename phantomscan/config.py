"""Configuration loader for PhantomScan."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any
import yaml

logger = logging.getLogger(__name__)

DEFAULT_CONFIG: dict[str, Any] = {
    "app": {
        "name": "PhantomScan",
        "version": "2.2.0",
        "tagline": "Scan Smart. Stay Secure.",
        "authorization_warning": True,
    },
    "scan": {
        "default_profile": "quick",
        "timeout_seconds": 8,
        "max_redirects": 5,
        "user_agent": "PhantomScan/2.2.0 authorized-security-assessment",
        "enforce_scope": True,
        "collect_evidence": False,
    },
    "ports": {
        "quick": "top100",
        "full": "top1000",
        "deep": "top1000",
        "deepscan": "top1000",
        "owasp": "top100",
        "api": "top100",
        "bug-bounty": "top1000",
        "network": "top1000",
        "custom": "",
    },
    "network": {
        "resolvers": ["8.8.8.8", "1.1.1.1", "9.9.9.9"],
        "allow_private_targets": True,
        "cidr_live_host_limit": 256,
    },
    "engines": {
        "go": {
            "path": "engines/go/bin/phantomscan-go",
            "enabled": True,
        },
        "rust": {
            "path": "engines/rust/target/release/phantomscan-rust",
            "enabled": True,
        },
        "node": {
            "path": "engines/node/browser_engine.js",
            "enabled": True,
        },
    },
    "performance": {
        "max_concurrent_modules_per_tier": 10,
        "time_budget_seconds": None,
        "cache_ttl": {
            "dns": 300,
            "ip_intel": 3600,
            "whois": 86400,
            "cve": 86400,
            "crtsh": 3600,
        },
    },
    "reliability": {
        "circuit_breaker": {
            "failure_threshold": 3,
            "recovery_timeout_seconds": 60,
        },
        "checkpoint_interval_seconds": 30,
        "max_memory_mb": 2048,
        "max_concurrent_scans": 5,
        "retry_max_attempts": 3,
    },
    "timeouts": {
        "http_request": 15,
        "http_connect": 8,
        "port_scan_per_port": 5,
        "ssl_handshake": 12,
        "dns_resolution": 5,
        "whois_lookup": 15,
        "crtsh_api": 30,
        "nvd_api": 15,
        "ip_api": 8,
        "browser_navigation": 30,
        "browser_network_idle": 10,
        "subprocess_go": 120,
        "subprocess_rust": 30,
        "oob_callback_wait": 15,
        "full_scan_budget": 600,
    },
}


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    merged = dict(base)
    for k, v in override.items():
        if k in merged and isinstance(merged[k], dict) and isinstance(v, dict):
            merged[k] = _deep_merge(merged[k], v)
        else:
            merged[k] = v
    return merged


def load_config(config_path: str | Path | None = None) -> dict[str, Any]:
    """Load configuration from config.yaml with fallback to defaults."""
    cfg = dict(DEFAULT_CONFIG)
    if config_path is None:
        candidate = Path("config.yaml")
        if candidate.exists():
            config_path = candidate
        else:
            parent_candidate = Path(__file__).resolve().parent.parent / "config.yaml"
            if parent_candidate.exists():
                config_path = parent_candidate

    if config_path:
        p = Path(config_path)
        if p.exists():
            try:
                with open(p, "r", encoding="utf-8") as f:
                    loaded = yaml.safe_load(f)
                    if isinstance(loaded, dict):
                        cfg = _deep_merge(cfg, loaded)
            except Exception as exc:
                logger.warning("Failed to parse config from %s: %s; using defaults", p, exc)
    return cfg
