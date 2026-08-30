"""Smart proxy and routing detector for PhantomScan.

Automatically detects active local proxies (Burp Suite, OWASP ZAP, Fiddler, Clash,
V2Ray, Tor, Privoxy) or system/environment proxies, tests connectivity to the target,
and provides transparent rerouting when direct target connections are blocked or dropped
by firewalls/ISPs.
"""

from __future__ import annotations

import asyncio
import logging
import os
import socket
import urllib.request
from typing import Optional, Tuple
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# Common local proxy ports to probe if direct target connectivity fails
LOCAL_PROXY_CANDIDATES = [
    # Port, Scheme, Description
    (8080, "http", "Burp Suite / OWASP ZAP / mitmproxy"),
    (8888, "http", "Fiddler / Charles Proxy"),
    (7890, "http", "Clash / Sing-box HTTP Proxy"),
    (10808, "http", "v2rayN / Xray HTTP Proxy"),
    (10809, "http", "v2rayN / Xray SOCKS/HTTP Proxy"),
    (1080, "http", "Generic SOCKS/HTTP Proxy"),
    (1087, "http", "ShadowsocksX HTTP Proxy"),
    (8118, "http", "Privoxy (Tor HTTP Bridge)"),
    (9050, "http", "Tor SOCKS/HTTP Proxy"),
    (8000, "http", "Local Development Relay"),
    (3128, "http", "Squid Proxy"),
]


def check_port_open(host: str, port: int, timeout: float = 0.3) -> bool:
    """Quick non-blocking check if a local port is listening."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        s.close()
        return True
    except Exception:
        return False


def get_system_proxies() -> list[str]:
    """Retrieve proxies configured in the OS or environment."""
    candidates = []
    # 1. Environment variables
    for var in ("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"):
        val = os.environ.get(var)
        if val and val.strip():
            proxy = val.strip()
            if not proxy.startswith("http://") and not proxy.startswith("https://") and not proxy.startswith("socks5://"):
                proxy = f"http://{proxy}"
            if proxy not in candidates:
                candidates.append(proxy)

    # 2. System / OS registry proxies
    try:
        sys_proxies = urllib.request.getproxies()
        for k, v in sys_proxies.items():
            if v:
                proxy = v.strip()
                if not proxy.startswith("http://") and not proxy.startswith("https://") and not proxy.startswith("socks5://"):
                    proxy = f"http://{proxy}"
                if proxy not in candidates:
                    candidates.append(proxy)
    except Exception:
        pass

    return candidates


def probe_target_via_proxy(target_url: str, proxy_url: str, timeout: float = 3.5) -> bool:
    """Synchronously test if a candidate proxy can successfully reach the target URL."""
    try:
        proxy_handler = urllib.request.ProxyHandler({
            "http": proxy_url,
            "https": proxy_url,
        })
        opener = urllib.request.build_opener(proxy_handler)
        req = urllib.request.Request(
            target_url,
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Accept": "*/*",
            },
        )
        with opener.open(req, timeout=timeout) as resp:
            status = resp.status if hasattr(resp, "status") else resp.getcode()
            return status is not None and status > 0
    except Exception as exc:
        logger.debug("Probe to %s via %s failed: %s", target_url, proxy_url, exc)
        return False


async def async_probe_target_via_proxy(target_url: str, proxy_url: str, timeout: float = 3.5) -> bool:
    """Asynchronously test if a candidate proxy can reach the target."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, probe_target_via_proxy, target_url, proxy_url, timeout)


async def find_working_proxy(
    target_url: str,
    custom_candidates: list[str] | None = None,
    timeout: float = 3.0,
) -> Optional[Tuple[str, str]]:
    """Scan local ports and environment for active proxies and verify route to target.

    Returns:
        A tuple of (proxy_url, description) or None if no working proxy is found.
    """
    candidates_to_test: list[Tuple[str, str]] = []

    # 1. Custom / passed candidates
    if custom_candidates:
        for c in custom_candidates:
            if c:
                candidates_to_test.append((c, "User configured proxy"))

    # 2. System and environment proxies
    for sp in get_system_proxies():
        candidates_to_test.append((sp, "System/Environment proxy"))

    # 3. Check which local proxy ports are actually listening
    for port, scheme, desc in LOCAL_PROXY_CANDIDATES:
        if check_port_open("127.0.0.1", port, timeout=0.25):
            proxy_str = f"{scheme}://127.0.0.1:{port}"
            candidates_to_test.append((proxy_str, f"Local {desc} on port {port}"))

    if not candidates_to_test:
        return None

    # Test candidates
    for proxy_url, desc in candidates_to_test:
        logger.debug("Testing candidate proxy %s (%s) against %s...", proxy_url, desc, target_url)
        is_working = await async_probe_target_via_proxy(target_url, proxy_url, timeout=timeout)
        if is_working:
            logger.info("Found working proxy: %s (%s)", proxy_url, desc)
            return proxy_url, desc

    return None


async def auto_resolve_route(
    target_url: str,
    configured_proxy: str | None = None,
    profile: str = "quick",
    force_auto: bool = True,
) -> Tuple[Optional[str], str]:
    """Smart routing resolver for PhantomScan.

    Checks if direct connection to the target works. If it fails or if configured,
    automatically detects active local proxies/VPN tunnels and reroutes.

    Returns:
        Tuple of (effective_proxy_url, resolution_summary)
    """
    # If user explicitly supplied a proxy, test and use it
    if configured_proxy:
        return configured_proxy, f"Explicit proxy: {configured_proxy}"

    # Auto-detection is enabled for deep/deepscan profiles by default, or when force_auto=True
    is_deep_profile = profile in ("deep", "deepscan", "full", "advanced", "owasp", "bug-bounty")
    if not (force_auto or is_deep_profile):
        return None, "Direct connection (auto-proxy disabled)"

    # Look for working proxies
    working = await find_working_proxy(target_url)
    if working:
        proxy_url, desc = working
        return proxy_url, f"Auto-detected working route via {desc} ({proxy_url})"

    return None, "Direct connection (no active local proxy detected)"
