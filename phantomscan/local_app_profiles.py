"""Local vulnerable application profiles for enhanced scanning.

Provides preconfigured profiles for popular vulnerable web applications
(OWASP Juice Shop, DVWA, WebGoat, etc.) that add known-vulnerable
endpoints to the crawl observations, skip irrelevant infrastructure
modules, and tune scanner parameters for the target's technology stack.
"""

from __future__ import annotations

import logging
import re
from typing import Any

logger = logging.getLogger(__name__)


# ── Application Profiles ─────────────────────────────────────────────────────

APP_PROFILES: dict[str, dict[str, Any]] = {
    "juiceshop": {
        "name": "OWASP Juice Shop",
        "is_spa": True,
        "default_port": 3000,
        "fingerprint_patterns": [
            "juice shop", "juice-shop", "OWASP Juice Shop",
        ],
        "known_endpoints": [
            "/rest/products/search?q=test",
            "/rest/user/login",
            "/rest/user/whoami",
            "/rest/user/change-password?current=test&new=test&repeat=test",
            "/rest/basket/1",
            "/rest/saveLoginIp",
            "/api/Users/",
            "/api/SecurityQuestions/",
            "/api/Feedbacks/",
            "/api/Complaints/",
            "/api/Challenges/",
            "/api/Quantitys/",
            "/api/Deliverys/",
            "/api/SecurityAnswers/",
            "/api/Recycles/",
            "/api/Cards/",
            "/api/Addresss/",
            "/b2b/v2/orders",
            "/ftp",
            "/encryptionkeys",
            "/snippets",
            "/promotion",
            "/file-upload",
            "/profile",
            "/redirect?to=https://owasp.org",
            "/#/search?q=test",
            "/#/login",
            "/#/register",
            "/#/basket",
        ],
        "skip_modules": [
            "subdomain_takeover", "dep_confusion", "cloud_metadata",
        ],
        "login_endpoint": "/rest/user/login",
        "login_body": {"email": "admin@juice-sh.op", "password": "admin123"},
    },
    "dvwa": {
        "name": "Damn Vulnerable Web Application",
        "is_spa": False,
        "default_port": 80,
        "fingerprint_patterns": [
            "DVWA", "Damn Vulnerable", "dvwa",
        ],
        "known_endpoints": [
            "/vulnerabilities/sqli/?id=1&Submit=Submit",
            "/vulnerabilities/sqli_blind/?id=1&Submit=Submit",
            "/vulnerabilities/xss_r/?name=test",
            "/vulnerabilities/xss_s/",
            "/vulnerabilities/fi/?page=include.php",
            "/vulnerabilities/upload/",
            "/vulnerabilities/exec/?ip=127.0.0.1&Submit=Submit",
            "/vulnerabilities/csrf/",
            "/vulnerabilities/brute/?username=admin&password=test&Login=Login",
            "/vulnerabilities/authbypass/",
            "/vulnerabilities/open_redirect/?redirect=https://owasp.org",
            "/setup.php",
            "/security.php",
        ],
        "skip_modules": [
            "subdomain_takeover", "dep_confusion", "cloud_metadata",
        ],
    },
    "webgoat": {
        "name": "WebGoat",
        "is_spa": True,
        "default_port": 8080,
        "fingerprint_patterns": [
            "WebGoat", "webgoat",
        ],
        "known_endpoints": [
            "/WebGoat/",
            "/WebGoat/login",
            "/WebGoat/register.mvc",
        ],
        "skip_modules": [
            "subdomain_takeover", "dep_confusion", "cloud_metadata",
        ],
    },
    "bwapp": {
        "name": "bWAPP",
        "is_spa": False,
        "default_port": 80,
        "fingerprint_patterns": [
            "bWAPP", "buggy web application",
        ],
        "known_endpoints": [
            "/sqli_1.php?title=test&action=search",
            "/xss_get.php?firstname=test&lastname=test&form=submit",
            "/rlfi.php?language=lang_en.php&action=go",
            "/traversal_1.php?page=message.txt",
        ],
        "skip_modules": [
            "subdomain_takeover", "dep_confusion", "cloud_metadata",
        ],
    },
    "vulnweb": {
        "name": "Acunetix Vulnweb",
        "is_spa": False,
        "default_port": 80,
        "fingerprint_patterns": [
            "acunetix", "vulnweb", "acuart", "testaspnet",
        ],
        "known_endpoints": [
            # testphp.vulnweb.com
            "/search.php?test=query",
            "/artists.php?artist=1",
            "/listproducts.php?cat=1",
            "/product.php?pic=1",
            "/showimage.php?file=./pictures/1.jpg",
            "/comment.php?aid=1",
            "/guestbook.php",
            "/cart.php",
            "/login.php",
            "/userinfo.php",
            "/AJAX/index.php",
            # testaspnet.vulnweb.com
            "/Search.aspx?tfSearch=test",
            "/ReadNews.aspx?id=1",
            "/Signup.aspx",
            "/Login.aspx",
        ],
        "skip_modules": [
            "subdomain_takeover", "dep_confusion",
        ],
    },
}


def detect_app_profile(
    body: str,
    headers: dict[str, str] | None = None,
    target_host: str = "",
) -> str | None:
    """Attempt to detect which vulnerable app profile matches.

    Returns the profile key (e.g., ``"juiceshop"``) or ``None``.
    """
    text = body.lower()
    host_lower = target_host.lower()

    for profile_key, profile in APP_PROFILES.items():
        for pattern in profile["fingerprint_patterns"]:
            if pattern.lower() in text or pattern.lower() in host_lower:
                logger.info("Detected local app profile: %s", profile["name"])
                return profile_key

    return None


def get_profile(name: str) -> dict[str, Any] | None:
    """Return the profile dict for *name*, or ``None`` if unknown."""
    return APP_PROFILES.get(name.lower())


def profile_to_observations(
    profile_key: str,
    base_url: str,
) -> list[dict[str, Any]]:
    """Convert a profile's known endpoints to observation dicts."""
    from phantomscan.models import Observation

    profile = APP_PROFILES.get(profile_key)
    if not profile:
        return []

    base = base_url.rstrip("/")
    urls = []
    for endpoint in profile.get("known_endpoints", []):
        if endpoint.startswith("http"):
            urls.append(endpoint)
        else:
            urls.append(f"{base}{endpoint}")

    observations = []
    if urls:
        observations.append(
            Observation(
                name="discovered_urls",
                value=urls,
                source=f"app-profile-{profile_key}",
            ).to_dict()
        )

    observations.append(
        Observation(
            name="local_app_profile",
            value={
                "name": profile["name"],
                "key": profile_key,
                "is_spa": profile.get("is_spa", False),
                "skip_modules": profile.get("skip_modules", []),
            },
            source="app-profile",
        ).to_dict()
    )

    return observations
