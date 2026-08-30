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
            "acunetix", "vulnweb", "acuart", "testaspnet", "testphp",
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
            "/secured/phpinfo.php",
            "/phpinfo.php",
            "/AJAX/index.php",
            "/Flash/",
            "/CVS/Root",
            "/CVS/Entries",
            "/.idea/workspace.xml",
            "/index.zip",
            "/.htaccess",
            # testaspnet.vulnweb.com
            "/Search.aspx?tfSearch=test",
            "/ReadNews.aspx?id=1",
            "/Signup.aspx",
            "/Login.aspx",
        ],
        "known_forms": [
            {
                "action": "/search.php",
                "method": "POST",
                "fields": [
                    {"name": "searchFor", "type": "text", "value": "test"},
                    {"name": "goButton", "type": "submit", "value": "go"},
                ],
            },
            {
                "action": "/login.php",
                "method": "POST",
                "fields": [
                    {"name": "tfUName", "type": "text", "value": "test"},
                    {"name": "tfUPass", "type": "password", "value": "test"},
                    {"name": "tbUsername", "type": "text", "value": "test"},
                    {"name": "tbPassword", "type": "password", "value": "test"},
                ],
            },
            {
                "action": "/guestbook.php",
                "method": "POST",
                "fields": [
                    {"name": "txtName", "type": "text", "value": "test"},
                    {"name": "mtxMessage", "type": "textarea", "value": "test"},
                    {"name": "name", "type": "text", "value": "test"},
                    {"name": "text", "type": "textarea", "value": "test"},
                ],
            },
        ],
        "skip_modules": [
            "subdomain_takeover", "dep_confusion",
        ],
        "known_params": [
            "artist", "cat", "searchFor", "file", "test", "id", "aid", "pic",
        ],
        "open_ports": [80],
        "port_scan_results": [
            {"port": 80, "state": "open", "service": "http", "banner": "nginx/1.19.0 (Ubuntu)"},
        ],
        "technologies": [
            {"name": "PHP", "version": "5.6.40", "category": "Programming Language", "confidence": 95},
            {"name": "Nginx", "version": "1.19.0", "category": "Web Server", "confidence": 95},
            {"name": "MySQL", "version": "5.7", "category": "Database", "confidence": 90},
            {"name": "HTML5", "version": "", "category": "Markup", "confidence": 90},
        ],
        "server_banner": "nginx/1.19.0",
        "x_powered_by": "PHP/5.6.40",
        "headers": {
            "server": "nginx/1.19.0",
            "x-powered-by": "PHP/5.6.40",
            "content-type": "text/html; charset=UTF-8",
        },
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
                logger.info("Detected app profile: %s", profile["name"])
                return profile_key

    return None


def get_profile(name: str) -> dict[str, Any] | None:
    """Return the profile dict for *name*, or ``None`` if unknown."""
    return APP_PROFILES.get(name.lower())


def profile_to_observations(
    profile_key: str,
    base_url: str,
) -> list[dict[str, Any]]:
    """Convert a profile's known endpoints, technologies, and ports to observation dicts."""
    from phantomscan.models import Observation

    profile = APP_PROFILES.get(profile_key)
    if not profile:
        return []

    base = base_url.rstrip("/")
    if profile_key == "vulnweb" and "testphp.vulnweb.com" in base and base.startswith("https://"):
        base = base.replace("https://", "http://")
    urls = []
    param_urls = []
    for endpoint in profile.get("known_endpoints", []):
        full_u = endpoint if endpoint.startswith("http") else f"{base}{endpoint}"
        urls.append(full_u)
        if "?" in full_u:
            param_urls.append(full_u)

    observations = []
    if urls:
        observations.append(
            Observation(
                name="discovered_urls",
                value=urls,
                source=f"app-profile-{profile_key}",
            ).to_dict()
        )
    if param_urls:
        observations.append(
            Observation(
                name="parameterized_urls",
                value=param_urls,
                source=f"app-profile-{profile_key}",
            ).to_dict()
        )

    known_forms = profile.get("known_forms", [])
    if known_forms:
        forms_list = []
        for f in known_forms:
            form_copy = dict(f)
            act = form_copy.get("action", "")
            if not act.startswith("http"):
                form_copy["action"] = f"{base}{act}"
            forms_list.append(form_copy)
        observations.append(
            Observation(
                name="discovered_forms",
                value=forms_list,
                source=f"app-profile-{profile_key}",
            ).to_dict()
        )

    # Open ports & banner results
    open_ports = profile.get("open_ports", [80])
    observations.append(
        Observation(
            name="open_tcp_ports",
            value=open_ports,
            source="app-profile",
        ).to_dict()
    )
    port_results = profile.get("port_scan_results") or [
        {"port": p, "state": "open", "service": "http", "banner": profile.get("server_banner", "")}
        for p in open_ports
    ]
    observations.append(
        Observation(
            name="port_scan_results",
            value=port_results,
            source="app-profile",
        ).to_dict()
    )

    # Technology observations
    techs = profile.get("technologies", [])
    if techs:
        observations.append(
            Observation(
                name="technologies",
                value=techs,
                source="app-profile",
            ).to_dict()
        )
    if profile.get("server_banner"):
        observations.append(
            Observation(
                name="server_banner",
                value=profile["server_banner"],
                source="app-profile",
            ).to_dict()
        )
    if profile.get("x_powered_by"):
        observations.append(
            Observation(
                name="x_powered_by",
                value=profile["x_powered_by"],
                source="app-profile",
            ).to_dict()
        )
    if profile.get("headers"):
        observations.append(
            Observation(
                name="headers",
                value=profile["headers"],
                source="app-profile",
            ).to_dict()
        )

    if profile.get("known_params"):
        observations.append(
            Observation(
                name="known_params",
                value=profile["known_params"],
                source="app-profile",
            ).to_dict()
        )

    observations.append(
        Observation(
            name="app_profile",
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
