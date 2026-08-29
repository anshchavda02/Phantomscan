"""Unified Injection Target and Parameter Extraction Engine for PhantomScan.

Provides a structured representation of testable injection points across:
- GET query parameters (preserving all sibling parameters)
- POST form fields (preserving hidden fields, __VIEWSTATE, __EVENTVALIDATION, CSRF tokens)
- REST path and JSON API parameters
"""

from __future__ import annotations

from dataclasses import dataclass, field
import html
import logging
from typing import Any
from urllib.parse import parse_qs, urljoin, urlparse, urlunparse

logger = logging.getLogger(__name__)


@dataclass
class InjectionTarget:
    """Represents a discrete parameter or injection point on an endpoint."""

    url: str
    method: str = "GET"  # "GET" or "POST"
    param_name: str = ""
    original_value: str = ""
    all_params: dict[str, str] = field(default_factory=dict)
    hidden_fields: dict[str, str] = field(default_factory=dict)
    target_type: str = "query"  # "query", "form", "json"

    @property
    def key(self) -> str:
        """Unique deduplication key based on method, path, and parameter name."""
        parsed = urlparse(self.url)
        path = parsed.path.rstrip("/") or "/"
        return f"{self.method.upper()}:{parsed.netloc.lower()}{path}:{self.param_name}"


def extract_injection_targets(
    observations: list[dict[str, Any]],
    base_url: str,
    max_targets: int = 50,
) -> list[InjectionTarget]:
    """Extract structured injection targets from scan observations.

    Preserves:
    1. Sibling query parameters for multi-parameter GET requests
       (e.g., id=3 is preserved when testing NewsAd=ads/def.html).
    2. Hidden form tokens for POST requests (__VIEWSTATE, __EVENTVALIDATION, csrf tokens).
    3. Endpoint-level deduplication (testing 'id' on /ReadNews.aspx and /Comments.aspx independently).
    """
    targets: list[InjectionTarget] = []
    seen_keys: set[str] = set()

    clean_base = base_url.rstrip("/")

    def add_target(target: InjectionTarget) -> None:
        if not target.param_name:
            return
        # Clean parameter name from HTML entities
        clean_pname = target.param_name.strip()
        if clean_pname.startswith("amp;"):
            clean_pname = clean_pname.removeprefix("amp;")
        if not clean_pname or clean_pname.lower() in {
            "__viewstate",
            "__viewstategenerator",
            "__eventvalidation",
            "__eventtarget",
            "__eventargument",
        }:
            return

        target.param_name = clean_pname
        k = target.key
        if k not in seen_keys and len(targets) < max_targets:
            seen_keys.add(k)
            targets.append(target)

    # 1. Base URL direct query parameters
    if "?" in clean_base:
        parsed_base = urlparse(clean_base)
        clean_url = urlunparse(parsed_base._replace(query=""))
        qs = parse_qs(parsed_base.query, keep_blank_values=True)
        all_p = {k: v[0] if v else "" for k, v in qs.items()}
        for pname, pval in all_p.items():
            add_target(
                InjectionTarget(
                    url=clean_url,
                    method="GET",
                    param_name=pname,
                    original_value=pval or "test",
                    all_params=dict(all_p),
                    target_type="query",
                )
            )

    for obs in observations:
        name = str(obs.get("name", ""))
        val = obs.get("value", "")

        # 2. Parameterized and Discovered URLs from Crawler / HTTP headers
        if name in ("parameterized_urls", "discovered_urls", "http_url") and isinstance(
            val, (str, list)
        ):
            url_list = [val] if isinstance(val, str) else val
            for u in url_list:
                if isinstance(u, str) and u.startswith("http") and "?" in u:
                    parsed = urlparse(u)
                    clean_url = urlunparse(parsed._replace(query=""))
                    qs = parse_qs(parsed.query, keep_blank_values=True)
                    all_p = {k: v[0] if v else "" for k, v in qs.items()}
                    for pname, pval in all_p.items():
                        add_target(
                            InjectionTarget(
                                url=clean_url,
                                method="GET",
                                param_name=pname,
                                original_value=pval or "test",
                                all_params=dict(all_p),
                                target_type="query",
                            )
                        )

        # 3. Discovered Forms (GET & POST)
        if name == "discovered_forms" and isinstance(val, list):
            for form in val:
                if not isinstance(form, dict):
                    continue
                action = form.get("action", clean_base)
                if not action.startswith("http"):
                    action = urljoin(clean_base + "/", action)
                method = form.get("method", "POST").upper()
                fields = form.get("fields", [])

                all_inputs: dict[str, str] = {}
                hidden_fields: dict[str, str] = {}
                fuzzable_fields: list[tuple[str, str]] = []

                injectable_types = {
                    "text",
                    "search",
                    "email",
                    "password",
                    "number",
                    "tel",
                    "url",
                    "textarea",
                    "",
                }

                for fld in fields:
                    if isinstance(fld, dict):
                        fname = fld.get("name", "").strip()
                        ftype = fld.get("type", "text").lower()
                        fval = str(fld.get("value", ""))
                        if not fname:
                            continue

                        if ftype == "hidden":
                            hidden_fields[fname] = fval
                        elif ftype in injectable_types:
                            all_inputs[fname] = fval or "test"
                            fuzzable_fields.append((fname, fval))
                        else:
                            all_inputs[fname] = fval

                for fname, fval in fuzzable_fields:
                    add_target(
                        InjectionTarget(
                            url=action,
                            method=method,
                            param_name=fname,
                            original_value=fval or "test",
                            all_params=dict(all_inputs),
                            hidden_fields=dict(hidden_fields),
                            target_type="form",
                        )
                    )

        # 4. Discovered API Routes
        if "discovered_api_routes" in name and isinstance(val, list):
            for route in val:
                if isinstance(route, str) and not route.startswith("#"):
                    full_url = urljoin(clean_base + "/", route.lstrip("/"))
                    parsed = urlparse(full_url)
                    if any(
                        kw in parsed.path.lower()
                        for kw in [
                            "search",
                            "product",
                            "user",
                            "order",
                            "item",
                            "query",
                            "filter",
                            "comment",
                            "news",
                        ]
                    ):
                        for p in ("q", "search", "id", "query", "name"):
                            add_target(
                                InjectionTarget(
                                    url=full_url,
                                    method="GET",
                                    param_name=p,
                                    original_value="test",
                                    all_params={p: "test"},
                                    target_type="query",
                                )
                            )

    # 5. Fallback: If no parameters found at all, test base URL with common search params
    if not targets:
        for p in ("q", "search", "id", "query", "name"):
            add_target(
                InjectionTarget(
                    url=clean_base,
                    method="GET",
                    param_name=p,
                    original_value="test",
                    all_params={p: "test"},
                    target_type="query",
                )
            )

    return targets
