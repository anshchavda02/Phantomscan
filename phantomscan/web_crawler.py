"""Lightweight async web crawler for parameter and form discovery.

Discovers:
  - Links (``<a href>``) recursively up to configurable depth
  - HTML forms (action, method, input fields) including ASP.NET WebForms
  - URLs with query parameters (e.g., ``?artist=1&id=5``)
  - Common API paths (``/api/``, ``/rest/``, ``/graphql``, etc.)

The observations emitted by this module are consumed by injection scanners
(SQLi, XSS, path traversal) to know *what* to test.
"""

from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin, urlparse, parse_qs

from phantomscan.http_client import RobustHTTPClient, http_client
from phantomscan.models import Observation

logger = logging.getLogger(__name__)

# ── Data types ────────────────────────────────────────────────────────────────


@dataclass
class FormField:
    """A single form input field."""
    name: str
    field_type: str = "text"       # text | password | hidden | email | etc.
    default_value: str = ""


@dataclass
class DiscoveredForm:
    """An HTML form discovered during crawling."""
    action: str
    method: str = "GET"
    fields: list[FormField] = field(default_factory=list)

    @property
    def text_fields(self) -> list[FormField]:
        """Return fields suitable for injection testing."""
        injectable = {"text", "search", "email", "password", "tel", "url", "number", ""}
        return [f for f in self.fields if f.field_type.lower() in injectable and f.name]


@dataclass
class CrawlResult:
    """Aggregated results from a crawl session."""
    urls: list[str] = field(default_factory=list)
    forms: list[DiscoveredForm] = field(default_factory=list)
    api_endpoints: list[dict[str, Any]] = field(default_factory=list)
    parameterized_urls: list[str] = field(default_factory=list)


# ── Common API paths to probe ────────────────────────────────────────────────

_API_PATHS = [
    "/api/", "/api/v1/", "/api/v2/",
    "/api/users", "/api/products", "/api/orders",
    "/rest/", "/rest/products", "/rest/user",
    "/rest/basket", "/rest/user/login",
    "/graphql",
    "/v1/", "/v2/",
    "/swagger.json", "/openapi.json", "/api-docs",
    # Juice Shop specific
    "/api/SecurityQuestions/", "/api/Challenges/",
    "/api/Feedbacks/", "/api/Complaints/",
    "/api/Users/", "/rest/products/search?q=test",
    "/rest/user/whoami", "/rest/basket/1",
]


# ── Web Crawler ──────────────────────────────────────────────────────────────


class WebCrawler:
    """Async web crawler that discovers links, forms, and API endpoints."""

    def __init__(
        self,
        http: RobustHTTPClient,
        max_pages: int = 50,
        max_depth: int = 2,
    ) -> None:
        self.http = http
        self.max_pages = max_pages
        self.max_depth = max_depth
        self._visited: set[str] = set()

    async def crawl(self, base_url: str) -> CrawlResult:
        """Crawl *base_url* and return discovered links, forms, and APIs."""
        import aiohttp as _aiohttp

        result = CrawlResult()
        base = base_url.rstrip("/")
        parsed_base = urlparse(base)
        allowed_netloc = parsed_base.netloc.lower()

        # Phase 1: Recursive link + form discovery
        await self._crawl_page(base + "/", base, allowed_netloc, 0, result)

        # Phase 2: Probe common API paths
        api_results = await self._discover_api_endpoints(base)
        result.api_endpoints.extend(api_results)

        # Phase 3: Extract parameterized URLs
        for url in result.urls:
            parsed = urlparse(url)
            if parsed.query:
                result.parameterized_urls.append(url)

        logger.info(
            "Crawl complete: %d URLs, %d forms, %d API endpoints, %d parameterized",
            len(result.urls), len(result.forms),
            len(result.api_endpoints), len(result.parameterized_urls),
        )
        return result

    async def _crawl_page(
        self,
        url: str,
        base: str,
        allowed_netloc: str,
        depth: int,
        result: CrawlResult,
    ) -> None:
        """Fetch a page and extract links and forms."""
        if depth > self.max_depth:
            return
        if len(self._visited) >= self.max_pages:
            return

        # Normalize URL for dedup
        normalized = url.split("#")[0].rstrip("/")
        if normalized in self._visited:
            return
        self._visited.add(normalized)

        import aiohttp as _aiohttp
        try:
            resp = await self.http.get(
                url,
                retries=1,
                timeout=_aiohttp.ClientTimeout(total=5),
            )
        except Exception as exc:
            logger.debug("Crawl fetch failed %s: %s", url, exc)
            return

        if resp.status >= 400:
            return

        content_type = resp.content_type.lower() if resp.content_type else ""
        if "html" not in content_type and "text" not in content_type:
            return

        body = resp.text()
        result.urls.append(url)

        # Extract links
        links = self._extract_links(body, url, allowed_netloc)

        # Extract forms
        forms = self._extract_forms(body, url)
        result.forms.extend(forms)

        # Recurse into discovered links
        tasks = []
        for link in links:
            if len(self._visited) >= self.max_pages or len(tasks) >= 15:
                break
            link_norm = link.split("#")[0].rstrip("/")
            if link_norm not in self._visited:
                tasks.append(
                    self._crawl_page(link, base, allowed_netloc, depth + 1, result)
                )

        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    def _extract_links(self, body: str, current_url: str, allowed_netloc: str) -> list[str]:
        """Extract same-origin links from HTML body."""
        import html
        links: list[str] = []
        for match in re.finditer(r'<a\s[^>]*href=["\']([^"\'#][^"\']*)', body, re.I):
            href = html.unescape(match.group(1).strip())
            if href.startswith(("javascript:", "mailto:", "tel:", "data:")):
                continue

            full_url = urljoin(current_url, href)
            parsed = urlparse(full_url)

            # Only follow same-origin links
            if parsed.netloc.lower() != allowed_netloc:
                continue
            # Skip non-HTTP
            if parsed.scheme not in ("http", "https"):
                continue
            # Skip binary resources
            ext = parsed.path.rsplit(".", 1)[-1].lower() if "." in parsed.path else ""
            if ext in {"jpg", "jpeg", "png", "gif", "svg", "ico", "css", "js",
                       "woff", "woff2", "ttf", "eot", "pdf", "zip", "mp4", "mp3"}:
                continue

            links.append(full_url)

        return links

    def _extract_forms(self, body: str, page_url: str) -> list[DiscoveredForm]:
        """Extract HTML forms and their input fields."""
        import html
        forms: list[DiscoveredForm] = []

        for form_match in re.finditer(
            r"<form\s([^>]*?)>(.*?)</form>", body, re.I | re.S
        ):
            attrs = form_match.group(1)
            form_body = form_match.group(2)

            # Extract action
            action_match = re.search(r'action=["\']([^"\']*)', attrs, re.I)
            action = html.unescape(action_match.group(1).strip()) if action_match else ""
            if action:
                action = urljoin(page_url, action)
            else:
                action = page_url

            # Extract method
            method_match = re.search(r'method=["\']([^"\']*)', attrs, re.I)
            method = (method_match.group(1) if method_match else "GET").upper()

            # Extract input fields
            fields: list[FormField] = []
            for input_match in re.finditer(
                r"<(?:input|textarea|select)\s([^>]*?)/?>"  , form_body, re.I
            ):
                input_attrs = input_match.group(1)
                name_match = re.search(r'name=["\']([^"\']*)', input_attrs, re.I)
                type_match = re.search(r'type=["\']([^"\']*)', input_attrs, re.I)
                value_match = re.search(r'value=["\']([^"\']*)', input_attrs, re.I)

                if name_match:
                    fname = html.unescape(name_match.group(1).strip())
                    ftype = type_match.group(1).lower() if type_match else "text"
                    fvalue = html.unescape(value_match.group(1).strip()) if value_match else ""

                    # Skip submit/button/image types
                    if ftype in ("submit", "button", "image", "reset", "file"):
                        continue

                    fields.append(FormField(
                        name=fname,
                        field_type=ftype,
                        default_value=fvalue,
                    ))

            if fields:
                forms.append(DiscoveredForm(
                    action=action,
                    method=method,
                    fields=fields,
                ))

        return forms

    async def _discover_api_endpoints(self, base: str) -> list[dict[str, Any]]:
        """Probe common API paths and return those that respond with data."""
        found: list[dict[str, Any]] = []
        import aiohttp as _aiohttp

        sem = asyncio.Semaphore(15)

        async def probe(path: str) -> dict[str, Any] | None:
            url = base + path
            async with sem:
                try:
                    r = await self.http.get(
                        url,
                        retries=1,
                        timeout=_aiohttp.ClientTimeout(total=4),
                    )
                    ct = r.headers.get("content-type", "")
                    # Accept JSON, JavaScript, XML, and HTML responses with data
                    if r.status == 200 and (
                        "json" in ct or "javascript" in ct or "xml" in ct
                        or (r.status == 200 and len(r.body) > 50)
                    ):
                        return {
                            "url": url,
                            "status": r.status,
                            "content_type": ct,
                            "body_length": len(r.body),
                        }
                except Exception:
                    pass
            return None

        results = await asyncio.gather(
            *(probe(p) for p in _API_PATHS),
            return_exceptions=True,
        )
        for r in results:
            if isinstance(r, dict):
                found.append(r)

        return found

    def to_observations(self, result: CrawlResult, base_url: str) -> list[Observation]:
        """Convert crawl results into observations for the scan pipeline."""
        observations: list[Observation] = []

        # All discovered URLs (including parameterized)
        if result.urls:
            observations.append(
                Observation("discovered_urls", result.urls, "crawler")
            )

        # Parameterized URLs specifically (easier for injection modules)
        if result.parameterized_urls:
            observations.append(
                Observation("parameterized_urls", result.parameterized_urls, "crawler")
            )

        # Forms as serializable dicts
        if result.forms:
            form_dicts = []
            for form in result.forms:
                form_dicts.append({
                    "action": form.action,
                    "method": form.method,
                    "fields": [
                        {"name": f.name, "type": f.field_type, "value": f.default_value}
                        for f in form.fields
                    ],
                })
            observations.append(
                Observation("discovered_forms", form_dicts, "crawler")
            )

        # API endpoints
        if result.api_endpoints:
            observations.append(
                Observation("discovered_api_endpoints", result.api_endpoints, "crawler")
            )

        # Crawl summary
        observations.append(
            Observation("crawl_summary", {
                "total_urls": len(result.urls),
                "total_forms": len(result.forms),
                "total_api_endpoints": len(result.api_endpoints),
                "parameterized_urls": len(result.parameterized_urls),
            }, "crawler")
        )

        return observations
