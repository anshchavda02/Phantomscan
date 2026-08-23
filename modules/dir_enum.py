"""Directory enumeration module with catch-all route protection."""
from __future__ import annotations

import logging
from typing import Any, Optional
from urllib.parse import urlparse

from phantomscan.models import Finding
from modules.catch_all_detector import CatchAllDetector, CatchAllResult
from modules.response_validator import ResponseContentValidator

logger = logging.getLogger(__name__)


class DirectoryEnumerator:
    def __init__(self, http_client: Any = None) -> None:
        self.http = http_client

    async def probe_directory(
        self,
        web_root: str,
        path: str,
        catch_all: Optional[CatchAllResult] = None,
    ) -> Optional[Finding]:
        parsed = urlparse(web_root)
        if parsed.scheme and parsed.netloc:
            root = f"{parsed.scheme}://{parsed.netloc}"
        else:
            root = web_root.rstrip("/")

        probe_url = root.rstrip("/") + ("/" + path.lstrip("/"))
        client = self.http
        should_close = False
        if client is None:
            from phantomscan.http_client import RobustHTTPClient
            client = RobustHTTPClient()
            await client.start()
            should_close = True

        if catch_all is None:
            detector = CatchAllDetector(http_client=client)
            catch_all = await detector.detect(root)

        try:
            response = await client.get(probe_url, allow_redirects=False, timeout=8)
            status = getattr(response, "status", getattr(response, "status_code", 0))

            if status not in [200, 301, 302, 403]:
                return None

            if status in [301, 302]:
                headers = getattr(response, "headers", {})
                location = ""
                if isinstance(headers, dict):
                    location = headers.get("location", headers.get("Location", ""))
                if location == probe_url.rstrip("/") + "/":
                    # Just a trailing-slash redirect — normal
                    return None

            if status == 200:
                if hasattr(response, "text"):
                    if callable(response.text):
                        body = response.text()
                    else:
                        body = str(response.text)
                elif hasattr(response, "body"):
                    if isinstance(response.body, bytes):
                        body = response.body.decode("utf-8", errors="ignore")
                    else:
                        body = str(response.body)
                else:
                    body = str(response)

                headers = getattr(response, "headers", {})
                ct = ""
                if isinstance(headers, dict):
                    ct = headers.get("content-type", headers.get("Content-Type", "")).lower()

                # Reject if looks like HTML catch-all
                if ResponseContentValidator.is_html_page(body, ct):
                    logger.debug(
                        "Suppressed directory enumeration false positive: %s returned HTML (catch-all routing)",
                        probe_url,
                    )
                    return None

                # Reject if same size as catch-all baseline
                if catch_all.has_catch_all and ResponseContentValidator.is_catch_all_response(
                    body, catch_all.baseline_body_length
                ):
                    logger.debug("Suppressed: %s body length matches catch-all baseline", probe_url)
                    return None

            return Finding(
                id=f"DIR-ENUM-{path.replace('/', '-').strip('-').upper()}",
                title=f"Directory Accessible: {path}",
                severity="low",
                confidence="medium",
                category="web",
                target=probe_url,
                evidence=f"GET {probe_url} → HTTP {status}",
                recommendation=f"Restrict directory browsing for {path} if not intended for public access.",
                verification_method="baseline_differential",
                cwe="CWE-538",
            )
        except Exception as e:
            logger.debug("Directory probe failed for %s: %s", probe_url, e)
            return None
        finally:
            if should_close and client:
                await client.close()
