"""ASP.NET / Framework catch-all route detection."""
from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


@dataclass
class CatchAllResult:
    has_catch_all: bool = False
    baseline_body_length: int = 0
    note: str = ""


class CatchAllDetector:
    def __init__(self, http_client: Any = None) -> None:
        self.http = http_client

    async def detect(self, web_root: str) -> CatchAllResult:
        """Test if the server returns 200 for a path that definitely doesn't exist (randomly generated).
        If yes, it uses catch-all routing and every 200 response must be body-verified before
        any finding is created.
        """
        parsed = urlparse(web_root)
        if parsed.scheme and parsed.netloc:
            root = f"{parsed.scheme}://{parsed.netloc}"
        else:
            root = web_root.rstrip("/")

        test_path = f"/{uuid.uuid4().hex}"
        test_url = root.rstrip("/") + test_path

        client = self.http
        should_close = False
        if client is None:
            from phantomscan.http_client import RobustHTTPClient
            client = RobustHTTPClient()
            await client.start()
            should_close = True

        try:
            response = await client.get(
                test_url,
                allow_redirects=False,
                timeout=8,
            )

            status = getattr(response, "status", getattr(response, "status_code", 0))
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

                # Confirm it's actually a page not just empty 200
                if len(body) > 100:
                    return CatchAllResult(
                        has_catch_all=True,
                        baseline_body_length=len(body),
                        note=(
                            f"Server returned HTTP 200 for random path {test_path} "
                            f"({len(body)} bytes). Framework catch-all routing "
                            f"detected (ASP.NET, Laravel, Rails custom 404 etc.) — "
                            f"applying strict body verification to ALL sensitive path probes."
                        ),
                    )
        except Exception as e:
            logger.debug("Catch-all test error: %s", e)
        finally:
            if should_close and client:
                await client.close()

        return CatchAllResult(has_catch_all=False)
