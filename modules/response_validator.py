"""Response content validation utility."""
from __future__ import annotations

import re


class ResponseContentValidator:
    """Shared validator to confirm an HTTP 200 response actually contains the content type
    expected, rather than a framework catch-all HTML page.
    """

    @staticmethod
    def is_html_page(body: str, content_type: str = "") -> bool:
        """Returns True if the response is clearly an HTML page (login, error, or catch-all)."""
        if content_type and "text/html" in content_type.lower():
            return True
        html_markers = [
            "<!DOCTYPE", "<html", "<head>", "<body>",
            "<form", "<div", "<script>"
        ]
        sample = body[:1000].lower()
        marker_count = sum(
            1 for m in html_markers
            if m.lower() in sample
        )
        return marker_count >= 3

    @staticmethod
    def is_catch_all_response(body: str, catch_all_baseline_len: int) -> bool:
        """Returns True if response body length is suspiciously close to the known catch-all
        baseline length for this target.
        """
        if catch_all_baseline_len <= 0:
            return False
        ratio = len(body) / catch_all_baseline_len
        # Within 20% of baseline = probably catch-all
        return 0.8 <= ratio <= 1.2
