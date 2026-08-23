"""Extractor Engine for pulling dynamic variables out of HTTP responses."""
from __future__ import annotations

import json
import re
from typing import Any


class ExtractorEngine:
    """Extracts named variables from HTTP responses for multi-step template flows."""

    def _extract_part(self, response: Any, part: str) -> str:
        """Extract requested part of the response (body or header)."""
        part_clean = part.lower().strip()
        body_text = response.text() if hasattr(response, "text") and callable(response.text) else getattr(response, "body_text", "")
        if not body_text and hasattr(response, "body"):
            body_raw = response.body
            body_text = body_raw.decode("utf-8", errors="ignore") if isinstance(body_raw, bytes) else str(body_raw)

        headers_dict = getattr(response, "headers", {}) or {}
        headers_str = "\n".join(f"{k}: {v}" for k, v in headers_dict.items())

        if part_clean in ("header", "headers"):
            return headers_str
        return body_text

    def extract(self, response: Any, extractors: list[dict[str, Any]]) -> dict[str, str]:
        """Extract variables from response based on extractor definitions."""
        extracted: dict[str, str] = {}
        if not extractors:
            return extracted

        headers_dict = getattr(response, "headers", {}) or {}
        body_str = self._extract_part(response, "body")

        for ext in extractors:
            if not isinstance(ext, dict):
                continue
            name = ext.get("name")
            if not name:
                continue

            e_type = str(ext.get("type", "regex")).lower().strip()
            part = str(ext.get("part", "body"))
            target_text = self._extract_part(response, part)

            if e_type == "regex":
                regexes = ext.get("regex", [])
                if isinstance(regexes, str):
                    regexes = [regexes]
                group_idx = int(ext.get("group", 1))

                for pattern in regexes:
                    match = re.search(pattern, target_text)
                    if match:
                        try:
                            val = match.group(group_idx)
                            if val:
                                extracted[name] = str(val).strip()
                                break
                        except IndexError:
                            extracted[name] = str(match.group(0)).strip()
                            break

            elif e_type in ("kval", "header", "cookie"):
                key = ext.get("key", name)
                # Check headers (case-insensitive)
                for h_k, h_v in headers_dict.items():
                    if h_k.lower() == str(key).lower():
                        extracted[name] = str(h_v).strip()
                        break

            elif e_type == "json":
                json_key = ext.get("key") or ext.get("json") or name
                try:
                    data = json.loads(body_str)
                    if isinstance(data, dict) and json_key in data:
                        extracted[name] = str(data[json_key])
                except Exception:
                    pass

        return extracted

    @staticmethod
    def substitute_variables(text: str, variables: dict[str, str]) -> str:
        """Replace {{variable_name}} placeholders with their extracted values."""
        if not text or not variables:
            return text
        result = text
        for k, v in variables.items():
            result = result.replace(f"{{{{{k}}}}}", str(v))
        return result
