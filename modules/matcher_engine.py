"""Matcher Engine for evaluating HTTP responses against template matchers."""
from __future__ import annotations

import re
import ast
from dataclasses import dataclass, field
from typing import Any, Callable, Optional


@dataclass
class MatchResult:
    matched: bool
    matched_matchers: list[str] = field(default_factory=list)
    evidence: str = ""


class SafeDSLEvaluator:
    """Safely evaluates simple Python-like DSL expressions."""

    @staticmethod
    def evaluate(expression: str, context: dict[str, Any]) -> bool:
        """Evaluate expression with limited safe globals/functions."""
        # Provide helper functions
        def contains(haystack: Any, needle: str) -> bool:
            return needle in str(haystack)

        def matches(text: Any, pattern: str) -> bool:
            return bool(re.search(pattern, str(text), re.IGNORECASE))

        safe_env = {
            "status": context.get("status", 0),
            "status_code": context.get("status", 0),
            "body": context.get("body", ""),
            "headers": context.get("headers", {}),
            "len": len,
            "contains": contains,
            "matches": matches,
            "True": True,
            "False": False,
        }

        # Normalize common operators from Nuclei DSL syntax if present
        normalized = expression.replace("&&", " and ").replace("||", " or ").replace("!", " not ")
        try:
            # Parse to AST to verify it's only expressions
            tree = ast.parse(normalized, mode="eval")
            code = compile(tree, filename="<dsl>", mode="eval")
            result = eval(code, {"__builtins__": {}}, safe_env)
            return bool(result)
        except Exception:
            return False


class MatcherEngine:
    """Evaluates YAML template matchers against HTTP responses."""

    def __init__(self) -> None:
        self.dsl_evaluator = SafeDSLEvaluator()

    def _extract_part(self, response: Any, part: str) -> str:
        """Extract requested part of the response (body, header, or response)."""
        part_clean = part.lower().strip()
        body_text = response.text() if hasattr(response, "text") and callable(response.text) else getattr(response, "body_text", "")
        if not body_text and hasattr(response, "body"):
            body_raw = response.body
            body_text = body_raw.decode("utf-8", errors="ignore") if isinstance(body_raw, bytes) else str(body_raw)

        headers_dict = getattr(response, "headers", {}) or {}
        headers_str = "\n".join(f"{k}: {v}" for k, v in headers_dict.items())

        if part_clean in ("header", "headers"):
            return headers_str
        elif part_clean in ("response", "all"):
            status = getattr(response, "status", 200)
            return f"HTTP/1.1 {status}\n{headers_str}\n\n{body_text}"
        else:
            # default is body
            return body_text

    def evaluate_matcher(self, matcher: dict[str, Any], response: Any, current_oob_id: Optional[str] = None) -> tuple[bool, str]:
        """Evaluate a single matcher dictionary against response.

        Returns (is_matched, evidence_snippet).
        """
        m_type = str(matcher.get("type", "word")).lower().strip()
        part = str(matcher.get("part", "body"))
        target_text = self._extract_part(response, part)
        status_code = getattr(response, "status", 200)

        if m_type == "status":
            expected = matcher.get("status", [])
            if isinstance(expected, int):
                expected = [expected]
            elif not isinstance(expected, list):
                expected = []
            is_match = status_code in expected
            ev = f"Status code {status_code} in {expected}" if is_match else ""
            return is_match, ev

        elif m_type == "word":
            words = matcher.get("words", [])
            if isinstance(words, str):
                words = [words]
            elif not isinstance(words, list):
                words = []
            
            cond = str(matcher.get("condition", "or")).lower()
            matched_words: list[str] = []
            for w in words:
                if w in target_text:
                    matched_words.append(w)

            if cond == "and":
                is_match = (len(matched_words) == len(words)) and len(words) > 0
            else:
                is_match = len(matched_words) > 0

            ev = f"Matched words ({cond}): {matched_words}" if is_match else ""
            return is_match, ev

        elif m_type == "regex":
            regexes = matcher.get("regex", [])
            if isinstance(regexes, str):
                regexes = [regexes]
            elif not isinstance(regexes, list):
                regexes = []

            cond = str(matcher.get("condition", "or")).lower()
            matched_regexes: list[str] = []
            for r in regexes:
                try:
                    if re.search(r, target_text, re.MULTILINE):
                        matched_regexes.append(r)
                except Exception:
                    pass

            if cond == "and":
                is_match = (len(matched_regexes) == len(regexes)) and len(regexes) > 0
            else:
                is_match = len(matched_regexes) > 0

            ev = f"Matched regex ({cond}): {matched_regexes}" if is_match else ""
            return is_match, ev

        elif m_type == "size":
            expected_size = matcher.get("size", 0)
            body_len = len(target_text)
            is_match = body_len >= int(expected_size)
            ev = f"Body size {body_len} >= {expected_size}" if is_match else ""
            return is_match, ev

        elif m_type == "dsl":
            dsl_expressions = matcher.get("dsl", [])
            if isinstance(dsl_expressions, str):
                dsl_expressions = [dsl_expressions]
            elif not isinstance(dsl_expressions, list):
                dsl_expressions = []

            body_str = self._extract_part(response, "body")
            headers_dict = getattr(response, "headers", {}) or {}
            context = {
                "status": status_code,
                "body": body_str,
                "headers": headers_dict,
            }

            matched_dsl: list[str] = []
            for expr in dsl_expressions:
                if self.dsl_evaluator.evaluate(expr, context):
                    matched_dsl.append(expr)

            cond = str(matcher.get("condition", "and")).lower()
            if cond == "or":
                is_match = len(matched_dsl) > 0
            else:
                is_match = (len(matched_dsl) == len(dsl_expressions)) and len(dsl_expressions) > 0

            ev = f"Matched DSL: {matched_dsl}" if is_match else ""
            return is_match, ev

        elif m_type == "oob":
            from phantomscan.oob import oob_listener
            if current_oob_id and oob_listener.check_hit(current_oob_id):
                return True, f"OOB callback verified for ID: {current_oob_id}"
            return False, ""

        return False, ""

    def evaluate(
        self,
        response: Any,
        matchers: list[dict[str, Any]],
        condition: str = "and",
        current_oob_id: Optional[str] = None,
    ) -> MatchResult:
        """Evaluate all matchers against response using boolean composition and negative matcher rejection."""
        if not matchers:
            return MatchResult(matched=False)

        cond_clean = condition.lower().strip()
        positive_results: list[tuple[bool, str, str]] = []
        evidence_list: list[str] = []
        matched_matchers: list[str] = []

        for idx, matcher in enumerate(matchers):
            is_negative = bool(matcher.get("negative", False))
            m_type = str(matcher.get("type", "word")).lower().strip()
            label = f"{m_type}_{idx}"

            is_match, ev = self.evaluate_matcher(matcher, response, current_oob_id)

            if is_negative:
                # If negative matcher matches, the candidate is instantly rejected
                if is_match:
                    return MatchResult(
                        matched=False,
                        matched_matchers=[f"NEGATIVE_REJECT_{label}"],
                        evidence=f"Negative matcher triggered: {ev}",
                    )
            else:
                positive_results.append((is_match, label, ev))
                if is_match:
                    matched_matchers.append(label)
                    if ev:
                        evidence_list.append(ev)

        if not positive_results:
            return MatchResult(matched=False)

        if cond_clean == "or":
            overall_matched = any(res[0] for res in positive_results)
        else:
            # default is "and"
            overall_matched = all(res[0] for res in positive_results)

        evidence_str = "; ".join(evidence_list) if overall_matched else ""
        return MatchResult(
            matched=overall_matched,
            matched_matchers=matched_matchers if overall_matched else [],
            evidence=evidence_str,
        )
