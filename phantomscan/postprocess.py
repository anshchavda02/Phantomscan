"""False-positive controls, known-platform matching, and scoring."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


SEVERITY_ORDER = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
DEDUCTIONS = {"critical": 30, "high": 15, "medium": 8, "low": 3, "info": 1}
DEDUCTION_CAPS = {"critical": 60, "high": 45, "medium": 30, "low": 20, "info": 10}


def load_known_platform(data_dir: Path, host: str) -> dict[str, Any] | None:
    """Load known platform context for a host or root domain."""
    path = data_dir / "known_platforms.json"
    if not path.exists():
        return None
    payload = json.loads(path.read_text(encoding="utf-8"))
    platforms = payload.get("platforms", {})
    if isinstance(platforms, dict):
        direct = platforms.get(host)
        if direct:
            direct.setdefault("domain", host)
            return direct
        for domain, entry in platforms.items():
            aliases = set(entry.get("aliases", []))
            if host == domain or host in aliases or host.endswith(f".{domain}"):
                entry.setdefault("domain", domain)
                return entry
    if isinstance(platforms, list):
        for entry in platforms:
            domain = entry.get("domain", "")
            aliases = set(entry.get("aliases", []))
            if host == domain or host in aliases or host.endswith(f".{domain}"):
                return entry
    return None


def deduplicate_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Deduplicate findings by id, target, and evidence."""
    seen: set[tuple[str, str, str]] = set()
    output: list[dict[str, Any]] = []
    for finding in findings:
        key = (finding.get("id", ""), finding.get("target", ""), finding.get("evidence", ""))
        if key not in seen:
            seen.add(key)
            output.append(finding)
    return output


def post_process(
    findings: list[dict[str, Any]],
    observations: list[dict[str, Any]],
    data_dir: Path,
    target_host: str,
    include_medium: bool,
    include_low: bool,
    fp_log_path: Path | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    """Apply confidence filters and false-positive suppression rules."""
    platform = load_known_platform(data_dir, target_host)
    suppressed: list[dict[str, Any]] = []
    filtered: list[dict[str, Any]] = []
    confidence_floor = "low" if include_low else "medium" if include_medium else "high"
    floors = {"high": 3, "medium": 2, "low": 1}
    waf_detected = _observation_text(observations, "waf").lower()
    cdn_detected = _observation_text(observations, "cdn").lower()
    login_confirmed = "true" in _observation_text(observations, "login_page_detected").lower()

    for item in deduplicate_findings(findings):
        enriched = dict(item)
        confidence = str(enriched.get("confidence", "medium")).lower()
        if confidence == "low":
            enriched["manual_verification"] = True
            if SEVERITY_ORDER.get(str(enriched.get("severity")), 1) > SEVERITY_ORDER["medium"]:
                enriched["severity"] = "medium"
        title = str(enriched.get("title", ""))
        reason = _suppression_reason(title, platform, waf_detected, cdn_detected, login_confirmed)
        if reason:
            suppressed.append({**enriched, "suppression_reason": reason})
            continue
        if floors.get(confidence, 2) < floors[confidence_floor]:
            suppressed.append({**enriched, "suppression_reason": f"Below confidence filter: {confidence}"})
            continue
        filtered.append(enriched)

    if fp_log_path:
        fp_log_path.parent.mkdir(parents=True, exist_ok=True)
        fp_log_path.write_text(json.dumps(suppressed, indent=2, sort_keys=True), encoding="utf-8")
    return filtered, suppressed, observations


def score(findings: list[dict[str, Any]], observations: list[dict[str, Any]] | None = None) -> int:
    """Calculate a score from real confirmed findings and scan completeness."""
    totals = {key: 0 for key in DEDUCTIONS}
    for item in findings:
        severity = str(item.get("severity", "info")).lower()
        if severity in totals:
            totals[severity] = min(DEDUCTION_CAPS[severity], totals[severity] + DEDUCTIONS[severity])
    value = 100 - sum(totals.values())
    obs = observations or []

    completeness_penalty = _scan_completeness_penalty(obs)
    value -= completeness_penalty

    # Build a flat text blob for simple marker checks
    text = " ".join(f"{item.get('name', '')} {item.get('value', '')}" for item in obs).lower()

    # Extract SSL grade from structured observation first, then fall back to text
    ssl_grade = _extract_ssl_grade(obs)

    bonus_total = 0
    if ssl_grade in ("a+", "a"):
        bonus_total += 3 if ssl_grade == "a+" else 2
    if ssl_grade and ssl_grade not in ("f", "unknown"):
        bonus_total += 1  # cert is at least valid
    if any(
        any(w in str(item.get("value", "")).lower() for w in ("cloudflare", "waf", "shield", "armor"))
        for item in obs
        if "waf" in str(item.get("name", "")).lower() or "technologies" in str(item.get("name", "")).lower()
    ):
        bonus_total += 2
    if "cloudflare" in text or "fastly" in text or "akamai" in text or "cloudfront" in text:
        bonus_total += 1  # CDN bonus
    if "dmarc1" in text or "dmarc record" in text:
        bonus_total += 1
    if "hsts" in text or "strict-transport-security" in text:
        bonus_total += 2
    if "http/3" in text or "\"h3\"" in text or "alt-svc" in text:
        bonus_total += 1

    # Base score starts at 100 + bonus (capped at 100 before deductions)
    base_score = min(100, 100 + bonus_total)
    total_deductions = sum(totals.values()) + completeness_penalty
    value = base_score - total_deductions

    # Apply strict caps based on existing finding severities
    severities = {str(item.get("severity", "info")).lower() for item in findings}
    if "critical" in severities:
        value = min(value, 49)
    elif "high" in severities:
        value = min(value, 69)
    elif "medium" in severities:
        value = min(value, 84)
    elif findings:
        value = min(value, 99)

    if obs:
        value = max(20, value)
    return max(0, min(100, value))


def _extract_ssl_grade(observations: list[dict[str, Any]]) -> str:
    """Extract the SSL/TLS grade from observations."""
    for item in observations:
        name = str(item.get("name", "")).lower()
        val = item.get("value")
        # Direct ssl_grade observation
        if name == "ssl_grade" and isinstance(val, str):
            return val.lower()
        # tls_inspection dict may carry a 'grade' key
        if name == "tls_inspection" and isinstance(val, dict):
            g = val.get("grade", "")
            if g:
                return str(g).lower()
    return ""


def grade(value: int) -> str:
    """Return a letter grade for a numeric score."""
    if value >= 90:
        return "A+"
    if value >= 80:
        return "A"
    if value >= 70:
        return "B"
    if value >= 60:
        return "C"
    if value >= 50:
        return "D"
    return "F"


def _suppression_reason(
    title: str,
    platform: dict[str, Any] | None,
    waf_detected: str,
    cdn_detected: str,
    login_confirmed: bool,
) -> str | None:
    normalized = title.lower()
    if platform:
        for suppressed in platform.get("suppress_findings", []):
            if suppressed.lower() in normalized:
                return f"Known platform context: {platform.get('domain', 'platform')}"
    if "no rate limiting" in normalized and waf_detected:
        return "WAF provides rate-limiting capability at the edge."
    if "no waf" in normalized and any(name in cdn_detected for name in ["cloudflare", "akamai", "google", "aws", "cloudfront"]):
        return "Confirmed CDN edge provides WAF capability."
    if "no mfa" in normalized and not login_confirmed:
        return "No confirmed login page in scan scope."
    return None


def _observation_text(observations: list[dict[str, Any]], needle: str) -> str:
    return " ".join(
        str(item.get("value", ""))
        for item in observations
        if needle in str(item.get("name", "")).lower()
    )


def _scan_completeness_penalty(observations: list[dict[str, Any]]) -> int:
    names = {str(item.get("name", "")) for item in observations}
    text = " ".join(str(item.get("value", "")) for item in observations).lower()
    penalty = 0
    if "http_error" in names:
        penalty += 8
    if "tls_error" in names or "tls service could not be verified" in text:
        penalty += 6
    if "whois_info" in names and "unavailable" in text:
        penalty += 2
    # Port scan penalty — covers both Go engine and Python fallback observation names
    port_scan_done = (
        "open_tcp_ports" in names
        or "port_scan_results" in names
        or any("go-portscan" in name or "python-portscan" in name for name in names)
    )
    if not port_scan_done:
        penalty += 3
    if "dns_error" in names:
        penalty += 8
    return min(25, penalty)
