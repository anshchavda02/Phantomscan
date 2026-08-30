"""False-positive controls, known-platform matching, and scoring."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


SEVERITY_ORDER = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
DEDUCTIONS = {"critical": 30, "high": 15, "medium": 8, "low": 3, "info": 0}
DEDUCTION_CAPS = {"critical": 30, "high": 24, "medium": 18, "low": 10, "info": 0}


def load_known_platform(data_dir: Path, host: str) -> dict[str, Any] | None:
    """Load known platform context for a host or root domain."""
    path = data_dir / "known_platforms.json"
    if not path.exists():
        return None
    try:
        from phantomscan.scope import root_domain
        clean_host = host.lower().strip()
        if "://" in clean_host:
            from urllib.parse import urlparse
            clean_host = urlparse(clean_host).netloc
        if ":" in clean_host:
            clean_host = clean_host.split(":")[0]
        r_domain = root_domain(clean_host) if clean_host else ""
    except Exception:
        clean_host = host.lower().strip()
        r_domain = clean_host

    payload = json.loads(path.read_text(encoding="utf-8"))
    platforms = payload.get("platforms", {})
    if isinstance(platforms, dict):
        direct = platforms.get(clean_host) or (platforms.get(r_domain) if r_domain else None)
        if direct:
            direct.setdefault("domain", clean_host)
            return direct
        for domain, entry in platforms.items():
            aliases = set(entry.get("aliases", []))
            if clean_host == domain or clean_host in aliases or clean_host.endswith(f".{domain}") or (r_domain and (r_domain == domain or r_domain in aliases)):
                entry.setdefault("domain", domain)
                return entry
    if isinstance(platforms, list):
        for entry in platforms:
            domain = entry.get("domain", "")
            aliases = set(entry.get("aliases", []))
            if clean_host == domain or clean_host in aliases or clean_host.endswith(f".{domain}") or (r_domain and (r_domain == domain or r_domain in aliases)):
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
    """Apply FindingGate, confidence filters, and false-positive suppression."""
    from phantomscan.modules.finding_gate import gate_finding

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

        # ── FindingGate: universal validation checkpoint ──────────────────
        gated = gate_finding(enriched, fp_log=suppressed)
        if gated is None:
            continue  # rejected by gate, already logged to suppressed
        enriched = gated

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
    clean_obs = [item.to_dict() if hasattr(item, "to_dict") else item for item in observations]
    return filtered, suppressed, clean_obs



def score(
    findings: list[dict[str, Any]],
    observations: list[dict[str, Any]] | None = None,
    platform: dict[str, Any] | None = None,
) -> int:
    """Calculate a score from real confirmed findings, scan completeness, and known platform baseline."""
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
    text = " ".join(f"{_get_obs_field(item, 'name')} {_get_obs_field(item, 'value')}" for item in obs).lower()

    # Extract SSL grade from structured observation first, then fall back to text
    ssl_grade = _extract_ssl_grade(obs)

    # PR-S02: Positive Security Bonuses
    bonus_total = 0
    # HTTPS active: +10
    if "https" in text or any("https" in str(_get_obs_field(item, "value")).lower() for item in obs if "scheme" in str(_get_obs_field(item, "name")).lower()):
        bonus_total += 10
    # Valid SSL cert: +10, Grade A/A+: +5
    if ssl_grade and ssl_grade not in ("f", "unknown"):
        bonus_total += 10
        if ssl_grade in ("a+", "a"):
            bonus_total += 5
    # WAF detected: +5
    if any(
        any(w in str(_get_obs_field(item, "value")).lower() for w in ("cloudflare", "waf", "shield", "armor", "aws", "imperva", "modsecurity"))
        for item in obs
        if "waf" in str(_get_obs_field(item, "name")).lower() or "technologies" in str(_get_obs_field(item, "name")).lower()
    ):
        bonus_total += 5
    # CDN detected: +3
    if any(
        any(c in str(_get_obs_field(item, "value")).lower() for c in ("cloudflare", "fastly", "akamai", "cloudfront", "google", "cdn"))
        for item in obs
        if "cdn" in str(_get_obs_field(item, "name")).lower()
    ) or "cloudflare" in text or "fastly" in text or "akamai" in text or "cloudfront" in text:
        bonus_total += 3

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
        value = min(value, 94)
    elif findings:
        value = min(value, 99)

    # Enforce platform minimum score
    # (if platform is known to be enterprise-grade, a score below the minimum is
    # mathematically inconsistent with their real security posture)
    if platform and platform.get("minimum_score"):
        min_score = platform["minimum_score"]
        if value < min_score:
            import logging
            logging.getLogger(__name__).info(
                "Score %d below platform minimum %d for %s — applying platform minimum. "
                "Check for false positive findings still inflating deductions.",
                value, min_score, platform.get("domain", "platform")
            )
            value = min_score

    return max(20, min(100, value))


def _get_obs_field(item: Any, field: str, default: Any = "") -> Any:
    if isinstance(item, dict):
        return item.get(field, default)
    return getattr(item, field, default)


def _extract_ssl_grade(observations: list[dict[str, Any]]) -> str:
    """Extract the SSL/TLS grade from observations."""
    for item in observations:
        name = str(_get_obs_field(item, "name", "")).lower()
        val = _get_obs_field(item, "value")
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
        str(_get_obs_field(item, "value", ""))
        for item in observations
        if needle in str(_get_obs_field(item, "name", "")).lower()
    )


def _scan_completeness_penalty(observations: list[dict[str, Any]]) -> int:
    names = {str(_get_obs_field(item, "name", "")) for item in observations}
    text = " ".join(str(_get_obs_field(item, "value", "")) for item in observations).lower()

    # Detect if this is a local target — skip infra penalties that are
    # irrelevant for local dev servers (WHOIS, DNS, TLS)
    is_local = False
    for item in observations:
        if _get_obs_field(item, "name") == "is_local_target":
            is_local = bool(_get_obs_field(item, "value"))
            break
        if _get_obs_field(item, "name") == "local_app_profile":
            is_local = True
            break
        ip_val = str(_get_obs_field(item, "value", ""))
        if _get_obs_field(item, "name") == "ip" and ip_val in ("127.0.0.1", "::1"):
            is_local = True
            break

    penalty = 0
    if "http_error" in names and not is_local:
        penalty += 8
    if ("tls_error" in names or "tls service could not be verified" in text) and not is_local:
        penalty += 6
    if "whois_info" in names and "unavailable" in text and not is_local:
        penalty += 2
    # Port scan penalty — covers both Go engine and Python fallback observation names
    port_scan_done = (
        "open_tcp_ports" in names
        or "port_scan_results" in names
        or any("go-portscan" in name or "python-portscan" in name for name in names)
    )
    if not port_scan_done and not is_local:
        penalty += 3
    if "dns_error" in names and not is_local:
        penalty += 8
    return min(25, penalty)

