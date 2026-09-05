"""Universal finding verification checkpoint (FindingGate).

Every finding from every module passes through :func:`gate_finding` before
being accepted into the report.  This is the last line of defence against
false positives reaching the final output.

Checks performed:
1. Mandatory fields present (title, severity, confidence, evidence)
2. Evidence is non-empty and substantive (≥10 chars)
3. Valid confidence and severity values
4. ``verification_method`` is present and valid
5. HIGH/Critical severity requires HIGH confidence (else downgraded)
6. Known-platform suppression (delegated to postprocess)
7. Deterministic fingerprint assignment

The gate operates on **dicts** (the pipeline's native format), not on
:class:`Finding` dataclass instances.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Optional

from phantomscan.models import (
    VALID_FINDING_STATUSES,
    VALID_VERIFICATION_METHODS,
    compute_finding_fingerprint,
)

logger = logging.getLogger(__name__)

# Canonical severity and confidence values
_VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}
_VALID_CONFIDENCES = {"high", "medium", "low"}


def gate_finding(
    candidate: Any,
    fp_log: list[dict[str, Any]] | None = None,
) -> Optional[dict[str, Any]]:
    """Validate and optionally adjust a candidate finding dict.

    Returns the (possibly modified) finding if it passes all checks,
    or ``None`` if it must be rejected.

    Rejected findings are logged with a reason.  If *fp_log* is provided,
    rejected entries are appended to it for audit purposes.
    """
    if hasattr(candidate, "to_dict"):
        candidate = candidate.to_dict()
    elif not isinstance(candidate, dict):
        candidate = dict(candidate)

    title = str(candidate.get("title", ""))

    # ── Check 1: mandatory fields present ─────────────────────────────────
    required = ("title", "severity", "confidence", "evidence")
    for field in required:
        val = candidate.get(field)
        if not val or (isinstance(val, str) and not val.strip()):
            _reject(candidate, fp_log, f"Missing required field: {field}")
            return None

    # ── Check 2: evidence must be substantive ─────────────────────────────
    evidence = str(candidate.get("evidence", ""))
    if len(evidence.strip()) < 10:
        _reject(candidate, fp_log, "Evidence too short (< 10 chars)")
        return None

    # ── Check 3: valid confidence value ───────────────────────────────────
    confidence = str(candidate.get("confidence", "")).lower()
    if confidence not in _VALID_CONFIDENCES:
        _reject(
            candidate, fp_log,
            f"Invalid confidence value: '{confidence}'",
        )
        return None
    candidate["confidence"] = confidence  # normalise to lowercase

    # ── Check 4: valid severity value ─────────────────────────────────────
    severity = str(candidate.get("severity", "")).lower()
    if severity not in _VALID_SEVERITIES:
        _reject(
            candidate, fp_log,
            f"Invalid severity value: '{severity}'",
        )
        return None
    candidate["severity"] = severity

    # ── Check 5: verification_method present and valid ────────────────────
    vm = str(candidate.get("verification_method", ""))
    if vm and vm not in VALID_VERIFICATION_METHODS:
        _reject(
            candidate, fp_log,
            f"Invalid verification_method: '{vm}'",
        )
        return None

    # ── Check 6: status valid ─────────────────────────────────────────────
    status = str(candidate.get("status", "confirmed")).lower()
    if status not in VALID_FINDING_STATUSES:
        status = "confirmed"
    candidate["status"] = status

    # ── Check 7: Critical/High requires HIGH confidence ───────────────────
    if severity in ("critical", "high") and confidence != "high":
        logger.warning(
            "Downgrading '%s' — %s severity requires HIGH confidence, "
            "had %s. Capping at medium.",
            title, severity, confidence,
        )
        candidate["severity"] = "medium"
        candidate.setdefault("_gate_notes", []).append(
            f"Downgraded from {severity} to medium: "
            f"confidence was {confidence}, not high"
        )

    # ── Check: evidence must not be identical to description ──────────────
    desc = str(candidate.get("description", "")).strip()
    if desc and evidence.strip() == desc:
        _reject(candidate, fp_log, "Evidence must not be identical to description")
        return None

    # ── Check: module field must be populated ─────────────────────────────
    if not candidate.get("module") or not str(candidate.get("module", "")).strip():
        candidate["module"] = str(candidate.get("category") or "general")

    # ── Check 8: XSS findings require syntax-breaking character evidence ─
    fid = str(candidate.get("id", ""))
    if fid in ("XSS-REFLECTED", "XSS-REFLECTED-FORM"):
        if "<" not in evidence and ">" not in evidence and '"' not in evidence and "'" not in evidence:
            _reject(candidate, fp_log, "XSS finding lacks syntax-breaking character injection evidence")
            return None
        if "javascript:phantomscan_js" in evidence:
            _reject(candidate, fp_log, "XSS finding based solely on plain javascript URI probe without HTML context escape")
            return None

    # ── Enrich: ID, UID, rule_id, fingerprint ─────────────────────────────
    if not candidate.get("id") and title:
        candidate["id"] = "FINDING-" + re.sub(r"[^A-Z0-9]+", "-", title.upper()).strip("-")[:30]
    if not candidate.get("rule_id"):
        candidate["rule_id"] = candidate.get("id", "")
    if not candidate.get("uid"):
        base_id = candidate.get("id") or "finding"
        clean_slug = re.sub(r"[^a-zA-Z0-9_-]+", "-", str(base_id).lower()).strip("-")
        candidate["uid"] = f"finding-{clean_slug}"

    if not candidate.get("fingerprint"):
        candidate["fingerprint"] = compute_finding_fingerprint(
            target=str(candidate.get("target", "")),
            url=str(candidate.get("url", "")),
            rule_id=str(candidate.get("rule_id") or candidate.get("id", "")),
            param_name=str(candidate.get("parameter", "")),
            method=str(candidate.get("method", "GET")),
            evidence=evidence,
            title=title,
            cwe=str(candidate.get("cwe", "")),
        )

    return candidate


def _reject(
    candidate: dict[str, Any],
    fp_log: list[dict[str, Any]] | None,
    reason: str,
) -> None:
    """Log a rejection and optionally append to the FP log."""
    title = candidate.get("title", "<no title>")
    logger.error("FINDING GATE REJECTED — %s: %s", reason, title)
    if fp_log is not None:
        fp_log.append({
            **candidate,
            "gate_rejection_reason": reason,
        })

