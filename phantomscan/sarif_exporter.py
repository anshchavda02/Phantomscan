"""SARIF (Static Analysis Results Interchange Format) Exporter for PhantomScan.

Produces OASIS SARIF v2.1.0 compliant JSON reports compatible with:
- GitHub Advanced Security / Code Scanning (upload-sarif action)
- GitLab Security Dashboard
- Azure DevOps Security Alerts
- DefectDojo and enterprise vulnerability management platforms
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


SARIF_SCHEMA_URI = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
SARIF_VERSION = "2.1.0"


def _severity_to_sarif_level(severity: str) -> str:
    """Map PhantomScan severity to standard SARIF level."""
    s = str(severity).lower().strip()
    if s in ("critical", "high"):
        return "error"
    elif s == "medium":
        return "warning"
    else:  # low, info
        return "note"


def generate_sarif_report(report: dict[str, Any]) -> dict[str, Any]:
    """Convert a PhantomScan scan report dictionary into a SARIF v2.1.0 JSON object."""
    findings = report.get("findings", [])
    target = str(report.get("target", "target"))
    started_at = str(report.get("started_at", ""))
    finished_at = str(report.get("finished_at", ""))

    rules_map: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []

    for item in findings:
        if not isinstance(item, dict):
            continue

        rule_id = str(item.get("id") or item.get("rule_id") or "SECURITY-FINDING")
        title = str(item.get("title", "Security Finding"))
        severity = str(item.get("severity", "medium")).lower()
        confidence = str(item.get("confidence", "high")).lower()
        category = str(item.get("category", "general"))
        evidence = str(item.get("evidence", ""))
        recommendation = str(item.get("recommendation", ""))
        target_loc = str(item.get("target") or item.get("url") or target)
        cwe = str(item.get("cwe", ""))
        owasp = str(item.get("owasp_category", ""))
        fingerprint = str(item.get("fingerprint", ""))
        level = _severity_to_sarif_level(severity)

        # Build rule definition if not already recorded
        if rule_id not in rules_map:
            tags = [category]
            if cwe:
                tags.append(cwe)
            if owasp:
                tags.append(owasp)

            rules_map[rule_id] = {
                "id": rule_id,
                "name": rule_id.replace("-", "_").lower(),
                "shortDescription": {"text": title},
                "fullDescription": {"text": f"{title}. Recommendation: {recommendation}" if recommendation else title},
                "defaultConfiguration": {
                    "level": level,
                },
                "properties": {
                    "tags": [t for t in tags if t],
                    "precision": "very-high" if confidence == "high" else "high" if confidence == "medium" else "medium",
                    "problem.severity": severity,
                },
            }

        # Build SARIF result
        message_text = f"{title}\n\nEvidence:\n{evidence}"
        if recommendation:
            message_text += f"\n\nRemediation:\n{recommendation}"

        result_entry: dict[str, Any] = {
            "ruleId": rule_id,
            "level": level,
            "message": {
                "text": message_text,
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": target_loc,
                        },
                        "region": {
                            "snippet": {
                                "text": evidence[:300] if evidence else title,
                            },
                        },
                    },
                }
            ],
            "properties": {
                "severity": severity,
                "confidence": confidence,
                "category": category,
            },
        }

        if fingerprint:
            result_entry["partialFingerprints"] = {
                "primaryLocationLineHash": fingerprint,
            }

        results.append(result_entry)

    sarif_doc: dict[str, Any] = {
        "$schema": SARIF_SCHEMA_URI,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "PhantomScan",
                        "organization": "PhantomScan Team",
                        "semanticVersion": "2.2.0",
                        "informationUri": "https://github.com/anshchavda02/Phantomscan",
                        "rules": list(rules_map.values()),
                    }
                },
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "startTimeUtc": started_at,
                        "endTimeUtc": finished_at,
                    }
                ],
                "results": results,
            }
        ],
    }

    return sarif_doc


def write_sarif_report(path: Path, report: dict[str, Any]) -> None:
    """Serialize scan findings into a SARIF JSON file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    doc = generate_sarif_report(report)
    path.write_text(json.dumps(doc, indent=2, sort_keys=True), encoding="utf-8")
