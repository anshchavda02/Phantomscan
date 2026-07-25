"""Module 9 — Ticketing Integration.

Integrate PhantomScan findings with external ticketing and alert platforms:
Jira REST API, Slack webhooks, and Microsoft Teams webhooks.
Automatically creates tickets/notifications for Critical and High severity findings.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Any

from phantomscan.http_client import RobustHTTPClient

logger = logging.getLogger(__name__)


@dataclass
class TicketConfig:
    provider: str  # "jira", "slack", "teams"
    jira_url: str = ""
    jira_user: str = ""
    jira_token: str = ""
    jira_project: str = "SEC"
    slack_webhook_url: str = ""
    teams_webhook_url: str = ""
    min_severity: tuple[str, ...] = ("critical", "high")


@dataclass
class TicketResult:
    finding_id: str
    ticket_key: str = ""
    ticket_url: str = ""
    status: str = "created"


class TicketingIntegration:
    """Send findings to Jira, Slack, or Teams."""

    def __init__(self, http: RobustHTTPClient) -> None:
        self.http = http

    async def run(self, **kwargs: Any) -> list[dict[str, Any]]:
        """Module interface."""
        findings = kwargs.get("findings", [])
        config_dict = kwargs.get("ticket_config", {})

        if not config_dict:
            return []

        config = TicketConfig(**config_dict)
        results = await self.create_tickets(findings, config)
        logger.info("Processed %d tickets/notifications via %s", len(results), config.provider)
        return []

    async def create_tickets(
        self, findings: list[dict[str, Any]], config: TicketConfig
    ) -> list[TicketResult]:
        """Filter findings by severity and create tickets/alerts."""
        results: list[TicketResult] = []

        ticketable = [
            f for f in findings
            if f.get("severity", "").lower() in [s.lower() for s in config.min_severity]
        ]

        for finding in ticketable:
            try:
                if config.provider == "jira":
                    res = await self.create_jira_ticket(finding, config)
                elif config.provider == "slack":
                    res = await self.post_slack_message(finding, config)
                elif config.provider == "teams":
                    res = await self.post_teams_message(finding, config)
                else:
                    continue
                results.append(res)
            except Exception as exc:
                logger.error("Failed to send ticket for finding '%s': %s", finding.get("title"), exc)

        return results

    async def create_jira_ticket(
        self, finding: dict[str, Any], config: TicketConfig
    ) -> TicketResult:
        """Create a Jira issue via REST API v2."""
        import base64
        auth_str = base64.b64encode(f"{config.jira_user}:{config.jira_token}".encode()).decode()

        payload = {
            "fields": {
                "project": {"key": config.jira_project},
                "summary": f"[PhantomScan] {finding.get('severity', '').upper()}: {finding.get('title')}",
                "description": (
                    f"*Severity:* {finding.get('severity')}\n"
                    f"*Module:* {finding.get('module', 'N/A')}\n"
                    f"*Confidence:* {finding.get('confidence')}\n\n"
                    f"*Description:*\n{finding.get('description', '')}\n\n"
                    f"*Evidence:*\n{finding.get('evidence', '')}\n\n"
                    f"*Remediation:*\n{finding.get('recommendation', '')}\n\n"
                    f"*Finding ID:* {finding.get('id', 'N/A')}"
                ),
                "issuetype": {"name": "Bug"},
                "priority": {
                    "name": "Highest" if finding.get("severity") == "critical" else "High"
                },
                "labels": ["phantomscan", "security", finding.get("severity", "issue").lower()],
            }
        }

        resp = await self.http.request(
            "POST",
            f"{config.jira_url.rstrip('/')}/rest/api/2/issue",
            data=json.dumps(payload),
            extra_headers={
                "Authorization": f"Basic {auth_str}",
                "Content-Type": "application/json",
            },
            timeout=10,
        )

        body = resp.get("body", "{}")
        if isinstance(body, bytes):
            body = body.decode("utf-8", errors="ignore")

        data = json.loads(body) if body.startswith("{") else {}
        key = data.get("key", "")
        return TicketResult(
            finding_id=finding.get("id", ""),
            ticket_key=key,
            ticket_url=f"{config.jira_url.rstrip('/')}/browse/{key}" if key else "",
        )

    async def post_slack_message(
        self, finding: dict[str, Any], config: TicketConfig
    ) -> TicketResult:
        """Post alert to Slack webhook."""
        emoji = "🔴" if finding.get("severity") == "critical" else "🟠"
        payload = {
            "blocks": [
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": (
                            f"{emoji} *{finding.get('severity', '').upper()}*: {finding.get('title')}\n"
                            f"*Target:* {finding.get('target')}\n"
                            f"*Module:* {finding.get('module')}\n"
                            f"*Evidence:* {finding.get('evidence', '')[:200]}"
                        ),
                    },
                }
            ]
        }
        await self.http.request(
            "POST",
            config.slack_webhook_url,
            data=json.dumps(payload),
            extra_headers={"Content-Type": "application/json"},
            timeout=10,
        )
        return TicketResult(finding_id=finding.get("id", ""))

    async def post_teams_message(
        self, finding: dict[str, Any], config: TicketConfig
    ) -> TicketResult:
        """Post alert to MS Teams webhook (MessageCard format)."""
        theme_color = "FF0000" if finding.get("severity") == "critical" else "FFA500"
        payload = {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "themeColor": theme_color,
            "summary": f"PhantomScan Finding: {finding.get('title')}",
            "sections": [
                {
                    "activityTitle": f"PhantomScan Security Alert: {finding.get('title')}",
                    "facts": [
                        {"name": "Severity", "value": finding.get("severity", "").upper()},
                        {"name": "Target", "value": finding.get("target", "N/A")},
                        {"name": "Module", "value": finding.get("module", "N/A")},
                    ],
                    "text": finding.get("evidence", "")[:300],
                }
            ],
        }
        await self.http.request(
            "POST",
            config.teams_webhook_url,
            data=json.dumps(payload),
            extra_headers={"Content-Type": "application/json"},
            timeout=10,
        )
        return TicketResult(finding_id=finding.get("id", ""))
