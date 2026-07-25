"""Module 6 — Unified Expiry Calendar.

Aggregates domain WHOIS expiry dates, SSL certificate expiration dates, and subdomain SSL expiries
across multiple targets into a unified calendar view sorted by urgency.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from phantomscan.http_client import RobustHTTPClient

logger = logging.getLogger(__name__)


@dataclass
class CalendarEvent:
    target: str
    type: str  # "Domain Expiry", "SSL Certificate Expiry", "Subdomain SSL Expiry"
    date: str  # ISO date format
    icon: str  # 🌐 or 🔒
    days_remaining: int = 0
    urgency: str = "green"  # red (< 30d), yellow (31-90d), green (> 90d)


@dataclass
class ExpiryCalendar:
    events: list[CalendarEvent] = field(default_factory=list)


class ExpiryCalendarBuilder:
    """Aggregate expiry events from scan targets."""

    def __init__(self, http: RobustHTTPClient | None = None) -> None:
        self.http = http

    async def run(self, **kwargs: Any) -> list[dict[str, Any]]:
        """Module interface."""
        scans = kwargs.get("scans", [])
        if scans:
            cal = self.build(scans)
            return [e.__dict__ for e in cal.events]
        return []

    def build(self, all_targets: list[dict[str, Any]]) -> ExpiryCalendar:
        events: list[CalendarEvent] = []
        now = datetime.now()

        for scan in all_targets:
            target = scan.get("target", scan.get("scan_meta", {}).get("target", "Unknown"))
            intel = scan.get("intel", scan.get("observations", {}))

            # Domain WHOIS expiry
            whois_info = intel.get("whois", {}) if isinstance(intel, dict) else {}
            expiry_date = whois_info.get("expiry_date") or whois_info.get("expiration_date")
            if expiry_date:
                events.append(self._create_event(target, "Domain Expiry", str(expiry_date), "🌐", now))

            # Primary SSL Certificate Expiry
            ssl_info = intel.get("ssl", {}) if isinstance(intel, dict) else {}
            cert_not_after = ssl_info.get("cert_not_after") or ssl_info.get("valid_until")
            if cert_not_after:
                events.append(self._create_event(target, "SSL Certificate Expiry", str(cert_not_after), "🔒", now))

            # Subdomain SSL Expiries
            subdomains = intel.get("subdomains", []) if isinstance(intel, dict) else []
            if isinstance(subdomains, list):
                for sub in subdomains:
                    if isinstance(sub, dict) and sub.get("ssl_expiry"):
                        events.append(self._create_event(
                            sub.get("subdomain", target),
                            "Subdomain SSL Expiry",
                            str(sub["ssl_expiry"]),
                            "🔒",
                            now
                        ))

        events.sort(key=lambda e: e.days_remaining)
        return ExpiryCalendar(events=events)

    def _create_event(
        self, target: str, event_type: str, date_str: str, icon: str, now: datetime
    ) -> CalendarEvent:
        days = 999
        try:
            # Parse ISO or common date formats
            clean_str = date_str.split("T")[0].split(" ")[0]
            dt = datetime.strptime(clean_str, "%Y-%m-%d")
            days = (dt - now).days
        except Exception:
            pass

        if days <= 30:
            urgency = "red"
        elif days <= 90:
            urgency = "yellow"
        else:
            urgency = "green"

        return CalendarEvent(
            target=target,
            type=event_type,
            date=date_str,
            icon=icon,
            days_remaining=days,
            urgency=urgency,
        )
