"""AbuseIPDB feed — IP reputation with abuse score and categories.

Free tier: 1000 checks/day.
https://www.abuseipdb.com/api.html
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from threatfeed.feeds.base import BaseFeed
from threatfeed.types.ioc import IOC, IOCType, Severity, ThreatCategory

_ABUSE_CATEGORIES = {
    1: ThreatCategory.UNKNOWN,    # DNS Compromise
    2: ThreatCategory.UNKNOWN,    # DNS Poisoning
    3: ThreatCategory.SPAM,       # Fraud Orders
    4: ThreatCategory.MALWARE,    # DDoS Attack
    5: ThreatCategory.UNKNOWN,    # FTP Brute-Force
    6: ThreatCategory.UNKNOWN,    # Ping of Death
    7: ThreatCategory.SPAM,       # Phishing
    8: ThreatCategory.MALWARE,    # Fraud VoIP
    9: ThreatCategory.SCANNER,    # Open Proxy
    10: ThreatCategory.SPAM,      # Web Spam
    11: ThreatCategory.SPAM,      # Email Spam
    12: ThreatCategory.UNKNOWN,   # Blog Spam
    13: ThreatCategory.VPN,       # VPN IP
    14: ThreatCategory.SCANNER,   # Port Scan
    15: ThreatCategory.UNKNOWN,   # Hacking
    16: ThreatCategory.MALWARE,   # SQL Injection
    17: ThreatCategory.UNKNOWN,   # Spoofing
    18: ThreatCategory.BOTNET,    # Brute-Force
    19: ThreatCategory.BOTNET,    # Bad Web Bot
    20: ThreatCategory.UNKNOWN,   # Exploited Host
    21: ThreatCategory.SCANNER,   # Web App Attack
    22: ThreatCategory.SPAM,      # SSH
    23: ThreatCategory.BOTNET,    # IoT Targeted
}


def _score_to_severity(score: int) -> Severity:
    if score >= 90:
        return Severity.CRITICAL
    if score >= 60:
        return Severity.HIGH
    if score >= 25:
        return Severity.MEDIUM
    if score >= 5:
        return Severity.LOW
    return Severity.INFO


class AbuseIPDBFeed(BaseFeed):
    """AbuseIPDB IP reputation feed."""

    name = "abuseipdb"
    requires_api_key = True

    def _default_headers(self) -> dict[str, str]:
        h = super()._default_headers()
        if self.api_key:
            h["Key"] = self.api_key
        return h

    async def lookup(self, value: str, ioc_type: str) -> IOC | None:
        if ioc_type != "ip" or not self._client:
            return None

        try:
            resp = await self._client.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": value, "maxAgeInDays": 90, "verbose": True},
            )
            resp.raise_for_status()
            data: dict[str, Any] = resp.json().get("data", {})
        except Exception:
            return None

        score = data.get("abuseConfidenceScore", 0)
        if score == 0:
            return None

        cats_raw = data.get("reports", [])
        category_ids: set[int] = set()
        for report in cats_raw:
            for cid in report.get("categories", []):
                category_ids.add(cid)

        threat_cats = list({
            _ABUSE_CATEGORIES.get(cid, ThreatCategory.UNKNOWN)
            for cid in category_ids
            if cid in _ABUSE_CATEGORIES
        })

        last_reported = data.get("lastReportedAt")
        last_seen = datetime.now(timezone.utc)
        if last_reported:
            try:
                last_seen = datetime.fromisoformat(last_reported.replace("Z", "+00:00"))
            except Exception:
                pass

        return IOC(
            value=value,
            ioc_type=IOCType.IP,
            severity=_score_to_severity(score),
            confidence=score / 100,
            threat_categories=threat_cats,
            sources=[self.name],
            abuse_score=score,
            country=data.get("countryCode"),
            org=data.get("isp"),
            last_seen=last_seen,
            tags=[f"reports:{data.get('totalReports', 0)}", f"distinct_users:{data.get('numDistinctUsers', 0)}"],
            raw=data,
        )
