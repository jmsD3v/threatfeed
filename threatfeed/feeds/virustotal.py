"""VirusTotal v3 feed — multi-AV file/URL/IP/domain reputation.

Free tier: 4 lookups/min, 500/day.
https://developers.virustotal.com/reference
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from threatfeed.feeds.base import BaseFeed
from threatfeed.types.ioc import IOC, IOCType, Severity, ThreatCategory


def _positives_to_severity(positives: int, total: int) -> Severity:
    if total == 0:
        return Severity.INFO
    ratio = positives / total
    if positives >= 10 or ratio >= 0.3:
        return Severity.CRITICAL
    if positives >= 5 or ratio >= 0.15:
        return Severity.HIGH
    if positives >= 2 or ratio >= 0.05:
        return Severity.MEDIUM
    if positives >= 1:
        return Severity.LOW
    return Severity.INFO


_VT_ENDPOINTS = {
    "ip": "https://www.virustotal.com/api/v3/ip_addresses/{value}",
    "domain": "https://www.virustotal.com/api/v3/domains/{value}",
    "url": "https://www.virustotal.com/api/v3/urls/{value}",
    "file_hash": "https://www.virustotal.com/api/v3/files/{value}",
}

_TYPE_MAP = {
    "ip": IOCType.IP,
    "domain": IOCType.DOMAIN,
    "url": IOCType.URL,
    "file_hash": IOCType.FILE_HASH,
}


class VirusTotalFeed(BaseFeed):
    """VirusTotal v3 reputation feed."""

    name = "virustotal"
    requires_api_key = True

    def _default_headers(self) -> dict[str, str]:
        h = super()._default_headers()
        if self.api_key:
            h["x-apikey"] = self.api_key
        return h

    async def lookup(self, value: str, ioc_type: str) -> IOC | None:
        if ioc_type not in _VT_ENDPOINTS or not self._client:
            return None

        url = _VT_ENDPOINTS[ioc_type].format(value=value)
        try:
            resp = await self._client.get(url)
            if resp.status_code == 404:
                return None
            resp.raise_for_status()
            data: dict[str, Any] = resp.json().get("data", {}).get("attributes", {})
        except Exception:
            return None

        stats = data.get("last_analysis_stats", {})
        positives = stats.get("malicious", 0) + stats.get("suspicious", 0)
        total = sum(stats.values()) or 1

        if positives == 0:
            return None

        # Extract malware families from analysis results
        families: set[str] = set()
        for engine_result in data.get("last_analysis_results", {}).values():
            fam = engine_result.get("result")
            if fam and isinstance(fam, str) and len(fam) < 40:
                families.add(fam)

        # Threat categories from tags
        vt_cats = data.get("categories", {})
        threat_cats: list[ThreatCategory] = []
        for cat_str in list(vt_cats.values())[:5]:
            cat_lower = cat_str.lower()
            if "malware" in cat_lower:
                threat_cats.append(ThreatCategory.MALWARE)
            elif "phish" in cat_lower:
                threat_cats.append(ThreatCategory.PHISHING)
            elif "c2" in cat_lower or "command" in cat_lower:
                threat_cats.append(ThreatCategory.C2)
            elif "ransom" in cat_lower:
                threat_cats.append(ThreatCategory.RANSOMWARE)

        tags = data.get("tags", [])
        country = data.get("country")
        asn = data.get("asn")
        org = data.get("as_owner")

        last_mod = data.get("last_modification_date")
        last_seen = datetime.now(timezone.utc)
        if isinstance(last_mod, int):
            last_seen = datetime.fromtimestamp(last_mod, tz=timezone.utc)

        return IOC(
            value=value,
            ioc_type=_TYPE_MAP.get(ioc_type, IOCType.IP),
            severity=_positives_to_severity(positives, total),
            confidence=min(positives / max(total, 1), 1.0),
            threat_categories=list(set(threat_cats)) or [ThreatCategory.MALWARE],
            sources=[self.name],
            vt_positives=positives,
            vt_total=total,
            malware_families=sorted(families)[:10],
            country=country,
            asn=str(asn) if asn else None,
            org=org,
            last_seen=last_seen,
            tags=tags[:10],
            raw={"stats": stats, "tags": tags},
        )
