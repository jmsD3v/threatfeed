"""ThreatFox feed by abuse.ch — free IOC database, no API key required.

https://threatfox.abuse.ch/api/
Supports: IP:port, domain, URL, file hash (md5/sha256)
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from threatfeed.feeds.base import BaseFeed
from threatfeed.types.ioc import IOC, IOCType, Severity, ThreatCategory

_BASE = "https://threatfox-api.abuse.ch/api/v1/"

_THREAT_TYPE_MAP = {
    "botnet_cc": ThreatCategory.BOTNET,
    "payload": ThreatCategory.MALWARE,
    "payload_delivery": ThreatCategory.MALWARE,
    "dropper": ThreatCategory.MALWARE,
    "c2": ThreatCategory.C2,
    "malspam": ThreatCategory.SPAM,
    "phishing": ThreatCategory.PHISHING,
    "ransomware": ThreatCategory.RANSOMWARE,
}

_CONFIDENCE_MAP = {
    "100% confidence level": 1.0,
    "75% confidence level": 0.75,
    "50% confidence level": 0.50,
}


class ThreatFoxFeed(BaseFeed):
    """ThreatFox abuse.ch IOC feed — no API key required."""

    name = "threatfox"
    requires_api_key = False

    async def lookup(self, value: str, ioc_type: str) -> IOC | None:
        if not self._client:
            return None

        # Map our type to ThreatFox search type
        search_type = {
            "ip": "search_ioc",
            "domain": "search_ioc",
            "url": "search_ioc",
            "file_hash": "search_hash",
        }.get(ioc_type)
        if not search_type:
            return None

        payload: dict[str, Any] = {"query": search_type}
        if search_type == "search_hash":
            payload["hash"] = value
        else:
            payload["search_term"] = value

        try:
            resp = await self._client.post(
                _BASE,
                json=payload,
                headers={"Content-Type": "application/json"},
            )
            resp.raise_for_status()
            data: dict[str, Any] = resp.json()
        except Exception:
            return None

        if data.get("query_status") != "ok":
            return None

        results = data.get("data", [])
        if not results:
            return None

        # Take most recent hit
        hit = results[0]
        threat_type = hit.get("threat_type", "")
        malware = hit.get("malware", "")
        confidence_str = hit.get("confidence_level", "")

        cat = _THREAT_TYPE_MAP.get(threat_type, ThreatCategory.UNKNOWN)
        confidence = _CONFIDENCE_MAP.get(confidence_str, 0.5)

        # Severity from malware name and confidence
        if confidence >= 0.9:
            severity = Severity.CRITICAL
        elif confidence >= 0.7:
            severity = Severity.HIGH
        elif confidence >= 0.5:
            severity = Severity.MEDIUM
        else:
            severity = Severity.LOW

        first_seen_str = hit.get("first_seen", "")
        last_seen_str = hit.get("last_seen", "")
        first_seen = datetime.now(timezone.utc)
        last_seen = datetime.now(timezone.utc)
        try:
            if first_seen_str:
                first_seen = datetime.fromisoformat(first_seen_str.replace(" ", "T") + "+00:00")
            if last_seen_str:
                last_seen = datetime.fromisoformat(last_seen_str.replace(" ", "T") + "+00:00")
        except Exception:
            pass

        ioc_type_map = {
            "ip": IOCType.IP, "domain": IOCType.DOMAIN,
            "url": IOCType.URL, "file_hash": IOCType.FILE_HASH,
        }

        return IOC(
            value=value,
            ioc_type=ioc_type_map.get(ioc_type, IOCType.IP),
            severity=severity,
            confidence=confidence,
            threat_categories=[cat],
            sources=[self.name],
            malware_families=[malware] if malware else [],
            first_seen=first_seen,
            last_seen=last_seen,
            tags=[threat_type] if threat_type else [],
            raw=hit,
        )

    async def recent_iocs(self, days: int = 1, limit: int = 100) -> list[IOC]:
        """Fetch recently added IOCs from ThreatFox full data dump (free, no API key).

        Uses the public CSV export instead of the now-authenticated API endpoint.
        URL: https://threatfox.abuse.ch/export/json/recent/
        """
        if not self._client:
            return []

        # ThreatFox free JSON export — updated every 5 minutes, no auth needed
        try:
            resp = await self._client.get(
                "https://threatfox.abuse.ch/export/json/recent/",
                headers={"Accept": "application/json"},
            )
            resp.raise_for_status()
            raw_data: Any = resp.json()
        except Exception:
            return []

        # The export is a dict keyed by numeric IDs: {"1": {...}, "2": {...}}
        if not isinstance(raw_data, dict):
            return []

        results: list[IOC] = []
        _ioc_type_map = {
            "ip:port": IOCType.IP,
            "ip": IOCType.IP,
            "domain": IOCType.DOMAIN,
            "url": IOCType.URL,
            "md5_hash": IOCType.FILE_HASH,
            "sha256_hash": IOCType.FILE_HASH,
        }

        # Each value is a list of dicts — flatten
        all_hits: list[dict] = []
        for v in raw_data.values():
            if isinstance(v, list):
                all_hits.extend(v)
            elif isinstance(v, dict):
                all_hits.append(v)

        for hit in all_hits[:limit]:
            if not isinstance(hit, dict):
                continue
            ioc_val = hit.get("ioc_value", "") or hit.get("ioc", "")
            if not ioc_val:
                continue
            # Strip port from ip:port
            raw_type = hit.get("ioc_type", "")
            if raw_type == "ip:port" and ":" in ioc_val:
                ioc_val = ioc_val.split(":")[0]

            ioc_type_obj = _ioc_type_map.get(raw_type, IOCType.IP)
            threat_type = hit.get("threat_type", "")
            cat = _THREAT_TYPE_MAP.get(threat_type, ThreatCategory.UNKNOWN)
            malware = hit.get("malware", "") or ""

            results.append(IOC(
                value=ioc_val,
                ioc_type=ioc_type_obj,
                severity=Severity.HIGH,
                confidence=0.75,
                threat_categories=[cat],
                sources=[self.name],
                malware_families=[malware] if malware else [],
                tags=[threat_type] if threat_type else [],
                raw=hit,
            ))

        return results
