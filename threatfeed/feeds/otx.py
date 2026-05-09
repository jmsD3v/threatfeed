"""AlienVault OTX (Open Threat Exchange) feed.

Free API — no rate limit documented but be respectful.
https://otx.alienvault.com/api
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from threatfeed.feeds.base import BaseFeed
from threatfeed.types.ioc import IOC, IOCType, Severity, ThreatCategory

_OTX_SECTIONS = {
    "ip": ("indicators/IPv4/{value}/general", "indicators/IPv4/{value}/reputation"),
    "domain": ("indicators/domain/{value}/general", "indicators/domain/{value}/malware"),
    "file_hash": ("indicators/file/{value}/general", None),
    "url": ("indicators/url/{value}/general", None),
}

_TYPE_MAP = {
    "ip": IOCType.IP,
    "domain": IOCType.DOMAIN,
    "file_hash": IOCType.FILE_HASH,
    "url": IOCType.URL,
}

_BASE = "https://otx.alienvault.com/api/v1/"


def _pulse_count_to_severity(pulses: int) -> Severity:
    if pulses >= 20:
        return Severity.CRITICAL
    if pulses >= 10:
        return Severity.HIGH
    if pulses >= 3:
        return Severity.MEDIUM
    if pulses >= 1:
        return Severity.LOW
    return Severity.INFO


class OTXFeed(BaseFeed):
    """AlienVault OTX threat feed."""

    name = "otx"
    requires_api_key = True

    def _default_headers(self) -> dict[str, str]:
        h = super()._default_headers()
        if self.api_key:
            h["X-OTX-API-KEY"] = self.api_key
        return h

    async def lookup(self, value: str, ioc_type: str) -> IOC | None:
        if ioc_type not in _OTX_SECTIONS or not self._client:
            return None

        general_path, _ = _OTX_SECTIONS[ioc_type]
        url = _BASE + general_path.format(value=value)

        try:
            resp = await self._client.get(url)
            if resp.status_code == 404:
                return None
            resp.raise_for_status()
            data: dict[str, Any] = resp.json()
        except Exception:
            return None

        pulse_info = data.get("pulse_info", {})
        pulse_count = pulse_info.get("count", 0)

        if pulse_count == 0:
            return None

        # Gather tags from pulses
        tags: list[str] = []
        malware_families: list[str] = []
        threat_cats: set[ThreatCategory] = set()

        for pulse in pulse_info.get("pulses", [])[:10]:
            for tag in pulse.get("tags", [])[:3]:
                if tag and len(tag) < 30:
                    tags.append(tag.lower())
            for mal in pulse.get("malware_families", [])[:3]:
                name = mal.get("display_name") or mal.get("id", "")
                if name:
                    malware_families.append(name)
            pulse_name = pulse.get("name", "").lower()
            if "ransomware" in pulse_name:
                threat_cats.add(ThreatCategory.RANSOMWARE)
            elif "phishing" in pulse_name:
                threat_cats.add(ThreatCategory.PHISHING)
            elif "botnet" in pulse_name:
                threat_cats.add(ThreatCategory.BOTNET)
            elif "apt" in pulse_name:
                threat_cats.add(ThreatCategory.APT)
            elif "malware" in pulse_name or "trojan" in pulse_name:
                threat_cats.add(ThreatCategory.MALWARE)
            elif "c2" in pulse_name or "command" in pulse_name:
                threat_cats.add(ThreatCategory.C2)

        country = data.get("country_code") or data.get("country_name")
        asn = data.get("asn")

        return IOC(
            value=value,
            ioc_type=_TYPE_MAP.get(ioc_type, IOCType.IP),
            severity=_pulse_count_to_severity(pulse_count),
            confidence=min(pulse_count / 20, 1.0),
            threat_categories=list(threat_cats) or [ThreatCategory.UNKNOWN],
            sources=[self.name],
            malware_families=sorted(set(malware_families))[:10],
            country=country,
            asn=asn,
            tags=sorted(set(tags))[:10],
            raw={"pulse_count": pulse_count, "pulses": pulse_info.get("pulses", [])[:3]},
        )
