"""Shodan InternetDB feed — free IP enrichment without API key.

InternetDB: https://internetdb.shodan.io/{ip}
Returns open ports, CVEs, hostnames, tags, CPEs. No API key needed.
"""

from __future__ import annotations

from typing import Any

from threatfeed.feeds.base import BaseFeed
from threatfeed.types.ioc import IOC, IOCType, Severity, ThreatCategory


def _cves_to_severity(cves: list[str]) -> Severity:
    if len(cves) >= 5:
        return Severity.CRITICAL
    if len(cves) >= 2:
        return Severity.HIGH
    if cves:
        return Severity.MEDIUM
    return Severity.INFO


class ShodanInternetDBFeed(BaseFeed):
    """Shodan InternetDB — free, no API key, IP-only enrichment."""

    name = "shodan_internetdb"
    requires_api_key = False

    async def lookup(self, value: str, ioc_type: str) -> IOC | None:
        if ioc_type != "ip" or not self._client:
            return None

        try:
            resp = await self._client.get(f"https://internetdb.shodan.io/{value}")
            if resp.status_code == 404:
                return None
            resp.raise_for_status()
            data: dict[str, Any] = resp.json()
        except Exception:
            return None

        cves: list[str] = data.get("vulns", [])
        ports: list[int] = data.get("ports", [])
        tags: list[str] = data.get("tags", [])
        hostnames: list[str] = data.get("hostnames", [])
        cpes: list[str] = data.get("cpes", [])

        # Derive threat categories from Shodan tags
        threat_cats: set[ThreatCategory] = set()
        for tag in tags:
            tag_l = tag.lower()
            if "tor" in tag_l:
                threat_cats.add(ThreatCategory.TOR)
            elif "vpn" in tag_l:
                threat_cats.add(ThreatCategory.VPN)
            elif "scanner" in tag_l:
                threat_cats.add(ThreatCategory.SCANNER)
            elif "botnet" in tag_l:
                threat_cats.add(ThreatCategory.BOTNET)
            elif "malware" in tag_l:
                threat_cats.add(ThreatCategory.MALWARE)
            elif "c2" in tag_l:
                threat_cats.add(ThreatCategory.C2)

        if not cves and not threat_cats and not ports:
            return None

        ioc_tags = [f"port:{p}" for p in ports[:8]] + tags[:5]
        if hostnames:
            ioc_tags.append(f"hostname:{hostnames[0]}")

        severity = _cves_to_severity(cves) if cves else (
            Severity.MEDIUM if threat_cats else Severity.INFO
        )

        return IOC(
            value=value,
            ioc_type=IOCType.IP,
            severity=severity,
            confidence=0.8 if cves else 0.5,
            threat_categories=list(threat_cats) or [ThreatCategory.UNKNOWN],
            sources=[self.name],
            resolved_ips=hostnames[:5],
            tags=ioc_tags[:12],
            raw={"cves": cves[:10], "ports": ports, "cpes": cpes[:5]},
        )
