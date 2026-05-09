"""ThreatFeed core data models."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class IOCType(str, Enum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    FILE_HASH = "file_hash"
    EMAIL = "email"
    CVE = "cve"
    ASN = "asn"
    CIDR = "cidr"


class ThreatCategory(str, Enum):
    MALWARE = "malware"
    BOTNET = "botnet"
    RANSOMWARE = "ransomware"
    PHISHING = "phishing"
    C2 = "c2"
    SCANNER = "scanner"
    TOR = "tor"
    VPN = "vpn"
    PROXY = "proxy"
    SPAM = "spam"
    APT = "apt"
    EXPLOIT = "exploit"
    UNKNOWN = "unknown"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def weight(self) -> int:
        return {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}[self.value]

    @property
    def color(self) -> str:
        return {
            "critical": "red", "high": "dark_orange",
            "medium": "yellow", "low": "cyan", "info": "bright_black"
        }[self.value]


@dataclass
class IOC:
    """Indicator of Compromise — enriched from multiple CTI feeds."""
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:12])
    value: str = ""
    ioc_type: IOCType = IOCType.IP
    severity: Severity = Severity.MEDIUM
    confidence: float = 0.5          # 0.0–1.0
    threat_categories: list[ThreatCategory] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    first_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    sources: list[str] = field(default_factory=list)    # feed names that reported it
    # Enrichment data
    country: str | None = None
    asn: str | None = None
    org: str | None = None
    abuse_score: int | None = None          # AbuseIPDB 0-100
    vt_positives: int | None = None         # VirusTotal detections
    vt_total: int | None = None
    malware_families: list[str] = field(default_factory=list)
    # DNS / whois enrichment
    resolved_ips: list[str] = field(default_factory=list)
    registrar: str | None = None
    whois_created: str | None = None
    # AI enrichment
    ai_summary: str | None = None
    recommendations: list[str] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def source_count(self) -> int:
        return len(set(self.sources))

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "value": self.value,
            "type": self.ioc_type.value,
            "severity": self.severity.value,
            "confidence": self.confidence,
            "threat_categories": [c.value for c in self.threat_categories],
            "tags": self.tags,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "sources": self.sources,
            "country": self.country,
            "asn": self.asn,
            "org": self.org,
            "abuse_score": self.abuse_score,
            "vt_positives": self.vt_positives,
            "vt_total": self.vt_total,
            "malware_families": self.malware_families,
            "ai_summary": self.ai_summary,
            "recommendations": self.recommendations,
        }


@dataclass
class ThreatReport:
    """Aggregated result of a ThreatFeed run."""
    iocs: list[IOC] = field(default_factory=list)
    sources_queried: list[str] = field(default_factory=list)
    duration_seconds: float = 0.0
    scan_time: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    ai_threat_summary: str = ""

    def by_severity(self) -> dict[str, list[IOC]]:
        buckets: dict[str, list[IOC]] = {s.value: [] for s in Severity}
        for ioc in self.iocs:
            buckets[ioc.severity.value].append(ioc)
        return buckets

    def sorted_iocs(self) -> list[IOC]:
        return sorted(self.iocs, key=lambda i: (i.severity.weight, i.confidence), reverse=True)

    @property
    def summary(self) -> dict[str, Any]:
        return {
            "total": len(self.iocs),
            "critical": sum(1 for i in self.iocs if i.severity == Severity.CRITICAL),
            "high": sum(1 for i in self.iocs if i.severity == Severity.HIGH),
            "medium": sum(1 for i in self.iocs if i.severity == Severity.MEDIUM),
            "sources": len(self.sources_queried),
            "ips": sum(1 for i in self.iocs if i.ioc_type == IOCType.IP),
            "domains": sum(1 for i in self.iocs if i.ioc_type == IOCType.DOMAIN),
            "hashes": sum(1 for i in self.iocs if i.ioc_type == IOCType.FILE_HASH),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "scan_time": self.scan_time.isoformat(),
            "duration_seconds": self.duration_seconds,
            "sources_queried": self.sources_queried,
            "summary": self.summary,
            "ai_threat_summary": self.ai_threat_summary,
            "iocs": [i.to_dict() for i in self.sorted_iocs()],
        }
