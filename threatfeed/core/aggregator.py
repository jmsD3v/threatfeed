"""
ThreatFeed Aggregator — parallel multi-source IOC enrichment.

Flow:
  1. Parse IOC list (auto-detect type if not specified)
  2. Dispatch all available feeds in parallel for each IOC
  3. Merge results (de-dup, highest severity wins, union sources/tags)
  4. AI enrichment on top findings
  5. Return ThreatReport
"""

from __future__ import annotations

import asyncio
import os
import time
from datetime import datetime, timezone
from typing import Any

from threatfeed.feeds.abuseipdb import AbuseIPDBFeed
from threatfeed.feeds.otx import OTXFeed
from threatfeed.feeds.shodan import ShodanInternetDBFeed
from threatfeed.feeds.threatfox import ThreatFoxFeed
from threatfeed.feeds.virustotal import VirusTotalFeed
from threatfeed.types.ioc import IOC, IOCType, Severity, ThreatReport


def _detect_ioc_type(value: str) -> str:
    import re
    value = value.strip()
    # IPv4
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}(:\d+)?$", value):
        return "ip"
    # IPv6
    if ":" in value and re.match(r"^[0-9a-fA-F:]+$", value):
        return "ip"
    # MD5/SHA256/SHA1
    if re.match(r"^[0-9a-fA-F]{32}$", value) or \
       re.match(r"^[0-9a-fA-F]{40}$", value) or \
       re.match(r"^[0-9a-fA-F]{64}$", value):
        return "file_hash"
    # URL
    if value.startswith("http://") or value.startswith("https://"):
        return "url"
    # CVE
    if re.match(r"^CVE-\d{4}-\d+$", value, re.IGNORECASE):
        return "cve"
    # Domain (fallback)
    if re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$", value):
        return "domain"
    return "domain"


def _merge_iocs(iocs: list[IOC]) -> IOC:
    """Merge multiple feed results for the same IOC value into one."""
    if len(iocs) == 1:
        return iocs[0]

    base = max(iocs, key=lambda i: i.severity.weight)
    all_sources: list[str] = []
    all_tags: list[str] = []
    all_cats = []
    all_families: list[str] = []
    confidence_scores: list[float] = []

    for ioc in iocs:
        all_sources.extend(ioc.sources)
        all_tags.extend(ioc.tags)
        all_cats.extend(ioc.threat_categories)
        all_families.extend(ioc.malware_families)
        confidence_scores.append(ioc.confidence)

    base.sources = sorted(set(all_sources))
    base.tags = sorted(set(all_tags))[:15]
    base.threat_categories = list({c for c in all_cats})[:5]
    base.malware_families = sorted(set(all_families))[:10]
    base.confidence = max(confidence_scores)

    # Enrich fields from other hits
    for ioc in iocs:
        if not base.country and ioc.country:
            base.country = ioc.country
        if not base.asn and ioc.asn:
            base.asn = ioc.asn
        if not base.org and ioc.org:
            base.org = ioc.org
        if base.abuse_score is None and ioc.abuse_score is not None:
            base.abuse_score = ioc.abuse_score
        if base.vt_positives is None and ioc.vt_positives is not None:
            base.vt_positives = ioc.vt_positives
            base.vt_total = ioc.vt_total

    return base


class ThreatAggregator:
    """Orchestrates parallel lookups across all available CTI feeds."""

    def __init__(
        self,
        abuseipdb_key: str | None = None,
        virustotal_key: str | None = None,
        otx_key: str | None = None,
        semaphore_limit: int = 5,
    ):
        self._keys = {
            "abuseipdb": abuseipdb_key or os.getenv("ABUSEIPDB_API_KEY"),
            "virustotal": virustotal_key or os.getenv("VIRUSTOTAL_API_KEY"),
            "otx": otx_key or os.getenv("OTX_API_KEY"),
        }
        self._sem = asyncio.Semaphore(semaphore_limit)

    def _build_feeds(self) -> list[Any]:
        feeds = [ThreatFoxFeed(), ShodanInternetDBFeed()]
        if self._keys["abuseipdb"]:
            feeds.append(AbuseIPDBFeed(api_key=self._keys["abuseipdb"]))
        if self._keys["virustotal"]:
            feeds.append(VirusTotalFeed(api_key=self._keys["virustotal"]))
        if self._keys["otx"]:
            feeds.append(OTXFeed(api_key=self._keys["otx"]))
        return feeds

    async def _lookup_single(self, feed: Any, value: str, ioc_type: str) -> IOC | None:
        async with self._sem:
            try:
                async with feed as active_feed:
                    return await active_feed.lookup(value, ioc_type)
            except Exception:
                return None

    async def enrich_ioc(self, value: str, ioc_type: str | None = None) -> IOC | None:
        """Look up one IOC across all feeds and merge results."""
        resolved_type = ioc_type or _detect_ioc_type(value)
        feeds = self._build_feeds()

        tasks = [self._lookup_single(feed, value, resolved_type) for feed in feeds]
        results = await asyncio.gather(*tasks, return_exceptions=False)

        hits = [r for r in results if r is not None]
        if not hits:
            return None

        merged = _merge_iocs(hits)
        # Strip IP:port — normalize to just IP for display
        if ":" in merged.value and merged.ioc_type == IOCType.IP:
            merged.value = merged.value.split(":")[0]
        return merged

    async def enrich_many(
        self,
        values: list[str | tuple[str, str]],
        progress_callback=None,
    ) -> list[IOC]:
        """Enrich a list of IOC values in parallel."""
        normalized: list[tuple[str, str]] = []
        for v in values:
            if isinstance(v, tuple):
                normalized.append(v)
            else:
                normalized.append((v, _detect_ioc_type(v)))

        tasks = []
        for value, ioc_type in normalized:
            tasks.append(self.enrich_ioc(value, ioc_type))

        results: list[IOC] = []
        for i, coro in enumerate(asyncio.as_completed(tasks)):
            ioc = await coro
            if ioc:
                results.append(ioc)
            if progress_callback:
                progress_callback(i + 1, len(tasks))

        return results

    async def fetch_recent(self, days: int = 1, limit: int = 200) -> list[IOC]:
        """Fetch recent IOCs from ThreatFox (no API key needed)."""
        feed = ThreatFoxFeed()
        try:
            async with feed as active_feed:
                return await active_feed.recent_iocs(days=days, limit=limit)
        except Exception:
            return []

    async def run(
        self,
        iocs: list[str],
        include_recent: bool = False,
        recent_days: int = 1,
        recent_limit: int = 200,
    ) -> ThreatReport:
        start = time.perf_counter()
        report = ThreatReport()

        feeds_used = ["threatfox", "shodan_internetdb"]
        for key_name, feed_name in [("abuseipdb", "abuseipdb"),
                                     ("virustotal", "virustotal"),
                                     ("otx", "otx")]:
            if self._keys.get(key_name):
                feeds_used.append(feed_name)
        report.sources_queried = feeds_used

        enriched = await self.enrich_many(iocs)
        report.iocs.extend(enriched)

        if include_recent:
            recent = await self.fetch_recent(days=recent_days, limit=recent_limit)
            # De-dup with already-fetched
            existing = {i.value for i in report.iocs}
            report.iocs.extend(r for r in recent if r.value not in existing)

        report.duration_seconds = time.perf_counter() - start
        return report
