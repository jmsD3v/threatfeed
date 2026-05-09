"""Gemini AI enrichment for IOC context, MITRE mapping, and response recommendations."""

from __future__ import annotations

import asyncio
import os
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from threatfeed.types.ioc import IOC, ThreatReport


async def _call_gemini(prompt: str, model: str = "gemini-1.5-flash") -> str:
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        return ""
    try:
        import google.generativeai as genai
        genai.configure(api_key=api_key)
        gmodel = genai.GenerativeModel(model)
        loop = asyncio.get_event_loop()
        response = await loop.run_in_executor(None, lambda: gmodel.generate_content(prompt))
        return response.text.strip()
    except Exception:
        return ""


async def enrich_ioc(ioc: "IOC") -> None:
    """Add AI summary and recommendations to a single IOC."""
    sources_str = ", ".join(ioc.sources) if ioc.sources else "unknown"
    cats = ", ".join(c.value for c in ioc.threat_categories) if ioc.threat_categories else "unknown"
    families = ", ".join(ioc.malware_families[:5]) if ioc.malware_families else "none identified"
    vt_str = f"{ioc.vt_positives}/{ioc.vt_total} AV engines" if ioc.vt_positives else "N/A"

    prompt = f"""You are a threat intelligence analyst. Analyze this IOC and provide a concise security assessment.

IOC: {ioc.value}
Type: {ioc.ioc_type.value}
Severity: {ioc.severity.value}
Confidence: {ioc.confidence:.0%}
Sources: {sources_str}
Threat categories: {cats}
Malware families: {families}
VirusTotal: {vt_str}
AbuseIPDB score: {ioc.abuse_score if ioc.abuse_score is not None else 'N/A'}
Country: {ioc.country or 'unknown'}
Tags: {', '.join(ioc.tags[:8]) if ioc.tags else 'none'}

Provide:
1. A 2-3 sentence threat context (what this IOC is, why it's dangerous, who uses it)
2. 3 specific defensive recommendations (firewall rules, detection signatures, hunting queries)

Format:
CONTEXT: <2-3 sentence analysis>
RECOMMEND:
- <rec 1>
- <rec 2>
- <rec 3>"""

    response = await _call_gemini(prompt)
    if not response:
        return

    # Parse response
    context_part = ""
    recs: list[str] = []
    in_recs = False

    for line in response.splitlines():
        line = line.strip()
        if line.startswith("CONTEXT:"):
            context_part = line[8:].strip()
        elif line.startswith("RECOMMEND:"):
            in_recs = True
        elif in_recs and line.startswith("- "):
            recs.append(line[2:].strip())
        elif in_recs and line and not line.startswith("-"):
            if context_part and not recs:
                context_part += " " + line
            elif recs:
                recs[-1] += " " + line

    if context_part:
        ioc.ai_summary = context_part
    if recs:
        ioc.recommendations = recs[:3]


async def enrich_report(report: "ThreatReport", max_iocs: int = 10) -> None:
    """Enrich top IOCs with AI context and generate overall threat summary."""
    sem = asyncio.Semaphore(3)

    async def safe_enrich(ioc: "IOC") -> None:
        async with sem:
            await enrich_ioc(ioc)

    # Enrich top N by severity
    top_iocs = report.sorted_iocs()[:max_iocs]
    await asyncio.gather(*[safe_enrich(ioc) for ioc in top_iocs])

    # Generate overall threat summary
    if not report.iocs:
        return

    summary_data = report.summary
    sev_breakdown = (
        f"{summary_data['critical']} critical, {summary_data['high']} high, "
        f"{summary_data['medium']} medium"
    )

    # Gather top threat actors/families from all IOCs
    all_families: list[str] = []
    all_cats: set[str] = set()
    for ioc in report.iocs[:30]:
        all_families.extend(ioc.malware_families)
        for c in ioc.threat_categories:
            all_cats.add(c.value)

    top_families = sorted(set(all_families), key=all_families.count, reverse=True)[:5]

    prompt = f"""You are a senior threat intelligence analyst writing an executive summary.

Threat feed scan results:
- Total IOCs: {summary_data['total']}
- Severity breakdown: {sev_breakdown}
- IPs: {summary_data['ips']}, Domains: {summary_data['domains']}, File hashes: {summary_data['hashes']}
- Sources: {', '.join(report.sources_queried)}
- Threat categories observed: {', '.join(sorted(all_cats))}
- Malware families detected: {', '.join(top_families) if top_families else 'none identified'}

Write a 3-4 sentence executive summary covering:
1. Overall threat level assessment
2. Most significant threat types observed
3. Immediate recommended action for the security team

Be direct and actionable. No fluff."""

    summary = await _call_gemini(prompt)
    if summary:
        report.ai_threat_summary = summary
