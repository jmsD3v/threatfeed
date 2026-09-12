"""
ThreatFeed CLI

Commands:
  threatfeed lookup <ioc> [ioc...]     -- enrich one or more IOCs across all feeds
  threatfeed file <path>               -- read IOCs from file (one per line)
  threatfeed recent [--days N]         -- pull recent IOCs from ThreatFox (no key needed)
  threatfeed report <ioc|file> -o out  -- enrich + generate HTML/PDF report
  threatfeed feeds                     -- list available feeds and API key status

Usage:
  threatfeed lookup 185.220.101.42 evil.com
  threatfeed lookup d41d8cd98f00b204e9800998ecf8427e --type file_hash
  threatfeed file /path/to/iocs.txt --output report.html
  threatfeed recent --days 1 --limit 100
  threatfeed feeds
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from typing import Optional

import typer
from dotenv import load_dotenv
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

load_dotenv()

app = typer.Typer(
    name="threatfeed",
    help="D-02 CTI Aggregator — multi-source threat intelligence with AI enrichment.",
    add_completion=False,
)
console = Console()


def _banner() -> None:
    console.print(Panel(
        "[bold red]ThreatFeed[/bold red]  [bright_black]v0.1.0 — CTI Aggregator[/bright_black]\n"
        "[bright_black]D-02 — Defensive portfolio project | Sources: ThreatFox, Shodan, AbuseIPDB, VT, OTX[/bright_black]",
        border_style="bright_black",
        padding=(0, 2),
    ))


def _make_aggregator():
    from threatfeed.core.aggregator import ThreatAggregator
    return ThreatAggregator()


def _print_iocs(iocs) -> None:
    if not iocs:
        console.print("[yellow]No malicious IOCs found across all feeds.[/yellow]")
        return

    table = Table(
        title=f"Threat Intelligence Results — {len(iocs)} IOCs",
        show_header=True, header_style="bold",
    )
    table.add_column("Sev", width=9)
    table.add_column("Type", width=10)
    table.add_column("Value", width=38)
    table.add_column("Sources", width=22)
    table.add_column("Categories", width=22)
    table.add_column("VT", width=8)
    table.add_column("Abuse", width=6)
    table.add_column("Country", width=7)

    for ioc in iocs:
        sev_color = ioc.severity.color
        vt_str = f"{ioc.vt_positives}/{ioc.vt_total}" if ioc.vt_positives is not None else "-"
        abuse_str = str(ioc.abuse_score) if ioc.abuse_score is not None else "-"
        cats = ", ".join(c.value for c in ioc.threat_categories[:2])
        srcs = ", ".join(ioc.sources[:3])

        table.add_row(
            f"[{sev_color}]{ioc.severity.value.upper()}[/{sev_color}]",
            ioc.ioc_type.value,
            ioc.value[:38],
            srcs[:22],
            cats[:22],
            vt_str,
            abuse_str,
            ioc.country or "-",
        )
    console.print(table)

    # Show AI summaries for top IOCs
    for ioc in iocs[:3]:
        if ioc.ai_summary:
            console.print()
            console.print(Panel(
                f"{ioc.ai_summary}\n\n"
                + ("\n".join(f"  -> {r}" for r in ioc.recommendations) if ioc.recommendations else ""),
                title=f"[purple]AI Analysis — {ioc.value}[/purple]",
                border_style="purple",
            ))


def _print_summary(report) -> None:
    s = report.summary
    console.print(
        f"\n[bright_black]"
        f"{s['total']} IOCs — "
        f"{s['critical']} critical, {s['high']} high, {s['medium']} medium — "
        f"sources: {', '.join(report.sources_queried)} — "
        f"{report.duration_seconds:.1f}s"
        f"[/bright_black]"
    )
    if report.ai_threat_summary:
        console.print()
        console.print(Panel(
            report.ai_threat_summary,
            title="[cyan]Executive Threat Summary[/cyan]",
            border_style="cyan",
        ))


@app.command()
def lookup(
    iocs: list[str] = typer.Argument(..., help="IOC values to look up (IP, domain, hash, URL)"),
    ioc_type: Optional[str] = typer.Option(None, "--type", "-t",
                                            help="Force type: ip|domain|url|file_hash"),
    no_ai: bool = typer.Option(False, "--no-ai", help="Skip AI enrichment"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Save JSON output"),
    fmt: str = typer.Option("html", "--format", "-f", help="Report format: html|pdf (with -o)"),
) -> None:
    """Look up IOCs across ThreatFox, Shodan, AbuseIPDB, VirusTotal, OTX."""
    _banner()

    aggregator = _make_aggregator()
    values = [(v, ioc_type) if ioc_type else v for v in iocs]

    console.print(f"[cyan]Querying {len(iocs)} IOC(s) across available feeds...[/cyan]\n")

    report = asyncio.run(_run_with_ai(aggregator, iocs, no_ai))
    _print_iocs(report.sorted_iocs())
    _print_summary(report)

    if output:
        _save_output(report, output, fmt)


@app.command()
def file(
    path: Path = typer.Argument(..., help="File with one IOC per line"),
    no_ai: bool = typer.Option(False, "--no-ai"),
    output: Optional[Path] = typer.Option(None, "--output", "-o"),
    fmt: str = typer.Option("html", "--format", "-f"),
    skip_comments: bool = typer.Option(True, "--skip-comments", help="Skip lines starting with #"),
) -> None:
    """Read IOCs from a file (one per line) and enrich them all."""
    _banner()

    if not path.exists():
        console.print(f"[red]File not found: {path}[/red]")
        raise typer.Exit(1)

    lines = path.read_text(encoding="utf-8").splitlines()
    ioc_values = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        if skip_comments and line.startswith("#"):
            continue
        ioc_values.append(line)

    if not ioc_values:
        console.print("[yellow]No IOCs found in file.[/yellow]")
        raise typer.Exit(0)

    console.print(f"[cyan]Loaded {len(ioc_values)} IOCs from {path.name}[/cyan]\n")

    aggregator = _make_aggregator()
    report = asyncio.run(_run_with_ai(aggregator, ioc_values, no_ai))
    _print_iocs(report.sorted_iocs())
    _print_summary(report)

    if output:
        _save_output(report, output, fmt)


@app.command()
def recent(
    days: int = typer.Option(1, "--days", "-d", help="How many days back to fetch"),
    limit: int = typer.Option(100, "--limit", "-l", help="Max IOCs to fetch"),
    no_ai: bool = typer.Option(False, "--no-ai"),
    output: Optional[Path] = typer.Option(None, "--output", "-o"),
    fmt: str = typer.Option("html", "--format", "-f"),
    min_severity: str = typer.Option("medium", "--min-severity",
                                      help="Filter: critical|high|medium|low|info"),
) -> None:
    """Fetch recent IOCs from ThreatFox (no API key required)."""
    _banner()
    console.print(f"[cyan]Fetching last {days} day(s) of IOCs from ThreatFox (limit {limit})...[/cyan]\n")

    from threatfeed.core.aggregator import ThreatAggregator
    from threatfeed.types.ioc import ThreatReport, Severity

    aggregator = ThreatAggregator()

    async def _run():
        report = ThreatReport()
        report.sources_queried = ["threatfox"]
        import time
        start = time.perf_counter()
        iocs = await aggregator.fetch_recent(days=days, limit=limit)
        # Filter by severity
        sev_order = ["critical", "high", "medium", "low", "info"]
        min_idx = sev_order.index(min_severity) if min_severity in sev_order else 2
        filtered = [i for i in iocs if sev_order.index(i.severity.value) <= min_idx]
        report.iocs = filtered
        report.duration_seconds = time.perf_counter() - start
        if not no_ai and filtered:
            from threatfeed.analyzers.ai_enricher import enrich_report
            await enrich_report(report, max_iocs=5)
        return report

    report = asyncio.run(_run())
    _print_iocs(report.sorted_iocs())
    _print_summary(report)

    if output:
        _save_output(report, output, fmt)


@app.command()
def feeds() -> None:
    """Show available feeds and their API key status."""
    import os
    _banner()

    feed_info = [
        ("ThreatFox (abuse.ch)", "N/A — free", True, "IP, domain, URL, hash"),
        ("Shodan InternetDB", "N/A — free", True, "IP only"),
        ("AbuseIPDB", "ABUSEIPDB_API_KEY", bool(os.getenv("ABUSEIPDB_API_KEY")), "IP only"),
        ("VirusTotal", "VIRUSTOTAL_API_KEY", bool(os.getenv("VIRUSTOTAL_API_KEY")), "IP, domain, URL, hash"),
        ("AlienVault OTX", "OTX_API_KEY", bool(os.getenv("OTX_API_KEY")), "IP, domain, URL, hash"),
    ]

    table = Table(title="Available CTI Feeds", show_header=True, header_style="bold")
    table.add_column("Feed", width=22)
    table.add_column("API Key", width=22)
    table.add_column("Status", width=10)
    table.add_column("IOC Types", width=28)

    for name, key_var, available, types in feed_info:
        status = "[green]ACTIVE[/green]" if available else "[red]NO KEY[/red]"
        table.add_row(name, key_var, status, types)

    console.print(table)
    console.print("\n[dim]Add keys to .env to unlock premium feeds.[/dim]")
    console.print("[dim]Even without keys, ThreatFox + Shodan give solid free coverage.[/dim]")


async def _run_with_ai(aggregator, ioc_values: list[str], no_ai: bool):
    from threatfeed.types.ioc import ThreatReport
    import time

    report = ThreatReport()
    start = time.perf_counter()

    feeds_used = ["threatfox", "shodan_internetdb"]
    import os
    if os.getenv("ABUSEIPDB_API_KEY"):
        feeds_used.append("abuseipdb")
    if os.getenv("VIRUSTOTAL_API_KEY"):
        feeds_used.append("virustotal")
    if os.getenv("OTX_API_KEY"):
        feeds_used.append("otx")
    report.sources_queried = feeds_used

    report.iocs = await aggregator.enrich_many(ioc_values)
    report.duration_seconds = time.perf_counter() - start

    if not no_ai and report.iocs:
        from threatfeed.analyzers.ai_enricher import enrich_report
        await enrich_report(report, max_iocs=10)

    return report


def _save_output(report, output: Path, fmt: str) -> None:
    from threatfeed.report.generator import generate_html, generate_pdf

    if fmt == "json":
        output.write_text(json.dumps(report.to_dict(), indent=2, default=str), encoding="utf-8")
        console.print(f"\n[green]JSON saved -> {output}[/green]")
    elif fmt == "pdf":
        out = generate_pdf(report, output.with_suffix(".pdf"))
        console.print(f"\n[green]PDF report saved -> {out}[/green]")
    else:
        out = generate_html(report, output.with_suffix(".html"))
        console.print(f"\n[green]HTML report saved -> {out}[/green]")


if __name__ == "__main__":
    app()
