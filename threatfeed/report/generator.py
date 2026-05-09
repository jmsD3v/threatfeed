"""HTML + PDF report generator for ThreatFeed scan results."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from threatfeed.types.ioc import ThreatReport

_TEMPLATE_DIR = Path(__file__).parent
_VERSION = "0.1.0"


def _duration_str(seconds: float) -> str:
    if seconds < 60:
        return f"{seconds:.1f}s"
    m, s = divmod(int(seconds), 60)
    return f"{m}m {s}s"


def _build_context(report: ThreatReport) -> dict:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    iocs_data = []
    for ioc in report.sorted_iocs():
        d = ioc.to_dict()
        # flatten for template
        d["threat_categories"] = [c for c in d.get("threat_categories", [])]
        iocs_data.append(d)

    return {
        "scan_time": now,
        "duration": _duration_str(report.duration_seconds),
        "sources_queried": report.sources_queried,
        "summary": report.summary,
        "ai_threat_summary": report.ai_threat_summary,
        "iocs": iocs_data,
        "version": _VERSION,
    }


def generate_html(report: ThreatReport, output_path: str | Path) -> Path:
    """Render ThreatReport to HTML. Returns path to written file."""
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)

    env = Environment(loader=FileSystemLoader(str(_TEMPLATE_DIR)), autoescape=True)
    # Add 'in' test for Jinja2 (selectattr with 'in' operator)
    env.tests["in"] = lambda value, collection: value in collection

    template = env.get_template("template.html")
    html = template.render(**_build_context(report))
    output.write_text(html, encoding="utf-8")
    return output


def generate_pdf(report: ThreatReport, output_path: str | Path) -> Path:
    """Render ThreatReport to PDF via WeasyPrint. Falls back to HTML if unavailable."""
    output = Path(output_path)

    try:
        import weasyprint  # type: ignore
    except ImportError:
        html_path = output.with_suffix(".html")
        return generate_html(report, html_path)

    html_path = output.with_suffix(".html")
    generate_html(report, html_path)
    weasyprint.HTML(filename=str(html_path)).write_pdf(str(output))
    return output
