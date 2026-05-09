"""ThreatFeed — D-02 CTI Aggregator with multi-source IOC enrichment and AI analysis."""

from threatfeed.types.ioc import IOC, IOCType, ThreatCategory, ThreatReport, Severity
from threatfeed.core.aggregator import ThreatAggregator

__version__ = "0.1.0"
__all__ = ["ThreatAggregator", "IOC", "IOCType", "ThreatCategory", "ThreatReport", "Severity"]
