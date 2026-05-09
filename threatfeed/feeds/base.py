"""Base class for all CTI feed providers."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

import httpx

from threatfeed.types.ioc import IOC


class BaseFeed(ABC):
    """Abstract CTI feed provider."""

    name: str = "base"
    requires_api_key: bool = False
    supports_bulk: bool = False

    def __init__(self, api_key: str | None = None, timeout: int = 15):
        self.api_key = api_key
        self.timeout = timeout
        self._client: httpx.AsyncClient | None = None

    async def __aenter__(self) -> "BaseFeed":
        self._client = httpx.AsyncClient(
            timeout=self.timeout,
            headers=self._default_headers(),
            follow_redirects=True,
        )
        return self

    async def __aexit__(self, *_: Any) -> None:
        if self._client:
            await self._client.aclose()

    def _default_headers(self) -> dict[str, str]:
        return {
            "User-Agent": "ThreatFeed/0.1 (CTI Aggregator - authorized research)",
            "Accept": "application/json",
        }

    @abstractmethod
    async def lookup(self, value: str, ioc_type: str) -> IOC | None:
        """Look up a single IOC value. Returns enriched IOC or None if not found."""

    async def bulk_lookup(self, values: list[tuple[str, str]]) -> list[IOC]:
        """Look up multiple IOCs. Default: sequential lookup."""
        results = []
        for value, ioc_type in values:
            try:
                ioc = await self.lookup(value, ioc_type)
                if ioc:
                    results.append(ioc)
            except Exception:
                pass
        return results

    def is_available(self) -> bool:
        if self.requires_api_key and not self.api_key:
            return False
        return True
