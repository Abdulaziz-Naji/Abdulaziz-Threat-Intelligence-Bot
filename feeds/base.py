"""
feeds/base.py - Abstract base class for all feed collectors.
"""
from abc import ABC, abstractmethod
from typing import List, Dict


class FeedEntry:
    """Normalized IOC entry returned by every feed."""
    __slots__ = (
        "ioc", "ioc_type", "source", "threat_category",
        "risk_score", "confidence", "tags", "raw_data",
    )

    def __init__(
        self,
        ioc: str,
        ioc_type: str,
        source: str,
        threat_category: str = "",
        risk_score: int = 50,
        confidence: int = 70,
        tags: list = None,
        raw_data: dict = None,
    ):
        self.ioc             = ioc.strip()
        self.ioc_type        = ioc_type
        self.source          = source
        self.threat_category = threat_category
        self.risk_score      = risk_score
        self.confidence      = confidence
        self.tags            = tags or []
        self.raw_data        = raw_data or {}


class FeedBase(ABC):
    """Abstract base class for all threat feed collectors."""

    name: str         = "base"
    display_name: str = "Base Feed"
    tier: int         = 1

    def __init__(self):
        self.last_http_status: int  = None
        self.raw_fetched_count: int = 0
        self.parsed_ioc_count: int  = 0
        self.rejected_count: int    = 0
        self.inserted_db_count: int = 0

    @abstractmethod
    async def fetch(self) -> List[FeedEntry]:
        """Fetch and parse the feed. Returns a list of FeedEntry objects."""
        ...

    def _client_kwargs(self, timeout: int = 20) -> dict:
        """Common httpx client kwargs."""
        return {"timeout": timeout, "follow_redirects": True}
