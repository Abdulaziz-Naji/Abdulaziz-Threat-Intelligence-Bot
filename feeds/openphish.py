"""
feeds/openphish.py - OpenPhish phishing URL feed.

API: GET https://openphish.com/feed.txt  (plain-text, one URL per line)

Metrics tracked on self:
  raw_fetched_count : total non-empty lines
  parsed_ioc_count  : total IOCs emitted (URL + extracted host)
  rejected_count    : lines skipped (empty or non-http)
  last_http_status  : HTTP status code
"""
import httpx
from urllib.parse import urlparse
from typing import List
from feeds.base import FeedBase, FeedEntry
import config
import logging

logger = logging.getLogger(__name__)

_MAX_LINES   = 200
_VALID_SCHEMES = {"http", "https"}


def _is_ip(host: str) -> bool:
    """Return True if host looks like a bare IPv4 address."""
    parts = host.split(".")
    if len(parts) != 4:
        return False
    return all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


class OpenPhishFeed(FeedBase):
    name         = "openphish"
    display_name = "OpenPhish"
    tier         = 2

    async def fetch(self) -> List[FeedEntry]:
        url     = "https://openphish.com/feed.txt"
        entries: List[FeedEntry] = []

        try:
            logger.info(f"[OpenPhish] GET {url}")
            async with httpx.AsyncClient(**self._client_kwargs(timeout=30)) as client:
                resp = await client.get(url)

            self.last_http_status = resp.status_code
            logger.info(f"[OpenPhish] HTTP {resp.status_code}")

            if resp.status_code != 200:
                msg = f"[OpenPhish] HTTP {resp.status_code}: {resp.text[:300]}"
                logger.error(msg)
                raise RuntimeError(msg)

            lines = [l.strip() for l in resp.text.splitlines() if l.strip()]
            self.raw_fetched_count = len(lines)
            logger.info(f"[OpenPhish] raw lines fetched: {self.raw_fetched_count}")

            for line in lines[:_MAX_LINES]:
                parsed = urlparse(line)
                if parsed.scheme not in _VALID_SCHEMES:
                    self.rejected_count += 1
                    if config.FEED_DEBUG_MODE:
                        logger.debug(f"[OpenPhish] REJECT invalid scheme: {line!r}")
                    continue

                # URL IOC
                entries.append(FeedEntry(
                    ioc=line,
                    ioc_type="url",
                    source=self.name,
                    threat_category="phishing",
                    risk_score=80,
                    confidence=85,
                    tags=["phish"],
                    raw_data={"url": line},
                ))

                # Extract host as secondary IOC
                try:
                    host = parsed.netloc.split(":")[0].strip()
                    if host:
                        ioc_type = "ip" if _is_ip(host) else "domain"
                        entries.append(FeedEntry(
                            ioc=host,
                            ioc_type=ioc_type,
                            source=self.name,
                            threat_category="phishing",
                            risk_score=75,
                            confidence=80,
                            tags=["phish"],
                            raw_data={"url": line},
                        ))
                except Exception:
                    pass  # Non-fatal

            self.parsed_ioc_count = len(entries)
            logger.info(
                f"[OpenPhish] parsed={self.parsed_ioc_count} "
                f"rejected={self.rejected_count} "
                f"(of {self.raw_fetched_count} raw lines)"
            )

        except Exception as exc:
            logger.error(f"[OpenPhish] fetch() exception: {exc}")
            raise

        return entries
