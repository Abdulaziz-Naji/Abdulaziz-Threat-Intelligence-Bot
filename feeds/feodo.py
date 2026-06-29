"""
feeds/feodo.py - Feodo Tracker botnet C2 IP blocklist feed.

API: GET https://feodotracker.abuse.ch/downloads/ipblocklist.json

Metrics tracked on self:
  raw_fetched_count : total entries in the JSON array
  parsed_ioc_count  : valid IPs emitted
  rejected_count    : items dropped (missing ip_address field)
  last_http_status  : HTTP status code
"""
import httpx
from typing import List
from feeds.base import FeedBase, FeedEntry
import config
import logging

logger = logging.getLogger(__name__)

# Cap at 200 to avoid flooding the DB on a large list refresh
_MAX_ENTRIES = 200


class FeodoFeed(FeedBase):
    name         = "feodo"
    display_name = "Feodo Tracker"
    tier         = 1

    async def fetch(self) -> List[FeedEntry]:
        url     = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
        entries: List[FeedEntry] = []

        try:
            logger.info(f"[Feodo] GET {url}")
            async with httpx.AsyncClient(**self._client_kwargs(timeout=30)) as client:
                resp = await client.get(url)

            self.last_http_status = resp.status_code
            logger.info(f"[Feodo] HTTP {resp.status_code}")

            if resp.status_code != 200:
                msg = f"[Feodo] HTTP {resp.status_code}: {resp.text[:300]}"
                logger.error(msg)
                raise RuntimeError(msg)

            data = resp.json()
            if not isinstance(data, list):
                raise RuntimeError(
                    f"[Feodo] Expected JSON array at root, got {type(data).__name__}"
                )

            self.raw_fetched_count = len(data)
            logger.info(f"[Feodo] raw items fetched: {self.raw_fetched_count}")

            for item in data[:_MAX_ENTRIES]:
                ip = item.get("ip_address")
                if not ip or not isinstance(ip, str):
                    self.rejected_count += 1
                    if config.FEED_DEBUG_MODE:
                        logger.debug(f"[Feodo] REJECT missing ip_address: {item}")
                    continue

                ip      = ip.strip()
                malware = str(item.get("malware") or "Botnet C2").strip()
                as_name = str(item.get("as_name") or "unknown").strip()
                country = str(item.get("country") or "unknown").strip()

                entries.append(FeedEntry(
                    ioc=ip,
                    ioc_type="ip",
                    source=self.name,
                    threat_category=malware,
                    risk_score=95,
                    confidence=95,
                    tags=[as_name, country],
                    raw_data=item,
                ))

            self.parsed_ioc_count = len(entries)
            logger.info(
                f"[Feodo] parsed={self.parsed_ioc_count} "
                f"rejected={self.rejected_count} "
                f"(of {self.raw_fetched_count} raw)"
            )

        except Exception as exc:
            logger.error(f"[Feodo] fetch() exception: {exc}")
            raise

        return entries
