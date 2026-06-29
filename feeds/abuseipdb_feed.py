"""
feeds/abuseipdb_feed.py - AbuseIPDB blacklist feed.

API: GET https://api.abuseipdb.com/api/v2/blacklist
     Header: Key: <ABUSEIPDB_API_KEY>
     Params: confidenceMinimum=75, limit=200

Metrics tracked on self:
  raw_fetched_count : total entries in the response data array
  parsed_ioc_count  : valid IPs emitted
  rejected_count    : items dropped (missing ipAddress field)
  last_http_status  : HTTP status code
"""
import httpx
from typing import List
from feeds.base import FeedBase, FeedEntry
import config
import logging

logger = logging.getLogger(__name__)


class AbuseIPDBFeed(FeedBase):
    name         = "abuseipdb"
    display_name = "AbuseIPDB Blacklist"
    tier         = 1

    async def fetch(self) -> List[FeedEntry]:
        if not config.HAS_ABUSEIPDB:
            logger.info("[AbuseIPDB] ABUSEIPDB_API_KEY not configured — skipping.")
            return []

        url     = "https://api.abuseipdb.com/api/v2/blacklist"
        headers = {
            "Key":    config.ABUSEIPDB_API_KEY,
            "Accept": "application/json",
        }
        params  = {"confidenceMinimum": 75, "limit": 200}
        entries: List[FeedEntry] = []

        try:
            logger.info(f"[AbuseIPDB] GET {url}")
            async with httpx.AsyncClient(**self._client_kwargs(timeout=30)) as client:
                resp = await client.get(url, headers=headers, params=params)

            self.last_http_status = resp.status_code
            logger.info(f"[AbuseIPDB] HTTP {resp.status_code}")

            if resp.status_code == 401:
                raise RuntimeError("[AbuseIPDB] 401 Unauthorized — check ABUSEIPDB_API_KEY.")
            if resp.status_code == 429:
                raise RuntimeError("[AbuseIPDB] 429 Too Many Requests — rate limit hit.")
            if resp.status_code != 200:
                msg = f"[AbuseIPDB] HTTP {resp.status_code}: {resp.text[:300]}"
                logger.error(msg)
                raise RuntimeError(msg)

            data_list = resp.json().get("data") or []
            if not isinstance(data_list, list):
                raise RuntimeError(
                    f"[AbuseIPDB] Expected 'data' list, got {type(data_list).__name__}"
                )

            self.raw_fetched_count = len(data_list)
            logger.info(f"[AbuseIPDB] raw items fetched: {self.raw_fetched_count}")

            for item in data_list:
                ip = item.get("ipAddress")
                if not ip or not isinstance(ip, str):
                    self.rejected_count += 1
                    if config.FEED_DEBUG_MODE:
                        logger.debug(f"[AbuseIPDB] REJECT missing ipAddress: {item}")
                    continue

                ip    = ip.strip()
                score = int(item.get("abuseConfidenceScore") or 75)

                entries.append(FeedEntry(
                    ioc=ip,
                    ioc_type="ip",
                    source=self.name,
                    threat_category="recon/abuse",
                    risk_score=score,
                    confidence=score,
                    tags=[f"abuse_score_{score}"],
                    raw_data=item,
                ))

            self.parsed_ioc_count = len(entries)
            logger.info(
                f"[AbuseIPDB] parsed={self.parsed_ioc_count} "
                f"rejected={self.rejected_count} "
                f"(of {self.raw_fetched_count} raw)"
            )

        except Exception as exc:
            logger.error(f"[AbuseIPDB] fetch() exception: {exc}")
            raise

        return entries
