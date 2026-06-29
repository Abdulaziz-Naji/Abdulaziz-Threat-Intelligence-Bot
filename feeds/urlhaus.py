"""
feeds/urlhaus.py - URLHaus (Abuse.ch) malicious URL feed.

API: GET https://urlhaus-api.abuse.ch/v1/urls/recent/
     Header: Auth-Key: <ABUSE_CH_API_KEY>

NOTE: URLHaus API v1 requires GET with Auth-Key header (not POST).
      POST returns HTTP 405 "http_get_expected".

Metrics tracked on self:
  raw_fetched_count : URL entries returned by the API
  parsed_ioc_count  : valid IOCs emitted (URL + extracted host)
  rejected_count    : items dropped (empty/missing url field)
  last_http_status  : HTTP status code
"""
import httpx
from urllib.parse import urlparse
from typing import List
from feeds.base import FeedBase, FeedEntry
import config
import logging

logger = logging.getLogger(__name__)


def _is_ip(host: str) -> bool:
    """Return True if host looks like a bare IPv4 address."""
    parts = host.split(".")
    if len(parts) != 4:
        return False
    return all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


class URLHausFeed(FeedBase):
    name         = "urlhaus"
    display_name = "URLHaus"
    tier         = 1

    async def fetch(self) -> List[FeedEntry]:
        url = "https://urlhaus-api.abuse.ch/v1/urls/recent/"

        if not config.HAS_ABUSE_CH:
            raise RuntimeError(
                "Abuse.ch API key (ABUSE_CH_API_KEY) not configured. URLHaus requires it."
            )

        headers = {"Auth-Key": config.ABUSE_CH_API_KEY}
        entries: List[FeedEntry] = []

        try:
            logger.info(f"[URLHaus] GET {url}")
            async with httpx.AsyncClient(**self._client_kwargs(timeout=30)) as client:
                resp = await client.get(url, headers=headers)

            self.last_http_status = resp.status_code
            logger.info(f"[URLHaus] HTTP {resp.status_code}")

            if resp.status_code == 401:
                raise RuntimeError("[URLHaus] 401 Unauthorized — check ABUSE_CH_API_KEY.")
            if resp.status_code == 405:
                raise RuntimeError(
                    "[URLHaus] 405 Method Not Allowed — ensure using GET with Auth-Key header."
                )
            if resp.status_code != 200:
                msg = f"[URLHaus] HTTP {resp.status_code}: {resp.text[:300]}"
                logger.error(msg)
                raise RuntimeError(msg)

            json_data    = resp.json()
            query_status = json_data.get("query_status", "")
            logger.info(f"[URLHaus] query_status={query_status!r}")

            if query_status != "ok":
                msg = f"[URLHaus] Unexpected query_status={query_status!r}"
                logger.error(msg)
                if config.FEED_DEBUG_MODE:
                    logger.debug(f"[URLHaus] Full payload:\n{json_data}")
                raise RuntimeError(msg)

            raw_items = json_data.get("urls") or []
            if not isinstance(raw_items, list):
                raise RuntimeError(
                    f"[URLHaus] Expected 'urls' list, got {type(raw_items).__name__}"
                )

            self.raw_fetched_count = len(raw_items)
            logger.info(f"[URLHaus] raw items fetched: {self.raw_fetched_count}")

            for item in raw_items:
                mal_url = item.get("url")
                if not mal_url or not isinstance(mal_url, str):
                    self.rejected_count += 1
                    if config.FEED_DEBUG_MODE:
                        logger.debug(f"[URLHaus] REJECT missing url: {item}")
                    continue

                mal_url = mal_url.strip()
                threat  = str(item.get("threat") or "malware").strip()
                tags    = item.get("tags") or []
                if not isinstance(tags, list):
                    tags = [str(tags)]

                # URL IOC
                entries.append(FeedEntry(
                    ioc=mal_url,
                    ioc_type="url",
                    source=self.name,
                    threat_category=threat,
                    risk_score=85,
                    confidence=90,
                    tags=tags,
                    raw_data=item,
                ))

                # Extract host as secondary IOC
                try:
                    parsed = urlparse(mal_url)
                    host   = parsed.netloc.split(":")[0].strip() if parsed.netloc else ""
                    if host:
                        ioc_type = "ip" if _is_ip(host) else "domain"
                        entries.append(FeedEntry(
                            ioc=host,
                            ioc_type=ioc_type,
                            source=self.name,
                            threat_category=threat,
                            risk_score=80,
                            confidence=85,
                            tags=tags,
                            raw_data=item,
                        ))
                except Exception:
                    pass  # Non-fatal

            self.parsed_ioc_count = len(entries)
            logger.info(
                f"[URLHaus] parsed={self.parsed_ioc_count} "
                f"rejected={self.rejected_count} "
                f"(of {self.raw_fetched_count} raw)"
            )

        except Exception as exc:
            logger.error(f"[URLHaus] fetch() exception: {exc}")
            raise

        return entries
