"""
feeds/threatfox.py - ThreatFox (Abuse.ch) IOC feed.

API: POST https://threatfox-api.abuse.ch/api/v1/
     {"query": "get_iocs", "days": 1}

Metrics tracked on self:
  raw_fetched_count : items returned by the API
  parsed_ioc_count  : items that passed validation
  rejected_count    : items dropped (missing/invalid fields)
  last_http_status  : HTTP status code of the last request
"""
import httpx
from typing import List
from feeds.base import FeedBase, FeedEntry
import config
import logging

logger = logging.getLogger(__name__)


class ThreatFoxFeed(FeedBase):
    name         = "threatfox"
    display_name = "ThreatFox"
    tier         = 1

    # ── Type-normalisation map ─────────────────────────────────────────────────
    _TYPE_MAP = {
        "ip:port":   "ip",
        "domain":    "domain",
        "url":       "url",
        "sha256_hash": "sha256",
        "md5_hash":  "md5",
    }

    async def fetch(self) -> List[FeedEntry]:
        if not config.HAS_ABUSE_CH:
            raise RuntimeError(
                "Abuse.ch API key (ABUSE_CH_API_KEY) not configured. ThreatFox requires it."
            )

        url     = "https://threatfox-api.abuse.ch/api/v1/"
        payload = {"query": "get_iocs", "days": 1}
        headers = {"Auth-Key": config.ABUSE_CH_API_KEY}

        entries: List[FeedEntry] = []

        try:
            logger.info(f"[ThreatFox] POST {url} payload={payload}")
            async with httpx.AsyncClient(**self._client_kwargs(timeout=30)) as client:
                resp = await client.post(url, json=payload, headers=headers)

            self.last_http_status = resp.status_code
            logger.info(f"[ThreatFox] HTTP {resp.status_code}")

            if resp.status_code != 200:
                raw_snippet = resp.text[:300]
                msg = f"[ThreatFox] HTTP {resp.status_code}: {raw_snippet}"
                logger.error(msg)
                if config.FEED_DEBUG_MODE:
                    logger.debug(f"[ThreatFox] Full raw response:\n{resp.text}")
                raise RuntimeError(msg)

            json_data = resp.json()
            query_status = json_data.get("query_status", "")
            logger.info(f"[ThreatFox] query_status={query_status!r}")

            if query_status != "ok":
                msg = f"[ThreatFox] Unexpected query_status={query_status!r}"
                logger.error(msg)
                if config.FEED_DEBUG_MODE:
                    logger.debug(f"[ThreatFox] Full payload:\n{json_data}")
                raise RuntimeError(msg)

            raw_items = json_data.get("data") or []
            if not isinstance(raw_items, list):
                raise RuntimeError(
                    f"[ThreatFox] Expected 'data' to be a list, got {type(raw_items).__name__}"
                )

            self.raw_fetched_count = len(raw_items)
            logger.info(f"[ThreatFox] raw items fetched: {self.raw_fetched_count}")

            for item in raw_items:
                raw_ioc  = item.get("ioc")
                raw_type = item.get("ioc_type")

                # ── Strict null / type validation ──────────────────────────────
                if not raw_ioc or not isinstance(raw_ioc, str):
                    self.rejected_count += 1
                    if config.FEED_DEBUG_MODE:
                        logger.debug(f"[ThreatFox] REJECT no ioc field: {item}")
                    continue
                if not raw_type or not isinstance(raw_type, str):
                    self.rejected_count += 1
                    if config.FEED_DEBUG_MODE:
                        logger.debug(f"[ThreatFox] REJECT no ioc_type field: {item}")
                    continue

                # ── Normalise type ─────────────────────────────────────────────
                ioc_type = self._TYPE_MAP.get(raw_type)
                if ioc_type is None:
                    self.rejected_count += 1
                    if config.FEED_DEBUG_MODE:
                        logger.debug(
                            f"[ThreatFox] REJECT unknown type={raw_type!r} for ioc={raw_ioc!r}"
                        )
                    continue

                # ── Extract IOC value ──────────────────────────────────────────
                ioc = raw_ioc.strip()
                if raw_type == "ip:port":
                    # Strip port suffix — store bare IP only
                    ioc = raw_ioc.split(":")[0].strip()

                if not ioc:
                    self.rejected_count += 1
                    continue

                family = str(item.get("malware_printable") or "Unknown Malware").strip()
                tags   = item.get("tags") or []
                if not isinstance(tags, list):
                    tags = [str(tags)]

                entries.append(FeedEntry(
                    ioc=ioc,
                    ioc_type=ioc_type,
                    source=self.name,
                    threat_category=family,
                    risk_score=85,
                    confidence=90,
                    tags=tags,
                    raw_data=item,
                ))

            self.parsed_ioc_count = len(entries)
            logger.info(
                f"[ThreatFox] parsed={self.parsed_ioc_count} "
                f"rejected={self.rejected_count} "
                f"(of {self.raw_fetched_count} raw)"
            )

        except Exception as exc:
            logger.error(f"[ThreatFox] fetch() exception: {exc}")
            raise

        return entries
