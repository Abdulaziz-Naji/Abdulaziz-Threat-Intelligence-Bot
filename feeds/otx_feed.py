"""
feeds/otx_feed.py - AlienVault OTX pulse activity feed.

API: GET https://otx.alienvault.com/api/v1/pulses/activity
     Header: X-OTX-API-KEY

Metrics tracked on self:
  raw_fetched_count : total pulses returned
  parsed_ioc_count  : total IOC entries emitted across all pulses
  rejected_count    : indicators dropped (unknown type / empty value)
  last_http_status  : HTTP status code
"""
import httpx
from typing import List
from feeds.base import FeedBase, FeedEntry
import config
import logging

logger = logging.getLogger(__name__)


# Supported OTX indicator type → normalised ioc_type
_OTX_TYPE_MAP = {
    "IPv4":              "ip",
    "IPv6":              "ip",
    "domain":            "domain",
    "hostname":          "domain",
    "URL":               "url",
    "FileHash-SHA256":   "sha256",
    "FileHash-MD5":      "md5",
    "FileHash-SHA1":     "sha1",
}


class OTXFeed(FeedBase):
    name         = "otx"
    display_name = "AlienVault OTX"
    tier         = 1

    async def fetch(self) -> List[FeedEntry]:
        if not config.HAS_OTX:
            raise RuntimeError(
                "AlienVault OTX API key (OTX_API_KEY) not configured. OTX requires it."
            )

        url     = "https://otx.alienvault.com/api/v1/pulses/activity"
        headers = {"X-OTX-API-KEY": config.OTX_API_KEY}

        entries: List[FeedEntry] = []

        try:
            logger.info(f"[OTX] GET {url}")
            async with httpx.AsyncClient(**self._client_kwargs(timeout=30)) as client:
                resp = await client.get(url, headers=headers)

            self.last_http_status = resp.status_code
            logger.info(f"[OTX] HTTP {resp.status_code}")

            if resp.status_code != 200:
                msg = f"[OTX] HTTP {resp.status_code}: {resp.text[:300]}"
                logger.error(msg)
                if config.FEED_DEBUG_MODE:
                    logger.debug(f"[OTX] Full response:\n{resp.text}")
                raise RuntimeError(msg)

            data   = resp.json()
            pulses = data.get("results") or []
            if not isinstance(pulses, list):
                raise RuntimeError(f"[OTX] Expected 'results' list, got {type(pulses).__name__}")

            self.raw_fetched_count = len(pulses)
            logger.info(f"[OTX] raw pulses fetched: {self.raw_fetched_count}")

            for pulse in pulses:
                pulse_name = str(pulse.get("name") or "OTX Pulse").strip()
                pulse_id   = str(pulse.get("id") or "unknown")
                tags       = pulse.get("tags") or []
                if not isinstance(tags, list):
                    tags = [str(tags)]

                for ind in (pulse.get("indicators") or []):
                    ind_type = ind.get("type")
                    value    = ind.get("indicator")

                    if not value or not isinstance(value, str):
                        self.rejected_count += 1
                        continue

                    value = value.strip()
                    if not value:
                        self.rejected_count += 1
                        continue

                    # Normalise type — reject unknowns
                    ioc_type = None
                    for key, mapped in _OTX_TYPE_MAP.items():
                        if key in str(ind_type):
                            ioc_type = mapped
                            break

                    if ioc_type is None:
                        self.rejected_count += 1
                        if config.FEED_DEBUG_MODE:
                            logger.debug(
                                f"[OTX] REJECT unknown indicator type={ind_type!r} value={value!r}"
                            )
                        continue

                    entries.append(FeedEntry(
                        ioc=value,
                        ioc_type=ioc_type,
                        source=self.name,
                        threat_category=pulse_name,
                        risk_score=75,
                        confidence=80,
                        tags=tags + [f"pulse_{pulse_id}"],
                        raw_data=ind,
                    ))

            self.parsed_ioc_count = len(entries)
            logger.info(
                f"[OTX] parsed={self.parsed_ioc_count} "
                f"rejected={self.rejected_count} "
                f"(of {self.raw_fetched_count} pulses)"
            )

        except Exception as exc:
            logger.error(f"[OTX] fetch() exception: {exc}")
            raise

        return entries
