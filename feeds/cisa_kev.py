"""
feeds/cisa_kev.py - CISA Known Exploited Vulnerabilities (KEV) feed.

API: GET https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json

Metrics tracked on self:
  raw_fetched_count : total CVEs in the JSON
  parsed_ioc_count  : valid CVE entries emitted
  rejected_count    : items dropped (missing cveID)
  last_http_status  : HTTP status code
"""
import httpx
from typing import List
from feeds.base import FeedBase, FeedEntry
import config
import logging

logger = logging.getLogger(__name__)

_MAX_ENTRIES = 100  # Most recent N after sort


class CISAKevFeed(FeedBase):
    name         = "cisa_kev"
    display_name = "CISA KEV"
    tier         = 1

    async def fetch(self) -> List[FeedEntry]:
        url     = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        entries: List[FeedEntry] = []

        try:
            logger.info(f"[CISA KEV] GET {url}")
            async with httpx.AsyncClient(**self._client_kwargs(timeout=60)) as client:
                resp = await client.get(url)

            self.last_http_status = resp.status_code
            logger.info(f"[CISA KEV] HTTP {resp.status_code}")

            if resp.status_code != 200:
                msg = f"[CISA KEV] HTTP {resp.status_code}: {resp.text[:300]}"
                logger.error(msg)
                raise RuntimeError(msg)

            data  = resp.json()
            vulns = data.get("vulnerabilities") or []
            if not isinstance(vulns, list):
                raise RuntimeError(
                    f"[CISA KEV] Expected 'vulnerabilities' list, got {type(vulns).__name__}"
                )

            # Sort newest first
            try:
                vulns.sort(key=lambda x: x.get("dateAdded", ""), reverse=True)
            except Exception as sort_err:
                logger.warning(f"[CISA KEV] Could not sort by dateAdded: {sort_err}")

            self.raw_fetched_count = len(vulns)
            logger.info(f"[CISA KEV] raw CVEs fetched: {self.raw_fetched_count}")

            for vuln in vulns[:_MAX_ENTRIES]:
                cve = vuln.get("cveID")
                if not cve or not isinstance(cve, str):
                    self.rejected_count += 1
                    if config.FEED_DEBUG_MODE:
                        logger.debug(f"[CISA KEV] REJECT missing cveID: {vuln}")
                    continue

                cve         = cve.strip().upper()
                vendor      = str(vuln.get("vendorProject") or "Unknown").strip()
                product     = str(vuln.get("product") or "Unknown").strip()
                vuln_name   = str(vuln.get("vulnerabilityName") or "Exploited Vulnerability").strip()
                date_added  = str(vuln.get("dateAdded") or "unknown")

                entries.append(FeedEntry(
                    ioc=cve,
                    ioc_type="cve",
                    source=self.name,
                    threat_category=vuln_name,
                    risk_score=95,
                    confidence=100,
                    tags=[f"{vendor} {product}".strip(), date_added],
                    raw_data=vuln,
                ))

            self.parsed_ioc_count = len(entries)
            logger.info(
                f"[CISA KEV] parsed={self.parsed_ioc_count} "
                f"rejected={self.rejected_count} "
                f"(of {self.raw_fetched_count} raw)"
            )

        except Exception as exc:
            logger.error(f"[CISA KEV] fetch() exception: {exc}")
            raise

        return entries
