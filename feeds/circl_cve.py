"""
feeds/circl_cve.py - CIRCL (Luxembourg) recent CVE feed.

API: GET https://cve.circl.lu/api/last

Schema (CVE 5.x format):
  {
    "dataType": "CVE_RECORD",
    "cveMetadata": { "cveId": "CVE-2026-XXXXX", ... },
    "containers": { "cna": { "descriptions": [...], "metrics": [...] } }
  }

NOTE: The top-level "id" field is null in CVE 5.x responses.
      The CVE ID lives at cveMetadata.cveId.
      CVSS score lives at containers.cna.metrics[*].cvssV3_1.baseScore

Metrics tracked on self:
  raw_fetched_count : total entries in the response array
  parsed_ioc_count  : valid CVE entries emitted
  rejected_count    : items dropped (missing cveId or non-CVE format)
  last_http_status  : HTTP status code
"""
import httpx
from typing import List, Optional
from feeds.base import FeedBase, FeedEntry
import config
import logging

logger = logging.getLogger(__name__)

_MAX_ENTRIES = 100


def _extract_cvss(item: dict) -> Optional[float]:
    """
    Extract CVSS base score from CVE 5.x containers structure.
    Tries cvssV3_1, then cvssV3_0, then cvssV2_0.
    Returns float or None.
    """
    try:
        cna = item.get("containers", {}).get("cna", {})
        metrics = cna.get("metrics", [])
        for m in metrics:
            for key in ("cvssV3_1", "cvssV3_0", "cvssV4_0", "cvssV2_0"):
                score = m.get(key, {}).get("baseScore")
                if score is not None:
                    return float(score)
    except Exception:
        pass
    return None


def _extract_description(item: dict) -> str:
    """Extract English description from CVE 5.x containers.cna.descriptions."""
    try:
        cna = item.get("containers", {}).get("cna", {})
        for desc in cna.get("descriptions", []):
            if desc.get("lang", "").lower().startswith("en"):
                return str(desc.get("value", ""))[:200]
    except Exception:
        pass
    return "No description available."


class CIRCLCVEFeed(FeedBase):
    name         = "circl_cve"
    display_name = "CIRCL CVE Feed"
    tier         = 1

    async def fetch(self) -> List[FeedEntry]:
        url     = "https://cve.circl.lu/api/last"
        entries: List[FeedEntry] = []

        try:
            logger.info(f"[CIRCL CVE] GET {url}")
            async with httpx.AsyncClient(**self._client_kwargs(timeout=60)) as client:
                resp = await client.get(url)

            self.last_http_status = resp.status_code
            logger.info(f"[CIRCL CVE] HTTP {resp.status_code}")

            if resp.status_code != 200:
                msg = f"[CIRCL CVE] HTTP {resp.status_code}: {resp.text[:300]}"
                logger.error(msg)
                raise RuntimeError(msg)

            data = resp.json()
            if not isinstance(data, list):
                raise RuntimeError(
                    f"[CIRCL CVE] Expected JSON array at root, got {type(data).__name__}"
                )

            self.raw_fetched_count = len(data)
            logger.info(f"[CIRCL CVE] raw CVEs fetched: {self.raw_fetched_count}")

            for item in data[:_MAX_ENTRIES]:
                # CVE 5.x: ID lives in cveMetadata.cveId (not top-level id)
                cve_meta = item.get("cveMetadata") or {}
                cve = (
                    cve_meta.get("cveId")          # CVE 5.x format
                    or item.get("id")               # Legacy format fallback
                    or item.get("CVE_data_meta", {}).get("ID")  # CVE 4.x
                )

                if not cve or not isinstance(cve, str):
                    self.rejected_count += 1
                    if config.FEED_DEBUG_MODE:
                        logger.debug(f"[CIRCL CVE] REJECT no cveId found: keys={list(item.keys())}")
                    continue

                cve = cve.strip().upper()
                if not cve.startswith("CVE-"):
                    self.rejected_count += 1
                    if config.FEED_DEBUG_MODE:
                        logger.debug(f"[CIRCL CVE] REJECT non-CVE id: {cve!r}")
                    continue

                # Extract CVSS score and compute risk
                cvss = _extract_cvss(item)
                try:
                    risk_score = max(0, min(100, int(float(cvss) * 10))) if cvss is not None else 50
                except (TypeError, ValueError):
                    risk_score = 50

                description = _extract_description(item)
                tags = [f"cvss_{cvss:.1f}"] if cvss is not None else []

                # Add state tag if available
                state = cve_meta.get("state", "")
                if state:
                    tags.append(state.lower())

                entries.append(FeedEntry(
                    ioc=cve,
                    ioc_type="cve",
                    source=self.name,
                    threat_category="vulnerability",
                    risk_score=risk_score,
                    confidence=90,
                    tags=tags,
                    raw_data={"cveId": cve, "description": description, "cvss": cvss},
                ))

            self.parsed_ioc_count = len(entries)
            logger.info(
                f"[CIRCL CVE] parsed={self.parsed_ioc_count} "
                f"rejected={self.rejected_count} "
                f"(of {self.raw_fetched_count} raw)"
            )

        except Exception as exc:
            logger.error(f"[CIRCL CVE] fetch() exception: {exc}")
            raise

        return entries
