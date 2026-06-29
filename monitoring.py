"""
monitoring.py - Background jobs for feed polling and watchlist re-checking.

Feeds are ingested silently (no Telegram notifications ever sent).
All metrics are persisted to feed_sources for analyst review via /feeddebug.
"""
import asyncio
import logging

import config
import database as db
import api_clients as api
import report_builder as rb

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════════════
#  IOC Watchlist Monitor
# ═══════════════════════════════════════════════════════════════════════════════

async def run_watchlist_monitor(context) -> None:
    """Periodically re-checks all active watchlist IOCs and updates DB state."""
    watchlist = db.get_watchlist()

    if not watchlist:
        return

    logger.info(f"[Monitor] Checking {len(watchlist)} watchlist IOCs...")

    for item in watchlist:
        ioc      = item["ioc"]
        ioc_type = item["ioc_type"]

        try:
            new_vt_mal = 0
            new_abuse  = 0
            new_otx    = 0

            if ioc_type == "ip":
                vt_data, abuse_data, otx_data, _ = await asyncio.gather(
                    api.vt_check_ip(ioc),
                    api.abuseipdb_check(ioc),
                    api.otx_check_ip(ioc),
                    api.geoip_lookup(ioc),
                )
                new_vt_mal = vt_data.get("malicious", 0)
                new_abuse  = abuse_data.get("abuse_score", 0)
                new_otx    = otx_data.get("pulse_count", 0)
                ts = rb.compute_threat_score(
                    new_vt_mal, vt_data.get("suspicious", 0), new_abuse, new_otx
                )

            elif ioc_type == "domain":
                vt_data, otx_data = await asyncio.gather(
                    api.vt_check_domain(ioc),
                    api.otx_check_domain(ioc),
                )
                new_vt_mal = vt_data.get("malicious", 0)
                new_otx    = otx_data.get("pulse_count", 0)
                ts = rb.compute_threat_score(
                    new_vt_mal, vt_data.get("suspicious", 0), 0, new_otx
                )

            elif ioc_type in ("md5", "sha1", "sha256"):
                vt_data, otx_data = await asyncio.gather(
                    api.vt_check_hash(ioc),
                    api.otx_check_hash(ioc),
                )
                new_vt_mal = vt_data.get("malicious", 0)
                new_otx    = otx_data.get("pulse_count", 0)
                ts = rb.compute_threat_score(
                    new_vt_mal, vt_data.get("suspicious", 0), 0, new_otx
                )

            else:
                continue

            new_risk, _ = rb.risk_level(ts)
            db.update_watchlist_state(ioc, new_risk, new_vt_mal, new_abuse, new_otx)

        except Exception as e:
            logger.error(f"[Monitor] Error checking {ioc}: {e}")

        await asyncio.sleep(1)


# ═══════════════════════════════════════════════════════════════════════════════
#  Threat Feed Polling Job — silent ingestion only, no Telegram output
# ═══════════════════════════════════════════════════════════════════════════════

async def poll_feed_job(context) -> None:
    """
    Generic job to poll a single threat feed.
    Ingests IOCs silently into the database. Never sends Telegram messages.
    Full diagnostic counters are stored in feed_sources for /feeddebug.
    """
    job  = context.job
    feed = job.data

    logger.info(f"[Feeds] Polling {feed.display_name}...")
    db.register_feed_source(feed.name, feed.display_name, feed.tier)

    try:
        entries = await feed.fetch()

        new_count      = 0
        inserted_count = 0

        for entry in entries:
            try:
                res = db.upsert_feed_entry(
                    ioc=entry.ioc,
                    ioc_type=entry.ioc_type,
                    source=entry.source,
                    threat_category=entry.threat_category,
                    risk_score=entry.risk_score,
                    confidence=entry.confidence,
                    tags=entry.tags,
                    raw_data=entry.raw_data,
                )
                inserted_count += 1
                if res.get("action") in ("new", "new_source"):
                    new_count += 1
            except Exception as upsert_err:
                logger.error(
                    f"[Feeds] DB upsert failed for {entry.ioc} ({feed.name}): {upsert_err}"
                )

        # Persist all diagnostic counters
        db.update_feed_source_status(
            name=feed.name,
            status="ok",
            new_entries=new_count,
            last_http_status=getattr(feed, "last_http_status", None),
            raw_fetched_count=getattr(feed, "raw_fetched_count", len(entries)),
            parsed_ioc_count=getattr(feed, "parsed_ioc_count", len(entries)),
            rejected_count=getattr(feed, "rejected_count", 0),
            inserted_db_count=inserted_count,
        )

        logger.info(
            f"[Feeds] {feed.display_name}: "
            f"fetched={getattr(feed, 'raw_fetched_count', '?')} "
            f"parsed={getattr(feed, 'parsed_ioc_count', '?')} "
            f"rejected={getattr(feed, 'rejected_count', '?')} "
            f"inserted={inserted_count} "
            f"new={new_count}"
        )

    except Exception as e:
        logger.error(f"[Feeds] Error polling {feed.display_name}: {e}")

        if config.FEED_DEBUG_MODE:
            import traceback
            logger.debug(f"[Feeds] Full traceback for {feed.display_name}:\n{traceback.format_exc()}")

        db.update_feed_source_status(
            name=feed.name,
            status="error",
            error_msg=str(e)[:500],
            last_http_status=getattr(feed, "last_http_status", None),
            raw_fetched_count=getattr(feed, "raw_fetched_count", None),
            parsed_ioc_count=getattr(feed, "parsed_ioc_count", None),
            rejected_count=getattr(feed, "rejected_count", 0),
            inserted_db_count=0,
        )
