"""
main.py - Threat Intelligence Assistant — Entry Point

Architecture:
  config.py         → Environment & API key loading
  database.py       → SQLite persistence (history, watchlist, feeds, alerts)
  ioc_classifier.py → Auto-detect IOC type
  api_clients.py    → Async clients: VT, AbuseIPDB, OTX, GeoIP, DNS, RDAP, feeds
  report_builder.py → Threat score, risk level, formatted HTML reports
  monitoring.py     → Background jobs: watchlist monitor + feed poller
  handlers/
    start.py        → /start, /help
    check.py        → /check <ioc>   (primary command)
    monitor.py      → /monitor, /remove
    watchlist.py    → /watchlist
    stats.py        → /stats
    history.py      → /history
    callbacks.py    → Inline keyboard callbacks

Future integration stubs:
  - MISP, OpenCTI, TheHive, Wazuh, Sentinel, Elastic SIEM
"""
import sys
import logging
import config

# Force UTF-8 output so box-drawing / emoji don't crash on Windows CP1256
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

# ── Validate config early ─────────────────────────────────────────────────────
config.validate()

from telegram.ext import (
    Application,
    CommandHandler,
    CallbackQueryHandler,
    MessageHandler,
    filters,
)

import database as db
import monitoring

from handlers.start     import start_handler, help_handler
from handlers.check     import check_handler
from handlers.monitor   import monitor_handler, remove_handler
from handlers.watchlist import watchlist_handler
from handlers.stats     import stats_handler
from handlers.history   import history_handler
from handlers.callbacks import callback_handler

from handlers.feeds_cmd import feeds_command, feedstatus_command, feedsource_command, feeddebug_command
from handlers.threats_cmd import threats_command, hunt_command
from handlers.soc_cmd import (
    iocstats_command,
    topmalware_command,
    topcountries_command,
    topasns_command,
    topfeeds_command,
)
from handlers.file_cmd import file_handler
from handlers.username_cmd import username_handler
from handlers.email_cmd import email_command, header_command
from handlers.phishing_cmd import phish_command
from handlers.investigate_cmd import investigate_command
from handlers.message_router import smart_router
from handlers.dfir_cmd import (
    dfir_handler,
    timeline_handler,
    iocs_handler,
    casereport_handler,
)
from handlers.case_workbench_cmd import (
    newcase_command,
    case_command,
    cases_command,
    note_command,
    mode_command,
    graph_command,
)
from handlers.auto_dfir_handler import auto_dfir_handler
from handlers.malware_cmd import malware_command
from handlers.actor_cmd   import actor_command, actors_command
from handlers.cve_cmd     import cve_command
from handlers.news_cmd    import news_command
from handlers.brief_cmd   import brief_command
from handlers.insta_cmd   import insta_command
from handlers.tik_cmd     import tik_command

# ─── Logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    level=logging.INFO,
)
logging.getLogger("httpx").setLevel(logging.WARNING)
logger = logging.getLogger(__name__)


from http.server import BaseHTTPRequestHandler
import json
import datetime

class HealthCheckHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/health":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            now_utc = datetime.datetime.now(datetime.timezone.utc).isoformat()
            response = {
                "status": "ok",
                "service": "Threat Intelligence Bot",
                "version": "1.0",
                "timestamp": now_utc
            }
            self.wfile.write(json.dumps(response).encode("utf-8"))
        else:
            self.send_response(404)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Not Found")
            
    def log_message(self, format, *args):
        pass  # suppress log spam


def run_dummy_server():
    import os
    port = int(os.getenv("PORT", "8080"))
    try:
        from http.server import HTTPServer
        server = HTTPServer(("0.0.0.0", port), HealthCheckHandler)
        logger.info(f"🟢 Health check server listening on port {port}")
        logger.info("Health endpoint available:\nGET /health")
        server.serve_forever()
    except Exception as e:
        logger.error(f"🔴 Failed to start health check server: {e}")


def main():
    # ── Start health check server for Render compatibility ────────────────────
    import threading
    threading.Thread(target=run_dummy_server, daemon=True).start()

    # ── Init DB ───────────────────────────────────────────────────────────────
    db.init_db()
    logger.info("✅ Database initialized.")

    # ── Build application ─────────────────────────────────────────────────────
    app = Application.builder().token(config.TELEGRAM_BOT_TOKEN).build()

    # ── Store config in bot_data ──────────────────────────────────────────────
    app.bot_data["admin_users"]      = list(config.AUTHORIZED_USERS)
    app.bot_data["monitor_interval"] = config.MONITOR_INTERVAL_MINUTES

    # ── Register command handlers ─────────────────────────────────────────────
    app.add_handler(CommandHandler("start",     start_handler))
    app.add_handler(CommandHandler("help",      help_handler))
    app.add_handler(CommandHandler("check",     check_handler))
    app.add_handler(CommandHandler("monitor",   monitor_handler))
    app.add_handler(CommandHandler("remove",    remove_handler))
    app.add_handler(CommandHandler("watchlist", watchlist_handler))
    app.add_handler(CommandHandler("stats",     stats_handler))
    app.add_handler(CommandHandler("history",   history_handler))
    
    app.add_handler(CommandHandler("feeds",        feeds_command))
    app.add_handler(CommandHandler("feedstatus",   feedstatus_command))
    app.add_handler(CommandHandler("feedsource",   feedsource_command))
    app.add_handler(CommandHandler("feeddebug",    feeddebug_command))
    app.add_handler(CommandHandler("threats",      threats_command))
    app.add_handler(CommandHandler("topthreats",   threats_command))
    app.add_handler(CommandHandler("hunt",         hunt_command))
    app.add_handler(CommandHandler("file",         file_handler))
    app.add_handler(CommandHandler("username",     username_handler))
    app.add_handler(CommandHandler("email",        email_command))
    app.add_handler(CommandHandler("header",       header_command))
    app.add_handler(CommandHandler("phish",        phish_command))
    app.add_handler(CommandHandler("investigate",  investigate_command))
    # SOC Operations Dashboard
    app.add_handler(CommandHandler("iocstats",     iocstats_command))
    app.add_handler(CommandHandler("topmalware",   topmalware_command))
    app.add_handler(CommandHandler("topcountries", topcountries_command))
    app.add_handler(CommandHandler("topasns",      topasns_command))
    app.add_handler(CommandHandler("topfeeds",     topfeeds_command))
    # DFIR Investigation Platform
    app.add_handler(CommandHandler("dfir",         dfir_handler))
    app.add_handler(CommandHandler("timeline",     timeline_handler))
    app.add_handler(CommandHandler("iocs",         iocs_handler))
    app.add_handler(CommandHandler("casereport",   casereport_handler))
    # Case Engine & Analyst Workbench (Phase 5 & 6)
    app.add_handler(CommandHandler("newcase",      newcase_command))
    app.add_handler(CommandHandler("case",         case_command))
    app.add_handler(CommandHandler("cases",        cases_command))
    app.add_handler(CommandHandler("note",         note_command))
    app.add_handler(CommandHandler("mode",         mode_command))
    app.add_handler(CommandHandler("graph",        graph_command))
    # Phase 3 — Threat Intelligence Platform
    app.add_handler(CommandHandler("malware",      malware_command))
    app.add_handler(CommandHandler("actor",        actor_command))
    app.add_handler(CommandHandler("actors",       actors_command))
    app.add_handler(CommandHandler("cve",          cve_command))
    app.add_handler(CommandHandler("news",         news_command))
    app.add_handler(CommandHandler("brief",        brief_command))
    # Social Media Intelligence
    app.add_handler(CommandHandler("insta",        insta_command))
    app.add_handler(CommandHandler("tik",          tik_command))

    # ── AUTONOMOUS DFIR: Auto-fires on ANY file upload (no command needed) ────
    # Placed BEFORE text router so file uploads bypass command handling entirely
    app.add_handler(MessageHandler(
        filters.Document.ALL | filters.PHOTO,
        auto_dfir_handler,
    ))

    # ── Register smart input router MessageHandler ────────────────────────────
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, smart_router))

    # ── Register inline keyboard callback handler ─────────────────────────────
    app.add_handler(CallbackQueryHandler(callback_handler))

    # ── Register background jobs ──────────────────────────────────────────────
    job_queue = app.job_queue

    # Watchlist monitor: runs every MONITOR_INTERVAL_MINUTES
    job_queue.run_repeating(
        monitoring.run_watchlist_monitor,
        interval=config.MONITOR_INTERVAL_MINUTES * 60,
        first=60,
        name="watchlist_monitor",
    )
    logger.info(f"📡 Watchlist monitor scheduled every {config.MONITOR_INTERVAL_MINUTES} min.")

    # Ingest threat feeds with their respective intervals
    from feeds import ALL_FEEDS
    for feed, interval in ALL_FEEDS:
        job_queue.run_repeating(
            monitoring.poll_feed_job,
            interval=interval,
            first=10,
            name=f"feed_poll_{feed.name}",
            data=feed,
        )
        logger.info(f"🌐 Feed '{feed.display_name}' scheduled every {interval}s.")

    # ── Print startup banner ──────────────────────────────────────────────────
    print("=" * 65)
    print("  AUTONOMOUS DFIR & Threat Intelligence Platform")
    print("=" * 65)
    print("  🤖 AUTO-DFIR: Upload ANY file → instant forensic report")
    print("  📁 Supported: PDF, ZIP, EXE, PCAP, DOCX, APK, Images, ...")
    print("  🔬 No command needed. Just upload.")
    print("-" * 65)
    print("  DFIR Commands (manual):")
    print("    /dfir        -- DFIR investigation (with caption on file)")
    print("    /timeline    -- Attack timeline for last DFIR case")
    print("    /iocs        -- Export IOCs extracted from last DFIR case")
    print("    /casereport  -- Full investigator report (multi-page)")
    print("  SOC Intelligence Commands:")
    print("    /check       -- Unified external IOC lookup")
    print("    /hunt        -- Correlation & feed sightings search")
    print("    /file        -- Deep File Static & Metadata OSINT")
    print("    /username    -- Multi-platform username OSINT")
    print("    /email       -- MX/SPF validation + breach check")
    print("    /header      -- Email header originating IP analysis")
    print("    /phish       -- SOC phishing analysis engine")
    print("    /investigate -- Auto-detected multi-module search")
    print("    /feeds       -- Threat feed health diagnostics")
    print("    /iocstats    -- SOC Operations Dashboard")
    print("=" * 65)
    logger.info("Bot started. Polling for updates...")

    app.run_polling(drop_pending_updates=True)


if __name__ == "__main__":
    main()
