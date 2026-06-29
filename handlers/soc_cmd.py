"""
handlers/soc_cmd.py — SOC Operations Dashboard Commands

Commands:
  /iocstats   — IOC type breakdown + activity metrics
  /topmalware — Top malware families by detection count
  /topcountries — Top countries by malicious IP origin
  /topasns    — Top ASNs associated with malicious IPs
  /topfeeds   — Top feed sources by IOC volume
"""
from telegram import Update
from telegram.ext import ContextTypes
from telegram.constants import ParseMode
import database as db
import html as html_lib


# ─── Helper ───────────────────────────────────────────────────────────────────

def _bar(value: int, max_val: int, width: int = 12) -> str:
    """Render a simple ASCII progress bar."""
    if max_val == 0:
        return "░" * width
    filled = int((value / max_val) * width)
    return "█" * filled + "░" * (width - filled)


# ─── /iocstats ────────────────────────────────────────────────────────────────

async def iocstats_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """/iocstats - Full IOC statistics dashboard."""
    stats = db.get_stats()
    counts_24h = db.get_feed_count_by_type(hours=24)
    counts_7d  = db.get_feed_count_by_type(hours=168)

    sources = db.get_all_feed_sources()
    ok_feeds     = sum(1 for s in sources if s.get("status") == "ok")
    error_feeds  = sum(1 for s in sources if s.get("status") == "error")
    total_feeds  = len(sources)

    # From user queries
    total_queries = stats.get("total", 0)
    high_risk     = stats.get("high_risk", 0)
    watchlist_cnt = stats.get("watchlist", 0)
    alerts_cnt    = stats.get("alerts", 0)
    feed_total    = stats.get("feed_iocs", 0)

    # 24h breakdown
    h24_hashes  = counts_24h.get("sha256", 0) + counts_24h.get("sha1", 0) + counts_24h.get("md5", 0)
    h24_ips     = counts_24h.get("ip", 0)
    h24_domains = counts_24h.get("domain", 0)
    h24_urls    = counts_24h.get("url", 0)
    h24_cves    = counts_24h.get("cve", 0)
    h24_total   = h24_hashes + h24_ips + h24_domains + h24_urls + h24_cves

    # 7d breakdown
    d7_hashes  = counts_7d.get("sha256", 0) + counts_7d.get("sha1", 0) + counts_7d.get("md5", 0)
    d7_ips     = counts_7d.get("ip", 0)
    d7_domains = counts_7d.get("domain", 0)
    d7_urls    = counts_7d.get("url", 0)
    d7_cves    = counts_7d.get("cve", 0)

    msg = (
        f"📊 <b>SOC IOC Statistics Dashboard</b>\n"
        f"━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
        f"<b>🗂 Feed Database:</b>\n"
        f"  • Total IOCs collected: <code>{feed_total:,}</code>\n"
        f"  • Active feeds: <b>{ok_feeds}/{total_feeds}</b>  ❌ Errors: <b>{error_feeds}</b>\n\n"
        f"<b>📈 Last 24 Hours:</b>\n"
        f"  🔒 Hashes:  <b>{h24_hashes:,}</b>\n"
        f"  🌐 IPs:     <b>{h24_ips:,}</b>\n"
        f"  🔗 Domains: <b>{h24_domains:,}</b>\n"
        f"  🔗 URLs:    <b>{h24_urls:,}</b>\n"
        f"  ⚠️ CVEs:    <b>{h24_cves:,}</b>\n"
        f"  ─────────────\n"
        f"  📦 Total:   <b>{h24_total:,}</b>\n\n"
        f"<b>📅 Last 7 Days:</b>\n"
        f"  🔒 Hashes:  <b>{d7_hashes:,}</b>\n"
        f"  🌐 IPs:     <b>{d7_ips:,}</b>\n"
        f"  🔗 Domains: <b>{d7_domains:,}</b>\n"
        f"  🔗 URLs:    <b>{d7_urls:,}</b>\n"
        f"  ⚠️ CVEs:    <b>{d7_cves:,}</b>\n\n"
        f"<b>🔍 Analyst Activity:</b>\n"
        f"  • Total queries: <code>{total_queries:,}</code>\n"
        f"  • High/Critical results: <code>{high_risk:,}</code>\n"
        f"  • Watchlist entries: <code>{watchlist_cnt}</code>\n"
        f"  • Alerts generated: <code>{alerts_cnt:,}</code>\n\n"
        f"━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"<i>Use /topmalware, /topcountries, /topfeeds for breakdowns.</i>"
    )
    await update.message.reply_text(msg, parse_mode=ParseMode.HTML)


# ─── /topmalware ──────────────────────────────────────────────────────────────

async def topmalware_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """/topmalware - Top malware families by detection count."""
    # Try 7 days for richer data
    families_7d  = db.get_top_malware_families(limit=10, hours=168)
    families_24h = db.get_top_malware_families(limit=10, hours=24)

    if not families_7d:
        await update.message.reply_text(
            "🦠 <b>Top Malware Families</b>\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
            "⚪ <i>No malware family data available yet.</i>\n\n"
            "<i>Feeds with malware classification: MalwareBazaar, ThreatFox, OTX</i>",
            parse_mode=ParseMode.HTML
        )
        return

    max_cnt = families_7d[0]["cnt"] if families_7d else 1
    lines = []
    for idx, f in enumerate(families_7d, 1):
        name = html_lib.escape(str(f.get("threat_category", "Unknown"))[:40])
        cnt  = f["cnt"]
        bar  = _bar(cnt, max_cnt)
        lines.append(f"  {idx:2}. <b>{name}</b>\n      {bar} <code>{cnt}</code>")

    # 24h comparison
    fam_24h_map = {f["threat_category"]: f["cnt"] for f in families_24h}

    msg = (
        f"🦠 <b>Top Malware Families (7 Days)</b>\n"
        f"━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
        + "\n\n".join(lines)
        + "\n\n<i>Active in last 24h: "
        + ", ".join(html_lib.escape(f["threat_category"]) for f in families_24h[:3])
        + "</i>"
    )
    await update.message.reply_text(msg, parse_mode=ParseMode.HTML)


# ─── /topcountries ────────────────────────────────────────────────────────────

async def topcountries_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """/topcountries - Top countries by malicious IP origin (from ioc_history)."""
    countries = db.get_top_countries(limit=10)

    if not countries:
        await update.message.reply_text(
            "🌍 <b>Top Countries</b>\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
            "⚪ <i>No geolocation data available yet.</i>\n\n"
            "<i>Run /check on IPs to populate country data.</i>",
            parse_mode=ParseMode.HTML
        )
        return

    max_cnt = countries[0]["cnt"] if countries else 1
    lines = []
    flag_map = {
        "US": "🇺🇸", "RU": "🇷🇺", "CN": "🇨🇳", "DE": "🇩🇪", "NL": "🇳🇱",
        "FR": "🇫🇷", "GB": "🇬🇧", "BR": "🇧🇷", "IN": "🇮🇳", "UA": "🇺🇦",
        "KP": "🇰🇵", "IR": "🇮🇷", "RO": "🇷🇴", "TR": "🇹🇷", "VN": "🇻🇳",
        "SG": "🇸🇬", "HK": "🇭🇰", "CA": "🇨🇦", "JP": "🇯🇵", "KR": "🇰🇷",
    }
    for idx, row in enumerate(countries, 1):
        country = str(row.get("country") or "Unknown")[:30]
        cnt  = row["cnt"]
        bar  = _bar(cnt, max_cnt)
        flag = flag_map.get(country.upper(), "🌐")
        lines.append(f"  {idx:2}. {flag} <b>{html_lib.escape(country)}</b>\n      {bar} <code>{cnt}</code>")

    msg = (
        f"🌍 <b>Top Countries — Threat Origin</b>\n"
        f"━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
        + "\n\n".join(lines)
        + "\n\n<i>Based on IOC history from /check queries.</i>"
    )
    await update.message.reply_text(msg, parse_mode=ParseMode.HTML)


# ─── /topasns ────────────────────────────────────────────────────────────────

async def topasns_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """/topasns - Top ASNs associated with malicious IPs."""
    asns = db.get_top_asns(limit=10)

    if not asns:
        await update.message.reply_text(
            "🌐 <b>Top ASNs</b>\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
            "⚪ <i>No ASN data available yet.</i>\n\n"
            "<i>Run /check on IPs to populate ASN data.</i>",
            parse_mode=ParseMode.HTML
        )
        return

    max_cnt = asns[0]["cnt"] if asns else 1
    lines = []
    for idx, row in enumerate(asns, 1):
        asn = html_lib.escape(str(row.get("asn") or "Unknown")[:50])
        cnt = row["cnt"]
        bar = _bar(cnt, max_cnt)
        lines.append(f"  {idx:2}. <code>{asn}</code>\n      {bar} <code>{cnt}</code>")

    msg = (
        f"🌐 <b>Top ASNs — Threat Infrastructure</b>\n"
        f"━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
        + "\n\n".join(lines)
        + "\n\n<i>Based on IOC history from /check queries.</i>"
    )
    await update.message.reply_text(msg, parse_mode=ParseMode.HTML)


# ─── /topfeeds ────────────────────────────────────────────────────────────────

async def topfeeds_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """/topfeeds - Top threat feed sources by IOC volume."""
    sources = db.get_all_feed_sources()

    if not sources:
        await update.message.reply_text(
            "📡 <b>Top Threat Feeds</b>\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
            "⚪ <i>No feeds registered yet.</i>",
            parse_mode=ParseMode.HTML
        )
        return

    # Sort by total entries descending
    ranked = sorted(sources, key=lambda s: s.get("entries_total", 0), reverse=True)
    max_total = ranked[0]["entries_total"] if ranked else 1

    lines = []
    for idx, s in enumerate(ranked[:10], 1):
        total   = s.get("entries_total", 0)
        new24h  = s.get("entries_new_24h", 0)
        status  = s.get("status", "unknown")
        bar     = _bar(total, max(max_total, 1))
        s_em    = "🟢" if status == "ok" else "🔴" if status == "error" else "🟡"
        name    = html_lib.escape(s.get("display_name", s["name"]))
        lines.append(
            f"  {idx:2}. {s_em} <b>{name}</b> (T{s['tier']})\n"
            f"      {bar} Total: <code>{total:,}</code>  |  24h: <code>{new24h}</code>"
        )

    total_iocs = sum(s.get("entries_total", 0) for s in sources)
    ok_count   = sum(1 for s in sources if s.get("status") == "ok")

    msg = (
        f"📡 <b>Top Threat Feed Sources</b>\n"
        f"━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"Active: <b>{ok_count}/{len(sources)}</b>  |  Total IOCs: <code>{total_iocs:,}</code>\n"
        f"━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
        + "\n\n".join(lines)
        + "\n\n<i>Use /feedstatus for full health details.</i>"
    )
    await update.message.reply_text(msg, parse_mode=ParseMode.HTML)
