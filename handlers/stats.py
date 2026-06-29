"""
handlers/stats.py - /stats SOC dashboard command.
"""
from telegram import Update
from telegram.ext import ContextTypes
from telegram.constants import ParseMode
from datetime import datetime

import database as db


async def stats_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    s = db.get_stats()
    history = db.get_ioc_history(limit=5)

    sep = "━━━━━━━━━━━━━━━━━━━━━━━━━━"
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

    # Build bar for risk distribution
    total = s["total"] or 1
    high_pct = int((s["high_risk"] / total) * 20)
    safe_pct = 20 - high_pct
    risk_bar = "🔴" * high_pct + "🟢" * safe_pct

    top_ioc_text = "N/A"
    if s.get("top_ioc"):
        top_ioc_text = f"<code>{s['top_ioc']['ioc']}</code> ({s['top_ioc']['cnt']} queries)"

    recent_lines = ""
    for item in history:
        ts      = (item.get("queried_at") or "")[:16].replace("T", " ")
        risk    = item.get("risk_level") or "?"
        em      = {"Low": "🟢", "Medium": "🟡", "High": "🟠", "Critical": "🔴"}.get(risk, "⚪")
        recent_lines += f"  {em} <code>{item['ioc'][:25]}</code> <i>({ts})</i>\n"

    msg = (
        f"📊 <b>SOC Dashboard — TI-Bot Statistics</b>\n"
        f"<code>{sep}</code>\n\n"
        f"<b>📈 IOC Analysis Totals</b>\n"
        f"  🔢 Total Queries:   <b>{s['total']}</b>\n"
        f"  🌐 IPs Analyzed:    <b>{s['ips']}</b>\n"
        f"  🔗 Domains:         <b>{s['domains']}</b>\n"
        f"  🔒 Hashes:          <b>{s['hashes']}</b>\n"
        f"  🔗 URLs:            <b>{s['urls']}</b>\n\n"
        f"<b>⚠️ Risk Summary</b>\n"
        f"  🔴 High/Critical:   <b>{s['high_risk']}</b> IOCs\n"
        f"  Risk Distribution:\n  {risk_bar}\n\n"
        f"<b>👁 Monitoring</b>\n"
        f"  📡 Active Watchlist: <b>{s['watchlist']}</b> IOCs\n"
        f"  🔔 Total Alerts Sent: <b>{s['alerts']}</b>\n\n"
        f"<b>🏆 Most Queried IOC</b>\n"
        f"  {top_ioc_text}\n\n"
        f"<b>🕐 Recent Lookups</b>\n"
        f"{recent_lines or '  No recent lookups.'}"
        f"\n<code>{sep}</code>\n"
        f"<i>Generated: {now}</i>"
    )

    await update.message.reply_text(msg, parse_mode=ParseMode.HTML)
