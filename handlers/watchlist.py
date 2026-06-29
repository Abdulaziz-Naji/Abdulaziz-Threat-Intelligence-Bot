"""
handlers/watchlist.py - /watchlist command handler.
"""
from telegram import Update
from telegram.ext import ContextTypes
from telegram.constants import ParseMode

import database as db


_RISK_EMOJI = {"Low": "🟢", "Medium": "🟡", "High": "🟠", "Critical": "🔴"}


async def watchlist_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    items = db.get_watchlist()

    if not items:
        await update.message.reply_text(
            "👁 <b>Watchlist is empty.</b>\n\n"
            "Use <code>/monitor &lt;ioc&gt;</code> to start monitoring an IOC.",
            parse_mode=ParseMode.HTML,
        )
        return

    sep = "━━━━━━━━━━━━━━━━━━━━━━━━━━"
    lines = [f"👁 <b>Active Watchlist</b> ({len(items)} IOCs)\n<code>{sep}</code>\n"]

    for i, item in enumerate(items, 1):
        ioc       = item["ioc"]
        ioc_type  = item["ioc_type"].upper()
        risk      = item.get("last_risk_level") or "Unknown"
        em        = _RISK_EMOJI.get(risk, "⚪")
        checked   = (item.get("last_checked") or "Never")[:16].replace("T", " ")
        added     = (item.get("added_at") or "")[:10]
        vt_mal    = item.get("last_vt_mal")
        abuse     = item.get("last_abuse")
        otx       = item.get("last_otx_pulses")

        lines.append(
            f"<b>{i}.</b> <code>{ioc}</code>\n"
            f"   Type: <b>{ioc_type}</b>  |  Risk: {em} <b>{risk}</b>\n"
            f"   VT: <b>{vt_mal if vt_mal is not None else '—'}</b>  "
            f"Abuse: <b>{abuse if abuse is not None else '—'}</b>  "
            f"OTX: <b>{otx if otx is not None else '—'}</b>\n"
            f"   Last check: <i>{checked}</i>  Added: <i>{added}</i>\n"
        )

    lines.append(f"<code>{sep}</code>")
    msg = "\n".join(lines)

    await update.message.reply_text(
        msg,
        parse_mode=ParseMode.HTML,
    )
