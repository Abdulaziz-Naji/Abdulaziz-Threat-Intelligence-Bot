"""
handlers/history.py - /history command handler.
"""
from telegram import Update
from telegram.ext import ContextTypes
from telegram.constants import ParseMode

import database as db

_RISK_EMOJI = {"Low": "🟢", "Medium": "🟡", "High": "🟠", "Critical": "🔴"}


async def history_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    # Optional: /history 20  (limit)
    limit = 10
    if context.args:
        try:
            limit = max(1, min(int(context.args[0]), 50))
        except ValueError:
            pass

    items = db.get_ioc_history(limit=limit)

    if not items:
        await update.message.reply_text(
            "📋 <b>No history yet.</b>\n\nUse <code>/check &lt;ioc&gt;</code> to start analyzing IOCs.",
            parse_mode=ParseMode.HTML,
        )
        return

    sep = "━━━━━━━━━━━━━━━━━━━━━━━━━━"
    lines = [f"📋 <b>Recent IOC History</b> (last {len(items)})\n<code>{sep}</code>\n"]

    for item in items:
        ioc      = item["ioc"]
        ioc_type = item["ioc_type"].upper()
        risk     = item.get("risk_level") or "Unknown"
        em       = _RISK_EMOJI.get(risk, "⚪")
        ts       = (item.get("queried_at") or "")[:16].replace("T", " ")
        ts_str   = item.get("threat_score", "?")
        vt_mal   = item.get("vt_malicious", "?")
        abuse    = item.get("abuse_score", "?")

        lines.append(
            f"{em} <code>{ioc[:30]}</code>\n"
            f"   [{ioc_type}] Score: <b>{ts_str}/100</b>  "
            f"VT: <b>{vt_mal}</b>  Abuse: <b>{abuse}</b>\n"
            f"   <i>{ts} UTC</i>\n"
        )

    lines.append(f"<code>{sep}</code>")
    msg = "\n".join(lines)

    await update.message.reply_text(msg, parse_mode=ParseMode.HTML)
