"""
handlers/monitor.py - /monitor and /remove commands.
"""
from telegram import Update
from telegram.ext import ContextTypes
from telegram.constants import ParseMode

import ioc_classifier as clf
import database as db


async def monitor_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text(
            "⚠️ Usage: <code>/monitor &lt;ip | domain | hash&gt;</code>",
            parse_mode=ParseMode.HTML,
        )
        return

    ioc      = context.args[0].strip()
    ioc_type = clf.classify(ioc)

    if ioc_type == "unknown":
        await update.message.reply_text(
            f"❓ Cannot classify <code>{ioc}</code> as a monitorable IOC.",
            parse_mode=ParseMode.HTML,
        )
        return

    user_id = update.effective_user.id
    is_new  = db.add_to_watchlist(ioc, ioc_type, user_id)
    friendly = clf.friendly_type(ioc_type)

    # Register user for alerts
    admins: list = context.bot_data.setdefault("admin_users", [])
    if user_id not in admins:
        admins.append(user_id)

    if is_new:
        msg = (
            f"✅ <b>IOC Added to Watchlist</b>\n\n"
            f"IOC:  <code>{ioc}</code>\n"
            f"Type: {friendly}\n\n"
            f"The bot will monitor this IOC and alert you when:\n"
            f"  • Risk level changes\n"
            f"  • New VT detections appear\n"
            f"  • AbuseIPDB score increases\n"
            f"  • New OTX pulses are published\n\n"
            f"<i>Check interval: every {context.bot_data.get('monitor_interval', 60)} minutes</i>"
        )
    else:
        msg = (
            f"🔄 <b>IOC Re-activated in Watchlist</b>\n\n"
            f"IOC:  <code>{ioc}</code>\n"
            f"Type: {friendly}\n\n"
            f"<i>This IOC was already in the watchlist and has been re-activated.</i>"
        )

    await update.message.reply_text(msg, parse_mode=ParseMode.HTML)


async def remove_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text(
            "⚠️ Usage: <code>/remove &lt;ioc&gt;</code>",
            parse_mode=ParseMode.HTML,
        )
        return

    ioc = context.args[0].strip()
    item = db.get_watchlist_item(ioc)

    if not item:
        await update.message.reply_text(
            f"⚠️ <code>{ioc}</code> is not in the active watchlist.",
            parse_mode=ParseMode.HTML,
        )
        return

    db.remove_from_watchlist(ioc)
    await update.message.reply_text(
        f"🗑 <b>Removed from Watchlist</b>\n\n"
        f"IOC: <code>{ioc}</code> is no longer being monitored.",
        parse_mode=ParseMode.HTML,
    )
