"""
handlers/insta_cmd.py - /insta command handler

/insta <username>  — Full Instagram profile intelligence report
"""
import html as html_lib
from telegram import Update
from telegram.ext import ContextTypes
from telegram.constants import ParseMode

import osint_instagram as ig


async def insta_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """/insta <username> — Instagram profile intelligence."""
    message = update.effective_message
    if not message:
        return

    if not context.args:
        await message.reply_text(
            "📱 <b>Instagram Intelligence Engine</b>\n\n"
            "Usage:\n"
            "  <code>/insta username</code>\n"
            "  <code>/insta @username</code>\n\n"
            "<i>Extracts profile metrics, account status, and risk analysis "
            "from the public Instagram profile.</i>",
            parse_mode=ParseMode.HTML,
        )
        return

    username = context.args[0].strip().lstrip("@")

    if not username or len(username) > 50:
        await message.reply_text(
            "❌ Invalid username. Instagram usernames are 1-30 characters.",
            parse_mode=ParseMode.HTML,
        )
        return

    status_msg = await message.reply_text(
        f"🔍 Investigating Instagram profile <code>@{html_lib.escape(username)}</code>...",
        parse_mode=ParseMode.HTML,
    )

    try:
        profile = await ig.investigate_instagram(username)
        report  = ig.format_instagram_report(profile)
        await status_msg.edit_text(report, parse_mode=ParseMode.HTML, disable_web_page_preview=True)
    except Exception as e:
        await status_msg.edit_text(
            f"❌ Error during Instagram investigation:\n<code>{html_lib.escape(str(e))}</code>",
            parse_mode=ParseMode.HTML,
        )
