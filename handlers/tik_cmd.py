"""
handlers/tik_cmd.py - /tik command handler

/tik <username>  — Full TikTok profile intelligence report
"""
import html as html_lib
from telegram import Update
from telegram.ext import ContextTypes
from telegram.constants import ParseMode

import osint_tiktok as tt


async def tik_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """/tik <username> — TikTok profile intelligence."""
    message = update.effective_message
    if not message:
        return

    if not context.args:
        await message.reply_text(
            "📱 <b>TikTok Intelligence Engine</b>\n\n"
            "Usage:\n"
            "  <code>/tik username</code>\n"
            "  <code>/tik @username</code>\n\n"
            "<i>Extracts profile metrics, follower/likes counts, engagement estimation, "
            "and risk analysis from the public TikTok profile.</i>",
            parse_mode=ParseMode.HTML,
        )
        return

    username = context.args[0].strip().lstrip("@")

    if not username or len(username) > 50:
        await message.reply_text(
            "❌ Invalid username.",
            parse_mode=ParseMode.HTML,
        )
        return

    status_msg = await message.reply_text(
        f"🔍 Investigating TikTok profile <code>@{html_lib.escape(username)}</code>...",
        parse_mode=ParseMode.HTML,
    )

    try:
        profile = await tt.investigate_tiktok(username)
        report  = tt.format_tiktok_report(profile)
        await status_msg.edit_text(report, parse_mode=ParseMode.HTML, disable_web_page_preview=True)
    except Exception as e:
        await status_msg.edit_text(
            f"❌ Error during TikTok investigation:\n<code>{html_lib.escape(str(e))}</code>",
            parse_mode=ParseMode.HTML,
        )
