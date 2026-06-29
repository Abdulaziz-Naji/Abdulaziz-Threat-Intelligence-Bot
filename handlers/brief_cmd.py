"""
handlers/brief_cmd.py - Executive Daily Threat Briefing Command Handler
"""
import html as html_lib
from telegram import Update
from telegram.ext import ContextTypes
from telegram.constants import ParseMode

import threat_news

async def brief_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """/brief — Get the daily executive threat briefing."""
    message = update.effective_message
    if not message:
        return

    status_msg = await message.reply_text(
        "🔮 Compiling executive threat briefing…",
        parse_mode=ParseMode.HTML,
    )

    try:
        # Fetch latest prioritized news
        cache = await threat_news.get_threat_news(force_refresh=False)
        articles = cache.get("articles", [])
        
        brief_html = threat_news.format_daily_brief(articles)
        
        await status_msg.edit_text(
            brief_html, 
            parse_mode=ParseMode.HTML, 
            disable_web_page_preview=True
        )

    except Exception as e:
        await status_msg.edit_text(
            f"❌ Error compiling threat briefing:\n<code>{html_lib.escape(str(e))}</code>",
            parse_mode=ParseMode.HTML,
        )
