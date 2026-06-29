"""
handlers/username_cmd.py - Sherlock-style username OSINT lookup across 20 platforms.
"""
import asyncio
import logging
from telegram import Update
from telegram.ext import ContextTypes
from telegram.constants import ParseMode
import osint_username

logger = logging.getLogger(__name__)

async def username_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    message = update.effective_message
    if not context.args:
        await message.reply_text(
            "⚠️ Usage: <code>/username &lt;handle&gt;</code>",
            parse_mode=ParseMode.HTML
        )
        return

    username = context.args[0].strip().replace("@", "")
    
    # Validation of username structure
    if not re_valid_username(username):
        await message.reply_text(
            "❌ Invalid username format. Use alphanumeric characters, underscores, and hyphens.",
            parse_mode=ParseMode.HTML
        )
        return

    thinking = await message.reply_text(
        f"⏳ Probing 20 platforms for username <code>{username}</code>…\nProgress: <b>0%</b>",
        parse_mode=ParseMode.HTML
    )

    async def progress_callback(current, total):
        try:
            percent = int((current / total) * 100)
            await thinking.edit_text(
                f"⏳ Probing 20 platforms for username <code>{username}</code>…\n"
                f"Progress: <b>{percent}%</b> ({current}/{total} checked)",
                parse_mode=ParseMode.HTML
            )
        except Exception as e:
            logger.debug(f"Failed to update progress: {e}")

    try:
        # Run the scan using the core engine
        results = await osint_username.run_username_scan(username, progress_callback=progress_callback)
        
        # Formulate reports
        messages = osint_username.format_report_messages(username, results)
        
        # Delete the thinking/progress message
        try:
            await thinking.delete()
        except Exception:
            pass

        for idx, msg in enumerate(messages):
            await message.reply_text(
                msg,
                parse_mode=ParseMode.HTML,
                disable_web_page_preview=True,
            )

    except Exception as e:
        logger.error(f"Error during username scan: {e}", exc_info=True)
        try:
            await thinking.delete()
        except Exception:
            pass
        await message.reply_text(
            f"❌ An error occurred during the scan: <code>{str(e)}</code>",
            parse_mode=ParseMode.HTML
        )


def re_valid_username(username: str) -> bool:
    import re
    return bool(re.match(r'^[a-zA-Z0-9_\-\.]{2,30}$', username))
