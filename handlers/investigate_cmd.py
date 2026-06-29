"""
handlers/investigate_cmd.py - Unified investigation hub.

Auto-detects target type and routes to the correct analyst module:
  @  → Email OSINT (/email)
  image/photo reply → Phishing analysis (/phish)
  no dots, not hex hash → Username OSINT (/username)
  everything else → Unified Threat Intelligence check (/check)
"""
import logging
from telegram import Update
from telegram.ext import ContextTypes
from telegram.constants import ParseMode

import ioc_classifier as clf
from handlers.check import check_handler
from handlers.username_cmd import username_handler
from handlers.email_cmd import email_command
from handlers.phishing_cmd import phish_command

logger = logging.getLogger(__name__)


async def investigate_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """/investigate <target> - Auto-detects target type and routes to the correct module."""
    message = update.effective_message

    # ── Route image replies to phishing engine ─────────────────────────────
    replied = message.reply_to_message
    if replied and (replied.photo or (replied.document and replied.document.mime_type and
                                      replied.document.mime_type.startswith("image/"))):
        logger.info("[Investigate] Image reply detected → routing to Phishing analyser")
        # Pass through to phish_command (it reads reply_to_message itself)
        context.args = context.args or []
        await phish_command(update, context)
        return

    if not context.args:
        # If replying to a text message with no args, route to phishing analyser
        if replied and replied.text:
            logger.info("[Investigate] Text reply with no args → routing to Phishing analyser")
            await phish_command(update, context)
            return

        await message.reply_text(
            "⚠️ Usage:\n"
            "  <code>/investigate &lt;ip | domain | url | hash | email | username&gt;</code>\n\n"
            "  Or <b>reply</b> to:\n"
            "  • An <b>image</b> → Email phishing screenshot analysis\n"
            "  • A <b>text message</b> → Email content phishing analysis",
            parse_mode=ParseMode.HTML
        )
        return

    target = context.args[0].strip()

    # ── 1. Email address (contains '@') ────────────────────────────────────
    if "@" in target:
        logger.info(f"[Investigate] Routing '{target}' → Email OSINT")
        context.args = [target]
        await email_command(update, context)
        return

    # ── 2. Username (no dots, not a hex hash) ──────────────────────────────
    if "." not in target:
        is_hash = len(target) in (32, 40, 64) and all(c in "0123456789abcdefABCDEF" for c in target)
        if not is_hash:
            logger.info(f"[Investigate] Routing '{target}' → Username OSINT")
            context.args = [target]
            await username_handler(update, context)
            return

    # ── 3. Everything else → Unified threat check ───────────────────────────
    logger.info(f"[Investigate] Routing '{target}' → Unified Threat Intelligence")
    context.args = [target]
    await check_handler(update, context)
