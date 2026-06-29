"""
handlers/cve_cmd.py - Phase 3.5 CVE Intelligence Command Handler

Commands:
  /cve <CVE-ID>  — Full CVE intelligence: CVSS, EPSS, CISA KEV, affected products
"""
import html as html_lib
from telegram import Update
from telegram.ext import ContextTypes
from telegram.constants import ParseMode

import cve_engine


async def cve_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """/cve <CVE-ID> — Full CVE intelligence report."""
    message = update.effective_message
    if not message:
        return

    if not context.args:
        await message.reply_text(
            "🔓 <b>CVE Intelligence Engine</b>\n\n"
            "Usage:\n"
            "  <code>/cve CVE-2021-44228</code>  (Log4Shell)\n"
            "  <code>/cve CVE-2023-23397</code>  (Outlook 0-click)\n\n"
            "<i>Queries NVD, EPSS, and CISA KEV for exploitation status.</i>",
            parse_mode=ParseMode.HTML,
        )
        return

    raw = context.args[0].strip()

    # Auto-prefix CVE- if needed
    if not raw.upper().startswith("CVE-"):
        # Try to detect year-number pattern without prefix
        import re
        if re.match(r"^\d{4}-\d{4,7}$", raw):
            raw = f"CVE-{raw}"

    if not cve_engine.is_valid_cve(raw):
        await message.reply_text(
            f"❌ <b>Invalid CVE format:</b> <code>{html_lib.escape(raw)}</code>\n\n"
            "Expected format: <code>CVE-YYYY-NNNNN</code>",
            parse_mode=ParseMode.HTML,
        )
        return

    cve_id = raw.upper()
    status_msg = await message.reply_text(
        f"🔍 Looking up <code>{html_lib.escape(cve_id)}</code> — querying NVD, EPSS, and CISA KEV...",
        parse_mode=ParseMode.HTML,
    )

    try:
        profile = await cve_engine.lookup_cve(cve_id)
        report  = cve_engine.format_cve_report(profile)
        await status_msg.edit_text(report, parse_mode=ParseMode.HTML)
    except Exception as e:
        await status_msg.edit_text(
            f"❌ Error looking up CVE:\n<code>{html_lib.escape(str(e))}</code>",
            parse_mode=ParseMode.HTML,
        )
