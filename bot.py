"""
Async Telegram bot example integrating LeakSearch engine.
Requires: python-telegram-bot>=20, requests, pyyaml
Set TELEGRAM token in config.yaml (telegram_bot_token) or env TELEGRAM_TOKEN
"""

import os
import json
import asyncio
import logging
from typing import Optional

from telegram import __version__ as TG_VER
from telegram import Bot
from telegram.ext import ApplicationBuilder, CommandHandler, ContextTypes
from telegram import Update

# Import engine
from engine import run_leaksearch_async, CFG, load_config

log = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

CONFIG = CFG or load_config()
TOKEN = os.environ.get("TELEGRAM_TOKEN") or CONFIG.get("telegram_bot_token")

if not TOKEN:
    log.warning("No Telegram token configured. Set TELEGRAM_TOKEN or telegram_bot_token in config.yaml")


async def format_email_report(data: dict) -> str:
    # Structured but human-friendly message
    lines = ["📧 Email Intelligence Report", f"- Target: {data.get('target')}", f"- Breach Count: {data.get('count')}", f"- Risk Level: {data.get('risk_level')}", f"- Sources: {', '.join(data.get('sources', []))}", f"- Exposure Type: {data.get('exposure_type')}"]
    return "\n".join(lines)


async def handle_email(update: Update, context: ContextTypes.DEFAULT_TYPE):
    args = context.args
    if not args:
        await update.message.reply_text("Usage: /email <target>")
        return
    target = args[0]
    await update.message.reply_text(f"Searching leaks for {target}... (this may take a few seconds)")

    try:
        payload = await asyncio.wait_for(run_leaksearch_async(target=target, source='proxynova', limit=50), timeout=30)
    except asyncio.TimeoutError:
        await update.message.reply_text("Search timed out. Try again later.")
        return
    except Exception as e:
        log.exception("Search failed: %s", e)
        await update.message.reply_text("Internal error occurred during search.")
        return

    text = await format_email_report(payload)
    await update.message.reply_text(text)

    # Also attach raw JSON as file for structured consumption
    await update.message.reply_document(document=json.dumps(payload, indent=2).encode('utf-8'), filename=f"leak_{target}.json")


async def handle_username(update: Update, context: ContextTypes.DEFAULT_TYPE):
    args = context.args
    if not args:
        await update.message.reply_text("Usage: /username <target>")
        return
    target = args[0]
    await update.message.reply_text(f"Collecting username footprint for {target}...")

    try:
        payload = await asyncio.wait_for(run_leaksearch_async(target=target, source='local', limit=100), timeout=30)
    except asyncio.TimeoutError:
        await update.message.reply_text("Search timed out.")
        return
    except Exception as e:
        log.exception("Username search failed: %s", e)
        await update.message.reply_text("Internal error.")
        return

    # Basic "identity footprint score" example
    score = min(100, payload.get('count', 0) * 10)
    lines = [f"Username report for {target}", f"- Verified matches: {payload.get('count')}", f"- Identity footprint score: {score}/100"]
    await update.message.reply_text("\n".join(lines))
    await update.message.reply_document(document=json.dumps(payload, indent=2).encode('utf-8'), filename=f"username_{target}.json")


async def handle_ip(update: Update, context: ContextTypes.DEFAULT_TYPE):
    args = context.args
    if not args:
        await update.message.reply_text("Usage: /ip <target>")
        return
    target = args[0]
    await update.message.reply_text(f"Searching IP exposure for {target}...")

    try:
        payload = await asyncio.wait_for(run_leaksearch_async(target=target, source='proxynova', limit=50), timeout=30)
    except asyncio.TimeoutError:
        await update.message.reply_text("Search timed out.")
        return
    except Exception as e:
        log.exception("IP search failed: %s", e)
        await update.message.reply_text("Internal error.")
        return

    lines = [f"IP report for {target}", f"- Exposure count: {payload.get('count')}", f"- Risk Level: {payload.get('risk_level')}"]
    await update.message.reply_text("\n".join(lines))
    await update.message.reply_document(document=json.dumps(payload, indent=2).encode('utf-8'), filename=f"ip_{target}.json")


def main():
    if not TOKEN:
        raise RuntimeError("Telegram token not configured")

    app = ApplicationBuilder().token(TOKEN).build()

    app.add_handler(CommandHandler("email", handle_email))
    app.add_handler(CommandHandler("username", handle_username))
    app.add_handler(CommandHandler("ip", handle_ip))

    log.info("Starting bot...")
    app.run_polling()


if __name__ == '__main__':
    main()
