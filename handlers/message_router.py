"""
handlers/message_router.py - Intelligent input parser and router.
Classifies raw text inputs and forwards them internally to the appropriate handlers.
"""
import re
import logging
from telegram import Update
from telegram.ext import ContextTypes
from telegram.constants import ParseMode

import ioc_classifier as clf
from handlers.check import check_handler
from handlers.username_cmd import username_handler
from handlers.email_cmd import email_command

logger = logging.getLogger(__name__)


def detect_input_type(text: str) -> tuple[str, str]:
    """
    Classifies a raw string into: username, ip, domain, email, hash, url, or unknown.
    Returns (type, sanitized_value).
    """
    v = text.strip()
    if not v:
        return "unknown", v

    v_lower = v.lower()

    # 1. URL Detection
    if v_lower.startswith(("http://", "https://")):
        return "url", v

    # 2. IP Detection (IPv4 / IPv6)
    ipv4_pattern = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
    if ipv4_pattern.match(v):
        octets = v.split(".")
        if all(0 <= int(o) <= 255 for o in octets):
            return "ip", v

    ipv6_pattern = re.compile(r"^[0-9a-fA-F:]{2,39}$")
    if ipv6_pattern.match(v) and ":" in v:
        return "ip", v

    # 3. Email Detection
    # If contains @ but not starting with @ (which is a username)
    if "@" in v and not v.startswith("@"):
        email_pattern = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
        if email_pattern.match(v):
            return "email", v

    # 4. File Hash Detection (MD5, SHA1, SHA256)
    md5_pattern = re.compile(r"^[a-fA-F0-9]{32}$")
    sha1_pattern = re.compile(r"^[a-fA-F0-9]{40}$")
    sha256_pattern = re.compile(r"^[a-fA-F0-9]{64}$")
    if md5_pattern.match(v) or sha1_pattern.match(v) or sha256_pattern.match(v):
        return "hash", v

    # 5. Username Detection
    # Username starting with @
    if v.startswith("@"):
        username_val = v[1:]
        if re.match(r"^[a-zA-Z0-9_\-\.]{2,30}$", username_val):
            return "username", username_val

    # Username without @ (alphanumeric + underscore + hyphen, length 2 to 30, no dot)
    if re.match(r"^[a-zA-Z0-9_\-]{2,30}$", v):
        return "username", v

    # 6. Domain Detection
    domain_pattern = re.compile(
        r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    )
    if domain_pattern.match(v):
        return "domain", v

    return "unknown", v


async def smart_router(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """
    Intelligent message router that handles plain text messages (excluding commands).
    """
    message = update.effective_message
    if not message or not message.text:
        return

    text = message.text.strip()
    if text.startswith("/"):
        return  # Let CommandHandlers process command inputs

    # ── Check if input is a valid local file path ────────────────────────
    import os
    if os.path.exists(text) and os.path.isfile(text):
        logger.info(f"[Smart Router] Local path detected: {text} -> Routing to analyze_local_path_dfir")
        from handlers.auto_dfir_handler import analyze_local_path_dfir
        await analyze_local_path_dfir(update, context, text)
        return

    input_type, value = detect_input_type(text)
    logger.info(f"[Smart Router] Processing input '{text}' -> classified: {input_type}, value: {value}")

    # Set context.args to contain the sanitized value for the downstream handlers
    context.args = [value]

    if input_type in ("ip", "domain", "url", "hash"):
        logger.info("[Smart Router] Routing to check_handler")
        await check_handler(update, context)

    elif input_type == "email":
        logger.info("[Smart Router] Routing to email_command")
        await email_command(update, context)

    elif input_type == "username":
        logger.info("[Smart Router] Routing to username_handler")
        await username_handler(update, context)

    else:
        logger.info("[Smart Router] Fallback: Unknown input type")
        await message.reply_text(
            f"❓ Unrecognized input structure: <code>{text}</code>\n\n"
            f"I can automatically analyze:\n"
            f"• 🌐 <b>IP Address:</b> e.g. <code>185.220.101.1</code>\n"
            f"• 🔗 <b>Domain:</b> e.g. <code>example.com</code>\n"
            f"• 🔗 <b>URL:</b> e.g. <code>https://example.com/login</code>\n"
            f"• 📧 <b>Email:</b> e.g. <code>user@domain.com</code>\n"
            f"• 🔒 <b>File Hash:</b> e.g. <code>c5d246...</code>\n"
            f"• 🕵️‍♂️ <b>Username:</b> e.g. <code>@john_doe</code> or <code>john_doe</code>\n\n"
            f"Send the raw value directly here!",
            parse_mode=ParseMode.HTML
        )
