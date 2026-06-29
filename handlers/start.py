"""
handlers/start.py - /start and /help command handlers (Public TI & OSINT Platform).
"""
from telegram import Update
from telegram.ext import ContextTypes
from telegram.constants import ParseMode
import config


WELCOME_MSG = (
    "━━━━━━━━━━━━━━━━━━━━━━\n"
    "🛡 <b>Abdulaziz Threat Intelligence Bot</b>\n"
    "━━━━━━━━━━━━━━━━━━━━━━\n\n"
    "This bot is a Threat Intelligence platform that analyzes:\n"
    "• IP Addresses\n"
    "• Domains\n"
    "• URLs\n"
    "• File Hashes\n"
    "• Emails (phishing / validation)\n"
    "• Usernames (OSINT)\n\n"
    "It uses multiple intelligence sources:\n"
    "• VirusTotal\n"
    "• AbuseIPDB\n"
    "• OTX\n"
    "• ThreatFox\n"
    "• DNS Intelligence\n"
    "• WHOIS / RDAP\n\n"
    "<b>Usage Examples:</b>\n"
    "• Send an IP → <code>8.8.8.8</code>\n"
    "• Send a domain → <code>example.com</code>\n"
    "• Send a URL → <code>https://site.com</code>\n"
    "• Send a hash → <code>d41d8cd98f00b204e9800998ecf8427e</code>\n"
    "• Send an email → <code>test@gmail.com</code>"
)


async def start_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    admins: list = context.bot_data.setdefault("admin_users", [])
    if user_id not in admins:
        admins.append(user_id)

    await update.message.reply_text(
        WELCOME_MSG,
        parse_mode=ParseMode.HTML,
    )


async def help_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    help_text = (
        "❓ <b>Command Reference</b>\n"
        "<code>━━━━━━━━━━━━━━━━━━━━━━━━━━</code>\n\n"

        "<b>🔍 IOC Investigation</b>\n"
        "<b>/check &lt;ioc&gt;</b>\n"
        "  Analyze any IP, domain, URL, or file hash.\n"
        "  Queries VirusTotal, AbuseIPDB, OTX, GreyNoise,\n"
        "  ThreatFox, Shodan, and more.\n\n"
        "  Examples:\n"
        "  <code>/check 8.8.8.8</code>\n"
        "  <code>/check google.com</code>\n"
        "  <code>/check https://phishing-site.com</code>\n"
        "  <code>/check d41d8cd98f00b204e9800998ecf8427e</code>\n\n"

        "<code>━━━━━━━━━━━━━━━━━━━━━━━━━━</code>\n"
        "<b>📧 Email Intelligence</b>\n"
        "<b>/email &lt;address&gt;</b>\n"
        "  Validates the email, queries DNS records (MX, SPF,\n"
        "  DMARC, DKIM), checks breach databases, and runs\n"
        "  threat intelligence on the sending domain.\n\n"
        "  Example: <code>/email admin@example.com</code>\n\n"

        "<code>━━━━━━━━━━━━━━━━━━━━━━━━━━</code>\n"
        "<b>👤 Username Investigation</b>\n"
        "<b>/username &lt;handle&gt;</b>\n"
        "  Searches 115+ platforms for a username and returns\n"
        "  discovered profiles, links, and presence map.\n\n"
        "  Example: <code>/username johndoe</code>\n\n"

        "<code>━━━━━━━━━━━━━━━━━━━━━━━━━━</code>\n"
        "<b>🖼 Image Forensics</b>\n"
        "  Upload any image directly to this chat.\n"
        "  The bot will extract EXIF metadata, GPS coordinates,\n"
        "  detect steganography, hidden payloads, and AI generation.\n\n"

        "<code>━━━━━━━━━━━━━━━━━━━━━━━━━━</code>\n"
        "<b>🧬 Threat Intelligence Lookup</b>\n"
        "<b>/malware &lt;hash&gt;</b>  — Malware family, C2, detections\n"
        "<b>/actor &lt;name&gt;</b>   — APT / ransomware group profile\n"
        "<b>/cve &lt;CVE-ID&gt;</b>   — CVSS, EPSS, CISA KEV status\n\n"

        "<code>━━━━━━━━━━━━━━━━━━━━━━━━━━</code>\n"
        "<b>📰 Threat News</b>\n"
        "<b>/news</b>  — Latest cybersecurity news and advisories\n"
        "<b>/brief</b> — Daily SOC intelligence briefing\n\n"

        "<code>━━━━━━━━━━━━━━━━━━━━━━━━━━</code>\n"
        "<i>Use /start to return to the main menu.</i>"
    )

    # Support both direct command and callback query
    if update.callback_query:
        await update.callback_query.message.edit_text(help_text, parse_mode=ParseMode.HTML)
    else:
        await update.message.reply_text(help_text, parse_mode=ParseMode.HTML)
