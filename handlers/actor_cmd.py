"""
handlers/actor_cmd.py - Phase 3.4 Threat Actor Intelligence Command Handler

Commands:
  /actor <name>     — Lookup a specific threat actor / APT group
  /actors           — List all tracked threat actors
  /actors apt       — List only APT groups
  /actors ransomware — List only ransomware groups
"""
import html as html_lib
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import ContextTypes
from telegram.constants import ParseMode

import threat_actor_db as tadb


_RISK_EMOJI = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢"}


async def actor_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """/actor <name> — Look up a threat actor."""
    message = update.effective_message
    if not message:
        return

    if not context.args:
        await message.reply_text(
            "🎭 <b>Threat Actor Intelligence</b>\n\n"
            "Usage:\n"
            "  <code>/actor APT28</code>\n"
            "  <code>/actor Lazarus</code>\n"
            "  <code>/actor LockBit</code>\n\n"
            "<i>Tip: Use /actors to see all tracked groups.</i>",
            parse_mode=ParseMode.HTML,
        )
        return

    query = " ".join(context.args).strip()
    actor = tadb.lookup_actor(query)

    if not actor:
        # Try keyword search for partial matches
        matches = tadb.search_actors(query)
        if matches:
            lines = [f"🎭 <b>Threat Actor Search Results for:</b> <code>{html_lib.escape(query)}</code>\n"]
            for a in matches[:8]:
                em = _RISK_EMOJI.get(a["risk"], "⚪")
                active = "✅" if a["active"] else "🚫"
                lines.append(
                    f"{em} <b>{html_lib.escape(a['name'])}</b> {active} | "
                    f"{a['category']} | {a['origin']}\n"
                    f"   <i>{html_lib.escape(', '.join(a['aliases'][:2]))}</i>\n"
                )
            lines.append("\n<i>Use /actor &lt;exact name&gt; for full profile.</i>")
            await message.reply_text("".join(lines), parse_mode=ParseMode.HTML)
        else:
            await message.reply_text(
                f"❌ <b>Threat actor not found:</b> <code>{html_lib.escape(query)}</code>\n\n"
                "Check the name or alias. Use /actors to see all tracked groups.",
                parse_mode=ParseMode.HTML,
            )
        return

    report = tadb.format_actor_report(actor)
    await message.reply_text(report, parse_mode=ParseMode.HTML)


async def actors_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """/actors [category] — List all tracked threat actors."""
    message = update.effective_message
    if not message:
        return

    category = " ".join(context.args).strip() if context.args else None
    actors = tadb.get_all_actors(category=category)

    if not actors:
        await message.reply_text(
            f"❌ No actors found for category: <code>{html_lib.escape(category or '')}</code>",
            parse_mode=ParseMode.HTML,
        )
        return

    sep = "━━━━━━━━━━━━━━━━━━━━━━━━━━"
    cat_title = f" [{category}]" if category else ""
    msg = (
        f"🎭 <b>Threat Actor Database{cat_title}</b>\n"
        f"<code>{sep}</code>\n\n"
    )

    # Group by category
    by_cat: dict[str, list] = {}
    for actor in actors:
        cat = actor["category"]
        by_cat.setdefault(cat, []).append(actor)

    for cat, group in by_cat.items():
        msg += f"<b>📁 {html_lib.escape(cat)}:</b>\n"
        for a in group:
            em     = _RISK_EMOJI.get(a["risk"], "⚪")
            active = "✅" if a["active"] else "🚫"
            name   = html_lib.escape(a["name"])
            origin = html_lib.escape(a["origin"])
            msg += f"  {em} <b>{name}</b> {active} — {origin}\n"
        msg += "\n"

    msg += (
        f"<code>{sep}</code>\n"
        f"<i>Total: {len(actors)} tracked groups. Use /actor &lt;name&gt; for full profile.</i>"
    )

    if len(msg) > 4000:
        msg = msg[:3997] + "…"

    await message.reply_text(msg, parse_mode=ParseMode.HTML)
