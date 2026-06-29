"""
handlers/news_cmd.py - Threat News command handler with advanced filtering and search
"""
import html as html_lib
from telegram import Update
from telegram.ext import ContextTypes
from telegram.constants import ParseMode

import threat_news


async def news_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """/news [keyword/CVE/time/critical] — Latest threat intelligence news."""
    message = update.effective_message
    if not message:
        return

    # Build filter from args
    keyword = " ".join(context.args).strip() if context.args else None
    
    title = "Latest Threat Intelligence News"
    if keyword:
        title = f"Threat News: {keyword.title()}"

    status_msg = await message.reply_text(
        "📡 Fetching latest threat intelligence news…",
        parse_mode=ParseMode.HTML,
    )

    try:
        # Fetch from Cache (15 min cache)
        cache = await threat_news.get_threat_news(force_refresh=False)
        articles = cache.get("articles", [])
        telemetry = cache.get("telemetry", {})
        health = cache.get("health", {})

        # Filter articles list based on keyword argument
        filtered_articles = articles
        if keyword:
            kw = keyword.lower()
            if kw == "last24h":
                from datetime import datetime, timezone, timedelta
                now = datetime.now(timezone.utc)
                filtered_articles = [
                    a for a in articles 
                    if a["date_dt"] and (now - a["date_dt"]) <= timedelta(days=1)
                ]
            elif kw == "critical":
                filtered_articles = [
                    a for a in articles 
                    if a["priority_level"] in ("Immediate", "High")
                ]
            else:
                # Search across title, category, summary, source, CVEs, and actors
                filtered_articles = []
                for a in articles:
                    match_found = False
                    if kw in a["category"].lower():
                        match_found = True
                    elif kw in a["title"].lower():
                        match_found = True
                    elif kw in a["summary"].lower():
                        match_found = True
                    elif kw in a["source"].lower():
                        match_found = True
                    elif any(kw in c["cve_id"].lower() for c in a["cves_enriched"]):
                        match_found = True
                    elif any(kw in act["name"].lower() or kw in act["aliases"].lower() for act in a["actors_matched"]):
                        match_found = True
                    
                    if match_found:
                        filtered_articles.append(a)

        # Update telemetry counts for the filtered view
        filtered_telemetry = telemetry.copy()
        
        chunks = threat_news.format_news_report(
            articles=filtered_articles, 
            telemetry=filtered_telemetry, 
            health=health, 
            title=title
        )

        # Send first chunk as edit, rest as new messages
        await status_msg.edit_text(chunks[0], parse_mode=ParseMode.HTML, disable_web_page_preview=True)
        for chunk in chunks[1:]:
            await message.reply_text(chunk, parse_mode=ParseMode.HTML, disable_web_page_preview=True)

    except Exception as e:
        import traceback
        traceback.print_exc()
        await status_msg.edit_text(
            f"❌ Error fetching threat news:\n<code>{html_lib.escape(str(e))}</code>",
            parse_mode=ParseMode.HTML,
        )
