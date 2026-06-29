from telegram import Update
from telegram.ext import ContextTypes
from telegram.constants import ParseMode
import database as db
import ioc_classifier
import html as html_lib
from datetime import datetime, timezone


async def feeds_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """/feeds - Show brief summary of threat feed statistics."""
    stats = db.get_stats()
    sources = db.get_all_feed_sources()

    active_count = sum(1 for s in sources if s.get("status") == "ok")
    error_count  = sum(1 for s in sources if s.get("status") == "error")
    total_count  = len(sources)

    msg = (
        f"📡 <b>Threat Intelligence Feeds</b>\n"
        f"━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
        f"🔹 <b>Total Collected IOCs:</b> <code>{stats.get('feed_iocs', 0):,}</code>\n"
        f"🔹 <b>Active Feeds:</b> <code>{active_count}/{total_count}</code>\n"
        f"🔹 <b>Error Feeds:</b> <code>{error_count}</code>\n\n"
        f"<i>Use /feedstatus for per-feed health.\n"
        f"Use /feedsource &lt;ioc&gt; to search a specific indicator.\n"
        f"Use /feeddebug for live diagnostics.</i>"
    )
    await update.message.reply_text(msg, parse_mode=ParseMode.HTML)


async def feedstatus_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """/feedstatus - Detailed per-feed health, last poll, entry counts."""
    sources = db.get_all_feed_sources()
    if not sources:
        await update.message.reply_text("❌ No threat feeds registered yet. The feeds will register on their first poll cycle.")
        return

    lines = []
    for s in sources:
        status = s.get("status", "unknown")
        if status == "ok":
            status_emoji = "🟢"
        elif status == "error":
            status_emoji = "🔴"
        elif status == "pending":
            status_emoji = "⏳"
        else:
            status_emoji = "🟡"

        last_checked = s.get("last_checked") or "Never"
        if last_checked != "Never":
            last_checked = last_checked[:16].replace("T", " ")

        last_success = s.get("last_success") or "Never"
        if last_success != "Never":
            last_success = last_success[:16].replace("T", " ")

        entry_line = (
            f"{status_emoji} <b>{html_lib.escape(s['display_name'])}</b> (Tier {s['tier']})\n"
            f"  • Total IOCs: <code>{s['entries_total']:,}</code>  "
            f"New (24h): <code>{s['entries_new_24h']}</code>\n"
            f"  • Last Poll: <code>{last_checked}</code>\n"
            f"  • Last OK: <code>{last_success}</code>"
        )
        if status == "error" and s.get("error_msg"):
            err = html_lib.escape(str(s["error_msg"])[:80])
            entry_line += f"\n  ⚠️ <i>{err}</i>"
        lines.append(entry_line)

    msg = (
        f"📡 <b>Threat Feed Health Status</b>\n"
        f"━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
        + "\n\n".join(lines) + "\n\n"
        f"<i>Use /feeddebug to run live health tests.</i>"
    )
    await update.message.reply_text(msg, parse_mode=ParseMode.HTML)


async def feedsource_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """/feedsource <ioc_or_name> - Search feed entries for an IOC, or show source details by name."""
    if not context.args:
        await update.message.reply_text(
            "❌ Usage:\n"
            "  <code>/feedsource &lt;ioc&gt;</code>   — Search indicator across all feeds\n"
            "  <code>/feedsource &lt;name&gt;</code>  — Show details for a specific feed source",
            parse_mode=ParseMode.HTML
        )
        return

    query = " ".join(context.args).strip()

    # ── 1. Try as IOC first (lookup in feed_entries) ──────────────────────────
    ioc_type = ioc_classifier.classify(query)
    if ioc_type != "unknown":
        await _feedsource_ioc_search(update, query, ioc_type)
        return

    # ── 2. Fallback: treat as feed source name ─────────────────────────────────
    sources = db.get_all_feed_sources()
    feed = next((s for s in sources if s["name"].lower() == query.lower()), None)

    if not feed:
        # Try partial match
        feed = next(
            (s for s in sources if query.lower() in s["name"].lower() or
             query.lower() in s.get("display_name", "").lower()),
            None
        )

    if not feed:
        await update.message.reply_text(
            f"❌ No feed source named <code>{html_lib.escape(query)}</code> found.\n\n"
            f"<i>Available sources: {', '.join(s['name'] for s in sources[:8])}</i>",
            parse_mode=ParseMode.HTML
        )
        return

    # Show source details
    status = feed.get("status", "unknown")
    status_emoji = "🟢" if status == "ok" else "🔴" if status == "error" else "🟡"

    msg = (
        f"📡 <b>Feed Source: {html_lib.escape(feed['display_name'])}</b>\n"
        f"━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
        f"🔹 <b>ID:</b> <code>{feed['name']}</code>\n"
        f"🔹 <b>Tier:</b> {feed['tier']}\n"
        f"🔹 <b>Status:</b> {status_emoji} <b>{status.upper()}</b>\n"
        f"🔹 <b>Total IOCs:</b> <code>{feed['entries_total']:,}</code>\n"
        f"🔹 <b>New (24h):</b> <code>{feed['entries_new_24h']}</code>\n"
        f"🔹 <b>Last Poll:</b> <code>{(feed['last_checked'] or 'N/A')[:16].replace('T',' ')}</code>\n"
        f"🔹 <b>Last Success:</b> <code>{(feed['last_success'] or 'N/A')[:16].replace('T',' ')}</code>\n"
    )
    if feed.get("error_msg"):
        msg += f"\n⚠️ <b>Last Error:</b>\n<code>{html_lib.escape(str(feed['error_msg'])[:200])}</code>\n"

    await update.message.reply_text(msg, parse_mode=ParseMode.HTML)


async def _feedsource_ioc_search(update: Update, ioc: str, ioc_type: str) -> None:
    """Search an IOC across feed entries, watchlist, history, and enrichment cache."""
    # 1. Search feed_entries
    feed_sightings = db.get_ioc_all_sources(ioc)

    # 2. Search watchlist
    watchlist_item = db.get_watchlist_item(ioc)

    # 3. Search ioc_history
    history_items = db.get_ioc_history_for(ioc)

    # 4. Search ioc_enrichment_cache
    enrichment = db.get_ioc_enrichment(ioc)

    # If not found anywhere, reply not found
    if not feed_sightings and not watchlist_item and not history_items and not enrichment:
        await update.message.reply_text(
            f"🔍 <b>Feed & Intelligence Search Result</b>\n"
            f"━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
            f"IOC: <code>{html_lib.escape(ioc)}</code>\n"
            f"Type: <b>{ioc_type.upper()}</b>\n\n"
            f"⚪ <b>Not found</b> in feed entries, watchlist, history, or enrichment cache.\n\n"
            f"<i>Use /check to run external analysis.</i>",
            parse_mode=ParseMode.HTML
        )
        return

    # Compute verdict & risk
    max_risk = 0
    if feed_sightings:
        max_risk = max(max_risk, max((s.get("risk_score") or 0) for s in feed_sightings))
    if enrichment:
        max_risk = max(max_risk, enrichment.get("risk_score", 0))

    src_count = len(feed_sightings) + (1 if enrichment else 0)
    src_bonus = min(max(src_count - 1, 0) * 5, 20)
    watch_bonus = 10 if watchlist_item else 0
    composite_risk = min(max_risk + src_bonus + watch_bonus, 100)

    if composite_risk >= 75:
        verdict_em = "🔴"
        verdict = "Critical"
    elif composite_risk >= 50:
        verdict_em = "🟠"
        verdict = "High"
    elif composite_risk >= 25:
        verdict_em = "🟡"
        verdict = "Medium"
    else:
        verdict_em = "🟢"
        verdict = "Low"

    ioc_display = html_lib.escape(ioc)
    if len(ioc) > 44:
        ioc_display = html_lib.escape(ioc[:42]) + "…"

    msg = (
        f"🔍 <b>Unified Intelligence Search: {ioc_display}</b>\n"
        f"━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
        f"🔹 <b>Type:</b> <b>{ioc_type.upper()}</b>\n"
        f"🔹 <b>Verdict:</b> {verdict_em} <b>{verdict}</b> ({composite_risk}/100)\n\n"
    )

    # ── Feed Sightings ────────────────────────────────────────────────────
    if feed_sightings:
        msg += f"<b>📡 Feed Sources ({len(feed_sightings)}):</b>\n"
        for s in feed_sightings:
            first = (s.get("first_seen") or "")[:10]
            last  = (s.get("last_seen") or "")[:10]
            risk  = s.get("risk_score") or 0
            cat   = html_lib.escape(s.get("threat_category") or "N/A")
            r_em  = "🔴" if risk >= 75 else "🟠" if risk >= 50 else "🟡" if risk >= 25 else "🟢"
            src   = html_lib.escape(s.get("source", "Unknown").upper())

            import json
            tags_raw = s.get("tags") or "[]"
            try:
                tags_list = json.loads(tags_raw) if isinstance(tags_raw, str) else tags_raw
                tags_str = ", ".join(tags_list[:3]) if tags_list else ""
            except Exception:
                tags_str = ""

            msg += (
                f"  {r_em} <b>{src}</b> | Risk: <b>{risk}/100</b> | Cat: <i>{cat}</i>\n"
                f"    First: <code>{first}</code> | Last: <code>{last}</code>\n"
            )
            if tags_str:
                msg += f"    Tags: <code>{html_lib.escape(tags_str)}</code>\n"
        msg += "\n"
    else:
        msg += "📡 <b>Feed Sources:</b> <i>Not observed in threat feeds.</i>\n\n"

    # ── Live Intelligence Cache ───────────────────────────────────────────
    if enrichment:
        import json
        try:
            cached_srcs = json.loads(enrichment.get("sources") or "[]")
        except Exception:
            cached_srcs = []

        msg += f"<b>⚡ Live Intelligence Cache:</b>\n"
        msg += f"  • Sources: <b>{', '.join(cached_srcs) if cached_srcs else 'N/A'}</b>\n"
        msg += f"  • Verdict: <b>{enrichment.get('verdict', 'Low')}</b> (Score: {enrichment.get('risk_score', 0)}/100)\n"
        msg += f"  • Vt Malicious: <b>{enrichment.get('vt_malicious', 0)}</b> | Abuse Score: <b>{enrichment.get('abuse_score', 0)}</b>\n"
        if enrichment.get('country') or enrichment.get('asn'):
            msg += f"  • Origin: <b>{enrichment.get('country', 'N/A')}</b> | ASN: <code>{enrichment.get('asn', 'N/A')}</code>\n"
        msg += "\n"
    else:
        msg += "⚡ <b>Live Intelligence Cache:</b> <i>Not cached. Use /check to enrich.</i>\n\n"

    # ── Watchlist Status ──────────────────────────────────────────────────
    if watchlist_item:
        msg += f"👁 <b>Watchlist:</b> <b>YES</b> — Added: <code>{(watchlist_item.get('added_at') or '')[:10]}</code>\n\n"

    # ── User Query History ─────────────────────────────────────────────────
    if history_items:
        msg += f"📋 <b>Recent Queries ({len(history_items)}):</b>\n"
        for h in history_items[:3]:
            ts = (h.get("queried_at") or "")[:16].replace("T", " ")
            rl = h.get("risk_level") or "N/A"
            msg += f"  • <code>{ts}</code> — <b>{rl}</b> ({h.get('threat_score', 0)}/100)\n"
        msg += "\n"

    msg += (
        f"━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"<i>Use /hunt {html_lib.escape(ioc[:40])} for full correlation analysis.</i>"
    )

    await update.message.reply_text(msg, parse_mode=ParseMode.HTML)


async def feeddebug_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """/feeddebug - Run live health diagnostics for all registered feeds."""
    status_msg = await update.message.reply_text(
        "🔧 <b>Running feed diagnostics...</b>\n<i>Testing all registered feeds...</i>",
        parse_mode=ParseMode.HTML
    )

    sources = db.get_all_feed_sources()

    if not sources:
        await status_msg.edit_text(
            "⚠️ <b>No feeds registered yet.</b>\n\n"
            "<i>Feeds register on first poll cycle (within 10 seconds of bot start).</i>",
            parse_mode=ParseMode.HTML
        )
        return

    now_utc = datetime.now(timezone.utc)
    lines = []

    for s in sources:
        name = s.get("name", "?")
        display = html_lib.escape(s.get("display_name", name))
        tier = s.get("tier", 1)
        status = s.get("status", "unknown")
        total = s.get("entries_total", 0)
        new_24h = s.get("entries_new_24h", 0)
        last_checked = s.get("last_checked")
        error_msg = s.get("error_msg")

        # Status badge
        if status == "ok":
            badge = "✅ HEALTHY"
        elif status == "error":
            badge = "❌ ERROR"
        elif status == "pending":
            badge = "⏳ PENDING"
        else:
            badge = "❔ UNKNOWN"

        # Time since last check
        time_since = "Never polled"
        if last_checked:
            try:
                last_dt = datetime.fromisoformat(last_checked.replace("Z", "+00:00"))
                if last_dt.tzinfo is None:
                    from datetime import timezone as tz
                    last_dt = last_dt.replace(tzinfo=tz.utc)
                delta = now_utc - last_dt
                mins = int(delta.total_seconds() // 60)
                if mins < 60:
                    time_since = f"{mins}m ago"
                else:
                    time_since = f"{mins // 60}h {mins % 60}m ago"
            except Exception:
                time_since = last_checked[:16].replace("T", " ")

        # Get diagnostic metrics
        last_http       = s.get("last_http_status")
        last_http_str   = str(last_http) if last_http is not None else "N/A"
        raw_fetched     = s.get("raw_fetched_count")
        raw_fetched_str = f"{raw_fetched:,}" if raw_fetched is not None else "N/A"
        parsed_ioc      = s.get("parsed_ioc_count")
        parsed_ioc_str  = f"{parsed_ioc:,}" if parsed_ioc is not None else "N/A"
        rejected        = s.get("rejected_count")
        rejected_str    = f"{rejected:,}" if rejected is not None else "N/A"
        inserted_db     = s.get("inserted_db_count")
        inserted_db_str = f"{inserted_db:,}" if inserted_db is not None else "N/A"

        # Warn if rejection rate is high (>20% of fetched)
        rejection_warn = ""
        if raw_fetched and rejected is not None and raw_fetched > 0:
            rate = (rejected / raw_fetched) * 100
            if rate > 20:
                rejection_warn = f" ⚠️ <i>{rate:.0f}% rejection rate</i>"

        entry = (
            f"<b>[T{tier}] {display}</b> — {badge}\n"
            f"  📊 Total: <code>{total:,}</code>  |  New 24h: <code>{new_24h}</code>\n"
            f"  🕐 Last Poll: <code>{time_since}</code>\n"
            f"  ⚡ HTTP: <code>{last_http_str}</code>\n"
            f"  📥 Fetched: <code>{raw_fetched_str}</code>  "
            f"Parsed: <code>{parsed_ioc_str}</code>  "
            f"Rejected: <code>{rejected_str}</code>  "
            f"Inserted: <code>{inserted_db_str}</code>{rejection_warn}"
        )
        if status == "error" and error_msg:
            entry += f"\n  ⚠️ <i>{html_lib.escape(str(error_msg)[:120])}</i>"
        lines.append(entry)

    # Summary counts
    ok_count      = sum(1 for s in sources if s.get("status") == "ok")
    error_count   = sum(1 for s in sources if s.get("status") == "error")
    pending_count = sum(1 for s in sources if s.get("status") in ("pending", "unknown"))
    total_iocs    = sum(s.get("entries_total", 0) for s in sources)

    msg = (
        f"🔧 <b>Feed Health Diagnostics</b>\n"
        f"━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"✅ Healthy: <b>{ok_count}</b>  |  "
        f"❌ Error: <b>{error_count}</b>  |  "
        f"⏳ Pending: <b>{pending_count}</b>\n"
        f"📦 Total IOCs in DB: <code>{total_iocs:,}</code>\n"
        f"━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
        + "\n\n".join(lines)
        + "\n\n<i>Diagnostics complete. Feeds poll automatically per configured interval.</i>"
    )

    await status_msg.edit_text(msg, parse_mode=ParseMode.HTML)
