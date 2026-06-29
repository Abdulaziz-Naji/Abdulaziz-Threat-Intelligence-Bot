"""
handlers/callbacks.py - InlineKeyboard callback query handler.
Handles all callback_data from inline buttons throughout the bot.
Includes routing for: menu:*, action:*, dfir:*, nav:* callbacks.
"""
import asyncio
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import ContextTypes
from telegram.constants import ParseMode

import ioc_classifier as clf
import api_clients as api
import report_builder as rb
import database as db
from handlers.check import _run_analysis, resolve_ioc_token
from handlers.start import WELCOME_MSG, _build_menu
from handlers.dfir_cmd import handle_dfir_callback


_RISK_EMOJI = {"Low": "🟢", "Medium": "🟡", "High": "🟠", "Critical": "🔴"}


async def callback_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()

    data: str = query.data or ""

    # ── Menu navigation ───────────────────────────────────────────────────────
    if data == "menu:home":
        await query.edit_message_text(
            WELCOME_MSG,
            parse_mode=ParseMode.HTML,
            reply_markup=_build_menu(),
        )

    elif data == "menu:check":
        await query.edit_message_text(
            "🔍 <b>Quick Check</b>\n\n"
            "Send a command like:\n"
            "<code>/check 8.8.8.8</code>\n"
            "<code>/check google.com</code>\n"
            "<code>/check https://example.com</code>\n"
            "<code>/check e3b0c44298fc1c149afbf4c8996fb924</code>\n\n"
            "<i>The bot auto-detects the IOC type and queries all sources.</i>",
            parse_mode=ParseMode.HTML,
            reply_markup=InlineKeyboardMarkup([[
                InlineKeyboardButton("🏠 Back", callback_data="menu:home")
            ]]),
        )

    elif data == "menu:email":
        await query.edit_message_text(
            "📧 <b>Email Analysis</b>\n\n"
            "Send a command like:\n"
            "<code>/email test@gmail.com</code>\n\n"
            "<i>The bot validates the email, queries DNS records (MX, SPF, DMARC, DKIM), and checks breach databases.</i>",
            parse_mode=ParseMode.HTML,
            reply_markup=InlineKeyboardMarkup([[
                InlineKeyboardButton("🏠 Back", callback_data="menu:home")
            ]]),
        )

    elif data == "menu:username":
        await query.edit_message_text(
            "👤 <b>Username OSINT</b>\n\n"
            "Send a command like:\n"
            "<code>/username johndoe</code>\n\n"
            "<i>The bot searches for the handle across 20 curated platforms.</i>",
            parse_mode=ParseMode.HTML,
            reply_markup=InlineKeyboardMarkup([[
                InlineKeyboardButton("🏠 Back", callback_data="menu:home")
            ]]),
        )

    elif data == "menu:stats":
        s = db.get_stats()
        sep = "━━━━━━━━━━━━━━━━━━━━━━━━━━"
        top_ioc_text = "N/A"
        if s.get("top_ioc"):
            top_ioc_text = f"<code>{s['top_ioc']['ioc']}</code> ({s['top_ioc']['cnt']}x)"
        msg = (
            f"📊 <b>SOC Dashboard</b>\n<code>{sep}</code>\n\n"
            f"  🔢 Total Queries:    <b>{s['total']}</b>\n"
            f"  🌐 IPs:             <b>{s['ips']}</b>\n"
            f"  🔗 Domains:         <b>{s['domains']}</b>\n"
            f"  🔒 Hashes:          <b>{s['hashes']}</b>\n"
            f"  🔗 URLs:            <b>{s['urls']}</b>\n\n"
            f"  🔴 High/Critical:   <b>{s['high_risk']}</b>\n"
            f"  📡 Watchlist:       <b>{s['watchlist']}</b>\n"
            f"  🔔 Alerts:          <b>{s['alerts']}</b>\n\n"
            f"  🏆 Top IOC: {top_ioc_text}\n"
            f"<code>{sep}</code>"
        )
        await query.edit_message_text(
            msg,
            parse_mode=ParseMode.HTML,
            reply_markup=InlineKeyboardMarkup([[
                InlineKeyboardButton("🏠 Back", callback_data="menu:home")
            ]]),
        )

    elif data == "menu:watchlist":
        items = db.get_watchlist()
        sep = "━━━━━━━━━━━━━━━━━━━━━━━━━━"
        if not items:
            msg = (
                "👁 <b>Watchlist is empty.</b>\n\n"
                "Use <code>/monitor &lt;ioc&gt;</code> to start monitoring an IOC."
            )
        else:
            lines = [f"👁 <b>Watchlist</b> ({len(items)} IOCs)\n<code>{sep}</code>\n"]
            for i, item in enumerate(items[:10], 1):
                risk = item.get("last_risk_level") or "Unknown"
                em   = _RISK_EMOJI.get(risk, "⚪")
                lines.append(f"<b>{i}.</b> {em} <code>{item['ioc'][:30]}</code> [{item['ioc_type'].upper()}]")
            msg = "\n".join(lines)
        await query.edit_message_text(
            msg,
            parse_mode=ParseMode.HTML,
            reply_markup=InlineKeyboardMarkup([[
                InlineKeyboardButton("🏠 Back", callback_data="menu:home")
            ]]),
        )

    elif data == "menu:history":
        items = db.get_ioc_history(limit=8)
        sep = "━━━━━━━━━━━━━━━━━━━━━━━━━━"
        if not items:
            msg = "📋 <b>No history yet.</b>"
        else:
            lines = [f"📋 <b>Recent Lookups</b>\n<code>{sep}</code>\n"]
            for item in items:
                risk = item.get("risk_level") or "?"
                em   = _RISK_EMOJI.get(risk, "⚪")
                ts   = (item.get("queried_at") or "")[:16].replace("T", " ")
                lines.append(f"{em} <code>{item['ioc'][:28]}</code> <i>({ts})</i>")
            msg = "\n".join(lines)
        await query.edit_message_text(
            msg,
            parse_mode=ParseMode.HTML,
            reply_markup=InlineKeyboardMarkup([[
                InlineKeyboardButton("🏠 Back", callback_data="menu:home")
            ]]),
        )

    elif data == "menu:feeds":
        sources = db.get_all_feed_sources()
        lines = []
        for s in sources[:5]:
            status_emoji = "🟢" if s.get("status") == "ok" else "🔴" if s.get("status") == "error" else "🟡"
            lines.append(f"{status_emoji} <b>{s['display_name']}</b>: {s['entries_total']} entries")
        feed_summary = "\n".join(lines) or "No feeds registered."
        
        sep = "━━━━━━━━━━━━━━━━━━━━━━━━━━"
        msg = (
            f"📡 <b>Threat Intelligence Feeds</b>\n"
            f"<code>{sep}</code>\n\n"
            f"{feed_summary}\n\n"
            f"<i>Use /feedstatus for full health details.\n"
            f"Use /feedsource &lt;ioc&gt; to search an indicator.\n"
            f"Use /feeddebug for live diagnostics.</i>"
        )
        await query.edit_message_text(
            msg,
            parse_mode=ParseMode.HTML,
            reply_markup=InlineKeyboardMarkup([[
                InlineKeyboardButton("🏠 Back", callback_data="menu:home")
            ]]),
        )

    elif data == "menu:iocstats":
        stats = db.get_stats()
        counts_24h = db.get_feed_count_by_type(hours=24)
        h24_hashes  = counts_24h.get("sha256", 0) + counts_24h.get("sha1", 0) + counts_24h.get("md5", 0)
        h24_ips     = counts_24h.get("ip", 0)
        h24_domains = counts_24h.get("domain", 0)
        h24_urls    = counts_24h.get("url", 0)
        h24_cves    = counts_24h.get("cve", 0)
        h24_total   = h24_hashes + h24_ips + h24_domains + h24_urls + h24_cves
        sep = "━━━━━━━━━━━━━━━━━━━━━━━━━━"
        msg = (
            f"📊 <b>IOC Statistics</b>\n<code>{sep}</code>\n\n"
            f"<b>Feed DB Total:</b> <code>{stats.get('feed_iocs', 0):,}</code>\n\n"
            f"<b>Last 24 Hours:</b>\n"
            f"  🔒 Hashes:  <b>{h24_hashes:,}</b>\n"
            f"  🌐 IPs:     <b>{h24_ips:,}</b>\n"
            f"  🔗 Domains: <b>{h24_domains:,}</b>\n"
            f"  🔗 URLs:    <b>{h24_urls:,}</b>\n"
            f"  ⚠️ CVEs:    <b>{h24_cves:,}</b>\n"
            f"  📦 Total:   <b>{h24_total:,}</b>\n\n"
            f"<b>Analyst Queries:</b> <code>{stats.get('total', 0):,}</code>\n"
            f"<b>High/Critical:</b> <code>{stats.get('high_risk', 0):,}</code>\n"
            f"<b>Watchlist:</b> <code>{stats.get('watchlist', 0)}</code>\n"
            f"<code>{sep}</code>\n"
            f"<i>See /iocstats for full breakdown.</i>"
        )
        await query.edit_message_text(
            msg,
            parse_mode=ParseMode.HTML,
            reply_markup=InlineKeyboardMarkup([[
                InlineKeyboardButton("🏠 Back", callback_data="menu:home")
            ]]),
        )

    elif data == "menu:threats":
        top = db.get_top_threats(limit=5, hours=24)
        sep = "━━━━━━━━━━━━━━━━━━━━━━━━━━"
        if not top:
            msg = (
                f"🔥 <b>Top Threats (24h)</b>\n<code>{sep}</code>\n\n"
                "⚪ <i>No high-risk IOCs in the last 24 hours.</i>\n\n"
                "<i>Use /threats to check again or /feedstatus to verify feeds.</i>"
            )
        else:
            lines = [f"🔥 <b>Top Threats (24h)</b>\n<code>{sep}</code>\n"]
            for idx, t in enumerate(top, 1):
                risk = t.get("max_risk", 0)
                r_em = "🔴" if risk >= 75 else "🟠" if risk >= 50 else "🟡"
                ioc_disp = t["ioc"][:32] + "…" if len(t["ioc"]) > 32 else t["ioc"]
                lines.append(
                    f"{idx}. {r_em} <code>{ioc_disp}</code> [{t['ioc_type'].upper()}] — <b>{risk}/100</b>"
                )
            msg = "\n".join(lines)
        await query.edit_message_text(
            msg,
            parse_mode=ParseMode.HTML,
            reply_markup=InlineKeyboardMarkup([[
                InlineKeyboardButton("🏠 Back", callback_data="menu:home")
            ]]),
        )

    elif data == "menu:topmalware":
        families = db.get_top_malware_families(limit=7, hours=168)
        sep = "━━━━━━━━━━━━━━━━━━━━━━━━━━"
        if not families:
            msg = (
                f"🦠 <b>Top Malware Families</b>\n<code>{sep}</code>\n\n"
                "⚪ <i>No family data yet. Feeds with classification: MalwareBazaar, ThreatFox, OTX.</i>"
            )
        else:
            lines = [f"🦠 <b>Top Malware Families (7d)</b>\n<code>{sep}</code>\n"]
            for idx, f in enumerate(families, 1):
                name = str(f.get("threat_category", "Unknown"))[:35]
                lines.append(f"  {idx}. <b>{name}</b>: <code>{f['cnt']}</code>")
            msg = "\n".join(lines)
        await query.edit_message_text(
            msg,
            parse_mode=ParseMode.HTML,
            reply_markup=InlineKeyboardMarkup([[
                InlineKeyboardButton("🏠 Back", callback_data="menu:home")
            ]]),
        )

    elif data == "menu:subscriptions":
        msg = (
            f"🕵️‍♂️ <b>Unified Investigation Hub</b>\n"
            f"━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
            f"The <code>/investigate</code> command automatically determines the input type and runs all corresponding intelligence modules:\n\n"
            f"  • <b>IP Address:</b> VT + AbuseIPDB + OTX + GeoIP + Feeds\n"
            f"  • <b>Domain:</b> VT + OTX + DNS + RDAP + Feeds\n"
            f"  • <b>URL:</b> VT + OTX + Domain/IP check\n"
            f"  • <b>File Hash:</b> VT + OTX + MalwareBazaar\n"
            f"  • <b>Email:</b> MX/SPF/DMARC + HIBP Breach Intel + Domain Reputation\n"
            f"  • <b>Username:</b> Sherlock-style probing of 13 social networks\n\n"
            f"Usage: <code>/investigate &lt;target&gt;</code>"
        )
        await query.edit_message_text(
            msg,
            parse_mode=ParseMode.HTML,
            reply_markup=InlineKeyboardMarkup([[
                InlineKeyboardButton("🏠 Back", callback_data="menu:home")
            ]]),
        )

    elif data == "menu:hunt":
        msg = (
            f"🕵️ <b>Threat Hunting Search</b>\n"
            f"━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
            f"Hunt for an indicator across all threat feeds and retrieve correlation data:\n\n"
            f"Usage: <code>/hunt &lt;ioc&gt;</code>\n\n"
            f"Example:\n"
            f"<code>/hunt 8.8.8.8</code>\n"
            f"<code>/hunt evil-domain.com</code>"
        )
        await query.edit_message_text(
            msg,
            parse_mode=ParseMode.HTML,
            reply_markup=InlineKeyboardMarkup([[
                InlineKeyboardButton("🏠 Back", callback_data="menu:home")
            ]]),
        )

    elif data == "menu:dfir":
        sep = "━━━━━━━━━━━━━━━━━━━━━━━━━━"
        msg = (
            f"🔬 <b>DFIR Investigation Engine</b>\n"
            f"<code>{sep}</code>\n\n"
            f"This engine acts as a <b>Senior DFIR Investigator</b>.\n\n"
            f"<b>For every file submitted it answers:</b>\n"
            f"  • What happened?\n"
            f"  • When did it happen?\n"
            f"  • How did the attacker gain access?\n"
            f"  • What actions were performed?\n"
            f"  • What MITRE ATT&amp;CK techniques were used?\n"
            f"  • What should be investigated next?\n"
            f"  • What containment is recommended?\n\n"
            f"<b>Supported Evidence Types:</b>\n"
            f"  📄 PDF documents\n"
            f"  📦 ZIP archives\n"
            f"  🤖 Android APK\n"
            f"  🖼 Images (JPG/PNG/GIF/WEBP)\n"
            f"  📁 Any file (IOC extraction + hash TI)\n\n"
            f"<b>How to use:</b>\n"
            f"  1. Upload a file to Telegram\n"
            f"  2. Use <code>/dfir</code> as the file caption\n"
            f"     — OR —\n"
            f"  3. Reply <code>/dfir</code> to an existing file message\n\n"
            f"<b>Follow-up commands:</b>\n"
            f"  <code>/timeline</code>   — View attack timeline\n"
            f"  <code>/iocs</code>       — Export extracted IOCs\n"
            f"  <code>/casereport</code> — Full multi-page report\n"
            f"<code>{sep}</code>"
        )
        await query.edit_message_text(
            msg,
            parse_mode=ParseMode.HTML,
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton("🏠 Back to Menu", callback_data="menu:home")]
            ]),
        )

    elif data == "menu:help":
        msg = (
            "📖 <b>Command Reference</b>\n\n"
            "<b>🔍 Analysis Commands:</b>\n"
            "• <code>/check &lt;ioc&gt;</code> — Immediate VT/AbuseIPDB/OTX lookup\n"
            "• <code>/hunt &lt;ioc&gt;</code> — Cross-feed correlation search\n"
            "• <code>/investigate &lt;target&gt;</code> — Auto-detect type & run all modules\n\n"
            "<b>📂 Forensic Modules:</b>\n"
            "• <code>/file</code> — Deep image (EXIF), PDF, ZIP, APK analysis (reply to file)\n"
            "• <code>/username &lt;user&gt;</code> — Sherlock-style 13-platform probe\n"
            "• <code>/email &lt;addr&gt;</code> — SPF/MX/DMARC lookup + HIBP breach check\n"
            "• <code>/header &lt;headers&gt;</code> — Parse email headers for hop origin IP & fraud\n\n"
            "<b>📊 Watchlist & Feeds:</b>\n"
            "• <code>/monitor &lt;ioc&gt;</code> — Add IOC to watchlist (silent re-check)\n"
            "• <code>/watchlist</code> — View watchlist\n"
            "• <code>/feeds</code> — List integrated feed health status\n"
            "• <code>/iocstats</code> — View analyst lookup statistics"
        )
        await query.edit_message_text(
            msg,
            parse_mode=ParseMode.HTML,
            reply_markup=InlineKeyboardMarkup([[
                InlineKeyboardButton("🏠 Back", callback_data="menu:home")
            ]]),
        )

    # ── Action buttons from check report ─────────────────────────────────────
    elif data.startswith("action:"):
        parts  = data.split(":", 2)
        action = parts[1] if len(parts) > 1 else ""
        token  = parts[2] if len(parts) > 2 else ""

        # Resolve short token → full IOC
        ioc = resolve_ioc_token(token)
        if not ioc:
            await query.answer(
                "⚠️ IOC reference expired. Please run /check again.",
                show_alert=True
            )
            return

        if action == "monitor" and ioc:
            ioc_type = clf.classify(ioc)
            user_id  = query.from_user.id
            admins: list = context.bot_data.setdefault("admin_users", [])
            if user_id not in admins:
                admins.append(user_id)
            is_new = db.add_to_watchlist(ioc, ioc_type, user_id)
            status = "Added to" if is_new else "Re-activated in"
            await query.answer(f"✅ {status} watchlist!", show_alert=True)

        elif action == "summary" and ioc:
            ioc_type = clf.classify(ioc)
            history  = db.get_ioc_history_for(ioc)
            if history:
                result = history[0]
                summary = rb.build_executive_summary(ioc, ioc_type, result)
                await query.message.reply_text(
                    f"<pre>{summary}</pre>",
                    parse_mode=ParseMode.HTML,
                )
            else:
                await query.answer("No history found. Run /check first.", show_alert=True)

        elif action == "recheck" and ioc:
            ioc_type = clf.classify(ioc)
            if ioc_type == "unknown":
                await query.answer("Cannot classify this IOC.", show_alert=True)
                return

            await query.answer("⏳ Re-checking IOC…")
            try:
                report_text, result_dict = await _run_analysis(ioc, ioc_type)
                db.save_ioc_result(ioc, ioc_type, result_dict)
                # Build fresh tokens for the re-check keyboard
                import hashlib as _hl
                from handlers.check import _IOC_TOKEN_STORE
                tok = _hl.md5(ioc.encode()).hexdigest()[:8]
                _IOC_TOKEN_STORE[tok] = ioc
                kb = InlineKeyboardMarkup([
                    [
                        InlineKeyboardButton("🔄 Re-check", callback_data=f"action:recheck:{tok}"),
                        InlineKeyboardButton("🏠 Main Menu", callback_data="menu:home"),
                    ]
                ])
                await query.message.reply_text(
                    report_text,
                    parse_mode=ParseMode.HTML,
                    reply_markup=kb,
                    disable_web_page_preview=True,
                )
            except Exception as e:
                await query.message.reply_text(f"❌ Re-check failed: {e}")

        elif action == "history" and ioc:
            items = db.get_ioc_history_for(ioc)
            if not items:
                await query.answer("No history for this IOC.", show_alert=True)
                return
            sep = "━━━━━━━━━━━━━━━━━━━━━━━━━━"
            lines = [f"📋 <b>History for</b> <code>{ioc[:30]}</code>\n<code>{sep}</code>\n"]
            for item in items:
                risk = item.get("risk_level") or "?"
                em   = _RISK_EMOJI.get(risk, "⚪")
                ts   = (item.get("queried_at") or "")[:16].replace("T", " ")
                ts_score = item.get("threat_score", "?")
                lines.append(f"{em} Score: <b>{ts_score}/100</b>  <i>{ts} UTC</i>")
            msg = "\n".join(lines)
            await query.message.reply_text(msg, parse_mode=ParseMode.HTML)

        elif action == "hunt" and ioc:
            context.args = [ioc]
            from handlers.threats_cmd import hunt_command
            await hunt_command(update, context)

        elif action == "phish" and ioc:
            ioc_type = clf.classify(ioc)
            from handlers.phishing_cmd import analyse_phishing, format_phishing_report
            import html as html_lib
            
            thinking = await query.message.reply_text(
                f"⏳ Running deep phishing analysis for <code>{html_lib.escape(ioc)}</code>…",
                parse_mode=ParseMode.HTML
            )
            try:
                sender = ""
                body = ""
                if ioc_type == "email":
                    sender = ioc
                elif ioc_type == "url":
                    body = ioc
                elif ioc_type == "domain":
                    body = f"https://{ioc}"
                else:
                    body = ioc

                result = await analyse_phishing(
                    sender=sender,
                    body=body,
                )
                report = format_phishing_report(result)
                try:
                    await thinking.delete()
                except Exception:
                    pass
                await query.message.reply_text(
                    report,
                    parse_mode=ParseMode.HTML,
                    disable_web_page_preview=True
                )
            except Exception as e:
                try:
                    await thinking.delete()
                except Exception:
                    pass
                await query.message.reply_text(
                    f"❌ Phishing analysis failed: <code>{html_lib.escape(str(e))}</code>",
                    parse_mode=ParseMode.HTML
                )

        elif action == "pivot" and ioc:
            import correlation
            import html as html_lib
            from handlers.check import _ioc_token
            
            thinking = await query.message.reply_text(
                f"⏳ Retrieving related pivots for <code>{html_lib.escape(ioc)}</code>…",
                parse_mode=ParseMode.HTML
            )
            try:
                ioc_type = clf.classify(ioc)
                corr = await correlation.correlate_ioc(ioc, ioc_type)
                ips = corr.get("related_ips", [])
                domains = corr.get("related_domains", [])
                
                try:
                    await thinking.delete()
                except Exception:
                    pass
                
                if not ips and not domains:
                    await query.message.reply_text(
                        f"🔗 No related IPs or domains resolved for <code>{html_lib.escape(ioc)}</code>.",
                        parse_mode=ParseMode.HTML
                    )
                    return
                
                buttons = []
                msg_lines = [f"🔗 <b>Related Indicators for</b> <code>{html_lib.escape(ioc)}</code>:\n"]
                
                for ip in ips[:5]:
                    tok = _ioc_token(ip)
                    buttons.append([InlineKeyboardButton(f"🌐 IP: {ip}", callback_data=f"action:recheck:{tok}")])
                    msg_lines.append(f"  • 🌐 IP: <code>{ip}</code>")
                    
                for d in domains[:5]:
                    tok = _ioc_token(d)
                    buttons.append([InlineKeyboardButton(f"🔗 Domain: {d}", callback_data=f"action:recheck:{tok}")])
                    msg_lines.append(f"  • 🔗 Domain: <code>{d}</code>")
                    
                buttons.append([InlineKeyboardButton("🏠 Main Menu", callback_data="menu:home")])
                
                await query.message.reply_text(
                    "\n".join(msg_lines),
                    parse_mode=ParseMode.HTML,
                    reply_markup=InlineKeyboardMarkup(buttons)
                )
            except Exception as e:
                try:
                    await thinking.delete()
                except Exception:
                    pass
                await query.message.reply_text(
                    f"❌ Pivot retrieval failed: <code>{html_lib.escape(str(e))}</code>",
                    parse_mode=ParseMode.HTML
                )

        elif action == "extract" and ioc:
            import correlation
            import html as html_lib
            from handlers.check import _ioc_token
            
            thinking = await query.message.reply_text(
                f"⏳ Extracting indicators from <code>{html_lib.escape(ioc)}</code>…",
                parse_mode=ParseMode.HTML
            )
            try:
                ioc_type = clf.classify(ioc)
                extracted = []
                
                if ioc_type == "url":
                    from urllib.parse import urlparse
                    parsed = urlparse(ioc)
                    host = parsed.netloc.split(":")[0] if parsed.netloc else ""
                    if host:
                        extracted.append((host, "domain"))
                        dns_res = await api.dns_resolve(host, "A")
                        if "error" not in dns_res:
                            for ans in dns_res.get("answers", []):
                                if ans.get("type") == "A" and ans.get("data"):
                                    extracted.append((ans["data"], "ip"))
                elif ioc_type == "domain":
                    dns_res = await api.dns_resolve(ioc, "A")
                    if "error" not in dns_res:
                        for ans in dns_res.get("answers", []):
                            if ans.get("type") == "A" and ans.get("data"):
                                extracted.append((ans["data"], "ip"))
                elif ioc_type == "ip":
                    corr = await correlation.correlate_ioc(ioc, ioc_type)
                    for d in corr.get("related_domains", []):
                        extracted.append((d, "domain"))
                elif ioc_type in ("md5", "sha1", "sha256"):
                    corr = await correlation.correlate_ioc(ioc, ioc_type)
                    for ip in corr.get("related_ips", []):
                        extracted.append((ip, "ip"))
                    for d in corr.get("related_domains", []):
                        extracted.append((d, "domain"))
                
                # Deduplicate
                seen = set()
                unique_extracted = []
                for val, t in extracted:
                    if val not in seen and val != ioc:
                        seen.add(val)
                        unique_extracted.append((val, t))
                
                try:
                    await thinking.delete()
                except Exception:
                    pass
                
                if not unique_extracted:
                    await query.message.reply_text(
                        f"📋 No additional sub-indicators could be extracted from <code>{html_lib.escape(ioc)}</code>.",
                        parse_mode=ParseMode.HTML
                    )
                    return

                buttons = []
                msg_lines = [f"📋 <b>Extracted sub-indicators from</b> <code>{html_lib.escape(ioc)}</code>:\n"]
                for val, t in unique_extracted[:8]:
                    tok = _ioc_token(val)
                    icon = "🌐" if t == "ip" else "🔗" if t == "domain" else "🔒"
                    buttons.append([InlineKeyboardButton(f"{icon} {val}", callback_data=f"action:recheck:{tok}")])
                    msg_lines.append(f"  • {icon} <code>{val}</code> ({t.upper()})")
                    
                buttons.append([InlineKeyboardButton("🏠 Main Menu", callback_data="menu:home")])
                
                await query.message.reply_text(
                    "\n".join(msg_lines),
                    parse_mode=ParseMode.HTML,
                    reply_markup=InlineKeyboardMarkup(buttons)
                )
            except Exception as e:
                try:
                    await thinking.delete()
                except Exception:
                    pass
                await query.message.reply_text(
                    f"❌ Extraction failed: <code>{html_lib.escape(str(e))}</code>",
                    parse_mode=ParseMode.HTML
                )

    # ── Case Workbench Callbacks ──────────────────────────────────────────────
    elif data.startswith("case:"):
        parts  = data.split(":", 2)
        action = parts[1] if len(parts) > 1 else ""
        val    = parts[2] if len(parts) > 2 else ""
        if action == "switch" and val:
            import case_engine
            chat_id = query.message.chat.id
            success = case_engine.switch_active_case(chat_id, val)
            if success:
                await query.answer(f"Switched to case {val}")
                dash = case_engine.generate_case_dashboard(val)
                mode = case_engine.get_chat_mode(chat_id)
                report_pages = case_engine.format_case_report(val, mode)
                
                await query.message.reply_text(
                    f"📂 Active case switched to: <code>{val}</code>",
                    parse_mode=ParseMode.HTML
                )
                for page in report_pages:
                    if page.strip():
                        await query.message.reply_text(
                            page,
                            parse_mode=ParseMode.HTML,
                            disable_web_page_preview=True
                        )
            else:
                await query.answer(f"Failed to switch to case {val}", show_alert=True)

    # ── DFIR Investigation Callbacks ──────────────────────────────────────────
    elif data.startswith("dfir:"):
        parts  = data.split(":", 2)
        action = parts[1] if len(parts) > 1 else ""
        token  = parts[2] if len(parts) > 2 else ""
        try:
            await handle_dfir_callback(query, context, action, token)
        except Exception as e:
            await query.answer(f"DFIR error: {e}", show_alert=True)

    # ── Nav shortcuts (from DFIR / action buttons) ────────────────────────────
    elif data == "nav:main":
        try:
            await query.edit_message_text(
                WELCOME_MSG,
                parse_mode=ParseMode.HTML,
                reply_markup=_build_menu(),
            )
        except Exception:
            await query.message.reply_text(
                WELCOME_MSG,
                parse_mode=ParseMode.HTML,
                reply_markup=_build_menu(),
            )

    elif data == "nav:history":
        items = db.get_ioc_history(limit=8)
        sep = "━━━━━━━━━━━━━━━━━━━━━━━━━━"
        if not items:
            msg = "📋 <b>No history yet.</b>"
        else:
            lines = [f"📋 <b>Recent Lookups</b>\n<code>{sep}</code>\n"]
            for item in items:
                risk = item.get("risk_level") or "?"
                em   = _RISK_EMOJI.get(risk, "⚪")
                ts   = (item.get("queried_at") or "")[:16].replace("T", " ")
                lines.append(f"{em} <code>{item['ioc'][:28]}</code> <i>({ts})</i>")
            msg = "\n".join(lines)
        try:
            await query.edit_message_text(
                msg,
                parse_mode=ParseMode.HTML,
                reply_markup=InlineKeyboardMarkup([[
                    InlineKeyboardButton("🏠 Back", callback_data="menu:home")
                ]]),
            )
        except Exception:
            await query.message.reply_text(msg, parse_mode=ParseMode.HTML)
