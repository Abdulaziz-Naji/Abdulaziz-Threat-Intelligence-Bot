from telegram import Update
from telegram.ext import ContextTypes
from telegram.constants import ParseMode
import database as db
import ioc_classifier
import correlation
import html as html_lib
import decision_engine as de
import json


# ─── /hunt <ioc> ─────────────────────────────────────────────────────────────

async def threats_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """/threats and /topthreats - Show top critical threats from last 24 hours."""
    top = db.get_top_threats(limit=10, hours=24)
    if not top:
        await update.message.reply_text(
            "🟢 <b>No critical threat IOCs collected in the last 24 hours.</b>\n\n"
            "<i>Feed polling is active — new threats will be reported automatically.</i>",
            parse_mode=ParseMode.HTML
        )
        return

    lines = []
    for idx, t in enumerate(top, 1):
        sources = t.get("sources") or "Unknown"
        categories = t.get("categories") or "Unknown"
        risk = t.get("max_risk", 0)
        if risk >= 75:
            risk_em = "🔴"
        elif risk >= 50:
            risk_em = "🟠"
        elif risk >= 25:
            risk_em = "🟡"
        else:
            risk_em = "🟢"

        ioc_display = html_lib.escape(t["ioc"])
        if len(t["ioc"]) > 40:
            ioc_display = html_lib.escape(t["ioc"][:38]) + "…"

        lines.append(
            f"{idx}. <code>{ioc_display}</code>\n"
            f"   {risk_em} <b>{risk}/100</b> | <b>{t['ioc_type'].upper()}</b>\n"
            f"   📡 <i>{html_lib.escape(sources[:60])}</i>"
        )

    msg = (
        f"🔥 <b>Top Critical Threats (Last 24 Hours)</b>\n"
        f"━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
        + "\n\n".join(lines) + "\n\n"
        f"<i>Use /hunt &lt;ioc&gt; for full correlation analysis.</i>"
    )
    await update.message.reply_text(msg, parse_mode=ParseMode.HTML)


# ─── /hunt <ioc> ─────────────────────────────────────────────────────────────

async def hunt_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """/hunt <ioc> - Full correlation search across feeds, history and watchlist."""
    message = update.effective_message
    if not message:
        return

    if not context.args:
        await message.reply_text(
            "❌ Usage: <code>/hunt &lt;ioc&gt;</code>\n\n"
            "<i>Searches all local feed databases, IOC history, watchlist, "
            "and performs network enrichment.</i>",
            parse_mode=ParseMode.HTML
        )
        return

    ioc = context.args[0].strip()
    ioc_type = ioc_classifier.classify(ioc)

    if ioc_type == "unknown":
        await message.reply_text(
            "❌ Could not classify IOC format.\n"
            "Ensure it's an IP, domain, URL, MD5, SHA1, or SHA256 hash."
        )
        return

    status_msg = await message.reply_text(
        f"🔍 Running full correlation hunt for <code>{html_lib.escape(ioc)}</code>...",
        parse_mode=ParseMode.HTML
    )

    try:
        corr = await correlation.correlate_ioc(ioc, ioc_type)
        decision = de.fuse_from_correlation(ioc, ioc_type, corr)

        sep = "━━━━━━━━━━━━━━━━━━━━━━━━━━"

        # IOC display (truncate long hashes)
        ioc_display = html_lib.escape(ioc)
        if len(ioc) > 44:
            ioc_display = html_lib.escape(ioc[:42]) + "…"

        # Compute total sources count
        live_sources = corr.get("live_intelligence_sources", []) or []
        obs = corr.get("observed_sources", []) or []
        total_sources_count = len(obs) + len(live_sources)

        if total_sources_count == 0:
            if decision.mode == "FALLBACK":
                sources_text = "<i>Unavailable (Fallback Mode)</i>"
            else:
                sources_text = f"<i>Cached/Local intelligence only ({decision.mode})</i>"
        else:
            sources_text = f"<b>{total_sources_count} source(s)</b>"

        msg = (
            f"🕵️ <b>Threat Hunt &amp; Correlation Report</b>\n"
            f"<code>{sep}</code>\n\n"
            f"🔹 <b>Indicator:</b> <code>{ioc_display}</code>\n"
            f"🔹 <b>Type:</b> <b>{ioc_type.upper()}</b>\n\n"
            f"🎯 <b>Verdict:</b> {decision.verdict_em} <b>{decision.verdict}</b>\n"
            f"📊 <b>Composite Risk:</b> <code>{decision.risk_score}/100</code>\n"
            f"🔬 <b>Confidence:</b> <code>{decision.confidence}%</code>\n"
            f"📡 <b>Seen in {sources_text}</b>\n\n"
        )

        # ── Feed Sightings ────────────────────────────────────────────────────
        if obs:
            msg += f"<b>📡 Feed Sources ({len(obs)}):</b>\n"
            for o in obs[:6]:
                first = (o.get("first_seen") or "")[:10]
                last  = (o.get("last_seen") or "")[:10]
                category = html_lib.escape(o.get("threat_category") or "N/A")
                risk_val = o.get("risk_score") or 0
                r_em = "🔴" if risk_val >= 75 else "🟠" if risk_val >= 50 else "🟡" if risk_val >= 25 else "🟢"
                msg += (
                    f"  • <b>{html_lib.escape(o['source'].upper())}</b>\n"
                    f"    {r_em} Risk: <b>{risk_val}</b> | Cat: <i>{category}</i>\n"
                    f"    First: <code>{first}</code> → Last: <code>{last}</code>\n"
                )
            if len(obs) > 6:
                msg += f"  <i>… and {len(obs)-6} more sources</i>\n"
            msg += "\n"
        else:
            msg += "📡 <b>Feed Sources:</b> <i>Not found in any feed database.</i>\n\n"

        # ── Live Intelligence Sources ─────────────────────────────────────────
        if live_sources:
            msg += f"<b>⚡ Live Intelligence Sources ({len(live_sources)}):</b>\n"
            for s in live_sources:
                msg += f"  • <b>{html_lib.escape(s)}</b>\n"
            msg += "\n"
        else:
            msg += "⚡ <b>Live Intelligence Sources:</b> <i>No live enrichment intelligence cached.</i>\n\n"

        # ── IOC History ───────────────────────────────────────────────────────
        history = corr.get("ioc_history", [])
        if history:
            msg += "📋 <b>Query History:</b>\n"
            for h in history:
                ts = (h.get("queried_at") or "")[:16].replace("T", " ")
                rl = h.get("risk_level") or "N/A"
                ts_score = h.get("threat_score") or 0
                msg += f"  • <code>{ts}</code> — <b>{rl}</b> ({ts_score}/100)\n"
            msg += "\n"

        # ── Watchlist ─────────────────────────────────────────────────────────
        if corr.get("in_watchlist"):
            wl_risk = corr.get("watchlist_risk", "N/A")
            msg += f"👁 <b>Watchlist:</b> <b>YES</b> — Current Risk: <b>{wl_risk}</b>\n\n"

        # ── Network details ───────────────────────────────────────────────────
        if corr.get("asn") or corr.get("country"):
            msg += (
                f"🌍 <b>Network Context:</b>\n"
                f"  • Country: <b>{html_lib.escape(corr.get('country', 'N/A'))}</b>\n"
                f"  • City: <b>{html_lib.escape(corr.get('city', 'N/A') or 'N/A')}</b>\n"
                f"  • ASN: <code>{html_lib.escape(corr.get('asn', 'N/A'))}</code>\n"
                f"  • ISP: <b>{html_lib.escape(corr.get('isp', 'N/A'))}</b>\n\n"
            )

        # ── Related indicators ────────────────────────────────────────────────
        related_lines = []
        if corr.get("related_ips"):
            ips = ", ".join(f"<code>{html_lib.escape(ip)}</code>" for ip in corr["related_ips"][:4])
            related_lines.append(f"  • IPs: {ips}")
        if corr.get("related_domains"):
            doms = ", ".join(f"<code>{html_lib.escape(d)}</code>" for d in corr["related_domains"][:4])
            related_lines.append(f"  • Domains: {doms}")

        if related_lines:
            msg += "🔗 <b>Related Indicators:</b>\n" + "\n".join(related_lines) + "\n\n"

        # ── Malware Associations (Phase 3) ────────────────────────────────────
        families = corr.get("malware_families", [])
        c2_for   = corr.get("tf_c2_for", [])
        if families or c2_for:
            msg += "🦠 <b>Malware Association (ThreatFox):</b>\n"
            if families:
                fam_str = ", ".join(f"<code>{html_lib.escape(f)}</code>" for f in families[:4])
                msg += f"  • Families: {fam_str}\n"
            if c2_for:
                c2_str = ", ".join(f"<code>{html_lib.escape(a)}</code>" for a in c2_for[:3])
                msg += f"  • C2 for: {c2_str}\n"
            msg += "\n"

        # ── Tags ─────────────────────────────────────────────────────────────
        top_tags = corr.get("top_tags", [])
        if top_tags:
            tag_str = " ".join(f"<code>#{html_lib.escape(t)}</code>" for t in top_tags)
            msg += f"🏷 <b>Top Tags:</b> {tag_str}\n\n"

        # ── Enrichment ───────────────────────────────────────────────────────
        enrichment_lines = []
        if corr.get("shodan_ports"):
            ports = ", ".join(str(p) for p in corr["shodan_ports"][:8])
            enrichment_lines.append(f"  • Shodan Ports: <code>{ports}</code>")
        if corr.get("greynoise_activity"):
            gn = corr["greynoise_activity"]
            noise_em = "⚠️" if gn.get("noise") else "✅"
            cls = html_lib.escape(str(gn.get("classification", "N/A")))
            enrichment_lines.append(
                f"  • GreyNoise: {noise_em} Noise: <b>{gn.get('noise')}</b> | "
                f"Classification: <b>{cls}</b>"
            )
        if enrichment_lines:
            msg += "⚡ <b>Host Enrichment:</b>\n" + "\n".join(enrichment_lines) + "\n\n"
        msg += (
            f"<code>{sep}</code>\n"
            f"<i>Hunt complete. Use /check {html_lib.escape(ioc[:40])} for full external analysis.</i>"
        )

        await status_msg.edit_text(msg, parse_mode=ParseMode.HTML)

    except Exception as e:
        await status_msg.edit_text(
            f"❌ Error during hunt: <code>{html_lib.escape(str(e))}</code>",
            parse_mode=ParseMode.HTML
        )
