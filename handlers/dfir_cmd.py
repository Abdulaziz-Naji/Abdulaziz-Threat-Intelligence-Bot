"""
handlers/dfir_cmd.py - DFIR Investigation Command Handler

Commands:
  /dfir        → Full forensic investigation of uploaded file
  /timeline    → Show attack timeline for last DFIR case
  /iocs        → Export extracted IOCs from last DFIR case
  /casereport  → Full case report (multi-page)

Also upgrades the existing /file handler to embed DFIR output.
"""
import os
import io
import hashlib
import logging
import asyncio

from telegram import Update
from telegram.ext import ContextTypes
from telegram.constants import ParseMode

import database as db
import dfir_engine as dfir
import dfir_extractor as extractor
from handlers.file_cmd import (
    detect_file_type, parse_pdf, parse_image_exif,
    parse_zip, parse_apk, query_malwarebazaar
)

logger = logging.getLogger(__name__)

# ── Session cache: stores last DFIR report per user ──────────────────────────
_dfir_sessions: dict[int, dfir.DFIRReport] = {}


# ─── /dfir Handler ────────────────────────────────────────────────────────────

async def dfir_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """
    Full DFIR investigation of an uploaded file.
    Usage: Send /dfir as caption on a file upload,
           OR reply /dfir to an existing file message,
           OR send /dfir <local_file_path> to analyze a local file.
    """
    message = update.effective_message
    user_id = update.effective_user.id if update.effective_user else 0

    # ── Check if a local file path argument is provided ───────────────────
    filepath_arg = " ".join(context.args) if context.args else ""
    if filepath_arg and os.path.exists(filepath_arg) and os.path.isfile(filepath_arg):
        from handlers.auto_dfir_handler import analyze_local_path_dfir
        await analyze_local_path_dfir(update, context, filepath_arg)
        return

    # ── Resolve target message with attachment ─────────────────────────────
    target_msg = message
    if not message.document and not message.photo:
        if message.reply_to_message and (
            message.reply_to_message.document or message.reply_to_message.photo
        ):
            target_msg = message.reply_to_message
        else:
            await message.reply_text(
                "🔬 <b>DFIR Investigation Engine</b>\n\n"
                "Usage:\n"
                "  • Send a file with <code>/dfir</code> as caption\n"
                "  • Reply <code>/dfir</code> to an existing file\n"
                "  • Send <code>/dfir &lt;local_file_path&gt;</code> to analyze local evidence\n\n"
                "<b>Supported evidence types:</b>\n"
                "  📄 PDF Documents\n"
                "  📦 ZIP Archives\n"
                "  🤖 Android APK\n"
                "  🖼 Images (JPG/PNG/GIF/WEBP)\n"
                "  📁 Any file (IOC extraction + hash TI)\n\n"
                "<i>The engine will act as a Senior DFIR Investigator and answer: "
                "What happened? When? How? MITRE ATT&CK mapping, "
                "timeline, containment recommendations.</i>",
                parse_mode=ParseMode.HTML,
            )
            return

    bot = context.bot
    document = target_msg.document
    photo = target_msg.photo

    file_id = ""
    filename = "unknown_file"
    file_size = 0

    if document:
        file_id = document.file_id
        filename = document.file_name or "uploaded_file"
        file_size = document.file_size or 0
    elif photo:
        largest = photo[-1]
        file_id = largest.file_id
        filename = "photo.jpg"
        file_size = largest.file_size or 0

    if not file_id:
        await message.reply_text("❌ Failed to resolve file ID.")
        return

    thinking = await message.reply_text(
        "🔬 <b>DFIR Engine Initialising…</b>\n\n"
        "⏳ Downloading evidence and performing forensic analysis…\n"
        "This includes: magic bytes detection, metadata extraction,\n"
        "anomaly scanning, IOC extraction, threat intelligence lookup\n"
        "and full investigator narrative generation.",
        parse_mode=ParseMode.HTML,
    )

    temp_filepath = None
    download_success = False
    try:
        # ── Download file ────────────────────────────────────────────────────
        size_mb = file_size / (1024 * 1024)
        logger.info(f"[DFIR-CMD] File received: {filename}")
        logger.info(f"[DFIR-CMD] Reported size: {size_mb:.2f} MB ({file_size} bytes)")
        logger.info(f"[DFIR-CMD] Telegram download limit: 20.00 MB")

        # CRITICAL: Check file size BEFORE calling get_file().
        # Telegram's /getFile endpoint rejects files > 20,000,000 bytes with BadRequest.
        # We must gate on size FIRST — before any API call — to avoid silent fallback.
        TG_DOWNLOAD_LIMIT = 20 * 1024 * 1024

        if file_size > TG_DOWNLOAD_LIMIT:
            logger.warning(
                f"[DFIR-CMD] File {filename} is {size_mb:.2f} MB which exceeds the "
                f"Telegram public API download limit. Skipping get_file(). "
                f"Routing to metadata-only mode."
            )
            download_success = False
            sha256 = hashlib.sha256(filename.encode()).hexdigest()
            ftype = extractor.detect_file_type(b'\x00', filename)
        else:
            logger.info(f"[DFIR-CMD] File within limit. Calling get_file()...")
            try:
                tg_file = await bot.get_file(file_id)
                logger.info(f"[DFIR-CMD] get_file() succeeded.")
                logger.info(f"[DFIR-CMD] Starting download_to_memory()...")

                buf = io.BytesIO()
                await tg_file.download_to_memory(out=buf)
                file_bytes = buf.getvalue()
                logger.info(f"[DFIR-CMD] Download complete. Bytes: {len(file_bytes)}")

                sha256 = hashlib.sha256(file_bytes).hexdigest()
                ftype = detect_file_type(file_bytes, filename)
                logger.info(f"[DFIR-CMD] SHA-256: {sha256}, type: {ftype}")
                download_success = True
            except Exception as dl_err:
                logger.error(
                    f"[DFIR-CMD] Download FAILED for {filename} ({size_mb:.2f} MB). "
                    f"Exception type: {type(dl_err).__name__}. Message: {dl_err}. "
                    f"Routing to metadata-only mode."
                )
                download_success = False
                sha256 = hashlib.sha256(filename.encode()).hexdigest()
                ftype = extractor.detect_file_type(b'\x00', filename)

        logger.info(f"[DFIR-CMD] download_success={download_success}, ftype={ftype}")

        if download_success:
            await thinking.edit_text(
                f"🔬 <b>DFIR Engine — Step 2/4</b>\n\n"
                f"📁 File: <code>{filename}</code>\n"
                f"📦 Type: <code>{ftype.upper()}</code>\n"
                f"🔒 SHA-256: <code>{sha256[:32]}…</code>\n\n"
                f"⏳ Running deep forensic routing & analysis…",
                parse_mode=ParseMode.HTML,
            )
            
            # ── Threat Intelligence lookups (parallel) ────────────────────────
            vt_res, otx_res, mb_res = await asyncio.gather(
                api.vt_check_hash(sha256),
                api.otx_check_hash(sha256),
                query_malwarebazaar(sha256),
            )
        else:
            await thinking.edit_text(
                f"🔬 <b>DFIR Engine — Step 2/4</b>\n\n"
                f"📁 File: <code>{filename}</code>\n"
                f"📦 Type: <code>{ftype.upper()}</code>\n"
                f"⚠️ Status: <code>Download Limit Fallback</code>\n\n"
                f"⏳ Running metadata & static profile analysis…",
                parse_mode=ParseMode.HTML,
            )
            vt_res, otx_res, mb_res = {}, {}, {}

        await thinking.edit_text(
            "🔬 <b>DFIR Engine — Step 4/4</b>\n\n"
            "🧠 Generating investigator narrative…\n"
            "  • Answering 11 DFIR questions\n"
            "  • Mapping MITRE ATT&CK techniques\n"
            "  • Building attack timeline\n"
            "  • Producing containment recommendations",
            parse_mode=ParseMode.HTML,
        )

        # ── Run DFIR engine ──────────────────────────────────────────
        if not download_success:
            logger.info(f"[DFIR-CMD] ↳ ROUTE: metadata-only")
            report = dfir.analyze_file_dfir_metadata_only(
                filename=filename,
                file_size=file_size,
                file_type=ftype,
            )
        elif temp_filepath:
            logger.info(f"[DFIR-CMD] ↳ ROUTE: streaming path-based (temp={temp_filepath})")
            report = dfir.analyze_file_dfir_path(
                filepath=temp_filepath,
                filename=filename,
                file_type=ftype,
                metadata={},
                anomalies=[],
                vt_result=vt_res,
                mb_result=mb_res,
            )
            logger.info(f"[DFIR-CMD] analyze_file_dfir_path() done. findings={len(report.findings)}")
        else:
            # ── Type-specific metadata extraction ─────────────────────────────
            metadata = {}
            anomalies = []

            if ftype in ("png", "jpg", "jpeg", "gif", "webp"):
                metadata = parse_image_exif(file_bytes)
                if metadata.get("GPSInfo"):
                    anomalies.append("GPS location data found in EXIF")
            elif ftype == "pdf":
                metadata = parse_pdf(file_bytes)
                if metadata.get("has_js"):
                    anomalies.append("Embedded JavaScript in PDF (/JS, /JavaScript)")
                if metadata.get("has_openaction"):
                    anomalies.append("Auto-execution action in PDF (/OpenAction, /AA)")
            elif ftype == "zip":
                metadata = parse_zip(file_bytes)
                if metadata.get("hidden_files"):
                    anomalies.append(f"Hidden files in ZIP: {metadata['hidden_files'][:3]}")
                if metadata.get("encrypted"):
                    anomalies.append("Password-protected ZIP archive")
            elif ftype == "apk":
                metadata = parse_apk(file_bytes)
                dangerous = [p.split(".")[-1] for p in metadata.get("permissions", [])
                             if p.split(".")[-1] in (
                                 "SEND_SMS","RECEIVE_SMS","RECORD_AUDIO",
                                 "CAMERA","READ_CONTACTS","WRITE_SETTINGS"
                             )]
                if dangerous:
                    anomalies.append(f"Dangerous permissions: {', '.join(dangerous)}")

            report = dfir.analyze_file_dfir(
                file_bytes=file_bytes,
                filename=filename,
                file_type=ftype,
                metadata=metadata,
                anomalies=anomalies,
                vt_result=vt_res,
                mb_result=mb_res,
            )

        # Store in session
        _dfir_sessions[user_id] = report

        # ── Ingest into Active Case ───────────────────────────────────────
        import case_engine
        case_id = case_engine.resolve_active_case(update.effective_chat.id)
        case_engine.ingest_artifact(case_id, report)

        # Save to DB (Legacy support)
        try:
            db.save_dfir_case(
                case_id=f"DFIR-{report.case_id}",
                evidence_type=report.evidence_type,
                evidence_name=report.evidence_name,
                verdict=report.verdict,
                risk_score=report.risk_score,
                findings_count=len(report.findings),
                mitre_count=len(report.mitre_techniques),
                iocs_count=sum(len(v) for v in report.extracted_iocs.values() if isinstance(v, list)),
            )
        except Exception as db_err:
            logger.warning(f"DB save error: {db_err}")

        await thinking.delete()

        # ── Send case report pages ─────────────────────────────────────────
        mode = case_engine.get_chat_mode(update.effective_chat.id)
        pages = case_engine.format_case_report(case_id, mode)
        for i, page in enumerate(pages):
            if not page.strip():
                continue
            try:
                await message.reply_text(
                    page,
                    parse_mode=ParseMode.HTML,
                    disable_web_page_preview=True,
                )
            except Exception as send_err:
                logger.warning(f"DFIR page {i} send error: {send_err}")
                # Try without markup
                await message.reply_text(
                    page[:4000],
                    parse_mode=ParseMode.HTML,
                    disable_web_page_preview=True,
                )

    except Exception as e:
        logger.error(f"DFIR handler error: {e}", exc_info=True)
        try:
            await thinking.delete()
        except Exception:
            pass
        await message.reply_text(
            f"❌ <b>DFIR Analysis Failed:</b> <code>{e}</code>",
            parse_mode=ParseMode.HTML,
        )
    finally:
        if temp_filepath and os.path.exists(temp_filepath):
            try:
                os.unlink(temp_filepath)
            except Exception as e:
                logger.warning(f"Failed to delete temp file {temp_filepath}: {e}")


# ─── /timeline Handler ────────────────────────────────────────────────────────

async def timeline_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Show the attack timeline from the last DFIR case."""
    message = update.effective_message
    user_id = update.effective_user.id if update.effective_user else 0

    report = _dfir_sessions.get(user_id)
    if not report:
        await message.reply_text(
            "⚠️ No active DFIR case found.\n\n"
            "Run <code>/dfir</code> on a file first to start an investigation.",
            parse_mode=ParseMode.HTML,
        )
        return

    sep = "━━━━━━━━━━━━━━━━━━━━━━━━━━"
    import html as _h
    msg = (
        f"📅 <b>ATTACK TIMELINE</b>\n"
        f"<code>{sep}</code>\n"
        f"🔬 Case: <code>DFIR-{report.case_id}</code>\n"
        f"📁 Evidence: <code>{_h.escape(report.evidence_name)}</code>\n"
        f"<code>{sep}</code>\n\n"
    )

    if not report.attack_timeline:
        msg += "<i>No timeline events recorded for this case.</i>"
    else:
        for entry in report.attack_timeline:
            t = _h.escape(str(entry.get("time", "Unknown"))[:30])
            ev = _h.escape(str(entry.get("event", ""))[:120])
            msg += f"  <code>[{t}]</code>\n  ➜ {ev}\n\n"

    await message.reply_text(msg, parse_mode=ParseMode.HTML, disable_web_page_preview=True)


# ─── /iocs Handler ────────────────────────────────────────────────────────────

async def iocs_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Export extracted IOCs from the last DFIR case."""
    message = update.effective_message
    user_id = update.effective_user.id if update.effective_user else 0

    report = _dfir_sessions.get(user_id)
    if not report:
        await message.reply_text(
            "⚠️ No active DFIR case.\nRun <code>/dfir</code> on a file first.",
            parse_mode=ParseMode.HTML,
        )
        return

    iocs = report.extracted_iocs
    sep = "━━━━━━━━━━━━━━━━━━━━━━━━━━"
    import html as _h

    total = sum(len(v) for v in iocs.values() if isinstance(v, list))
    msg = (
        f"📡 <b>EXTRACTED IOCs</b>\n"
        f"<code>{sep}</code>\n"
        f"🔬 Case: <code>DFIR-{report.case_id}</code>\n"
        f"📊 Total: <code>{total}</code> indicators\n"
        f"<code>{sep}</code>\n\n"
    )

    if not total:
        msg += "<i>No IOCs extracted from this evidence.</i>"
    else:
        if iocs.get("ips"):
            msg += f"<b>🌐 IP Addresses ({len(iocs['ips'])}):</b>\n"
            for ip in iocs["ips"][:15]:
                msg += f"  <code>{_h.escape(ip)}</code>\n"
            msg += "\n"

        if iocs.get("domains"):
            msg += f"<b>🔗 Domains ({len(iocs['domains'])}):</b>\n"
            for d in iocs["domains"][:15]:
                msg += f"  <code>{_h.escape(d)}</code>\n"
            msg += "\n"

        if iocs.get("urls"):
            msg += f"<b>🌍 URLs ({len(iocs['urls'])}):</b>\n"
            for u in iocs["urls"][:10]:
                msg += f"  <code>{_h.escape(u[:70])}</code>\n"
            msg += "\n"

        if iocs.get("emails"):
            msg += f"<b>📧 Emails ({len(iocs['emails'])}):</b>\n"
            for em in iocs["emails"][:10]:
                msg += f"  <code>{_h.escape(em)}</code>\n"
            msg += "\n"

        if iocs.get("hashes"):
            msg += f"<b>🔒 Hashes ({len(iocs['hashes'])}):</b>\n"
            for h in iocs["hashes"][:10]:
                msg += f"  <code>{_h.escape(h[:48])}</code>\n"
            msg += "\n"

    await message.reply_text(
        msg, parse_mode=ParseMode.HTML,
        disable_web_page_preview=True,
    )


# ─── /casereport Handler ──────────────────────────────────────────────────────

async def casereport_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Send the full DFIR case report for the active session."""
    message = update.effective_message
    user_id = update.effective_user.id if update.effective_user else 0

    report = _dfir_sessions.get(user_id)
    if not report:
        await message.reply_text(
            "⚠️ No active DFIR case.\nRun <code>/dfir</code> on a file first.",
            parse_mode=ParseMode.HTML,
        )
        return

    pages = dfir.format_dfir_report_html(report, max_findings=20)
    await message.reply_text(
        f"📋 Sending full case report for <b>DFIR-{report.case_id}</b> "
        f"({len(pages)} sections)…",
        parse_mode=ParseMode.HTML,
    )
    for i, page in enumerate(pages):
        if not page.strip():
            continue
        try:
            await message.reply_text(
                page, parse_mode=ParseMode.HTML, disable_web_page_preview=True
            )
        except Exception as e:
            logger.warning(f"casereport page {i} error: {e}")





# ─── DFIR Callback Dispatcher ─────────────────────────────────────────────────

async def handle_dfir_callback(query, context: ContextTypes.DEFAULT_TYPE, action: str, token: str):
    """
    Dispatch dfir:* callbacks.
    Called from the main callbacks.py dispatcher.
    """
    user_id = query.from_user.id if query.from_user else 0
    report = _dfir_sessions.get(user_id)

    if action == "timeline":
        if not report:
            await query.answer("No active DFIR case. Run /dfir on a file first.", show_alert=True)
            return
        sep = "━━━━━━━━━━━━━━━━━━━━━━━━━━"
        import html as _h
        msg = (
            f"📅 <b>ATTACK TIMELINE — DFIR-{report.case_id}</b>\n<code>{sep}</code>\n\n"
        )
        for entry in (report.attack_timeline or [{"time": "N/A", "event": "No timeline recorded"}]):
            t = _h.escape(str(entry.get("time", "?"))[:28])
            ev = _h.escape(str(entry.get("event", ""))[:120])
            msg += f"  <code>[{t}]</code> {ev}\n"
        await query.message.reply_text(msg, parse_mode=ParseMode.HTML, disable_web_page_preview=True)
        await query.answer("✅ Timeline retrieved")

    elif action == "iocs":
        if not report:
            await query.answer("No active DFIR case.", show_alert=True)
            return
        # Reuse the /iocs logic
        class _FakeUpdate:
            effective_message = query.message
            effective_user = query.from_user
        await iocs_handler(_FakeUpdate(), context)
        await query.answer("✅ IOCs exported")

    elif action == "fullreport":
        if not report:
            await query.answer("No active DFIR case.", show_alert=True)
            return
        class _FakeUpdate:
            effective_message = query.message
            effective_user = query.from_user
        await casereport_handler(_FakeUpdate(), context)
        await query.answer("✅ Full report sent")

    else:
        await query.answer("Unknown DFIR action.", show_alert=True)
