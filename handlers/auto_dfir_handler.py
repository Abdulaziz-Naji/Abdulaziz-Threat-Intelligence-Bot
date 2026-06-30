"""
handlers/auto_dfir_handler.py - AUTONOMOUS DFIR DISPATCHER

THE KEY COMPONENT: This handler fires automatically on ANY file upload.
No command required. No user input. Zero-friction forensic analysis.

PIPELINE:
  1. File received (any Document or Photo)
  2. File downloaded and buffered
  3. Type detected (magic bytes + heuristics)
  4. If archive → recursive extraction → queue all children
  5. Each file routed to correct forensic engine
  6. TI enrichment on extracted IOCs
  7. 12-section DFIR report sent to user

SUPPORTED AUTO-TRIGGERS:
  - Any Document (PDF, EXE, ZIP, DOCX, PCAP, APK, RAR, PS1, ...)
  - Any Photo (JPEG, PNG, etc.)
  - Files in groups / private chats
  - Replies with attached files
"""
from __future__ import annotations

import io
import asyncio
import hashlib
import logging
from datetime import datetime, timezone

from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import ContextTypes
from telegram.constants import ParseMode

import config
import api_clients as api
import dfir_engine as dfir
import dfir_extractor as extractor
import database as db
import image_forensics as img_forensics

logger = logging.getLogger(__name__)

# Per-user DFIR session cache: user_id -> list[DFIRReport]
_auto_sessions: dict[int, list[dfir.DFIRReport]] = {}

# Maximum file size for auto-DFIR (Telegram bot limit = 20MB by default)
MAX_FILE_BYTES = config.MAX_FILE_SIZE_MB * 1024 * 1024


# ─── Main Auto-DFIR Dispatcher ────────────────────────────────────────────────

async def auto_dfir_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """
    AUTONOMOUS DFIR DISPATCHER

    Fires automatically on ANY document or photo upload.
    No command required — this IS the event-driven pipeline entry point.
    """
    message = update.effective_message
    if not message:
        return

    user_id = update.effective_user.id if update.effective_user else 0

    # ── Resolve attached file ──────────────────────────────────────────────
    document = message.document
    photos   = message.photo

    if document:
        file_id   = document.file_id
        filename  = document.file_name or "uploaded_file"
        file_size = document.file_size or 0
    elif photos:
        # Largest photo resolution
        largest   = photos[-1]
        file_id   = largest.file_id
        filename  = "photo.jpg"
        file_size = largest.file_size or 0
    else:
        return  # Not a file upload

    # ── Stage 1: Acknowledge receipt ──────────────────────────────────────
    now_label = datetime.now(timezone.utc).strftime("%H:%M:%S UTC")
    size_mb = file_size / (1024 * 1024)
    logger.info(f"[DFIR] ━━━━━━━━━━ NEW CASE ━━━━━━━━━━")
    logger.info(f"[DFIR] File received: {filename}")
    logger.info(f"[DFIR] File ID: {file_id}")
    logger.info(f"[DFIR] Reported size: {size_mb:.2f} MB ({file_size} bytes)")
    logger.info(f"[DFIR] Telegram download limit: 20.00 MB (20,000,000 bytes)")

    status_msg = await message.reply_text(
        f"🔬 <b>DFIR AUTO-EXECUTION ENGINE</b>\n"
        f"<code>━━━━━━━━━━━━━━━━━━━━━━━━━━</code>\n"
        f"📁 <b>Evidence:</b> <code>{_h(filename)}</code>\n"
        f"📐 <b>Size:</b> <code>{size_mb:.1f} MB</code>\n"
        f"🕐 <b>Received:</b> <code>{now_label}</code>\n\n"
        f"<b>⏳ Stage 1/5:</b> Downloading evidence…",
        parse_mode=ParseMode.HTML,
    )

    temp_filepath = None
    download_success = False
    try:
        # ── Download ──────────────────────────────────────────────────────
        # CRITICAL: Check file size BEFORE calling get_file().
        # Telegram's public Bot API /getFile endpoint hard-rejects files > 20,000,000 bytes.
        # If we call get_file() on a large file, it raises BadRequest immediately
        # — the download never starts, and we fall through to metadata-only mode.
        # The correct fix: gate on size FIRST, before any Telegram API call.
        TG_DOWNLOAD_LIMIT = 20 * 1024 * 1024  # 20 MB hard limit on public Bot API

        if file_size > TG_DOWNLOAD_LIMIT:
            logger.warning(
                f"[DFIR] File size {file_size} bytes ({size_mb:.2f} MB) exceeds Telegram "
                f"public API download limit ({TG_DOWNLOAD_LIMIT} bytes). "
                f"Skipping get_file() — download is impossible on public servers. "
                f"Routing to metadata-only mode."
            )
            download_success = False
            sha256 = hashlib.sha256(filename.encode()).hexdigest()
            ftype  = extractor.detect_file_type(b'\x00', filename)
        else:
            logger.info(f"[DFIR] File within download limit. Calling get_file() for file_id={file_id[:20]}…")
            try:
                tg_file = await context.bot.get_file(file_id)
                logger.info(f"[DFIR] get_file() succeeded. file_path={getattr(tg_file, 'file_path', 'N/A')!r}")
                logger.info(f"[DFIR] Starting download_to_memory()…")

                buf      = io.BytesIO()
                await tg_file.download_to_memory(out=buf)
                raw_data = buf.getvalue()
                logger.info(f"[DFIR] Download complete. Bytes received: {len(raw_data)}")

                sha256 = hashlib.sha256(raw_data).hexdigest()
                ftype  = extractor.detect_file_type(raw_data, filename)
                logger.info(f"[DFIR] SHA-256: {sha256}")
                logger.info(f"[DFIR] Detected type: {ftype}")
                download_success = True
            except Exception as dl_err:
                logger.error(
                    f"[DFIR] Download FAILED for {filename} ({size_mb:.2f} MB). "
                    f"Exception type: {type(dl_err).__name__}. "
                    f"Exception: {dl_err}. "
                    f"Routing to metadata-only mode."
                )
                download_success = False
                sha256 = hashlib.sha256(filename.encode()).hexdigest()
                ftype  = extractor.detect_file_type(b'\x00', filename)

        logger.info(f"[DFIR] download_success={download_success}, ftype={ftype}")

        if download_success:
            await status_msg.edit_text(
                f"🔬 <b>DFIR AUTO-EXECUTION ENGINE</b>\n"
                f"<code>━━━━━━━━━━━━━━━━━━━━━━━━━━</code>\n"
                f"📁 <code>{_h(filename)}</code>\n"
                f"🔍 <b>Type Detected:</b> <code>{ftype.upper()}</code>\n"
                f"🔒 <b>SHA-256:</b> <code>{sha256[:24]}…</code>\n\n"
                f"<b>⏳ Stage 2/5:</b> File intelligence & forensic analysis…",
                parse_mode=ParseMode.HTML,
            )
            
            # ── Stage 3: Parallel TI lookups ─────────────────────────────────
            vt_res, otx_res, mb_res = await asyncio.gather(
                api.vt_check_hash(sha256),
                api.otx_check_hash(sha256),
                _safe_mb_check(sha256),
            )
        else:
            await status_msg.edit_text(
                f"🔬 <b>DFIR AUTO-EXECUTION ENGINE</b>\n"
                f"<code>━━━━━━━━━━━━━━━━━━━━━━━━━━</code>\n"
                f"📁 <code>{_h(filename)}</code>\n"
                f"🔍 <b>Type:</b> <code>{ftype.upper()}</code>\n"
                f"⚠️ <b>Status:</b> <code>Download Limit Fallback</code>\n\n"
                f"<b>⏳ Stage 2/5:</b> Running metadata & static profile analysis…",
                parse_mode=ParseMode.HTML,
            )
            vt_res, otx_res, mb_res = {}, {}, {}

        reports: list[dfir.DFIRReport] = []
        is_archive = False

        if not download_success:
            logger.info(f"[DFIR] ↳ ROUTE: metadata-only (download_success=False, file_size={file_size})")
            report = dfir.analyze_file_dfir_metadata_only(
                filename=filename,
                file_size=file_size,
                file_type=ftype,
            )
            reports.append(report)
        elif temp_filepath:
            # Stage 4 for Large Files: streaming path-based analysis
            logger.info(f"[DFIR] ↳ ROUTE: streaming path-based analysis (temp_filepath={temp_filepath})")
            report = dfir.analyze_file_dfir_path(
                filepath=temp_filepath,
                filename=filename,
                file_type=ftype,
                metadata={},
                anomalies=[],
                vt_result=vt_res,
                mb_result=mb_res,
            )
            logger.info(f"[DFIR] analyze_file_dfir_path() complete. findings={len(report.findings)}, risk={report.risk_score}")
            reports.append(report)
        else:
            # ── Stage 2: Recursive Extraction ────────────────────────────────
            analysis_queue = extractor.extract_all(raw_data, filename)
            total_files    = len(analysis_queue)

            # If extraction yielded nothing, treat the root file as the single item
            if not analysis_queue:
                analysis_queue = [(filename, raw_data, 0, "root")]
                total_files    = 1

            is_archive = total_files > 1
            archive_msg = f" → <b>{total_files} files extracted</b>" if is_archive else ""

            await status_msg.edit_text(
                f"🔬 <b>DFIR AUTO-EXECUTION ENGINE</b>\n"
                f"<code>━━━━━━━━━━━━━━━━━━━━━━━━━━</code>\n"
                f"📁 <code>{_h(filename)}</code> [{ftype.upper()}]{archive_msg}\n\n"
                f"<b>⏳ Stage 3/5:</b> Forensic routing & deep analysis…\n"
                f"  🔸 VT hash lookup\n"
                f"  🔸 Type-specific engine\n"
                f"  🔸 IOC extraction\n"
                f"  🔸 Entropy analysis",
                parse_mode=ParseMode.HTML,
            )

            # ── IMAGE: Full Metadata Extraction & Digital Forensics Report ────────────
            _IMAGE_TYPES = ('jpeg', 'jpg', 'png', 'gif', 'webp', 'tiff', 'bmp')
            if ftype in _IMAGE_TYPES:
                await status_msg.edit_text(
                    f"🔬 <b>DIGITAL FORENSICS ENGINE</b>\n"
                    f"<code>━━━━━━━━━━━━━━━━━━━━━━━━━━</code>\n"
                    f"📁 <code>{_h(filename)}</code>\n\n"
                    f"<b>⏳ Running full forensic image analysis…</b>",
                    parse_mode=ParseMode.HTML,
                )
                try:
                    img_analysis = img_forensics.analyze_image_full(raw_data, filename)
                    meta_pages   = img_forensics.format_metadata_report(img_analysis, is_photo=bool(photos))
                    try:
                        await status_msg.delete()
                    except Exception:
                        pass
                    for pg in meta_pages:
                        if pg.strip():
                            try:
                                await message.reply_text(
                                    pg, parse_mode=ParseMode.HTML,
                                    disable_web_page_preview=True,
                                )
                            except Exception:
                                await message.reply_text(pg[:3900], parse_mode=ParseMode.HTML)
                    # Complete image investigation immediately without buttons or generic AI text
                    return
                except Exception as img_err:
                    logger.warning(f"[AutoDFIR] Image forensics error: {img_err}")


            # ── Stage 4: Forensic Execution ────────────────────────────────────
            for fname, fdata, depth, parent in analysis_queue:
                ftype_child = extractor.detect_file_type(fdata, fname)

                # For child files, only run TI on root file sha256
                child_vt  = vt_res  if (fname == filename) else {}
                child_mb  = mb_res  if (fname == filename) else {}

                # Extract pre-metadata for image/pdf/zip/apk
                metadata, anomalies = _extract_metadata(fdata, fname, ftype_child)

                report = dfir.analyze_file_dfir(
                    file_bytes=fdata,
                    filename=fname,
                    file_type=ftype_child,
                    metadata=metadata,
                    anomalies=anomalies,
                    vt_result=child_vt,
                    mb_result=child_mb,
                )
                reports.append(report)

        # ── Merge multi-file reports if archive ───────────────────────────
        primary_report = _merge_reports(reports, filename, ftype, sha256)

        # ── Stage 5: IOC TI Enrichment ────────────────────────────────────
        await status_msg.edit_text(
            f"🔬 <b>DFIR AUTO-EXECUTION ENGINE</b>\n"
            f"<code>━━━━━━━━━━━━━━━━━━━━━━━━━━</code>\n"
            f"📁 <code>{_h(filename)}</code>\n\n"
            f"<b>⏳ Stage 4/5:</b> Threat Intelligence enrichment…\n"
            f"  🔸 AbuseIPDB reputation check\n"
            f"  🔸 OTX domain correlation\n"
            f"  🔸 Building attack hypothesis\n"
            f"  🔸 Kill chain reconstruction",
            parse_mode=ParseMode.HTML,
        )

        ti_enrichment = await _enrich_top_iocs(primary_report)
        primary_report.ti_enrichment = ti_enrichment

        # Rebuild hypothesis after enrichment
        primary_report.hypothesis    = dfir.generate_hypothesis(primary_report)
        primary_report.attack_chain  = dfir.reconstruct_attack_chain(primary_report)
        primary_report.finalize()

        # ── Ingest into Active Case ───────────────────────────────────────
        import case_engine
        case_id = case_engine.resolve_active_case(update.effective_chat.id)
        case_engine.ingest_artifact(case_id, primary_report)

        # ── Save to DB (Legacy support) ───────────────────────────────────
        try:
            db.save_dfir_case(
                case_id       = f"DFIR-{primary_report.case_id}",
                evidence_type = primary_report.evidence_type,
                evidence_name = primary_report.evidence_name,
                verdict       = primary_report.verdict,
                risk_score    = primary_report.risk_score,
                findings_count= len(primary_report.findings),
                mitre_count   = len(primary_report.mitre_techniques),
                iocs_count    = sum(len(v) for v in primary_report.extracted_iocs.values() if isinstance(v, list)),
            )
        except Exception as db_err:
            logger.warning(f"DB save error: {db_err}")

        # ── Store session ─────────────────────────────────────────────────
        _auto_sessions[user_id] = reports
        # Also update legacy dfir_cmd sessions
        try:
            from handlers.dfir_cmd import _dfir_sessions
            _dfir_sessions[user_id] = primary_report
        except Exception:
            pass

        # ── Delete status message ─────────────────────────────────────────
        try:
            await status_msg.delete()
        except Exception:
            pass

        # ── Stage 5: Send Case Report & Dashboard ─────────────────────────
        mode = case_engine.get_chat_mode(update.effective_chat.id)
        pages = case_engine.format_case_report(case_id, mode)

        for i, page in enumerate(pages):
            if not page.strip():
                continue
            keyboard = None
            if i == len(pages) - 1:
                keyboard = _build_action_keyboard(primary_report, sha256)
            try:
                await message.reply_text(
                    page,
                    parse_mode=ParseMode.HTML,
                    disable_web_page_preview=True,
                    reply_markup=keyboard,
                )
            except Exception as send_err:
                logger.warning(f"Page {i} send error: {send_err}")
                # Truncate and retry
                try:
                    await message.reply_text(
                        page[:3900],
                        parse_mode=ParseMode.HTML,
                        disable_web_page_preview=True,
                    )
                except Exception:
                    pass

        # ── Multi-file summary (for archives) ────────────────────────────
        if is_archive and len(reports) > 1:
            await _send_archive_summary(message, reports, filename)

    except Exception as e:
        logger.error(f"[AutoDFIR] Pipeline error: {e}", exc_info=True)
        try:
            await status_msg.delete()
        except Exception:
            pass
        await message.reply_text(
            f"❌ <b>DFIR Engine Error</b>\n\n"
            f"<code>{_h(str(e)[:200])}</code>\n\n"
            f"<i>Please report this issue if it persists.</i>",
            parse_mode=ParseMode.HTML,
        )
    finally:
        if temp_filepath:
            import os
            if os.path.exists(temp_filepath):
                try:
                    os.unlink(temp_filepath)
                except Exception as e:
                    logger.warning(f"Failed to delete temp file {temp_filepath}: {e}")


# ─── Metadata Pre-Extraction ──────────────────────────────────────────────────

def _extract_metadata(data: bytes, filename: str, ftype: str) -> tuple[dict, list[str]]:
    """Extract type-specific metadata before calling the DFIR engine."""
    metadata:  dict      = {}
    anomalies: list[str] = []

    try:
        from handlers.file_cmd import (
            parse_image_exif, parse_pdf, parse_zip, parse_apk,
        )
        if ftype in ("png", "jpg", "jpeg", "gif", "webp"):
            metadata = parse_image_exif(data)
            if metadata.get("GPSInfo"):
                anomalies.append("GPS location data found in EXIF")
        elif ftype == "pdf":
            metadata = parse_pdf(data)
            if metadata.get("has_js"):
                anomalies.append("Embedded JavaScript in PDF")
            if metadata.get("has_openaction"):
                anomalies.append("Auto-execution action in PDF (/OpenAction)")
        elif ftype == "zip":
            metadata = parse_zip(data)
            if metadata.get("hidden_files"):
                anomalies.append(f"Hidden files: {metadata['hidden_files'][:3]}")
            if metadata.get("encrypted"):
                anomalies.append("Password-protected ZIP")
        elif ftype == "apk":
            metadata = parse_apk(data)
    except Exception as e:
        logger.debug(f"[AutoDFIR] Metadata extraction: {e}")

    return metadata, anomalies


# ─── Multi-Report Merger ──────────────────────────────────────────────────────

def _merge_reports(
    reports: list[dfir.DFIRReport],
    filename: str,
    ftype: str,
    sha256: str
) -> dfir.DFIRReport:
    """
    For archives with multiple extracted files, merge all child reports
    into a single primary report with cross-evidence correlation.
    """
    if len(reports) == 1:
        return reports[0]

    # Use root file as base
    primary = reports[0]
    primary.evidence_name = f"{filename} [archive: {len(reports)} files]"

    # Aggregate findings and IOCs from all children
    for child_report in reports[1:]:
        primary.findings.extend(child_report.findings)
        primary.risk_score = min(100, primary.risk_score + child_report.risk_score // 2)

        for key in ("ips", "domains", "urls", "emails", "hashes"):
            existing  = primary.extracted_iocs.get(key, [])
            child_iocs = child_report.extracted_iocs.get(key, [])
            merged    = list(dict.fromkeys(existing + child_iocs))[:30]
            primary.extracted_iocs[key] = merged

        for t in child_report.mitre_techniques:
            if t not in primary.mitre_techniques:
                primary.mitre_techniques.append(t)

        primary.evidence_summary.extend(
            [f"[{child_report.evidence_name}] " + e
             for e in child_report.evidence_summary[:3]]
        )
        primary.attack_timeline.extend(child_report.attack_timeline)

    # Build correlation graph
    primary.correlation_graph = _build_correlation_graph(reports)

    # Sort merged timeline
    dfir._sort_timeline(primary)
    primary.finalize()
    return primary


def _build_correlation_graph(reports: list[dfir.DFIRReport]) -> dict:
    """Build IOC pivot graph across all reports."""
    ioc_to_reports: dict[str, list[str]] = {}

    for report in reports:
        for key in ("ips", "domains", "hashes"):
            for ioc in report.extracted_iocs.get(key, []):
                if ioc not in ioc_to_reports:
                    ioc_to_reports[ioc] = []
                if report.evidence_name not in ioc_to_reports[ioc]:
                    ioc_to_reports[ioc].append(report.evidence_name)

    # Only keep IOCs that appear in 2+ files (true cross-evidence correlation)
    return {
        ioc: files
        for ioc, files in ioc_to_reports.items()
        if len(files) >= 2
    }


# ─── TI Enrichment ───────────────────────────────────────────────────────────

async def _enrich_top_iocs(report: dfir.DFIRReport) -> dict:
    """Run TI enrichment on the top extracted IOCs."""
    enrichment: dict = {}
    tasks = []

    # Enrich top 3 IPs via AbuseIPDB
    for ip in report.extracted_iocs.get("ips", [])[:3]:
        tasks.append(_enrich_ip(ip, enrichment))

    # Enrich top 2 domains via OTX
    for domain in report.extracted_iocs.get("domains", [])[:2]:
        tasks.append(_enrich_domain(domain, enrichment))

    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)

    return enrichment


async def _enrich_ip(ip: str, enrichment: dict):
    """Async TI lookup for an IP address."""
    try:
        result = await api.abuseipdb_check(ip)
        if result and "error" not in result:
            enrichment[ip] = {
                "type":        "ip",
                "abuse_score": result.get("abuseConfidenceScore", 0),
                "country":     result.get("countryCode", ""),
                "isp":         result.get("isp", ""),
                "total_reports": result.get("totalReports", 0),
            }
    except Exception as e:
        logger.debug(f"[TI] IP enrichment {ip}: {e}")


async def _enrich_domain(domain: str, enrichment: dict):
    """Async TI lookup for a domain."""
    try:
        result = await api.otx_check_domain(domain)
        if result and "error" not in result:
            enrichment[domain] = {
                "type":   "domain",
                "pulses": result.get("pulse_count", 0),
                "risk":   result.get("risk_score", 0),
            }
    except Exception as e:
        logger.debug(f"[TI] Domain enrichment {domain}: {e}")


async def _safe_mb_check(sha256: str) -> dict:
    """Safely query MalwareBazaar, returning empty dict on error."""
    try:
        from handlers.file_cmd import query_malwarebazaar
        return await query_malwarebazaar(sha256)
    except Exception:
        return {}


# ─── Archive Summary Sender ───────────────────────────────────────────────────

async def _send_archive_summary(message, reports: list[dfir.DFIRReport], archive_name: str):
    """Send a summary table for multi-file archive analysis."""
    import html as _he
    lines = [
        f"📦 <b>ARCHIVE ANALYSIS SUMMARY</b>",
        f"<code>{'━'*26}</code>",
        f"🗜 Archive: <code>{_he.escape(archive_name)}</code>",
        f"📁 Files analysed: <code>{len(reports)}</code>",
        f"<code>{'━'*26}</code>\n",
    ]
    for i, rep in enumerate(reports[:10], 1):
        verdict_emoji = {
            "CONFIRMED THREAT": "🔴",
            "MALICIOUS":        "🟠",
            "SUSPICIOUS":       "🟡",
            "BENIGN":           "🟢",
        }.get(rep.verdict, "⚪")
        lines.append(
            f"{i}. {verdict_emoji} <code>{_he.escape(rep.evidence_name[:35])}</code>"
            f" [{rep.detected_type.upper()}] → Risk: <b>{rep.risk_score}/100</b>"
        )

    if len(reports) > 10:
        lines.append(f"\n<i>… and {len(reports) - 10} more files</i>")

    try:
        await message.reply_text(
            "\n".join(lines),
            parse_mode=ParseMode.HTML,
        )
    except Exception as e:
        logger.warning(f"Archive summary send error: {e}")


# ─── Keyboard Builder ─────────────────────────────────────────────────────────

def _build_action_keyboard(report: dfir.DFIRReport, sha256: str) -> InlineKeyboardMarkup:
    """Build post-report action buttons."""
    import base64

    def tok(val: str) -> str:
        return base64.urlsafe_b64encode(val.encode()).decode()[:40]

    sha_tok = tok(sha256)
    rows = [
        [
            InlineKeyboardButton("📅 Timeline",     callback_data=f"dfir:timeline:{sha_tok}"),
            InlineKeyboardButton("📡 IOC Export",   callback_data=f"dfir:iocs:{sha_tok}"),
        ],
        [
            InlineKeyboardButton("🔎 Hunt Hash",    callback_data=f"action:hunt:{sha_tok}"),
            InlineKeyboardButton("📋 Full Report",  callback_data=f"dfir:fullreport:{sha_tok}"),
        ],
        [
            InlineKeyboardButton("📊 History",      callback_data="nav:history"),
            InlineKeyboardButton("🏠 Main Menu",    callback_data="nav:main"),
        ],
    ]

    # Quick-check first extracted IP
    ips = report.extracted_iocs.get("ips", [])
    if ips:
        first_ip = ips[0]
        rows.insert(2, [
            InlineKeyboardButton(
                f"🌐 Check {first_ip}",
                callback_data=f"action:check:{tok(first_ip)}"
            )
        ])

    return InlineKeyboardMarkup(rows)


# ─── HTML Escape Helper ────────────────────────────────────────────────────────

def _h(text: str) -> str:
    """HTML-escape a string."""
    import html
    return html.escape(str(text))


async def analyze_local_path_dfir(update: Update, context: ContextTypes.DEFAULT_TYPE, filepath: str):
    """
    Forensic analysis of a file located directly on the local disk.
    Avoids downloading, streams directly.
    """
    message = update.effective_message
    if not message:
        return

    user_id = update.effective_user.id if update.effective_user else 0
    filename = os.path.basename(filepath)
    
    try:
        file_size = os.path.getsize(filepath)
    except Exception as e:
        await message.reply_text(f"❌ Failed to access file path: {e}")
        return

    now_label = datetime.now(timezone.utc).strftime("%H:%M:%S UTC")
    status_msg = await message.reply_text(
        f"🔬 <b>DFIR AUTO-EXECUTION ENGINE (Local Path Mode)</b>\n"
        f"<code>━━━━━━━━━━━━━━━━━━━━━━━━━━</code>\n"
        f"📁 <b>Evidence:</b> <code>{_h(filename)}</code>\n"
        f"📐 <b>Size:</b> <code>{file_size/(1024*1024):.1f} MB</code>\n"
        f"🕐 <b>Received:</b> <code>{now_label}</code>\n\n"
        f"<b>⏳ Stage 1/5:</b> Hashing and detecting file type on disk…",
        parse_mode=ParseMode.HTML,
    )

    try:
        # Stream-hash the file on disk to prevent OOM
        sha256_hash = hashlib.sha256()
        with open(filepath, "rb") as f:
            while True:
                chunk = f.read(64 * 1024)
                if not chunk:
                    break
                sha256_hash.update(chunk)
        sha256 = sha256_hash.hexdigest()

        # Detect file type using path-based extractor
        ftype = extractor.detect_file_type_path(filepath)

        await status_msg.edit_text(
            f"🔬 <b>DFIR AUTO-EXECUTION ENGINE (Local Path Mode)</b>\n"
            f"<code>━━━━━━━━━━━━━━━━━━━━━━━━━━</code>\n"
            f"📁 <code>{_h(filename)}</code>\n"
            f"🔍 <b>Type Detected:</b> <code>{ftype.upper()}</code>\n"
            f"🔒 <b>SHA-256:</b> <code>{sha256[:24]}…</code>\n\n"
            f"<b>⏳ Stage 2/5:</b> Querying threat intelligence & running forensics…",
            parse_mode=ParseMode.HTML,
        )

        # TI lookups in parallel
        vt_res, otx_res, mb_res = await asyncio.gather(
            api.vt_check_hash(sha256),
            api.otx_check_hash(sha256),
            _safe_mb_check(sha256),
        )

        # Run the path-based forensic analysis
        report = dfir.analyze_file_dfir_path(
            filepath=filepath,
            filename=filename,
            file_type=ftype,
            metadata={},
            anomalies=[],
            vt_result=vt_res,
            mb_result=mb_res,
        )

        await status_msg.edit_text(
            f"🔬 <b>DFIR AUTO-EXECUTION ENGINE (Local Path Mode)</b>\n"
            f"<code>━━━━━━━━━━━━━━━━━━━━━━━━━━</code>\n"
            f"📁 <code>{_h(filename)}</code> [{ftype.upper()}]\n\n"
            f"<b>⏳ Stage 4/5:</b> Threat Intelligence enrichment…\n"
            f"  🔸 AbuseIPDB reputation check\n"
            f"  🔸 OTX domain correlation\n"
            f"  🔸 Building attack hypothesis\n"
            f"  🔸 Kill chain reconstruction",
            parse_mode=ParseMode.HTML,
        )

        # Enrich IOCs
        ti_enrichment = await _enrich_top_iocs(report)
        report.ti_enrichment = ti_enrichment

        # Rebuild hypothesis after enrichment
        report.hypothesis = dfir.generate_hypothesis(report)
        report.attack_chain = dfir.reconstruct_attack_chain(report)
        report.finalize()

        # ── Ingest into Active Case ───────────────────────────────────────
        import case_engine
        case_id = case_engine.resolve_active_case(update.effective_chat.id)
        case_engine.ingest_artifact(case_id, report)

        # Save to DB (Legacy support)
        try:
            db.save_dfir_case(
                case_id       = f"DFIR-{report.case_id}",
                evidence_type = report.evidence_type,
                evidence_name = report.evidence_name,
                verdict       = report.verdict,
                risk_score    = report.risk_score,
                findings_count= len(report.findings),
                mitre_count   = len(report.mitre_techniques),
                iocs_count    = sum(len(v) for v in report.extracted_iocs.values() if isinstance(v, list)),
            )
        except Exception as db_err:
            logger.warning(f"DB save error: {db_err}")

        # Store session
        _auto_sessions[user_id] = [report]
        try:
            from handlers.dfir_cmd import _dfir_sessions
            _dfir_sessions[user_id] = report
        except Exception:
            pass

        try:
            await status_msg.delete()
        except Exception:
            pass

        # Send report pages
        mode = case_engine.get_chat_mode(update.effective_chat.id)
        pages = case_engine.format_case_report(case_id, mode)
        for i, page in enumerate(pages):
            if not page.strip():
                continue
            keyboard = None
            if i == len(pages) - 1:
                keyboard = _build_action_keyboard(report, sha256)
            try:
                await message.reply_text(
                    page,
                    parse_mode=ParseMode.HTML,
                    disable_web_page_preview=True,
                    reply_markup=keyboard,
                )
            except Exception as send_err:
                logger.warning(f"Page {i} send error: {send_err}")
                try:
                    await message.reply_text(page[:3900], parse_mode=ParseMode.HTML)
                except Exception:
                    pass

    except Exception as e:
        logger.error(f"[AutoDFIR] Path pipeline error: {e}", exc_info=True)
        try:
            await status_msg.delete()
        except Exception:
            pass
        await message.reply_text(
            f"❌ <b>DFIR Engine Error</b>\n\n"
            f"<code>{_h(str(e)[:200])}</code>",
            parse_mode=ParseMode.HTML,
        )
