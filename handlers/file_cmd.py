"""
handlers/file_cmd.py - /file forensic metadata & threat intelligence analysis.
"""
import io
import re
import hashlib
import zipfile
import logging
import asyncio

from PIL import Image
from PIL.ExifTags import TAGS
from pypdf import PdfReader

from telegram import Update
from telegram.ext import ContextTypes
from telegram.constants import ParseMode

import api_clients as api
import decision_engine as de
import database as db

logger = logging.getLogger(__name__)

# ── Magic Bytes Detection ──────────────────────────────────────────────────────

MAGIC_SIGNATURES = {
    b"\x89PNG\r\n\x1a\n": "png",
    b"%PDF-": "pdf",
    b"PK\x03\x04": "zip",  # Zip file (includes APK, JAR)
    b"\xff\xd8\xff": "jpg",  # JPG / JPEG
    b"GIF87a": "gif",
    b"GIF89a": "gif",
    b"RIFF": "webp",  # WebP starts with RIFF, but we verify 'WEBP' at offset 8
}

def detect_file_type(data: bytes, filename: str) -> str:
    """Identify file type using magic bytes first, falling back to extension."""
    for sig, ftype in MAGIC_SIGNATURES.items():
        if data.startswith(sig):
            if ftype == "webp" and b"WEBP" not in data[8:12]:
                continue
            # Check if it's an APK by looking at the filename extension
            if ftype == "zip" and filename.lower().endswith(".apk"):
                return "apk"
            return ftype
            
    # Fallback to extension
    ext = filename.split(".")[-1].lower() if "." in filename else ""
    if ext in ("png", "jpg", "jpeg", "gif", "webp", "pdf", "zip", "apk"):
        return ext
    return "unknown"


# ── Parser Helpers ─────────────────────────────────────────────────────────────

def parse_image_exif(data: bytes) -> dict:
    """Extract full EXIF and XMP metadata from image bytes, returning strictly existing fields."""
    exif_data = {}
    try:
        img = Image.open(io.BytesIO(data))
        # Basic Image Attributes
        exif_data["ImageWidth"] = str(img.width)
        exif_data["ImageHeight"] = str(img.height)
        exif_data["FileType"] = img.format if img.format else "JPEG"
        if hasattr(img, "mode"):
            exif_data["ColorMode"] = img.mode

        # Standard EXIF Tags
        info = img._getexif() if hasattr(img, "_getexif") else None
        if info:
            for tag, value in info.items():
                decoded = TAGS.get(tag, tag)
                if value is not None and str(value).strip() != "":
                    if isinstance(value, bytes):
                        try:
                            value = value.decode('utf-8', errors='ignore')
                        except Exception:
                            value = repr(value)
                    exif_data[str(decoded)] = str(value)
                    
        # Extract XMP / Photoshop Metadata if present in binary strings
        import re
        data_str = data.decode('latin-1', errors='ignore')
        
        # Look for TextLayerName / TextLayerText
        text_layers = re.findall(r'photoshop:LayerName="([^"]+)"', data_str)
        if text_layers:
            exif_data["TextLayerName"] = ", ".join(text_layers)
            
        text_texts = re.findall(r'photoshop:LayerText="([^"]+)"', data_str)
        if text_texts:
            exif_data["TextLayerText"] = ", ".join(text_texts)
            
        # Software & Software Agent
        softwares = re.findall(r'stEvt:softwareAgent="([^"]+)"', data_str)
        if softwares and "Software" not in exif_data:
            exif_data["Software"] = ", ".join(set(softwares))
            
        # CreateDate / ModifyDate from XMP
        create_dates = re.findall(r'xmp:CreateDate="([^"]+)"', data_str)
        if create_dates and "CreateDate" not in exif_data:
            exif_data["CreateDate"] = create_dates[0]
            
        modify_dates = re.findall(r'xmp:ModifyDate="([^"]+)"', data_str)
        if modify_dates and "ModifyDate" not in exif_data:
            exif_data["ModifyDate"] = modify_dates[0]

    except Exception as e:
        logger.warning(f"Error parsing image metadata: {e}")
    
    # Filter out empty or binary placeholder values
    clean_meta = {}
    for k, v in exif_data.items():
        if v and not v.startswith("(Binary data"):
            clean_meta[k] = v
    return clean_meta



def parse_pdf(data: bytes) -> dict:
    """Extract PDF metadata and inspect properties."""
    pdf_info = {
        "metadata": {},
        "pages": 0,
        "has_js": False,
        "has_openaction": False,
        "urls": [],
        "errors": []
    }
    try:
        reader = PdfReader(io.BytesIO(data))
        pdf_info["pages"] = len(reader.pages)
        
        meta = reader.metadata
        if meta:
            for k, v in meta.items():
                key = k.replace("/", "")
                pdf_info["metadata"][key] = str(v)
                
        # Probing raw stream for active components
        stream_lower = data.lower()
        if b"/javascript" in stream_lower or b"/js" in stream_lower:
            pdf_info["has_js"] = True
        if b"/aa" in stream_lower or b"/openaction" in stream_lower:
            pdf_info["has_openaction"] = True
            
        # Extract hyperlinked URLs
        urls = set()
        for page in reader.pages:
            try:
                if "/Annots" in page:
                    annots = page["/Annots"]
                    # Annots can be a list or an indirect object
                    for annot in annots:
                        obj = annot.get_object()
                        if obj.get("/Subtype") == "/Link":
                            action = obj.get("/A")
                            if action and action.get("/URI"):
                                urls.add(action["/URI"])
            except Exception:
                pass
        pdf_info["urls"] = list(urls)[:15]  # Cap at 15
    except Exception as e:
        pdf_info["errors"].append(str(e))
    return pdf_info


def parse_zip(data: bytes) -> dict:
    """List zip contents and inspect for hidden files."""
    zip_info = {"files": [], "hidden_files": [], "total_size": 0, "encrypted": False, "error": None}
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            for info in z.infolist():
                name = info.filename
                size = info.file_size
                zip_info["total_size"] += size
                
                # Hidden files detection (dot prefixed)
                parts = name.split('/')
                is_hidden = any(p.startswith('.') and len(p) > 1 for p in parts if p)
                
                zip_info["files"].append({
                    "name": name,
                    "size": size,
                    "is_dir": info.is_dir()
                })
                if is_hidden:
                    zip_info["hidden_files"].append(name)
                if info.flag_bits & 0x1:
                    zip_info["encrypted"] = True
    except Exception as e:
        zip_info["error"] = str(e)
    return zip_info


def parse_apk(data: bytes) -> dict:
    """Robust binary parsing of APK AndroidManifest.xml strings."""
    apk_info = {"package_name": "Unknown", "permissions": [], "files_count": 0, "error": None}
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            namelist = z.namelist()
            apk_info["files_count"] = len(namelist)
            
            if "AndroidManifest.xml" in namelist:
                manifest_bytes = z.read("AndroidManifest.xml")
                # Search printable ASCII sequences in binary format
                raw_strings = re.findall(rb'[a-zA-Z0-9_\-\.\:\/]{4,}', manifest_bytes)
                strings = []
                for s in raw_strings:
                    try:
                        strings.append(s.decode('utf-8', errors='ignore'))
                    except Exception:
                        pass
                
                # Extract package name and declared permissions
                permissions = set()
                packages = set()
                for s in strings:
                    if "android.permission." in s:
                        permissions.add(s)
                    elif (s.startswith("com.") or s.startswith("org.")) and len(s.split(".")) >= 3:
                        # Avoid matching permissions or resources
                        if "android" not in s and "schemas" not in s:
                            packages.add(s)
                
                apk_info["permissions"] = sorted(list(permissions))
                if packages:
                    apk_info["package_name"] = sorted(list(packages))[0]
    except Exception as e:
        apk_info["error"] = str(e)
    return apk_info


# ── Threat Intel Helpers ───────────────────────────────────────────────────────

async def query_malwarebazaar(sha256_hash: str) -> dict:
    """Direct query to MalwareBazaar API."""
    import httpx
    try:
        async with httpx.AsyncClient(timeout=8, follow_redirects=True) as client:
            response = await client.post(
                "https://mb-api.abuse.ch/api/v1/",
                data={"query": "get_info", "hash": sha256_hash}
            )
            if response.status_code == 200:
                res_data = response.json()
                if res_data.get("query_status") == "ok":
                    data = res_data.get("data", [])[0]
                    return {
                        "found": True,
                        "signature": data.get("signature", "Unknown"),
                        "file_name": data.get("file_name", "Unknown"),
                        "file_type": data.get("file_type", "Unknown"),
                        "first_seen": data.get("first_seen", "Unknown"),
                        "delivery_method": data.get("delivery_method", "Unknown"),
                    }
            return {"found": False}
    except Exception:
        return {"found": False}


# ── Main Handler ───────────────────────────────────────────────────────────────

async def file_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Processes uploaded files and replies with deep metadata & threat analysis."""
    message = update.effective_message
    
    # 1. Resolve attachment: Check message document or reply_to_message document/photo
    target_msg = message
    if not message.document and not message.photo:
        if message.reply_to_message and (message.reply_to_message.document or message.reply_to_message.photo):
            target_msg = message.reply_to_message
        else:
            await message.reply_text(
                "⚠️ Usage: Send <code>/file</code> as caption with a file upload, "
                "or reply <code>/file</code> to an existing file/image.",
                parse_mode=ParseMode.HTML
            )
            return

    # Extract bot and file variables
    bot = context.bot
    document = target_msg.document
    photo = target_msg.photo
    
    # Get file details
    file_id = ""
    filename = "unknown_file"
    file_size = 0
    
    if document:
        file_id = document.file_id
        filename = document.file_name or "uploaded_file"
        file_size = document.file_size or 0
    elif photo:
        # Get the highest resolution photo
        largest_photo = photo[-1]
        file_id = largest_photo.file_id
        filename = "photo.jpg"
        file_size = largest_photo.file_size or 0

    if not file_id:
        await message.reply_text("❌ Failed to resolve target file ID.")
        return

    # Cap size limit for download safety (15MB)
    MAX_SIZE = 15 * 1024 * 1024
    if file_size > MAX_SIZE:
        await message.reply_text(
            f"⚠️ File size ({file_size / (1024*1024):.1f}MB) exceeds safe threshold (15MB)."
        )
        return

    thinking = await message.reply_text(
        "📥 Downloading and analyzing file structure in memory…",
        parse_mode=ParseMode.HTML
    )

    try:
        # Download file bytes
        tg_file = await bot.get_file(file_id)
        file_buffer = io.BytesIO()
        await tg_file.download_to_memory(out=file_buffer)
        file_bytes = file_buffer.getvalue()
        
        # Calculate hashes
        md5 = hashlib.md5(file_bytes).hexdigest()
        sha1 = hashlib.sha1(file_bytes).hexdigest()
        sha256 = hashlib.sha256(file_bytes).hexdigest()
        
        # Detect type
        ftype = detect_file_type(file_bytes, filename)
        
        # Run deep inspection modules
        metadata_summary = ""
        anomalies = []
        
        if ftype in ("png", "jpg", "jpeg", "gif", "webp", "tiff", "bmp"):
            import image_forensics as img_forensics
            img_analysis = img_forensics.analyze_image_full(file_bytes, filename)
            meta_pages = img_forensics.format_metadata_report(img_analysis)
            try:
                await thinking.delete()
            except Exception:
                pass
            for pg in meta_pages:
                if pg.strip():
                    try:
                        await message.reply_text(pg, parse_mode=ParseMode.HTML, disable_web_page_preview=True)
                    except Exception:
                        await message.reply_text(pg[:3900], parse_mode=ParseMode.HTML)
            return


                
        elif ftype == "pdf":
            pdf = parse_pdf(file_bytes)
            metadata_summary += (
                f"<b>📄 PDF Document properties:</b>\n"
                f"  • Pages: <code>{pdf['pages']}</code>\n"
            )
            for k, v in pdf["metadata"].items():
                metadata_summary += f"  • {k}: <code>{v[:50]}</code>\n"
                
            if pdf["has_js"]:
                anomalies.append("⚠️ Contains <b>embedded JavaScript</b> (/JS, /JavaScript)")
            if pdf["has_openaction"]:
                anomalies.append("⚠️ Contains <b>auto-execution action</b> (/OpenAction, /AA)")
            if pdf["urls"]:
                metadata_summary += f"  • Hyperlinks detected: {len(pdf['urls'])}\n"
                for u in pdf["urls"][:3]:
                    metadata_summary += f"    - <code>{u[:45]}</code>\n"
                    
        elif ftype == "zip":
            zinfo = parse_zip(file_bytes)
            metadata_summary += (
                f"<b>📦 ZIP Archive properties:</b>\n"
                f"  • Total files: <code>{len(zinfo['files'])}</code>\n"
                f"  • Raw size: <code>{zinfo['total_size'] / 1024:.1f} KB</code>\n"
            )
            if zinfo["encrypted"]:
                metadata_summary += "  • Password protected: <code>Yes</code>\n"
            if zinfo["hidden_files"]:
                metadata_summary += f"  • Hidden files detected: {len(zinfo['hidden_files'])}\n"
                for h in zinfo["hidden_files"][:3]:
                    anomalies.append(f"Hidden file in zip: <code>{h}</code>")
                    
        elif ftype == "apk":
            apk = parse_apk(file_bytes)
            metadata_summary += (
                f"<b>🤖 Android Application Package (APK):</b>\n"
                f"  • Package name: <code>{apk['package_name']}</code>\n"
                f"  • Extracted files: <code>{apk['files_count']}</code>\n"
            )
            if apk["permissions"]:
                metadata_summary += f"  • Declared permissions: {len(apk['permissions'])}\n"
                dangerous_perms = ["android.permission.SEND_SMS", "android.permission.RECEIVE_SMS",
                                   "android.permission.RECORD_AUDIO", "android.permission.CAMERA",
                                   "android.permission.READ_CONTACTS", "android.permission.WRITE_SETTINGS"]
                for perm in apk["permissions"]:
                    pname = perm.split(".")[-1]
                    if perm in dangerous_perms:
                        metadata_summary += f"    - 🛑 <code>{pname}</code> (Sensitive)\n"
                        anomalies.append(f"Sensitive Permission declared: <code>{pname}</code>")
                    else:
                        metadata_summary += f"    - <code>{pname}</code>\n"
        else:
            metadata_summary += "<i>No deep inspection parser matches this file type.</i>\n"

        # 2. Query threat intelligence on hash
        await thinking.edit_text("🔍 Checking hashes in threat intelligence repositories…")
        vt_task = api.vt_check_hash(sha256)
        otx_task = api.otx_check_hash(sha256)
        mb_task = query_malwarebazaar(sha256)
        
        vt_res, otx_res, mb_res = await asyncio.gather(vt_task, otx_task, mb_task)
        
        # 3. Decision Engine Integration
        vt_mal = vt_res.get("malicious", 0) if "error" not in vt_res else 0
        vt_susp = vt_res.get("suspicious", 0) if "error" not in vt_res else 0
        otx_pulses = otx_res.get("pulse_count", 0) if "error" not in otx_res else 0
        
        # Build local feed sights mock for new files
        local_feeds = []
        if mb_res.get("found"):
            local_feeds.append({
                "source": "MalwareBazaar (File API)",
                "threat_category": mb_res.get("signature", "Malicious file"),
                "risk_score": 95
            })

        decision = de.make_decision(
            ioc=sha256,
            ioc_type="sha256",
            vt_malicious=vt_mal,
            vt_suspicious=vt_susp,
            vt_total=vt_res.get("harmless", 0) + vt_res.get("undetected", 0) + vt_mal + vt_susp if "error" not in vt_res else 0,
            vt_label=vt_res.get("threat_label", ""),
            abuse_score=0,
            is_tor=False,
            otx_pulses=otx_pulses,
            feed_sources=local_feeds,
            in_watchlist=False,
            from_cache=False,
            cache_risk=0,
            vt_available="error" not in vt_res,
            abuse_available=False,
            otx_available="error" not in otx_res
        )
        # 4. Compile HTML Report
        emoji_map = {"png": "🖼", "jpg": "🖼", "jpeg": "🖼", "gif": "🖼", "webp": "🖼", "pdf": "📄", "zip": "📦", "apk": "🤖"}
        type_emoji = emoji_map.get(ftype, "📁")
        
        anom_block = ""
        if anomalies:
            anom_block = "<b>⚠️ Anomaly Warnings:</b>\n" + "\n".join(f"  • {a}" for a in anomalies) + "\n\n"
            
        mb_block = ""
        if mb_res.get("found"):
            mb_block = (
                f"<b>🦠 MalwareBazaar Match:</b>\n"
                f"  • Signature: <b>{mb_res['signature']}</b>\n"
                f"  • File Type: <code>{mb_res['file_type']}</code>\n"
                f"  • First Seen: <code>{mb_res['first_seen']}</code>\n\n"
            )

        report_html = (
            f"📁 <b>FILE INTELLIGENCE REPORT</b>\n"
            f"━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            f"• <b>Filename:</b> <code>{filename}</code>\n"
            f"• <b>Size:</b> <code>{file_size / 1024:.1f} KB</code>\n"
            f"• <b>Detected Format:</b> {type_emoji} <code>{ftype.upper()}</code>\n\n"
            
            f"<b>🧬 File Hashes:</b>\n"
            f"  • MD5: <code>{md5}</code>\n"
            f"  • SHA-1: <code>{sha1}</code>\n"
            f"  • SHA-256: <code>{sha256}</code>\n\n"
            
            f"{metadata_summary}\n"
            f"{anom_block}"
            f"{mb_block}"
            f"<i>Manual Forensic Analyst Probing Output</i>"
        )

        # Save to DB enrichment cache
        db.save_ioc_enrichment(
            ioc=sha256,
            ioc_type="sha256",
            risk_score=decision.risk_score,
            verdict=decision.verdict,
            sources=["VirusTotal", "OTX", "MalwareBazaar"] if vt_mal > 0 or otx_pulses > 0 or mb_res.get("found") else [],
            abuse_score=0,
            vt_malicious=vt_mal,
            otx_pulses=otx_pulses,
            country="N/A",
            asn="N/A",
            tags=["file-analysis", f"format:{ftype}"] + ([f"sig:{mb_res['signature']}"] if mb_res.get("found") else [])
        )

        await thinking.delete()
        await message.reply_text(
            report_html,
            parse_mode=ParseMode.HTML,
            disable_web_page_preview=True
        )

    except Exception as e:
        logger.error(f"Error in file intelligence analysis: {e}", exc_info=True)
        try:
            await thinking.delete()
        except Exception:
            pass
        await message.reply_text(f"❌ <b>Analysis Failed:</b> <code>{e}</code>", parse_mode=ParseMode.HTML)
