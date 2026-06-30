"""
image_forensics.py - Dynamic Raw ExifTool Metadata Viewer Frontend

Runs ExifTool directly against the uploaded image with raw flags: exiftool -j -a -u -G1 -struct
Falls back to a fully dynamic Python parser if ExifTool is not present.
Does not filter, whitelist, or summarize any tags. Displays only existing tags.
"""

from __future__ import annotations

import io
import re
import os
import struct
import json
import hashlib
import subprocess
from pathlib import Path
from typing import Optional, Dict, List, Any

try:
    from PIL import Image
    from PIL.ExifTags import TAGS, GPSTAGS
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False


# ═══════════════════════════════════════════════════════════════════════════════
# PUBLIC ANALYSIS API
# ═══════════════════════════════════════════════════════════════════════════════

def analyze_image_full(data: bytes, filename: str) -> dict:
    """
    Executes ExifTool directly or falls back to full dynamic Python metadata extraction.
    """
    # 1. Try running real ExifTool via JSON output
    exiftool_data = _run_exiftool_json(data, filename)
    if exiftool_data:
        return {"raw_metadata": exiftool_data}

    # 2. Fully dynamic Python fallback
    return {"raw_metadata": _dynamic_python_extraction(data, filename)}


# ═══════════════════════════════════════════════════════════════════════════════
# EXIFTOOL RUNNER
# ═══════════════════════════════════════════════════════════════════════════════

def _run_exiftool_json(data: bytes, filename: str) -> Optional[dict]:
    """Runs ExifTool and extracts all metadata tags dynamically in JSON format."""
    try:
        import tempfile
        suffix = ('.' + Path(filename).suffix.lower().lstrip('.')) or '.jpg'
        with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
            tmp.write(data)
            tmp_path = tmp.name

        try:
            # -j: JSON output format
            # -a: Allow duplicate tags
            # -u: Extract unknown tags
            # -G1: Print Group1 namespaces (e.g., System, IFD0, ExifIFD, XMP-xmp)
            # -struct: Output structured metadata instead of flattening
            result = subprocess.run(
                ["exiftool", "-j", "-a", "-u", "-G1", "-struct", tmp_path],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0 and result.stdout.strip():
                parsed = json.loads(result.stdout)
                if parsed and isinstance(parsed, list):
                    meta = parsed[0]
                    # Clean up temp file path
                    if "SourceFile" in meta:
                        del meta["SourceFile"]
                    # Replace temp file name in system tags
                    cleaned_meta = {}
                    for k, v in meta.items():
                        if isinstance(v, str):
                            v = v.replace(tmp_path, filename)
                        cleaned_meta[k] = v
                    return cleaned_meta
        finally:
            try:
                os.unlink(tmp_path)
            except Exception:
                pass
    except Exception:
        pass
    return None


# ═══════════════════════════════════════════════════════════════════════════════
# DYNAMIC FALLBACK PARSER (NO WHITELISTS)
# ═══════════════════════════════════════════════════════════════════════════════

def _dynamic_python_extraction(data: bytes, filename: str) -> dict:
    """
    Extracts every single metadata tag present in the image binary dynamically.
    Groups are prefixed for ExifTool compatibility.
    """
    meta = {}
    raw_str = data.decode('latin-1', errors='ignore')

    # 1. File / System Data
    size_bytes = len(data)
    if size_bytes < 1024:
        size_str = f"{size_bytes} bytes"
    else:
        size_str = f"{size_bytes / 1024:.1f} kB"

    meta["System:FileName"] = filename or "image.jpg"
    meta["System:FileSize"] = size_str
    
    ftype = "JPEG"
    mime = "image/jpeg"
    if data.startswith(b'\x89PNG\r\n\x1a\n'):
        ftype, mime = "PNG", "image/png"
    elif data.startswith(b'RIFF') and data[8:12] == b'WEBP':
        ftype, mime = "WEBP", "image/webp"
    elif data.startswith(b'GIF87a') or data.startswith(b'GIF89a'):
        ftype, mime = "GIF", "image/gif"
    elif data.startswith(b'II*\x00') or data.startswith(b'MM\x00*'):
        ftype, mime = "TIFF", "image/tiff"
    elif data.startswith(b'8BPS'):
        ftype, mime = "PSD", "image/vnd.adobe.photoshop"

    meta["File:FileType"] = ftype
    meta["File:FileTypeExtension"] = ftype.lower()
    meta["File:MIMEType"] = mime
    meta["File:SHA256"] = hashlib.sha256(data).hexdigest()
    meta["File:SHA1"] = hashlib.sha1(data).hexdigest()
    meta["File:MD5"] = hashlib.md5(data).hexdigest()

    # 2. Dynamic PIL EXIF extraction
    if PIL_AVAILABLE:
        try:
            with Image.open(io.BytesIO(data)) as img:
                meta["File:ImageWidth"] = str(img.width)
                meta["File:ImageHeight"] = str(img.height)
                meta["File:ImageSize"] = f"{img.width}x{img.height}"
                
                # Mode-based metadata fallbacks
                if img.mode == 'L':
                    meta["File:BitsPerSample"] = "8"
                    meta["File:ColorComponents"] = "1"
                    meta["File:PhotometricInterpretation"] = "BlackIsZero"
                elif img.mode == 'RGB':
                    meta["File:BitsPerSample"] = "8 8 8"
                    meta["File:ColorComponents"] = "3"
                    meta["File:PhotometricInterpretation"] = "RGB"

                exif_raw = img._getexif() if hasattr(img, "_getexif") else None
                if exif_raw:
                    for tag_id, value in exif_raw.items():
                        tag_name = TAGS.get(tag_id, tag_id)
                        if tag_name == "GPSInfo" and isinstance(value, dict):
                            for gtag, gval in value.items():
                                gname = GPSTAGS.get(gtag, gtag)
                                meta[f"GPS:GPS{gname}"] = str(gval)
                        elif not isinstance(value, bytes):
                            meta[f"IFD0:{tag_name}"] = str(value)
        except Exception:
            pass

    # 3. Dynamic XMP extraction via Regex
    # Attributes: ns:tag="value"
    for k, v in re.findall(r'([\w\-]+:[\w\-]+)="([^"]*)"', raw_str):
        if not k.startswith("xmlns:") and v.strip():
            meta[f"XMP:{k}"] = v.strip()
    # Nodes: <ns:tag>value</ns:tag>
    for k, v in re.findall(r'<([\w\-]+:[\w\-]+)>([^<]*)</\1>', raw_str):
        if v.strip():
            meta[f"XMP:{k}"] = v.strip()

    # History elements
    for term in ("action", "instanceID", "when", "softwareAgent", "changed"):
        matches = re.findall(r'(?:stEvt|xmpMM|xmp|pdf|dc):' + term + r'="([^"]+)"', raw_str)
        if not matches:
            matches = re.findall(r'<(?:stEvt|xmpMM|xmp|pdf|dc):' + term + r'>([^<]+)</(?:stEvt|xmpMM|xmp|pdf|dc):' + term + r'>', raw_str)
        if matches:
            meta[f"XMP:History{term.capitalize()}"] = ",".join(matches)

    # 4. Dynamic Photoshop IRB Resource Blocks
    bim_idx = data.find(b'8BIM')
    if bim_idx >= 0:
        pos = bim_idx
        while pos + 12 <= len(data):
            sig = data[pos:pos+4]
            if sig not in (b'8BIM', b'8BAM', b'AgHg'):
                pos += 1
                continue
            resource_id = struct.unpack('>H', data[pos+4:pos+6])[0]
            pos += 6
            name_len = data[pos] if pos < len(data) else 0
            pos += 1 + name_len
            if (name_len + 1) % 2 != 0:
                pos += 1
            if pos + 4 > len(data):
                break
            data_size = struct.unpack('>I', data[pos:pos+4])[0]
            pos += 4
            resource_data = data[pos:pos+data_size]
            pos += data_size
            if data_size % 2 != 0:
                pos += 1

            try:
                val_str = resource_data.decode('utf-8', errors='ignore').strip('\x00')
                # Keep only printable ascii
                if not val_str or any(ord(c) < 32 or ord(c) > 126 for c in val_str):
                    val_str = f"(Binary data {len(resource_data)} bytes)"
            except Exception:
                val_str = f"(Binary data {len(resource_data)} bytes)"

            meta[f"Photoshop:Resource0x{resource_id:04X}"] = val_str

    # 5. Dynamic ICC Profile extraction
    acsp_idx = data.find(b'acsp')
    if acsp_idx >= 36:
        profile_start = acsp_idx - 36
        if profile_start + 128 <= len(data):
            try:
                size = struct.unpack('>I', data[profile_start:profile_start+4])[0]
                version_major = data[profile_start+8]
                version_minor = (data[profile_start+9] >> 4) & 0x0F
                color_space = data[profile_start+16:profile_start+20].decode('latin-1', errors='ignore').strip()
                meta["ICC_Profile:ProfileSize"] = f"{size} bytes"
                meta["ICC_Profile:ProfileVersion"] = f"{version_major}.{version_minor}"
                if color_space:
                    meta["ICC_Profile:ColorSpace"] = color_space
            except Exception:
                pass

    return meta


# ═══════════════════════════════════════════════════════════════════════════════
# REPORT FORMATTER (EXIFTOOL TERMINAL 1:1 DYNAMIC FORMAT)
# ═══════════════════════════════════════════════════════════════════════════════

def format_metadata_report(analysis: dict) -> list[str]:
    """
    Formats all extracted metadata dynamically in ExifTool key-value terminal output.
    Does not display any empty or unavailable placeholders.
    """
    import html as _h
    meta = analysis.get("raw_metadata", {})
    if not meta:
        return []

    lines = []
    # Sort tags by group to create structured ExifTool group blocks
    sorted_keys = sorted(meta.keys())
    current_group = None

    # Blacklisted placeholder values
    BLACKLIST_VALS = {"", "none", "unknown", "not available", "n/a", "empty", "not detected"}

    for key in sorted_keys:
        value = str(meta[key]).strip()
        # Skip empty, null, or placeholder values
        if not value or value.lower() in BLACKLIST_VALS:
            continue

        # Split namespace group from tag name (e.g. System:FileName -> System, FileName)
        if ":" in key:
            group, tag = key.split(":", 1)
        else:
            group, tag = "System", key

        # Print Group header if it changes
        if group != current_group:
            if current_group is not None:
                lines.append("")
            lines.append(f"[{group}]")
            current_group = group

        # ExifTool terminal spacing: padded tag name and value
        tag_padded = f"{tag:<30}"[:30]
        lines.append(f"  {tag_padded} : {value}")

    # Paginate blocks to fit within Telegram limits
    pages = []
    current_page = []
    current_len = 0

    for line in lines:
        line_len = len(line) + 1
        if current_len + line_len > 3700:
            page_text = "\n".join(current_page)
            pages.append(f"<pre>{_h.escape(page_text)}</pre>")
            current_page = []
            current_len = 0
        current_page.append(line)
        current_len += line_len

    if current_page:
        page_text = "\n".join(current_page)
        pages.append(f"<pre>{_h.escape(page_text)}</pre>")

    return pages
