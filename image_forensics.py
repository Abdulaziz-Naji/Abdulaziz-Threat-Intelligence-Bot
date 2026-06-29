"""
image_forensics.py - Upgraded Analyst-Grade Image Metadata & Forensics Engine

Extracts and classifies every forensic artifact from JPEG, PNG, TIFF, WebP, HEIC and PSD:
  - EXIF (recursively parsed modern PIL EXIF + sub-IFDs)
  - XMP (dynamically enumerates all namespaces)
  - Photoshop Metadata (layer names, text, visibility, groups, blend modes via psd-tools)
  - IPTC (datasets parsed dynamically)
  - ICC Profile (version, color space, model, manufacturer)
  - OCR (Tesseract + fallback, classifies credentials/secrets)
  - QR & Barcode (decodes QR/Barcodes via pyzbar)
  - Steganography (LSB ratio, appended data, statistical anomalies)
  - AI Image Detection (metadata and synthetic heuristic analysis)
"""
from __future__ import annotations

import io
import re
import struct
import hashlib
import math
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Dict, List, Any

try:
    from PIL import Image
    from PIL.ExifTags import TAGS, GPSTAGS
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False

try:
    import pytesseract
    TESSERACT_AVAILABLE = True
except ImportError:
    TESSERACT_AVAILABLE = False

try:
    from pyzbar.pyzbar import decode as zbar_decode
    ZBAR_AVAILABLE = True
except ImportError:
    ZBAR_AVAILABLE = False

try:
    from psd_tools import PSDImage
    PSD_TOOLS_AVAILABLE = True
except ImportError:
    PSD_TOOLS_AVAILABLE = False

# ─── JPEG marker constants ────────────────────────────────────────────────────
_JPEG_SOI  = b'\xff\xd8'
_JPEG_EOI  = b'\xff\xd9'
_APP1      = b'\xff\xe1'
_EXIF_HDR  = b'Exif\x00\x00'
_XMP_HDR   = b'http://ns.adobe.com/xap/1.0/\x00'
_IPTC_HDR  = b'Photoshop 3.0\x00'

_EXTRA_TAGS = {
    0x9C9B: "XPTitle", 0x9C9C: "XPComment", 0x9C9D: "XPAuthor",
    0x9C9E: "XPKeywords", 0x9C9F: "XPSubject", 0xA433: "LensMake",
    0xA434: "LensModel", 0xA435: "LensSerialNumber", 0x0131: "Software",
    0x013B: "Artist", 0x8298: "Copyright",
}


# ═══════════════════════════════════════════════════════════════════════════════
# PUBLIC API
# ═══════════════════════════════════════════════════════════════════════════════

def analyze_image_full(data: bytes, filename: str) -> dict:
    """
    Full forensic image analysis.
    Returns a structured dict with all metadata, classified intelligence, and secrets.
    """
    result = {
        "file": _file_info(data, filename),
        "exif": {},
        "xmp": {},
        "iptc": {},
        "photoshop": {},
        "text_layers": [],
        "psd_layers": [],
        "gps": {},
        "thumbnail": {},
        "steganography": {},
        "embedded_files": [],
        "strings": [],
        "forensic_flags": [],
        "raw_xmp": "",
        "icc_profile": {},
        "qr_barcodes": [],
        "ocr": {"text": "", "confidence": 0, "classified": {}},
        "ai_detection": {"likelihood": "Unknown", "score": 0, "clues": []},
        "classified_metadata": {"device": {}, "editing": {}, "hidden": {}, "privacy": {}},
    }

    # 1. Run ExifTool subprocess if available
    exiftool_data = _run_exiftool(data, filename)
    if exiftool_data:
        result["exif"] = exiftool_data
        result["forensic_flags"].append("ExifTool extraction successful")

    # 2. Parse Photoshop layers (if PSD)
    is_psd = data[:4] == b'8BPS'
    if is_psd:
        psd_parsed = _parse_psd_with_tools(data, result)
        if not psd_parsed:
            _parse_psd_fallback(data, result)

    # 3. Dynamic EXIF binary lookup (Universal scan)
    exif_idx = data.find(b'Exif\x00\x00')
    if exif_idx >= 0:
        _parse_exif_ifd(data[exif_idx+6:], result)
    else:
        exif_idx2 = data.find(b'Exif\x00')
        if exif_idx2 >= 0:
            _parse_exif_ifd(data[exif_idx2+5:], result)
        elif data[:4] in (b'II*\x00', b'MM\x00*'):
            _parse_exif_ifd(data, result)

    # 4. Dynamic XMP xml lookup (Universal scan)
    xmp_start = data.find(b'<x:xmpmeta')
    if xmp_start >= 0:
        xmp_end = data.find(b'</x:xmpmeta>', xmp_start)
        if xmp_end >= 0:
            xmp_bytes = data[xmp_start:xmp_end+12]
            xmp_text = xmp_bytes.decode('utf-8', errors='ignore')
            result["raw_xmp"] = xmp_text
            result["xmp"].update(_parse_xmp(xmp_text))
            
            # Extract text layers from cached XMP metadata
            cached_xmp_layers = parse_xmp_text_layers(xmp_text)
            if cached_xmp_layers:
                result["text_layers"].extend(cached_xmp_layers)

    # 5. Dynamic ICC Profile lookup (Universal scan)
    acsp_idx = data.find(b'acsp')
    if acsp_idx >= 36:
        profile_start = acsp_idx - 36
        if profile_start + 4 <= len(data):
            profile_size = struct.unpack('>I', data[profile_start:profile_start+4])[0]
            if 128 <= profile_size <= len(data) - profile_start:
                _parse_icc_profile(data[profile_start:profile_start+profile_size], result)

    # 6. Format-specific parsing
    if data[:2] == _JPEG_SOI:
        _parse_jpeg(data, result)
    elif data[:8] == b'\x89PNG\r\n\x1a\n':
        _parse_png(data, result)
    elif data[:4] == b'RIFF' and data[8:12] == b'WEBP':
        _parse_webp(data, result)

    # 7. PIL fallback for EXIF
    if not result["exif"] and PIL_AVAILABLE:
        _parse_pil_exif_dynamic(data, result)

    # 8. Decode QR / Barcodes
    result["qr_barcodes"] = decode_qr_barcodes(data)
    if result["qr_barcodes"]:
        result["forensic_flags"].append(f"{len(result['qr_barcodes'])} QR/BARCODE(S) DETECTED")

    # 9. OCR text extraction & secrets classification
    run_ocr_and_classify(data, result)

    # 10. Metadata classification
    result["classified_metadata"] = classify_image_metadata(
        result["exif"], result["xmp"], result["photoshop"], result.get("psd_layers", [])
    )

    # 11. AI generation estimator
    result["ai_detection"] = estimate_ai_generation(result["exif"], result["xmp"], result["file"])

    # 12. Steganography checks
    _check_steganography(data, result)

    # 13. Embedded file scan
    _scan_embedded_files(data, result)

    # Printable string extraction fallback
    raw_text = data.decode("latin-1", errors="ignore")
    printable = re.findall(r'[\x20-\x7e]{8,}', raw_text)
    result["strings"] = [s for s in printable[:20] if not s.startswith("Adobe")]

    # Compatibility mapping for legacy tests
    if result["text_layers"]:
        result["xmp"]["TextLayerName"] = result["text_layers"][0]["name"]
        result["xmp"]["TextLayerText"] = result["text_layers"][0]["text"]

    return result


# ═══════════════════════════════════════════════════════════════════════════════
# FILE INFO
# ═══════════════════════════════════════════════════════════════════════════════

def _file_info(data: bytes, filename: str) -> dict:
    freq = [0]*256
    for b in data[:65536]: freq[b] += 1
    total = min(len(data), 65536)
    entropy = -sum((f/total)*math.log2(f/total) for f in freq if f > 0) if total else 0.0

    ftype = _detect_type(data, filename)
    return {
        "FileName":      filename,
        "FileSize":      f"{len(data)/1024:.0f} kB",
        "FileSizeBytes": len(data),
        "FileType":      ftype.upper(),
        "MIMEType":      _mime_type(ftype),
        "SHA256":        hashlib.sha256(data).hexdigest(),
        "MD5":           hashlib.md5(data).hexdigest(),
        "SHA1":          hashlib.sha1(data).hexdigest(),
        "Entropy":       f"{entropy:.4f}/8.0",
        "MagicBytes":    data[:8].hex(),
    }

def _detect_type(data: bytes, filename: str) -> str:
    sigs = {
        b'\xff\xd8\xff': 'jpeg',
        b'\x89PNG':      'png',
        b'GIF8':         'gif',
        b'RIFF':         'webp',
        b'II*\x00':      'tiff',
        b'MM\x00*':      'tiff',
        b'BM':           'bmp',
        b'8BPS':         'psd',
    }
    for sig, t in sigs.items():
        if data[:len(sig)] == sig:
            return t
    return Path(filename).suffix.lower().lstrip('.')

def _mime_type(ftype: str) -> str:
    return {
        'jpeg': 'image/jpeg', 'jpg': 'image/jpeg',
        'png':  'image/png',  'gif': 'image/gif',
        'webp': 'image/webp', 'tiff': 'image/tiff',
        'bmp':  'image/bmp',  'psd': 'image/vnd.adobe.photoshop',
    }.get(ftype, f'image/{ftype}')


# ═══════════════════════════════════════════════════════════════════════════════
# EXIFTOOL SUBPROCESS
# ═══════════════════════════════════════════════════════════════════════════════

def _run_exiftool(data: bytes, filename: str) -> dict:
    try:
        import json, tempfile, os
        suffix = '.' + Path(filename).suffix.lower().lstrip('.') or '.jpg'
        with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
            tmp.write(data)
            tmp_path = tmp.name

        try:
            result = subprocess.run(
                ["exiftool", "-j", "-a", "-u", "-G1", "-struct", tmp_path],
                capture_output=True, text=True, timeout=15
            )
            if result.returncode == 0 and result.stdout.strip():
                parsed = json.loads(result.stdout)
                if parsed:
                    return parsed[0]
        finally:
            try: os.unlink(tmp_path)
            except Exception: pass
    except (FileNotFoundError, subprocess.TimeoutExpired, Exception):
        pass
    return {}


# ═══════════════════════════════════════════════════════════════════════════════
# FORMAT PARSERS (JPEG / PNG / WEBP)
# ═══════════════════════════════════════════════════════════════════════════════

def _parse_jpeg(data: bytes, result: dict):
    pos = 2
    while pos < len(data) - 4:
        if data[pos] != 0xFF: break
        marker = data[pos:pos+2]
        if marker == _JPEG_EOI: break
        if marker[1] in (0xD8, 0xD9, 0xDA):
            pos += 2
            continue
        if pos + 4 > len(data): break
        length = struct.unpack('>H', data[pos+2:pos+4])[0]
        if length < 2 or pos + 2 + length > len(data): break
        content = data[pos+4:pos+2+length]

        if marker == _APP1 and content[:6] == _EXIF_HDR:
            _parse_exif_ifd(content[6:], result)
        elif marker == _APP1 and content[:len(_XMP_HDR)] == _XMP_HDR:
            xmp_text = content[len(_XMP_HDR):].decode("utf-8", errors="ignore")
            result["raw_xmp"] = xmp_text
            result["xmp"].update(_parse_xmp(xmp_text))
        elif marker == b'\xff\xed' and content[:14] == _IPTC_HDR:
            _parse_iptc_photoshop(content[14:], result)

        pos += 2 + length


def _parse_png(data: bytes, result: dict):
    pos = 8
    while pos + 8 <= len(data):
        try:
            length = struct.unpack_from('>I', data, pos)[0]
            chunk_type = data[pos+4:pos+8].decode('ascii', errors='replace')
            chunk_data = data[pos+8:pos+8+length]
        except Exception:
            break

        if chunk_type == 'eXIf':
            _parse_exif_ifd(chunk_data, result)
        elif chunk_type == 'tEXt':
            try:
                null = chunk_data.index(b'\x00')
                key = chunk_data[:null].decode('latin-1')
                val = chunk_data[null+1:].decode('latin-1', errors='ignore')
                result["exif"][key] = val
                if "xmp" in key.lower():
                    result["raw_xmp"] = val
                    result["xmp"].update(_parse_xmp(val))
            except Exception: pass
        elif chunk_type == 'iTXt':
            try:
                parts = chunk_data.split(b'\x00', 4)
                if len(parts) >= 5:
                    key = parts[0].decode('latin-1')
                    val = parts[4].decode('utf-8', errors='ignore')
                    result["exif"][key] = val
                    if "xmp" in key.lower():
                        result["raw_xmp"] = val
                        result["xmp"].update(_parse_xmp(val))
            except Exception: pass
        elif chunk_type == 'iCCP':
            try:
                null = chunk_data.index(b'\x00')
                result["exif"]["ICCProfileName"] = chunk_data[:null].decode('latin-1')
            except Exception: pass
        elif chunk_type == 'IHDR' and length >= 13:
            w, h = struct.unpack_from('>II', chunk_data)
            bit_depth  = chunk_data[8]
            color_type = chunk_data[9]
            color_map  = {0:'Grayscale', 2:'RGB', 3:'Indexed', 4:'Grayscale+Alpha', 6:'RGBA'}
            result["exif"]["ImageWidth"]   = w
            result["exif"]["ImageHeight"]  = h
            result["exif"]["BitsPerSample"] = bit_depth
            result["exif"]["ColorType"]    = color_map.get(color_type, str(color_type))

        pos += 12 + length


def _parse_webp(data: bytes, result: dict):
    if data[:4] != b'RIFF' or data[8:12] != b'WEBP':
        return
    pos = 12
    while pos + 8 < len(data):
        chunk_type = data[pos:pos+4]
        chunk_len = struct.unpack('<I', data[pos+4:pos+8])[0]
        chunk_data = data[pos+8:pos+8+chunk_len]
        
        if chunk_type == b'EXIF':
            _parse_exif_ifd(chunk_data, result)
        elif chunk_type == b'XMP ':
            xmp_text = chunk_data.decode("utf-8", errors="ignore")
            result["raw_xmp"] = xmp_text
            result["xmp"].update(_parse_xmp(xmp_text))
        elif chunk_type == b'ICCP':
            _parse_icc_profile(chunk_data, result)
            
        pos += 8 + chunk_len + (chunk_len % 2)


def _parse_pil_exif_dynamic(data: bytes, result: dict):
    if not PIL_AVAILABLE:
        return
    try:
        img = Image.open(io.BytesIO(data))
        result["exif"]["Format"] = img.format or ""
        result["exif"]["Mode"] = img.mode
        result["exif"]["Width"] = img.size[0]
        result["exif"]["Height"] = img.size[1]
        
        exif = img.getexif()
        if exif:
            from PIL.ExifTags import TAGS
            for tag_id, val in exif.items():
                tag_name = TAGS.get(tag_id, f"Tag_0x{tag_id:04X}")
                if isinstance(val, bytes):
                    try: val = val.decode('utf-8', errors='ignore')
                    except: val = val.hex()
                result["exif"][tag_name] = str(val)[:200]
                
            exif_ifd = exif.get_ifd(0x8769)
            if exif_ifd:
                for tag_id, val in exif_ifd.items():
                    tag_name = TAGS.get(tag_id, f"ExifIFD_0x{tag_id:04X}")
                    if isinstance(val, bytes):
                        try: val = val.decode('utf-8', errors='ignore')
                        except: val = val.hex()
                    result["exif"][tag_name] = str(val)[:200]
                    
            gps_ifd = exif.get_ifd(0x8825)
            if gps_ifd:
                from PIL.ExifTags import GPSTAGS
                gps_dict = {}
                for tag_id, val in gps_ifd.items():
                    tag_name = GPSTAGS.get(tag_id, f"GPS_{tag_id}")
                    gps_dict[tag_name] = _format_exif_value(tag_id, val, is_gps=True)
                if gps_dict:
                    result["gps"] = gps_dict
                    lat = _gps_decimal(gps_dict.get("GPSLatitude"), gps_dict.get("GPSLatitudeRef", "N"))
                    lon = _gps_decimal(gps_dict.get("GPSLongitude"), gps_dict.get("GPSLongitudeRef", "E"))
                    if lat is not None and lon is not None:
                        result["gps"]["GPSDecimal"] = f"{lat:.6f}, {lon:.6f}"
                        result["gps"]["GoogleMapsURL"] = f"https://maps.google.com/?q={lat},{lon}"
                        result["forensic_flags"].append(f"GPS COORDINATES DETECTED: {lat:.6f}, {lon:.6f}")
    except Exception:
        pass


# ═══════════════════════════════════════════════════════════════════════════════
# EXIF IFD PARSER
# ═══════════════════════════════════════════════════════════════════════════════

def _parse_exif_ifd(tiff_data: bytes, result: dict):
    if len(tiff_data) < 8: return
    if tiff_data[:2] == b'II':
        bo = '<'
        result["exif"]["ExifByteOrder"] = "Little-endian"
    elif tiff_data[:2] == b'MM':
        bo = '>'
        result["exif"]["ExifByteOrder"] = "Big-endian"
    else:
        return

    try:
        ifd0_offset = struct.unpack_from(bo + 'I', tiff_data, 4)[0]
        _read_ifd(tiff_data, ifd0_offset, bo, result, depth=0)
    except Exception:
        pass


def _read_ifd(data: bytes, offset: int, bo: str, result: dict, depth: int = 0):
    if depth > 4 or offset + 2 > len(data): return
    try:
        num_entries = struct.unpack_from(bo + 'H', data, offset)[0]
    except Exception:
        return

    exif_ifd_offset   = None
    gps_ifd_offset    = None
    interop_offset    = None

    for i in range(num_entries):
        entry_offset = offset + 2 + i * 12
        if entry_offset + 12 > len(data): break
        try:
            tag_id, type_id, count = struct.unpack_from(bo + 'HHI', data, entry_offset)
            value_raw = data[entry_offset+8:entry_offset+12]
            value = _read_exif_value(data, bo, type_id, count, value_raw)
        except Exception:
            continue

        tag_name = TAGS.get(tag_id) or _EXTRA_TAGS.get(tag_id) or f"Tag_0x{tag_id:04X}"

        if tag_id == 0x8769:
            exif_ifd_offset = _to_int(value)
        elif tag_id == 0x8825:
            gps_ifd_offset = _to_int(value)
        elif tag_id == 0xA005:
            interop_offset = _to_int(value)
        else:
            str_val = _format_exif_value(tag_id, value)
            if str_val is not None:
                result["exif"][tag_name] = str_val

    if exif_ifd_offset:
        _read_ifd(data, exif_ifd_offset, bo, result, depth+1)
    if gps_ifd_offset:
        _read_gps_ifd(data, gps_ifd_offset, bo, result)
    if interop_offset:
        _read_ifd(data, interop_offset, bo, result, depth+1)


def _read_gps_ifd(data: bytes, offset: int, bo: str, result: dict):
    if offset + 2 > len(data): return
    try:
        num_entries = struct.unpack_from(bo + 'H', data, offset)[0]
    except Exception: return

    gps = {}
    for i in range(num_entries):
        entry_offset = offset + 2 + i * 12
        if entry_offset + 12 > len(data): break
        try:
            tag_id, type_id, count = struct.unpack_from(bo + 'HHI', data, entry_offset)
            value_raw = data[entry_offset+8:entry_offset+12]
            value = _read_exif_value(data, bo, type_id, count, value_raw)
            tag_name = GPSTAGS.get(tag_id, f"GPS_{tag_id}")
            gps[tag_name] = _format_exif_value(tag_id, value, is_gps=True)
        except Exception: continue

    if gps:
        result["gps"] = gps
        lat  = _gps_decimal(gps.get("GPSLatitude"), gps.get("GPSLatitudeRef", "N"))
        lon  = _gps_decimal(gps.get("GPSLongitude"), gps.get("GPSLongitudeRef", "E"))
        if lat is not None and lon is not None:
            result["gps"]["GPSDecimal"]   = f"{lat:.6f}, {lon:.6f}"
            result["gps"]["GoogleMapsURL"] = f"https://maps.google.com/?q={lat},{lon}"
            result["forensic_flags"].append(f"GPS COORDINATES DETECTED: {lat:.6f}, {lon:.6f}")


# ─── EXIF helper readers ──────────────────────────────────────────────────────
_EXIF_TYPE_SIZES = {1:1, 2:1, 3:2, 4:4, 5:8, 6:1, 7:1, 8:2, 9:4, 10:8, 11:4, 12:8}

def _read_exif_value(data: bytes, bo: str, type_id: int, count: int, value_raw: bytes):
    size = _EXIF_TYPE_SIZES.get(type_id, 1)
    total = size * count
    if total <= 4:
        value_data = value_raw[:total]
    else:
        offset = struct.unpack_from(bo + 'I', value_raw)[0]
        if offset + total > len(data): return None
        value_data = data[offset:offset+total]

    fmt_map = {1: 'B', 3: 'H', 4: 'I', 6: 'b', 8: 'h', 9: 'i', 11: 'f', 12: 'd'}
    try:
        if type_id == 2:
            return value_data.rstrip(b'\x00').decode('ascii', errors='replace').strip()
        elif type_id == 7:
            try: return value_data.decode('ascii', errors='ignore').strip() or value_data.hex()
            except: return value_data.hex()
        elif type_id in (5, 10):
            pairs = []
            sign = 'I' if type_id == 5 else 'i'
            for j in range(count):
                n, d = struct.unpack_from(bo + sign*2, value_data, j*8)
                pairs.append((n, d))
            return pairs if count > 1 else pairs[0]
        elif type_id in fmt_map:
            fmt = bo + fmt_map[type_id] * count
            vals = struct.unpack_from(fmt, value_data)
            return vals if count > 1 else vals[0]
    except Exception: pass
    return None

def _format_exif_value(tag_id: int, value, is_gps: bool = False) -> Optional[str]:
    if value is None: return None
    if isinstance(value, str): return value
    if isinstance(value, tuple) and len(value) == 2 and isinstance(value[0], int):
        n, d = value
        return f"{n/d:.4f}".rstrip('0').rstrip('.') if d else "0"
    if isinstance(value, (list, tuple)):
        if is_gps: return str(value)
        parts = []
        for v in value:
            if isinstance(v, tuple) and len(v) == 2:
                n, d = v
                parts.append(f"{n/d:.4f}".rstrip('0').rstrip('.') if d else "0")
            else:
                parts.append(str(v))
        return " ".join(parts)
    return str(value)

def _to_int(value) -> int:
    if isinstance(value, int): return value
    if isinstance(value, (list, tuple)) and value: return int(value[0])
    try: return int(value)
    except: return 0

def _gps_decimal(raw, ref) -> Optional[float]:
    try:
        if isinstance(raw, str): raw = eval(raw)
        if isinstance(raw, (list, tuple)) and len(raw) == 3:
            d = raw[0][0]/raw[0][1] if isinstance(raw[0], tuple) else float(raw[0])
            m = raw[1][0]/raw[1][1] if isinstance(raw[1], tuple) else float(raw[1])
            s = raw[2][0]/raw[2][1] if isinstance(raw[2], tuple) else float(raw[2])
            decimal = d + m/60 + s/3600
            if ref in ('S', 'W'): decimal = -decimal
            return decimal
    except: pass
    return None


# ═══════════════════════════════════════════════════════════════════════════════
# DYNAMIC XMP NAMESPACES PARSER
# ═══════════════════════════════════════════════════════════════════════════════

def _parse_xmp(xmp_text: str) -> dict:
    """Extract all custom namespaces and tags dynamically from XMP XML packet."""
    properties = {}
    
    # 1. Matches element form: <prefix:tag>value</prefix:tag> (excluding containers)
    tag_matches = re.findall(r'<(?!rdf\b|x\b|xmpmeta\b)([a-zA-Z0-9_\-]+):([a-zA-Z0-9_\-]+)[^>]*>(.*?)</\1:\2>', xmp_text, re.DOTALL)
    for prefix, tag, val in tag_matches:
        val = val.strip()
        if prefix.lower() in ("rdf", "x", "xmpmeta"): continue
        li_vals = re.findall(r'<rdf:li[^>]*>([^<]+)</rdf:li>', val, re.DOTALL)
        if li_vals:
            val = ", ".join(li.strip() for li in li_vals)
        else:
            val = re.sub('<[^<]+>', '', val).strip()
        key = f"{prefix}:{tag}"
        properties[key] = val

    # 2. Matches attribute form: prefix:tag="value"
    desc_matches = re.findall(r'<rdf:Description[^>]*?([a-zA-Z0-9_\-]+):([a-zA-Z0-9_\-]+)\s*=\s*(["\'])(.*?)\3', xmp_text, re.DOTALL)
    for prefix, tag, _, val in desc_matches:
        if prefix.lower() in ("rdf", "x", "xmpmeta"): continue
        key = f"{prefix}:{tag}"
        properties[key] = val.strip()
        
    # Also add keys without prefix for fallback compatibility
    for k, v in list(properties.items()):
        if ":" in k:
            tag = k.split(":")[-1]
            if tag not in properties:
                properties[tag] = v

    return properties


def parse_xmp_text_layers(xmp_text: str) -> list[dict]:
    """Parse photoshop:TextLayers sequence out of XMP metadata cache."""
    layers = []
    block_match = re.search(r'<photoshop:TextLayers>(.*?)</photoshop:TextLayers>', xmp_text, re.DOTALL)
    if block_match:
        content = block_match.group(1)
        li_matches = re.findall(r'<rdf:li[^>]*>(.*?)</rdf:li>', content, re.DOTALL)
        for li in li_matches:
            name_m = re.search(r'<photoshop:LayerName>(.*?)</photoshop:LayerName>', li, re.DOTALL)
            text_m = re.search(r'<photoshop:LayerText>(.*?)</photoshop:LayerText>', li, re.DOTALL)
            if name_m and text_m:
                layers.append({
                    "name": name_m.group(1).strip(),
                    "text": text_m.group(1).strip(),
                    "visible": True,
                    "hidden": False,
                    "kind": "type",
                })
    return layers


# ═══════════════════════════════════════════════════════════════════════════════
# PHOTOSHOP METADATA & PSD PARSERS
# ═══════════════════════════════════════════════════════════════════════════════

def _parse_psd_with_tools(data: bytes, result: dict) -> bool:
    if not PSD_TOOLS_AVAILABLE: return False
    try:
        psd = PSDImage.open(io.BytesIO(data))
        result["photoshop"]["DocumentID"] = getattr(psd, "document_id", "") or ""
        result["photoshop"]["InstanceID"] = getattr(psd, "instance_id", "") or ""
        result["photoshop"]["OriginalDocumentID"] = getattr(psd, "original_document_id", "") or ""
        
        layers_list = []
        text_layers_list = []
        
        for layer in psd.descendants():
            layer_info = {
                "name": layer.name or "Unnamed Layer",
                "visible": layer.visible,
                "hidden": not layer.visible,
                "kind": layer.kind,
                "opacity": layer.opacity,
                "blend_mode": layer.blend_mode,
                "is_group": layer.is_group(),
                "text": "",
            }
            if layer.kind == "type" and hasattr(layer, "text_data") and layer.text_data:
                td = layer.text_data
                if td and td.text:
                    layer_info["text"] = td.text.strip()
                    text_layers_list.append(layer_info)
            layers_list.append(layer_info)
            
        result["text_layers"] = text_layers_list
        result["psd_layers"] = layers_list
        result["forensic_flags"].append("PHOTOSHOP PSD LAYERS PARSED SUCCESSFULLY")
        return True
    except Exception:
        return False


def _parse_psd_fallback(data: bytes, result: dict) -> bool:
    if len(data) < 26 or data[:4] != b'8BPS': return False
    try:
        pos = 26
        color_len = struct.unpack('>I', data[pos:pos+4])[0]
        pos += 4 + color_len
        if pos + 4 > len(data): return False
        img_res_len = struct.unpack('>I', data[pos:pos+4])[0]
        pos += 4 + img_res_len
        if pos + 4 > len(data): return False
        layer_mask_len = struct.unpack('>I', data[pos:pos+4])[0]
        pos += 4
        if pos + 4 > len(data): return False
        layer_info_len = struct.unpack('>I', data[pos:pos+4])[0]
        pos += 4
        if layer_info_len == 0: return False
        
        layer_count = struct.unpack('>h', data[pos:pos+2])[0]
        pos += 2
        num_layers = abs(layer_count)
        
        layers_list = []
        text_layers_list = []
        
        for _ in range(num_layers):
            if pos + 16 > len(data): break
            pos += 16
            num_channels = struct.unpack('>H', data[pos:pos+2])[0]
            pos += 2 + num_channels * 6
            if data[pos:pos+4] != b'8BIM':
                idx = data.find(b'8BIM', pos)
                if idx >= 0: pos = idx
                else: break
            pos += 4
            blend_mode = data[pos:pos+4].decode('ascii', errors='ignore')
            pos += 4
            opacity = data[pos]
            clipping = data[pos+1]
            flags = data[pos+2]
            pos += 4
            
            extra_len = struct.unpack('>I', data[pos:pos+4])[0]
            extra_end = pos + 4 + extra_len
            pos += 4
            
            mask_len = struct.unpack('>I', data[pos:pos+4])[0]
            pos += 4 + mask_len
            range_len = struct.unpack('>I', data[pos:pos+4])[0]
            pos += 4 + range_len
            
            name_len = data[pos]
            name = data[pos+1:pos+1+name_len].decode('latin-1', errors='ignore').strip()
            pos += 1 + name_len
            rem = (1 + name_len) % 4
            if rem > 0: pos += (4 - rem)
            
            layer_info = {
                "name": name,
                "visible": not (flags & 2),
                "hidden": (flags & 2) != 0,
                "blend_mode": blend_mode,
                "opacity": opacity,
                "text": "",
                "kind": "pixel",
                "is_group": False,
            }
            
            # Extract luni / TySh tagged blocks
            extra_pos = pos
            while extra_pos + 12 < extra_end:
                sig = data[extra_pos:extra_pos+4]
                if sig not in (b'8BIM', b'8B64'):
                    extra_pos += 1
                    continue
                key = data[extra_pos+4:extra_pos+8].decode('ascii', errors='ignore')
                length = struct.unpack('>I', data[extra_pos+8:extra_pos+12])[0]
                length_padded = length + (length % 2)
                block_data = data[extra_pos+12:extra_pos+12+length]
                
                if key == 'luni' and len(block_data) > 4:
                    name_len_uni = struct.unpack('>I', block_data[:4])[0]
                    layer_info["name"] = block_data[4:4+name_len_uni*2].decode('utf-16-be', errors='ignore').strip('\x00')
                elif key == 'TySh':
                    layer_info["kind"] = "type"
                    matches = re.findall(b'\\(\\xfe\\xff(.*?)\\)', block_data, re.DOTALL)
                    texts = []
                    for m in matches:
                        try:
                            decoded = m.decode('utf-16-be', errors='ignore')
                            cleaned = re.sub(r'[\r\n\t]', ' ', decoded).strip()
                            if cleaned: texts.append(cleaned)
                        except: pass
                    if texts:
                        layer_info["text"] = " | ".join(texts)
                        text_layers_list.append(layer_info)
                elif key == 'lsct' and len(block_data) >= 4:
                    divider = struct.unpack('>I', block_data[:4])[0]
                    if divider in (1, 2): layer_info["is_group"] = True
                        
                extra_pos += 12 + length_padded
            
            layers_list.append(layer_info)
            pos = extra_end
            
        result["psd_layers"] = layers_list
        result["text_layers"] = text_layers_list
        result["forensic_flags"].append("PHOTOSHOP PSD LAYERS PARSED (FALLBACK)")
        return True
    except:
        return False


def _parse_iptc_photoshop(data: bytes, result: dict):
    pos = 0
    while pos + 12 <= len(data):
        if data[pos:pos+4] != b'8BIM':
            pos += 1
            continue
        pos += 4
        resource_id = struct.unpack_from('>H', data, pos)[0]
        pos += 2
        name_len = data[pos]
        pos += 1 + name_len
        if name_len % 2 == 0: pos += 1
        
        resource_len = struct.unpack_from('>I', data, pos)[0]
        pos += 4
        resource_data = data[pos:pos+resource_len]
        pos += resource_len
        if resource_len % 2: pos += 1

        if resource_id == 0x0404:
            _parse_iptc_dataset(resource_data, result)
        elif resource_id == 0x0407:
            result["photoshop"]["URL"] = resource_data.decode("utf-8", errors="ignore").strip()
        elif resource_id == 0x0406:
            result["photoshop"]["CopyrightFlag"] = bool(resource_data[0]) if resource_data else False
        elif resource_id == 0x0414:
            # XMP packet in Photoshop IRB
            x_text = resource_data.decode("utf-8", errors="ignore")
            result["raw_xmp"] = x_text
            result["xmp"].update(_parse_xmp(x_text))


def _parse_iptc_dataset(data: bytes, result: dict):
    iptc_tags = {
        (2, 5): "ObjectName", (2, 25): "Keywords", (2, 40): "SpecialInstructions",
        (2, 80): "Byline", (2, 85): "BylineTitle", (2, 90): "City",
        (2, 92): "Sub-Location", (2, 95): "Province-State", (2, 101): "Country",
        (2, 105): "Headline", (2, 110): "Credit", (2, 115): "Source",
        (2, 116): "CopyrightNotice", (2, 120): "Caption-Abstract"
    }
    pos = 0
    while pos + 5 <= len(data):
        marker = data[pos]
        if marker != 0x1C:
            pos += 1
            continue
        record = data[pos+1]
        dataset = data[pos+2]
        length = struct.unpack_from('>H', data, pos+3)[0]
        pos += 5
        value = data[pos:pos+length]
        pos += length

        tag_name = iptc_tags.get((record, dataset), f"IPTC_{record}:{dataset}")
        try:
            result["iptc"][tag_name] = value.decode("utf-8", errors="replace").strip()
        except Exception:
            result["iptc"][tag_name] = value.hex()


# ═══════════════════════════════════════════════════════════════════════════════
# ICC PROFILE PARSER
# ═══════════════════════════════════════════════════════════════════════════════

def _parse_icc_profile(icc_bytes: bytes, result: dict):
    if len(icc_bytes) < 128: return
    try:
        size = struct.unpack('>I', icc_bytes[0:4])[0]
        cmm = icc_bytes[4:8].decode('ascii', errors='ignore').strip()
        version_raw = icc_bytes[8:12]
        version = f"{version_raw[0]}.{version_raw[1] >> 4}.{version_raw[1] & 0xF}"
        pclass = icc_bytes[12:16].decode('ascii', errors='ignore').strip()
        colorspace = icc_bytes[16:20].decode('ascii', errors='ignore').strip()
        connspace = icc_bytes[20:24].decode('ascii', errors='ignore').strip()
        magic = icc_bytes[36:40].decode('ascii', errors='ignore').strip()
        if magic != 'acsp': return
        
        manufacturer = icc_bytes[48:52].decode('ascii', errors='ignore').strip()
        model = icc_bytes[52:56].decode('ascii', errors='ignore').strip()
        intent_code = struct.unpack('>I', icc_bytes[64:68])[0]
        intent = {0: "Perceptual", 1: "Relative Colorimetric", 2: "Saturation", 3: "Absolute Colorimetric"}.get(intent_code, str(intent_code))
        
        profile_name = ""
        tag_count = struct.unpack('>I', icc_bytes[128:132])[0]
        for i in range(tag_count):
            offset = 132 + i * 12
            if offset + 12 > len(icc_bytes): break
            tag_sig = icc_bytes[offset:offset+4].decode('ascii', errors='ignore')
            tag_offset, tag_size = struct.unpack('>II', icc_bytes[offset+4:offset+12])
            if tag_sig == 'desc' and tag_offset + tag_size <= len(icc_bytes):
                desc_data = icc_bytes[tag_offset:tag_offset+tag_size]
                if desc_data[:4] == b'desc':
                    desc_len = struct.unpack('>I', desc_data[8:12])[0]
                    profile_name = desc_data[12:12+desc_len-1].decode('latin-1', errors='ignore').strip()

        result["icc_profile"] = {
            "ProfileName":     profile_name or "Unknown",
            "ColorSpace":      colorspace,
            "RenderingIntent": intent,
            "ProfileVersion":  version,
            "Manufacturer":    manufacturer or "Unknown",
            "DeviceModel":     model or "Unknown",
            "CMMType":         cmm,
            "ProfileClass":    pclass,
        }
    except Exception:
        pass


# ═══════════════════════════════════════════════════════════════════════════════
# OCR & DECODERS (QR/BARCODES)
# ═══════════════════════════════════════════════════════════════════════════════

def decode_qr_barcodes(img_bytes: bytes) -> list:
    decoded = []
    if not PIL_AVAILABLE or not ZBAR_AVAILABLE: return decoded
    try:
        img = Image.open(io.BytesIO(img_bytes))
        barcodes = zbar_decode(img)
        for b in barcodes:
            decoded.append({
                "type": b.type,
                "data": b.data.decode('utf-8', errors='replace'),
                "rect": str(b.rect),
            })
    except Exception:
        pass
    return decoded


def run_ocr_and_classify(data: bytes, result: dict):
    ocr_text = ""
    confidence = 0
    
    if PIL_AVAILABLE and TESSERACT_AVAILABLE:
        try:
            img = Image.open(io.BytesIO(data))
            ocr_text = pytesseract.image_to_string(img)
            data_dict = pytesseract.image_to_data(img, output_type=pytesseract.Output.DICT)
            confidences = [int(c) for c in data_dict.get("conf", []) if c != -1 and c != '-1']
            confidence = sum(confidences) // len(confidences) if confidences else 70
        except Exception:
            pass

    # Extract strings from Photoshop text layers as OCR fallback
    layer_texts = []
    for l in result.get("text_layers", []):
        if l.get("text"): layer_texts.append(l["text"])
        
    combined_text = ocr_text + "\n" + "\n".join(layer_texts)
    result["ocr"] = {
        "text": ocr_text or " | ".join(layer_texts) or "(No text extracted)",
        "confidence": confidence if ocr_text else (85 if layer_texts else 0),
        "classified": classify_text_credentials(combined_text),
    }


def classify_text_credentials(text: str) -> dict:
    results = {}
    if not text.strip(): return results
    patterns = {
        "Emails":        r'\b[a-zA-Z0-9._%+\\-]+@[a-zA-Z0-9.\\-]+\.[a-zA-Z]{2,}\b',
        "URLs":          r'https?://[^\s<>"\']{4,200}',
        "Phone numbers": r'\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b',
        "AWS Keys":      r'\b(?:AKIA|ASCA|ACCA|ASIA)[A-Z0-9]{16}\b',
        "API Keys":      r'\b[a-f0-9]{32}\b|\b[A-Za-z0-9_\-]{24,40}\b',
        "JWT Tokens":    r'\beyJhbGciOi[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\b',
        "Private Keys":  r'-----BEGIN [A-Z ]+ PRIVATE KEY-----',
        "Flags":         r'\b(?:flag|CTF|ctf)\{[a-zA-Z0-9_\-!@#\$%\^&\*]+\}\b|\b[a-zA-Z0-9_\-]{8,32}_flag\b',
        "Passwords":     r'\b(?:password|passwd|pwd|pass|admin|root|user|username|login)\s*[:=]\s*([A-Za-z0-9_\-!@#\$%\^&\*]{6,30})\b',
        "Credentials":   r'\b(?:admin|root|user|username|login)\s*[:=]\s*([A-Za-z0-9_\-!@#\$%\^&\*]{3,30})\b',
    }
    for category, pat in patterns.items():
        matches = re.findall(pat, text, re.IGNORECASE if category not in ("AWS Keys", "JWT Tokens") else 0)
        if matches:
            cleaned = []
            for m in matches:
                if isinstance(m, tuple): m = m[0]
                m_str = str(m).strip()
                if m_str and m_str not in cleaned: cleaned.append(m_str)
            if cleaned: results[category] = cleaned
    return results


# ═══════════════════════════════════════════════════════════════════════════════
# ANALYST HEURISTIC CLASSIFIERS
# ═══════════════════════════════════════════════════════════════════════════════

def classify_image_metadata(exif: dict, xmp: dict, psdata: dict, layers: list) -> dict:
    classified = {"device": {}, "editing": {}, "hidden": {}, "privacy": {}}
    
    # 1. Device Info
    make = exif.get("Make") or xmp.get("Make") or ""
    model = exif.get("Model") or xmp.get("Model") or ""
    lens = exif.get("LensModel") or exif.get("Lens") or xmp.get("LensModel") or ""
    software = exif.get("Software") or xmp.get("CreatorTool") or ""
    cap_time = exif.get("DateTimeOriginal") or exif.get("DateTime") or xmp.get("CreateDate") or ""
    w = exif.get("ImageWidth") or exif.get("Width") or exif.get("ExifImageWidth") or ""
    h = exif.get("ImageHeight") or exif.get("Height") or exif.get("ExifImageHeight") or ""
    
    if make: classified["device"]["Manufacturer"] = make
    if model: classified["device"]["Camera Model"] = model
    if lens: classified["device"]["Lens Model"] = lens
    if w and h: classified["device"]["Resolution"] = f"{w} x {h}"
    if software: classified["device"]["Software"] = software
    if cap_time: classified["device"]["Capture Time"] = cap_time
    
    # 2. Editing Info
    edits = []
    for s in [software, xmp.get("CreatorTool", ""), xmp.get("XMPToolkit", "")]:
        if not s: continue
        s_lower = str(s).lower()
        if "photoshop" in s_lower: edits.append("Adobe Photoshop")
        elif "lightroom" in s_lower: edits.append("Adobe Lightroom")
        elif "canva" in s_lower: edits.append("Canva")
        elif "gimp" in s_lower: edits.append("GIMP")
    edits = list(set(edits))
    if edits: classified["editing"]["Editing Software"] = ", ".join(edits)
    if xmp.get("CreateDate"): classified["editing"]["Created Date"] = xmp["CreateDate"]
    if xmp.get("ModifyDate"): classified["editing"]["Modified Date"] = xmp["ModifyDate"]
    
    history_actions = []
    if xmp.get("HistoryAction"):
        actions = xmp["HistoryAction"].split(",")
        whens = xmp.get("HistoryWhen", "").split(",")
        agents = xmp.get("HistorySoftwareAgent", "").split(",")
        for idx, act in enumerate(actions):
            when = whens[idx] if idx < len(whens) else ""
            agent = agents[idx].rsplit("/", 1)[-1] if idx < len(agents) else ""
            history_actions.append(f"{act} ({agent})" + (f" at {when[:19]}" if when else ""))
    if history_actions: classified["editing"]["Editing Timeline"] = history_actions
    
    # 3. Hidden Content
    hidden_layers = []
    all_layers = []
    smart_objects = []
    adjustments = []
    for l in layers:
        all_layers.append(l.get("name", ""))
        if l.get("hidden"): hidden_layers.append(l.get("name", ""))
        if l.get("is_smart_object") or "smart" in str(l.get("kind", "")).lower():
            smart_objects.append(l.get("name", ""))
        if l.get("is_adjustment") or "adjust" in str(l.get("kind", "")).lower():
            adjustments.append(l.get("name", ""))
            
    if all_layers: classified["hidden"]["Layers"] = ", ".join(all_layers)
    if hidden_layers: classified["hidden"]["Hidden Layers"] = ", ".join(hidden_layers)
    if smart_objects: classified["hidden"]["Smart Objects"] = ", ".join(smart_objects)
    if adjustments: classified["hidden"]["Adjustment Layers"] = ", ".join(adjustments)
    if psdata.get("NumSlices"):
        classified["hidden"]["Slices"] = f"Group: {psdata.get('SlicesGroupName', 'N/A')} ({psdata.get('NumSlices')} slices)"

    # 4. Privacy Details
    gps_dec = exif.get("GPSDecimal") or xmp.get("GPSDecimal")
    owner = exif.get("OwnerName") or exif.get("CameraOwnerName") or xmp.get("OwnerName") or ""
    serial = exif.get("BodySerialNumber") or exif.get("SerialNumber") or exif.get("CameraSerialNumber") or ""
    artist = exif.get("Artist") or exif.get("XPAuthor") or xmp.get("Creator") or ""
    copyright_val = exif.get("Copyright") or xmp.get("Rights") or ""
    
    if gps_dec: classified["privacy"]["GPS Coordinates"] = gps_dec
    if owner: classified["privacy"]["Owner"] = owner
    if serial: classified["privacy"]["Camera Serial"] = serial
    if artist: classified["privacy"]["Artist"] = artist
    if copyright_val: classified["privacy"]["Copyright"] = copyright_val
    if xmp.get("DocumentAncestors"): classified["privacy"]["Document History"] = xmp["DocumentAncestors"]

    return classified


def estimate_ai_generation(exif: dict, xmp: dict, fi: dict) -> dict:
    clues = []
    score = 0
    
    software = str(exif.get("Software") or xmp.get("CreatorTool") or xmp.get("XMPToolkit") or "").lower()
    desc = str(xmp.get("Description") or exif.get("UserComment") or "").lower()
    
    ai_keywords = {
        "midjourney": ("Midjourney signature in metadata", 95),
        "dall-e": ("DALL-E signature in metadata", 95),
        "stable diffusion": ("Stable Diffusion signature in metadata", 95),
        "sdxl": ("Stable Diffusion XL tag", 95),
        "firefly": ("Adobe Firefly generative tag", 90),
        "generative ai": ("Generative AI tag detected", 80),
        "bing image creator": ("Bing Image Creator signature", 90),
        "novelai": ("NovelAI model tag", 90),
    }
    
    for kw, (reason, pts) in ai_keywords.items():
        if kw in software or kw in desc:
            clues.append(reason)
            score = max(score, pts)
            
    is_photo = fi.get("FileType", "").lower() in ("jpeg", "jpg", "png", "webp")
    has_camera = bool(exif.get("Make") or exif.get("Model") or exif.get("DateTimeOriginal"))
    
    if is_photo and not has_camera and score == 0:
        try:
            entropy = float(fi.get("Entropy", "0.0").split("/")[0])
        except:
            entropy = 0.0
        if entropy > 7.95:
            clues.append("Photographic dimensions with zero camera EXIF tags and high entropy (suggests synthetic noise)")
            score = 30
            
    if score >= 90: likelihood = "🔴 High Probability (AI Generated)"
    elif score >= 50: likelihood = "🟠 Medium Probability"
    elif score >= 20: likelihood = "🟡 Low Probability (Possible AI)"
    else: likelihood = "🟢 Clean (No AI signatures detected)"
        
    return {"likelihood": likelihood, "score": score, "clues": clues}


# ═══════════════════════════════════════════════════════════════════════════════
# STEGANOGRAPHY CHECKS
# ═══════════════════════════════════════════════════════════════════════════════

def _check_steganography(data: bytes, result: dict):
    steg = {}
    flags = []
    
    # 1. Appended data after marker
    if data[:2] == _JPEG_SOI:
        eoi = data.rfind(_JPEG_EOI)
        if eoi > 0 and eoi + 2 < len(data):
            sz = len(data) - (eoi + 2)
            steg["Appended Data"] = f"Detected ({sz} bytes after JPEG EOI)"
            flags.append("HIDDEN DATA APPENDED AFTER EOI")
    elif data[:8] == b'\x89PNG\r\n\x1a\n':
        iend = data.rfind(b'IEND')
        if iend > 0 and iend + 8 < len(data):
            sz = len(data) - (iend + 8)
            steg["Appended Data"] = f"Detected ({sz} bytes after PNG IEND)"
            flags.append("HIDDEN DATA APPENDED AFTER IEND")

    # 2. LSB distribution anomalies
    if PIL_AVAILABLE:
        try:
            img = Image.open(io.BytesIO(data)).convert('RGB')
            px = list(img.getdata())[:2000]
            lsb_r = [p[0] & 1 for p in px]
            ratio = sum(lsb_r) / len(lsb_r)
            if 0.48 < ratio < 0.52:
                steg["LSB Anomaly"] = f"LSB distribution near-perfect 50% ({ratio:.4f}), suggests LSB stego payload."
                flags.append("LSB STEGANOGRAPHY ANOMALY DETECTED")
        except Exception: pass

    # 3. High entropy segments
    high_entropy = []
    chunk = 10240
    for i in range(0, len(data), chunk):
        sub = data[i:i+chunk]
        if len(sub) < 1024: continue
        freq = [0]*256
        for b in sub: freq[b] += 1
        t = len(sub)
        ent = -sum((f/t)*math.log2(f/t) for f in freq if f > 0)
        if ent > 7.98:
            high_entropy.append(f"Offset {i} - {i+len(sub)} (Entropy: {ent:.4f})")
    if high_entropy:
        steg["High Entropy Regions"] = high_entropy
        flags.append("HIGH ENTROPY SEGMENT DETECTED (SUSPICIOUS)")

    result["steganography"] = steg
    result["forensic_flags"].extend(flags)


def _scan_embedded_files(data: bytes, result: dict):
    # Scan the entire file excluding the first 4 bytes to prevent self-matching
    search_region = data[4:]
    skip = 4

    sigs = {
        b'PK\x03\x04':       ('ZIP archive', 'zip'),
        b'\xff\xd8\xff':     ('JPEG image', 'jpg'),
        b'\x89PNG\r\n\x1a\n':('PNG image', 'png'),
        b'%PDF-':            ('PDF document', 'pdf'),
        b'MZ':               ('PE executable', 'exe'),
        b'\x7fELF':          ('ELF binary', 'elf'),
        b'Rar!\x1a\x07':     ('RAR archive', 'rar'),
        b'\x1f\x8b':         ('GZIP data', 'gz'),
    }
    found = []
    for sig, (name, ext) in sigs.items():
        pos = search_region.find(sig)
        if pos >= 0:
            offset = skip + pos
            found.append({"type": name, "ext": ext, "offset": offset, "suspicious": True})
            result["forensic_flags"].append(f"EMBEDDED FILE: {name} at offset {offset}")
            
    result["embedded_files"] = found


# ═══════════════════════════════════════════════════════════════════════════════
# REPORT FORMATTER
# ═══════════════════════════════════════════════════════════════════════════════

def format_metadata_report(analysis: dict) -> list[str]:
    """Format the full forensics report as Telegram HTML pages."""
    import html as _h
    pages = []
    sep = "━━━━━━━━━━━━━━━━━━━━━━"

    fi = analysis.get("file", {})
    flags = analysis.get("forensic_flags", [])
    steg = analysis.get("steganography", {})
    embeds = analysis.get("embedded_files", [])
    ocr = analysis.get("ocr", {})
    qrs = analysis.get("qr_barcodes", [])
    ai = analysis.get("ai_detection", {})
    cls_meta = analysis.get("classified_metadata", {})

    # Compute Image Risk Score & Analyst Verdict
    score = 0
    reasons = []
    
    # Check flags and results for VT malicious signals
    vt_mal_detected = False
    for f in flags:
        if "virustotal" in f.lower() or "vt malicious" in f.lower() or "malicious" in f.lower():
            if "no detections" not in f.lower() and "clean" not in f.lower():
                vt_mal_detected = True

    embedded_exe = False
    for e in embeds:
        if any(ext in e.get("type", "").lower() for ext in ("exe", "pe", "elf", "dll", "bin")):
            embedded_exe = True

    has_hidden_layers = bool(analysis.get("text_layers", [])) or bool(cls_meta.get("hidden", {}))
    is_edited = bool(cls_meta.get("editing", {}).get("Editing Software"))

    if vt_mal_detected:
        score = 98
        reasons.append("Active malware payload / VT detection matching found in OCR/QR or metadata.")
        action = "ISOLATE HOST"
        action_em = "🚨"
        verdict = "MALICIOUS"
        verdict_em = "🔴"
    elif embeds or embedded_exe:
        score = 85
        reasons.append("Appended payload or hidden embedded file detected.")
        action = "QUARANTINE"
        action_em = "🛑"
        verdict = "HIGH RISK"
        verdict_em = "🟠"
    elif steg.get("Appended Data") or steg.get("LSB Anomaly") or steg.get("High Entropy Regions"):
        score = 75
        reasons.append("Steganography anomalies or high entropy segment suggests hidden payload data.")
        action = "QUARANTINE"
        action_em = "🛑"
        verdict = "HIGH RISK"
        verdict_em = "🟠"
    elif ocr.get("classified") and any(k in ocr["classified"] for k in ("Passwords", "AWS Keys", "Private Keys", "JWT Tokens")):
        score = 80
        reasons.append("Sensitive credentials / secrets detected in OCR scan.")
        action = "QUARANTINE"
        action_em = "🛑"
        verdict = "MALICIOUS"
        verdict_em = "🔴"
    elif has_hidden_layers:
        score = 50
        reasons.append("Hidden layers or Photoshop text layers detected in metadata.")
        action = "MANUAL REVIEW"
        action_em = "⚠️"
        verdict = "SUSPICIOUS"
        verdict_em = "🟡"
    elif cls_meta.get("privacy", {}).get("GPS Coordinates"):
        score = 25
        reasons.append("Sensitive GPS geolocation coordinates exposed.")
        action = "REVIEW"
        action_em = "📝"
        verdict = "SUSPICIOUS"
        verdict_em = "🟡"
    elif is_edited:
        score = 20
        reasons.append("Photoshop/editing software indicators detected.")
        action = "REVIEW"
        action_em = "📝"
        verdict = "SUSPICIOUS"
        verdict_em = "🟡"
    elif ai.get("score", 0) >= 50:
        score = 15
        reasons.append("Image shows indicators of AI generation / synthetic source.")
        action = "REVIEW"
        action_em = "📝"
        verdict = "SUSPICIOUS"
        verdict_em = "🟡"
    else:
        score = 0
        action = "ALLOW"
        action_em = "✅"
        verdict = "CLEAN"
        verdict_em = "🟢"


    why_str = "\n".join(f"  • {_h.escape(r)}" for r in reasons) or "  • No security anomalies detected."

    # ── PAGE 1: Executive Analyst Brief + Geolocation + AI ───────────────────
    gps = cls_meta.get("privacy", {}).get("GPS Coordinates", "N/A")
    gmaps = analysis.get("gps", {}).get("GoogleMapsURL", "")
    gps_line = f"• <b>GPS Coords:</b> <code>{_h.escape(gps)}</code>"
    if gmaps:
        gps_line += f" <a href=\"{gmaps}\">🗺 [Google Maps]</a>"

    p1 = (
        f"🔬 <b>IMAGE FORENSIC BRIEF</b>\n"
        f"<code>{sep}</code>\n\n"
        f"<b>Verdict:</b>      {verdict_em} <b>{verdict}</b>\n"
        f"<b>Risk Score:</b>   <code>{score}/100</code>\n"
        f"<b>AI Likelihood:</b> <code>{_h.escape(ai.get('likelihood', 'Clean'))}</code>\n\n"
        f"<b>Filename:</b>  <code>{_h.escape(fi.get('FileName','?'))}</code>\n"
        f"<b>Size:</b>      <code>{fi.get('FileSize','?')}</code>\n"
        f"<b>Type:</b>      <code>{fi.get('FileType','?')}</code>\n"
        f"<b>SHA-256:</b>   <code>{fi.get('SHA256','')[:30]}…</code>\n"
        f"{gps_line}\n\n"
        f"<b>Findings:</b>\n{why_str}\n"
    )
    pages.append(p1)

    # ── PAGE 2: OCR & QR + Hidden Content ──────────────────────────────────
    p2 = f"🚨 <b>OCR & DETECTED CONTENT</b>\n<code>{sep}</code>\n\n"
    
    # Classified credentials
    secrets = ocr.get("classified", {})
    if secrets:
        p2 += "🔑 <b>Extracted Secrets:</b>\n"
        for cat, vals in secrets.items():
            val_txt = ", ".join(f"<code>{_h.escape(v)}</code>" for v in vals[:3])
            p2 += f"  • <b>{_h.escape(cat)}:</b> {val_txt}\n"
        p2 += "\n"
        
    # QR codes
    if qrs:
        p2 += "📡 <b>Decoded Barcodes / QR Codes:</b>\n"
        for q in qrs:
            p2 += f"  • <b>{_h.escape(q['type'])}:</b> <code>{_h.escape(q['data'])}</code>\n"
        p2 += "\n"
        
    # Text Layers
    layers = analysis.get("text_layers", [])
    if layers:
        p2 += "🖼 <b>Photoshop Text Layers:</b>\n"
        for l in layers:
            vis = "Hidden" if l.get("hidden") else "Visible"
            p2 += f"  • [<b>{vis}</b>] <b>{_h.escape(l['name'])}:</b> <code>{_h.escape(l['text'])}</code>\n"
        p2 += "\n"

    # Smart Objects & Groups
    hidden_meta = cls_meta.get("hidden", {})
    if hidden_meta:
        p2 += "📦 <b>Layers & Hidden Objects:</b>\n"
        for k, v in hidden_meta.items():
            p2 += f"  • <b>{_h.escape(k)}:</b> <code>{_h.escape(str(v)[:150])}</code>\n"
            
    if p2.count('\n') > 3:
        pages.append(p2)

    # ── PAGE 3: Stego & Details + Device Info + Editing ────────────────────
    p3 = f"🕵️ <b>STEGANOGRAPHY & STRUCTURE</b>\n<code>{sep}</code>\n\n"
    
    if steg:
        p3 += "🔍 <b>Steganography Indicators:</b>\n"
        for k, v in steg.items():
            p3 += f"  • <b>{_h.escape(k)}:</b> <code>{_h.escape(str(v))}</code>\n"
            
    if embeds:
        p3 += "\n⚠️ <b>Embedded File Offsets:</b>\n"
        for e in embeds:
            p3 += f"  • <b>{_h.escape(e['type'])}</b> at offset <code>{e['offset']}</code>\n"
            
    # Device Info
    dev = cls_meta.get("device", {})
    if dev:
        p3 += "\n📷 <b>Device Information:</b>\n"
        for k, v in dev.items():
            p3 += f"  • <b>{_h.escape(k)}:</b> <code>{_h.escape(str(v))}</code>\n"

    # Editing Info
    edit = cls_meta.get("editing", {})
    if edit:
        p3 += "\n📝 <b>Editing History:</b>\n"
        for k, v in edit.items():
            if k == "Editing Timeline":
                p3 += "  • <b>Timeline:</b>\n"
                for entry in v[:5]:
                    p3 += f"    - <code>{_h.escape(entry)}</code>\n"
            else:
                p3 += f"  • <b>{_h.escape(k)}:</b> <code>{_h.escape(str(v))}</code>\n"

    pages.append(p3)

    # ── PAGE 4: Raw EXIF/XMP (Expandable Spoiler Block) ────────────────────
    exif = analysis.get("exif", {})
    xmp = analysis.get("xmp", {})
    icc = analysis.get("icc_profile", {})

    p4 = f"📋 <b>TECHNICAL METADATA DETAIL</b>\n<code>{sep}</code>\n\n"
    raw_block = ""

    if icc:
        raw_block += "🎨 <b>ICC Profile Details:</b>\n"
        for k, v in icc.items():
            raw_block += f"  {k}: {v}\n"
        raw_block += "\n"

    if exif:
        raw_block += "📋 <b>EXIF Fields:</b>\n"
        for k, v in exif.items():
            if isinstance(v, bytes) or "thumbnail" in str(k).lower(): continue
            raw_block += f"  {k}: {str(v)[:80]}\n"
        raw_block += "\n"

    # Dynamic XMP namespacing output
    if xmp:
        raw_block += "🧬 <b>XMP Properties by Namespace:</b>\n"
        grouped_xmp = {}
        for k, v in xmp.items():
            prefix = k.split(":")[0] if ":" in k else "Additional XMP Properties"
            if prefix not in grouped_xmp: grouped_xmp[prefix] = []
            grouped_xmp[prefix].append((k.split(":")[-1], v))
            
        for ns, props in grouped_xmp.items():
            raw_block += f"  [{ns}]\n"
            for k, v in props[:15]:
                raw_block += f"    {k}: {str(v)[:85]}\n"
            if len(props) > 15:
                raw_block += f"    ... ({len(props) - 15} more properties)\n"
            raw_block += "\n"

    if raw_block:
        p4 += f"👁 <b>Tap/Click block to reveal raw metadata:</b>\n<tg-spoiler>{_h.escape(raw_block[:3500])}</tg-spoiler>"
        pages.append(p4)

    return pages
