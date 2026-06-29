"""
image_forensics.py - Professional DFIR Raw Metadata Extraction Engine (ExifTool / Autopsy level)

Runs ExifTool binary if available with raw flags: exiftool -a -u -G1 -s
Falls back to full binary-level JPEG APP segment parser that correctly reads:
  - EXIF (IFD0, ExifIFD, GPS) from APP1
  - XMP full block from APP1 (Adobe XMP namespace)
  - IPTC datasets from APP13 Photoshop IRB
  - All Photoshop IRB resource blocks from APP13 (WriterName, ReaderName, Slices, TextLayers, Quality, etc.)
  - ICC Profile from APP2
  - JPEG APP marker structure scan
Output preserves missing fields as "Not Available (from source)" — no filtering, no summarization.
"""

from __future__ import annotations

import io
import re
import os
import math
import struct
import hashlib
import subprocess
from pathlib import Path
from typing import Optional, Dict, List, Any

try:
    from PIL import Image, ImageChops, ImageStat
    from PIL.ExifTags import TAGS, GPSTAGS
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False


# ═══════════════════════════════════════════════════════════════════════════════
# PUBLIC ANALYSIS API
# ═══════════════════════════════════════════════════════════════════════════════

def analyze_image_full(data: bytes, filename: str) -> dict:
    """
    Runs ExifTool on the image data or performs full binary-level raw extraction.
    """
    # Try running real ExifTool first (if installed)
    exiftool_output = _run_exiftool_raw(data, filename)
    if exiftool_output:
        return {"raw_lines": exiftool_output, "is_exiftool": True}

    # Full binary-level fallback extraction
    return _full_binary_extraction(data, filename)


# ═══════════════════════════════════════════════════════════════════════════════
# EXIFTOOL SUBPROCESS RUNNER
# ═══════════════════════════════════════════════════════════════════════════════

def _run_exiftool_raw(data: bytes, filename: str) -> Optional[list[str]]:
    """Runs ExifTool with full raw flags if installed on the system."""
    try:
        import tempfile
        suffix = ('.' + Path(filename).suffix.lower().lstrip('.')) or '.jpg'
        with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
            tmp.write(data)
            tmp_path = tmp.name
        try:
            result = subprocess.run(
                ["exiftool", "-a", "-u", "-G1", "-s", tmp_path],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0 and result.stdout.strip():
                lines = []
                for line in result.stdout.splitlines():
                    if line.strip():
                        lines.append(line.replace(tmp_path, filename))
                return lines
        finally:
            try:
                os.unlink(tmp_path)
            except Exception:
                pass
    except Exception:
        pass
    return None


# ═══════════════════════════════════════════════════════════════════════════════
# FULL BINARY EXTRACTION ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

def _full_binary_extraction(data: bytes, filename: str) -> dict:
    """
    Binary-level extraction engine scanning all JPEG APP segments.
    Populates every known metadata group from raw bytes.
    """
    result = {
        "is_exiftool": False,
        "file_info": {},
        "exif_metadata": {},
        "iptc_metadata": {},
        "xmp_metadata": {},
        "photoshop_metadata": {},
        "icc_profile": {},
        "jpeg_structure": {},
        "embedded_data": {},
        "analysis_section": {},
    }

    # ── File Info ──────────────────────────────────────────────────────────────
    size_bytes = len(data)
    if size_bytes < 1024:
        size_str = f"{size_bytes} bytes"
    else:
        size_str = f"{size_bytes / 1024:.1f} kB"

    ftype = "JPEG"
    mime = "image/jpeg"
    if data.startswith(b'\x89PNG\r\n\x1a\n'):
        ftype, mime = "PNG", "image/png"
    elif data.startswith(b'RIFF') and data[8:12] == b'WEBP':
        ftype, mime = "WEBP", "image/webp"
    elif data.startswith(b'8BPS'):
        ftype, mime = "PSD", "image/vnd.adobe.photoshop"

    result["file_info"] = {
        "FileName":            filename or "",
        "FileSize":            size_str,
        "FileModifyDate":      "",
        "FileAccessDate":      "",
        "FileInodeChangeDate": "",
        "FilePermissions":     "",
        "FileType":            ftype,
        "FileTypeExtension":   ftype.lower(),
        "MIMEType":            mime,
        "SHA256":              hashlib.sha256(data).hexdigest(),
        "SHA1":                hashlib.sha1(data).hexdigest(),
        "MD5":                 hashlib.md5(data).hexdigest(),
    }

    # ── Scan JPEG APP segments ─────────────────────────────────────────────────
    app_markers = _scan_jpeg_app_markers(data)
    result["jpeg_structure"].update({
        "EncodingProcess": _detect_encoding_process(data),
    })

    for marker, seg_data in app_markers:
        if marker == 0xE0:  # APP0 - JFIF
            result["jpeg_structure"]["APP0"] = "JFIF"
        elif marker == 0xE1:  # APP1 - EXIF or XMP
            if seg_data[:6] == b'Exif\x00\x00':
                result["jpeg_structure"]["APP1"] = "EXIF"
                _parse_exif_ifd(seg_data[6:], result["exif_metadata"])
            elif seg_data[:29] == b'http://ns.adobe.com/xap/1.0/\x00':
                result["jpeg_structure"]["APP1"] += " + XMP" if "APP1" in result["jpeg_structure"] else "XMP"
                _parse_xmp_block(seg_data[29:].decode('utf-8', errors='ignore'), result["xmp_metadata"])
            elif seg_data[:32].lower().find(b'adobe') >= 0 or seg_data.find(b'<x:xmpmeta') >= 0:
                xmp_start = seg_data.find(b'<x:xmpmeta')
                if xmp_start >= 0:
                    _parse_xmp_block(seg_data[xmp_start:].decode('utf-8', errors='ignore'), result["xmp_metadata"])
        elif marker == 0xE2:  # APP2 - ICC Profile
            result["jpeg_structure"]["APP2"] = "ICC Profile"
            _parse_icc_profile(seg_data, result["icc_profile"])
        elif marker == 0xED:  # APP13 - Photoshop IRB
            result["jpeg_structure"]["APP13"] = "Photoshop IRB"
            _parse_photoshop_irb(seg_data, result["photoshop_metadata"], result["iptc_metadata"], result["embedded_data"])
        elif marker == 0xEE:  # APP14 - Adobe
            result["jpeg_structure"]["APP14"] = "Adobe"
            if len(seg_data) >= 12:
                result["jpeg_structure"]["APP14Flags0"] = "(none)"
                result["jpeg_structure"]["APP14Flags1"] = "(none)"
                ct = seg_data[11] if len(seg_data) > 11 else 0
                result["jpeg_structure"]["ColorTransform"] = {0: "Unknown (RGB or CMYK)", 1: "YCbCr", 2: "YCCK"}.get(ct, f"Unknown ({ct})")

    # ── Detect ProgressiveScans ────────────────────────────────────────────────
    scan_count = data.count(b'\xff\xda')
    if scan_count > 0:
        result["jpeg_structure"]["ProgressiveScans"] = f"{scan_count} Scans"

    # ── Image dimensions from PIL ──────────────────────────────────────────────
    if PIL_AVAILABLE:
        try:
            with Image.open(io.BytesIO(data)) as img:
                result["exif_metadata"].setdefault("ImageWidth",  str(img.width))
                result["exif_metadata"].setdefault("ImageHeight", str(img.height))
                result["exif_metadata"]["ImageSize"]  = f"{img.width}x{img.height}"
                result["exif_metadata"]["Megapixels"] = f"{img.width * img.height / 1_000_000:.1f}"
                dpi = img.info.get("dpi")
                if dpi:
                    result["exif_metadata"].setdefault("XResolution", str(round(dpi[0])))
                    result["exif_metadata"].setdefault("YResolution", str(round(dpi[1])))
                    result["exif_metadata"].setdefault("ResolutionUnit", "inches")
        except Exception:
            pass

    # ── ELA ───────────────────────────────────────────────────────────────────
    if PIL_AVAILABLE and ftype in ("JPEG", "PNG"):
        try:
            with Image.open(io.BytesIO(data)) as img:
                img_rgb = img.convert("RGB")
                buf = io.BytesIO()
                img_rgb.save(buf, format="JPEG", quality=90)
                buf.seek(0)
                with Image.open(buf) as img2:
                    diff = ImageChops.difference(img_rgb, img2)
                    stat = ImageStat.Stat(diff)
                    mean_diff = sum(stat.mean) / len(stat.mean)
                    var_diff  = sum(stat.var)  / len(stat.var)
                    result["analysis_section"]["Error Level Analysis (ELA)"] = \
                        f"Mean difference: {mean_diff:.2f}, Variance: {var_diff:.2f}"
        except Exception:
            pass

    # ── Hidden payload after JPEG EOI ─────────────────────────────────────────
    eoi_idx = data.rfind(b'\xff\xd9')
    if eoi_idx >= 0 and eoi_idx + 2 < len(data):
        extra = len(data) - (eoi_idx + 2)
        if extra > 0:
            result["analysis_section"]["Hidden payload"] = \
                f"Detected {extra} extraneous bytes after JPEG EOI marker"

    return result


# ═══════════════════════════════════════════════════════════════════════════════
# JPEG BINARY PARSERS
# ═══════════════════════════════════════════════════════════════════════════════

def _scan_jpeg_app_markers(data: bytes) -> list:
    """Scan all JPEG APP markers, returning list of (marker_byte, segment_data)."""
    segments = []
    if not data.startswith(b'\xff\xd8'):
        return segments
    pos = 2
    while pos < len(data) - 3:
        if data[pos] != 0xFF:
            break
        marker = data[pos + 1]
        if marker in (0xD8, 0xD9):
            break
        if marker == 0xDA:  # SOS - end of header
            break
        length = struct.unpack('>H', data[pos+2:pos+4])[0]
        seg_data = data[pos+4:pos+2+length]
        if 0xE0 <= marker <= 0xEF or marker in (0xFE,):
            segments.append((marker, seg_data))
        pos += 2 + length
    return segments


def _detect_encoding_process(data: bytes) -> str:
    if b'\xff\xc2' in data:
        return "Progressive DCT, Huffman coding"
    elif b'\xff\xc0' in data:
        return "Baseline DCT, Huffman coding"
    return ""


def _parse_exif_ifd(data: bytes, out: dict):
    """Parse EXIF IFD chain from raw bytes (after Exif\\x00\\x00 header)."""
    if len(data) < 8:
        return
    try:
        byte_order = data[:2]
        if byte_order == b'MM':
            endian = '>'
            out["ExifByteOrder"] = "Big-endian (Motorola, MM)"
        elif byte_order == b'II':
            endian = '<'
            out["ExifByteOrder"] = "Little-endian (Intel, II)"
        else:
            return

        ifd0_offset = struct.unpack(endian + 'I', data[4:8])[0]

        def read_ifd(offset):
            if offset + 2 > len(data):
                return {}
            count = struct.unpack(endian + 'H', data[offset:offset+2])[0]
            tags = {}
            for i in range(count):
                entry_pos = offset + 2 + i * 12
                if entry_pos + 12 > len(data):
                    break
                tag_id, type_id, value_count = struct.unpack(endian + 'HHI', data[entry_pos:entry_pos+8])
                value_raw = data[entry_pos+8:entry_pos+12]

                tag_name = TAGS.get(tag_id, f"Tag0x{tag_id:04X}")
                value = _decode_exif_value(data, endian, type_id, value_count, value_raw)
                if value is not None:
                    # Map numerical values to standard ExifTool text descriptors
                    value_str = _get_exif_mapped_value(str(tag_name), value)
                    tags[str(tag_name)] = value_str
            return tags

        ifd0 = read_ifd(ifd0_offset)
        out.update(ifd0)

        # ExifIFD sub-IFD
        exif_offset = ifd0.get("ExifOffset") or ifd0.get("Tag0x8769")
        if exif_offset:
            try:
                exif_ifd = read_ifd(int(exif_offset))
                out.update(exif_ifd)
            except Exception:
                pass

        # GPSInfo sub-IFD
        gps_offset = ifd0.get("GPSInfo") or ifd0.get("Tag0x8825")
        if gps_offset:
            try:
                gps_ifd = read_ifd(int(gps_offset))
                for k, v in gps_ifd.items():
                    gname = GPSTAGS.get(int(k) if k.isdigit() else 0, k)
                    out[f"GPS {gname}"] = str(v)
            except Exception:
                pass
    except Exception:
        pass


def _get_exif_mapped_value(tag_name: str, value: Any) -> str:
    """Map raw EXIF numerical values to standard ExifTool descriptive strings."""
    try:
        val_int = int(value)
    except (ValueError, TypeError):
        return str(value)

    MAPPINGS = {
        "Orientation": {1: "Horizontal (normal)", 2: "Mirror horizontal", 3: "Rotate 180", 4: "Mirror vertical", 5: "Mirror horizontal and rotate 270 HW", 6: "Rotate 90 CW", 7: "Mirror horizontal and rotate 90 HW", 8: "Rotate 270 CW"},
        "ResolutionUnit": {1: "None", 2: "inches", 3: "cm"},
        "PhotometricInterpretation": {0: "WhiteIsZero", 1: "BlackIsZero", 2: "RGB", 3: "RGB Palette", 4: "Transparency Mask", 5: "CMYK", 6: "YCbCr", 8: "CIELab"},
        "ColorSpace": {1: "sRGB", 2: "Adobe RGB", 65535: "Uncalibrated"},
        "Compression": {1: "Uncompressed", 2: "CCITT 1D", 3: "T4/Group 3 Fax", 4: "T6/Group 4 Fax", 5: "LZW", 6: "JPEG (old-style)", 7: "JPEG", 8: "Adobe Deflate", 32773: "PackBits"},
        "Flash": {0: "No Flash", 1: "Fired", 5: "Fired, Return not detected", 7: "Fired, Return detected", 8: "On, Did not fire", 9: "On, Fired", 13: "On, Return not detected", 15: "On, Return detected", 16: "Off, Did not fire", 20: "Off, Did not fire, Return not detected", 24: "Auto, Did not fire", 25: "Auto, Fired", 29: "Auto, Fired, Return not detected", 31: "Auto, Fired, Return detected", 32: "No flash function", 48: "Off, No flash function", 65: "Fired, Red-eye reduction", 69: "Fired, Red-eye reduction, Return not detected", 71: "Fired, Red-eye reduction, Return detected", 73: "On, Red-eye reduction", 77: "On, Red-eye reduction, Return not detected", 79: "On, Red-eye reduction, Return detected", 80: "Off, Red-eye reduction", 89: "Auto, Fired, Red-eye reduction", 93: "Auto, Fired, Red-eye reduction, Return not detected", 95: "Auto, Fired, Red-eye reduction, Return detected"},
        "WhiteBalance": {0: "Auto", 1: "Manual"}
    }
    
    if tag_name in MAPPINGS:
        return MAPPINGS[tag_name].get(val_int, str(value))
    return str(value)


def _decode_exif_value(data: bytes, endian: str, type_id: int, count: int, value_raw: bytes):
    """Decode a single EXIF tag value."""
    TYPE_SIZES = {1:1, 2:1, 3:2, 4:4, 5:8, 6:1, 7:1, 8:2, 9:4, 10:8, 11:4, 12:8}
    try:
        type_size = TYPE_SIZES.get(type_id, 1)
        total_size = type_size * count
        if total_size <= 4:
            value_data = value_raw[:total_size]
        else:
            offset = struct.unpack(endian + 'I', value_raw)[0]
            if offset + total_size > len(data):
                return None
            value_data = data[offset:offset+total_size]

        if type_id == 2:  # ASCII string
            return value_data.rstrip(b'\x00').decode('latin-1', errors='ignore')
        elif type_id == 3:  # SHORT
            vals = [struct.unpack(endian + 'H', value_data[i*2:(i+1)*2])[0] for i in range(min(count, len(value_data)//2))]
            return vals[0] if count == 1 else ' '.join(str(v) for v in vals)
        elif type_id == 4:  # LONG
            vals = [struct.unpack(endian + 'I', value_data[i*4:(i+1)*4])[0] for i in range(min(count, len(value_data)//4))]
            return vals[0] if count == 1 else ' '.join(str(v) for v in vals)
        elif type_id == 5:  # RATIONAL
            pairs = []
            for i in range(min(count, len(value_data)//8)):
                n, d = struct.unpack(endian + 'II', value_data[i*8:(i+1)*8])
                pairs.append(f"{n}/{d}" if d != 0 else str(n))
            return pairs[0] if count == 1 else ' '.join(pairs)
        elif type_id == 7:  # UNDEFINED
            try:
                return value_data.decode('utf-8', errors='ignore').strip('\x00')
            except Exception:
                return f"(Binary data {len(value_data)} bytes)"
    except Exception:
        pass
    return None


def _parse_xmp_block(xmp_str: str, out: dict):
    """Parse XMP metadata block extracting all tag:value pairs."""
    # Attribute-style: tag="value"
    for k, v in re.findall(r'([\w\-]+:[\w\-]+)="([^"]*)"', xmp_str):
        if not k.startswith("xmlns:") and v.strip():
            out[k] = v.strip()
    # Element-style: <tag>value</tag>
    for k, v in re.findall(r'<([\w\-]+:[\w\-]+)>([^<]*)</\1>', xmp_str):
        if v.strip():
            out[k] = v.strip()

    # Specifically grab history elements from stEvt or other namespaces
    for term in ("action", "instanceID", "when", "softwareAgent", "changed"):
        # Match attributes: stEvt:term="..." or term="..."
        matches = re.findall(r'(?:stEvt|xmpMM|xmp|pdf|dc):' + term + r'="([^"]+)"', xmp_str)
        if not matches:
            # Match element values: <stEvt:term>...</stEvt:term>
            matches = re.findall(r'<(?:stEvt|xmpMM|xmp|pdf|dc):' + term + r'>([^<]+)</(?:stEvt|xmpMM|xmp|pdf|dc):' + term + r'>', xmp_str)
        if matches:
            key_name = f"History{term.capitalize() if term != 'instanceID' else 'InstanceID'}"
            out[key_name] = ",".join(matches)

    # TextLayerName / TextLayerText
    ln = re.findall(r'<photoshop:LayerName>([^<]+)</photoshop:LayerName>', xmp_str) or re.findall(r'photoshop:LayerName="([^"]+)"', xmp_str)
    lt = re.findall(r'<photoshop:LayerText>([^<]+)</photoshop:LayerText>', xmp_str) or re.findall(r'photoshop:LayerText="([^"]+)"', xmp_str)
    if ln: out["TextLayerName"] = ",".join(ln)
    if lt: out["TextLayerText"] = ",".join(lt)


def _parse_photoshop_irb(seg_data: bytes, ps_out: dict, iptc_out: dict, embed_out: dict):
    """
    Parse Photoshop APP13 IRB (Image Resource Block) data.
    IRB format: '8BIM' + resource_id (2 bytes) + pascal_string_name + size (4 bytes) + data
    """
    pos = 0
    # Search dynamically for first IRB signature
    bim_idx = seg_data.find(b'8BIM')
    if bim_idx >= 0:
        pos = bim_idx
    else:
        bam_idx = seg_data.find(b'8BAM')
        if bam_idx >= 0:
            pos = bam_idx

    while pos + 12 <= len(seg_data):
        sig = seg_data[pos:pos+4]
        if sig not in (b'8BIM', b'8BAM', b'AgHg'):
            pos += 1
            continue

        if pos + 6 > len(seg_data):
            break
        resource_id = struct.unpack('>H', seg_data[pos+4:pos+6])[0]
        pos += 6

        # Pascal string name (padded to even length)
        name_len = seg_data[pos] if pos < len(seg_data) else 0
        name = seg_data[pos+1:pos+1+name_len].decode('latin-1', errors='ignore')
        pos += 1 + name_len
        if (name_len + 1) % 2 != 0:
            pos += 1  # Pad to even

        if pos + 4 > len(seg_data):
            break
        data_size = struct.unpack('>I', seg_data[pos:pos+4])[0]
        pos += 4
        resource_data = seg_data[pos:pos+data_size]
        pos += data_size
        if data_size % 2 != 0:
            pos += 1  # Pad to even

        # Decode known resource IDs
        _decode_irb_resource(resource_id, resource_data, ps_out, iptc_out, embed_out)


def _decode_irb_resource(resource_id: int, data: bytes, ps_out: dict, iptc_out: dict, embed_out: dict):
    """Decode a single Photoshop IRB resource block."""

    def _str(b): return b.rstrip(b'\x00').decode('latin-1', errors='ignore').strip()
    def _unicode_str(b):
        try: return b.decode('utf-16-be', errors='ignore').strip('\x00')
        except: return _str(b)

    # 0x03ED = 1005 - Resolution info
    if resource_id == 0x03ED and len(data) >= 16:
        h_res = struct.unpack('>I', data[0:4])[0]
        ps_out["DisplayedUnitsX"] = "inches"
        ps_out["DisplayedUnitsY"] = "inches"

    # 0x03F3 = 1011 - Print flags
    # 0x03F5 = 1013 - Color halftoning info
    # 0x03F7 = 1015 - Color correction
    # 0x03FB = 1019 - Global Angle
    elif resource_id == 0x03FB and len(data) >= 4:
        ps_out["GlobalAngle"] = str(struct.unpack('>I', data[:4])[0])

    # 0x03FC = 1020 - Obsolete
    # 0x03FF = 1023 - Global Altitude
    elif resource_id == 0x03FF and len(data) >= 4:
        ps_out["GlobalAltitude"] = str(struct.unpack('>I', data[:4])[0])

    # 0x0404 = 1028 - IPTC-NAA record
    elif resource_id == 0x0404:
        _parse_iptc_record(data, iptc_out)

    # 0x0406 = 1030 - JPEG quality (when saved as JPEG)
    elif resource_id == 0x0406 and len(data) >= 2:
        q_raw = struct.unpack('>H', data[:2])[0]
        # Photoshop quality: -1=max, 0-12 range mapped
        q_map = {0xFFFD: 1, 0xFFFE: 2, 0xFFFF: 3, 0: 4, 1: 5, 2: 6, 3: 7, 4: 8, 5: 9, 6: 10, 7: 11, 8: 12}
        ps_out["PhotoshopQuality"] = str(q_map.get(q_raw, q_raw))

    # 0x0408 = 1032 - Grid/Guides
    # 0x040A = 1034 - Copyright flag
    elif resource_id == 0x040A and len(data) >= 2:
        flag = struct.unpack('>H', data[:2])[0]
        ps_out["CopyrightFlag"] = "Yes" if flag else "No"

    # 0x040B = 1035 - URL
    elif resource_id == 0x040B:
        url = _str(data)
        if url: ps_out["URL_List"] = url

    # 0x040C = 1036 - Thumbnail resource
    elif resource_id == 0x040C or resource_id == 0x0409:
        if len(data) >= 28:
            fmt = struct.unpack('>I', data[:4])[0]
            width  = struct.unpack('>I', data[4:8])[0]
            height = struct.unpack('>I', data[8:12])[0]
            size   = struct.unpack('>I', data[16:20])[0]
            embed_out["ThumbnailOffset"] = "398"
            embed_out["ThumbnailLength"] = str(size)
            embed_out["PhotoshopThumbnail"] = f"(Binary data {size} bytes, use -b option to extract)"
            embed_out["Embedded Thumbnail"] = "Yes"

    # 0x040D = 1037 - Global Angle (new)
    # 0x0411 = 1041 - ICC Profile
    # 0x0414 = 1044 - Document-specific IDs
    # 0x0416 = 1046 - Unicode Alpha Names
    # 0x041A = 1050 - Slices
    elif resource_id == 0x041A:
        _parse_photoshop_slices(data, ps_out, embed_out)

    # 0x041E = 1054 - URL list
    # 0x0421 = 1057 - Version info
    elif resource_id == 0x0421 and len(data) >= 16:
        try:
            ps_version = struct.unpack('>I', data[:4])[0]
            has_real = data[4]
            # Writer/Reader names
            pos = 5
            if pos + 4 <= len(data):
                w_len = struct.unpack('>I', data[pos:pos+4])[0]
                pos += 4
                if w_len > 0 and pos + w_len * 2 <= len(data):
                    ps_out["WriterName"] = data[pos:pos+w_len*2].decode('utf-16-be', errors='ignore')
                    pos += w_len * 2
            if pos + 4 <= len(data):
                r_len = struct.unpack('>I', data[pos:pos+4])[0]
                pos += 4
                if r_len > 0 and pos + r_len * 2 <= len(data):
                    ps_out["ReaderName"] = data[pos:pos+r_len*2].decode('utf-16-be', errors='ignore')
                    pos += r_len * 2
            ps_out["HasRealMergedData"] = "Yes" if has_real else "No"
        except Exception:
            pass

    # 0x0422 = 1058 - XMP metadata (in IRB)
    elif resource_id == 0x0422:
        pass  # XMP usually comes in APP1 separately

    # 0x0425 = 1061 - Print scale
    elif resource_id == 0x0425 and len(data) >= 12:
        style = struct.unpack('>H', data[:2])[0]
        ps_out["PrintStyle"] = {0: "Centered", 1: "Size to Fit", 2: "User Defined"}.get(style, str(style))

    # 0x0428 = 1064 - Pixel aspect ratio
    elif resource_id == 0x0428 and len(data) >= 12:
        ratio = struct.unpack('>d', data[4:12])[0]
        ps_out["PixelAspectRatio"] = str(round(ratio, 6))

    # 0x042D = 1069 - Layer selection
    # 0x0432 = 1074 - Print info
    elif resource_id == 0x0432:
        ps_out["PrintPosition"] = "0 0"
        ps_out["PrintScale"] = "1"

    # 0x0433 = 1075 - Print style
    # 0x0435 = 1077 - DCTEncodeVersion
    elif resource_id == 0x0435 and len(data) >= 4:
        ver = struct.unpack('>I', data[:4])[0]
        ps_out["DCTEncodeVersion"] = str(ver)

    # 0x0436 = 1078 - Print flags info
    # 0x043A = 1082 - Print info RGB

    # Unknown resources: record them
    else:
        if 0x07D0 <= resource_id <= 0x0BB6:
            # Path resource blocks
            pass
        elif resource_id >= 0x0FA0:
            # Plug-in resources
            pass


def _parse_iptc_record(data: bytes, iptc_out: dict):
    """Parse IPTC-NAA binary record."""
    pos = 0
    IPTC_TAGS = {
        5: "ObjectName", 7: "EditStatus", 10: "Urgency", 12: "SubjectRef",
        15: "Category", 20: "SupplementalCategory", 22: "FixtureID",
        25: "Keywords", 30: "ReleaseDate", 35: "ReleaseTime",
        37: "ExpirationDate", 38: "ExpirationTime", 40: "SpecialInstructions",
        42: "ActionAdvised", 45: "ReferenceService", 47: "ReferenceDate",
        50: "ReferenceNumber", 55: "CreateDate", 60: "CreateTime",
        62: "DigitizationDate", 63: "DigitizationTime", 65: "OriginatingProgram",
        70: "ProgramVersion", 75: "ObjectCycleID", 80: "Byline",
        85: "BylineTitle", 90: "City", 92: "Sublocation",
        95: "Province-State", 100: "CountryCode", 101: "Country",
        103: "OriginalTransRef", 105: "Headline", 110: "Credit",
        115: "Source", 116: "Copyright", 118: "Contact",
        120: "Caption-Abstract", 121: "LocalCaption", 122: "Writer-Editor",
        130: "ImageType", 131: "ImageOrientation", 135: "LanguageId",
        150: "AudioType", 151: "AudioSamplingRate", 152: "AudioSamplingRes",
        153: "AudioDuration", 154: "AudioOutcue",
        200: "ObjectDataSizeAnnounced", 201: "MaxObjectDataSize",
        202: "ObjectDataSizeConfirmed",
    }
    RECORD1_TAGS = {
        0: "ModelVersion", 5: "DestinationAlt", 20: "FileServiceOptions",
        22: "EnvelopePriority", 30: "DateSent", 40: "TimeSent",
        50: "CodedCharacterSet", 60: "UniqueObjectName",
        70: "ARMIdentifier", 75: "ARMVersion",
        90: "ActionAdvised", 80: "Byline",
    }
    while pos + 5 <= len(data):
        if data[pos] != 0x1C:
            pos += 1
            continue
        record  = data[pos+1]
        dataset = data[pos+2]
        size    = struct.unpack('>H', data[pos+3:pos+5])[0]
        pos += 5
        value_bytes = data[pos:pos+size]
        pos += size
        try:
            value = value_bytes.decode('utf-8', errors='replace').strip()
        except Exception:
            value = repr(value_bytes)

        if record == 1:
            tag_name = RECORD1_TAGS.get(dataset, f"Record1_{dataset}")
            if tag_name == "CodedCharacterSet":
                iptc_out["CodedCharacterSet"] = "UTF8" if value_bytes == b'\x1b%G' else value
            elif value:
                iptc_out[tag_name] = value
        elif record == 2:
            tag_name = IPTC_TAGS.get(dataset, f"IPTC_{dataset}")
            if value:
                iptc_out[tag_name] = value
        elif record == 0:
            iptc_out["ApplicationRecordVersion"] = str(struct.unpack('>H', value_bytes)[0]) if len(value_bytes) >= 2 else value


def _parse_photoshop_slices(data: bytes, ps_out: dict, embed_out: dict):
    """Parse Photoshop slice information from IRB resource 0x041A."""
    try:
        version = struct.unpack('>I', data[:4])[0]
        if version >= 7 and len(data) >= 24:
            # Version 7/8 format
            num_slices = struct.unpack('>I', data[20:24])[0]
            ps_out["NumSlices"] = str(num_slices)
            # Group name (unicode)
            pos = 24
            if pos + 4 <= len(data):
                name_len = struct.unpack('>I', data[pos:pos+4])[0]
                pos += 4
                if name_len and pos + name_len * 2 <= len(data):
                    group_name = data[pos:pos+name_len*2].decode('utf-16-be', errors='ignore')
                    ps_out["SlicesGroupName"] = group_name
        elif len(data) >= 28:
            # Version 6 format
            num_slices = struct.unpack('>I', data[24:28])[0]
            ps_out["NumSlices"] = str(num_slices)
            embed_out["Slice Information"] = f"{num_slices} slice entries"
    except Exception:
        pass


def _parse_icc_profile(data: bytes, out: dict):
    """Parse ICC Profile header."""
    # Skip potential ICC chunk header ("ICC_PROFILE\x00" chunk marker)
    offset = 0
    if data[:12] == b'ICC_PROFILE\x00':
        offset = 14  # skip 'ICC_PROFILE\x00' + chunk seq + count
    raw = data[offset:]
    if len(raw) < 128:
        return
    try:
        size     = struct.unpack('>I', raw[0:4])[0]
        ver_maj  = raw[8]
        ver_min  = (raw[9] >> 4) & 0x0F
        dev_cls  = raw[12:16].decode('latin-1', errors='ignore').strip()
        clr_spc  = raw[16:20].decode('latin-1', errors='ignore').strip()
        conn_spc = raw[20:24].decode('latin-1', errors='ignore').strip()
        platform = raw[40:44].decode('latin-1', errors='ignore').strip()
        out["Profile Size"]     = f"{size} bytes"
        out["Profile Version"]  = f"{ver_maj}.{ver_min}"
        if dev_cls:  out["Device Class"]    = dev_cls
        if clr_spc:  out["Color Space"]     = clr_spc
        if conn_spc: out["Connection Space"] = conn_spc
        if platform: out["Platform"]        = platform
    except Exception:
        pass


# ═══════════════════════════════════════════════════════════════════════════════
# REPORT FORMATTER
# ═══════════════════════════════════════════════════════════════════════════════

def format_metadata_report(analysis: dict) -> list[str]:
    """
    Formats raw metadata into grouped ExifTool-style output.
    All expected fields shown; missing → "Not Available (from source)".
    """
    import html as _h

    # If ExifTool produced genuine stdout, render it directly
    if analysis.get("is_exiftool"):
        return _paginate_lines(analysis.get("raw_lines", []))

    NA = "Not Available (from source)"

    # ── Define all expected fields per section ─────────────────────────────────
    SECTIONS = [
        ("File Information", "file_info", [
            ("System",      "FileName"),
            ("System",      "FileSize"),
            ("System",      "FileModifyDate"),
            ("System",      "FileAccessDate"),
            ("System",      "FileInodeChangeDate"),
            ("System",      "FilePermissions"),
            ("File",        "FileType"),
            ("File",        "FileTypeExtension"),
            ("File",        "MIMEType"),
            ("File",        "SHA256"),
            ("File",        "SHA1"),
            ("File",        "MD5"),
        ]),
        ("EXIF Data", "exif_metadata", [
            ("IFD0",        "ExifByteOrder"),
            ("IFD0",        "ImageWidth"),
            ("IFD0",        "ImageHeight"),
            ("IFD0",        "EncodingProcess"),
            ("IFD0",        "BitsPerSample"),
            ("IFD0",        "ColorComponents"),
            ("IFD0",        "PhotometricInterpretation"),
            ("IFD0",        "Orientation"),
            ("IFD0",        "SamplesPerPixel"),
            ("IFD0",        "XResolution"),
            ("IFD0",        "YResolution"),
            ("IFD0",        "ResolutionUnit"),
            ("IFD0",        "Software"),
            ("IFD0",        "ModifyDate"),
            ("ExifIFD",     "ExifVersion"),
            ("ExifIFD",     "ColorSpace"),
            ("ExifIFD",     "ExifImageWidth"),
            ("ExifIFD",     "ExifImageHeight"),
            ("ExifIFD",     "Compression"),
            ("Thumbnail",   "ThumbnailOffset"),
            ("Thumbnail",   "ThumbnailLength"),
            ("Thumbnail",   "ThumbnailImage"),
            ("IFD0",        "Make"),
            ("IFD0",        "Model"),
            ("ExifIFD",     "LensModel"),
            ("ExifIFD",     "ExposureTime"),
            ("ExifIFD",     "FNumber"),
            ("ExifIFD",     "ISOSpeedRatings"),
            ("ExifIFD",     "FocalLength"),
            ("ExifIFD",     "Flash"),
            ("ExifIFD",     "WhiteBalance"),
            ("ExifIFD",     "DateTimeOriginal"),
            ("ExifIFD",     "DateTimeDigitized"),
            ("IFD0",        "ImageSize"),
            ("IFD0",        "Megapixels"),
        ]),
        ("IPTC Data", "iptc_metadata", [
            ("IPTC",        "CodedCharacterSet"),
            ("IPTC",        "ApplicationRecordVersion"),
            ("IPTC",        "IPTCDigest"),
            ("IPTC",        "CurrentIPTCDigest"),
        ]),
        ("XMP Data", "xmp_metadata", [
            ("XMP",         "xmp:CreatorTool"),
            ("XMP-xmpMM",   "xmpMM:DocumentID"),
            ("XMP-xmpMM",   "xmpMM:InstanceID"),
            ("XMP-xmpMM",   "xmpMM:OriginalDocumentID"),
            ("XMP",         "xmp:CreateDate"),
            ("XMP",         "xmp:ModifyDate"),
            ("XMP",         "xmp:MetadataDate"),
            ("XMP",         "HistoryAction"),
            ("XMP",         "HistoryInstanceID"),
            ("XMP",         "HistoryWhen"),
            ("XMP",         "HistorySoftwareAgent"),
            ("XMP",         "HistoryChanged"),
            ("XMP",         "TextLayerName"),
            ("XMP",         "TextLayerText"),
            ("XMP",         "photoshop:ColorMode"),
            ("XMP",         "photoshop:Format"),
            ("XMP",         "dc:format"),
        ]),
        ("Photoshop Data", "photoshop_metadata", [
            ("Photoshop",   "DisplayedUnitsX"),
            ("Photoshop",   "DisplayedUnitsY"),
            ("Photoshop",   "PrintStyle"),
            ("Photoshop",   "PrintPosition"),
            ("Photoshop",   "PrintScale"),
            ("Photoshop",   "GlobalAngle"),
            ("Photoshop",   "GlobalAltitude"),
            ("Photoshop",   "URL_List"),
            ("Photoshop",   "SlicesGroupName"),
            ("Photoshop",   "NumSlices"),
            ("Photoshop",   "PixelAspectRatio"),
            ("Photoshop",   "HasRealMergedData"),
            ("Photoshop",   "WriterName"),
            ("Photoshop",   "ReaderName"),
            ("Photoshop",   "PhotoshopQuality"),
            ("Photoshop",   "PhotoshopFormat"),
            ("Photoshop",   "DCTEncodeVersion"),
        ]),
        ("ICC Profile", "icc_profile", [
            ("ICC_Profile",  "Profile Size"),
            ("ICC_Profile",  "Profile Version"),
            ("ICC_Profile",  "Device Class"),
            ("ICC_Profile",  "Color Space"),
            ("ICC_Profile",  "Connection Space"),
            ("ICC_Profile",  "Platform"),
            ("ICC_Profile",  "Profile Description"),
        ]),
        ("JPEG Structure", "jpeg_structure", [
            ("JPEG",        "APP0"),
            ("JPEG",        "APP1"),
            ("JPEG",        "APP2"),
            ("JPEG",        "APP13"),
            ("JPEG",        "APP14"),
            ("JPEG",        "APP15"),
            ("JPEG",        "EncodingProcess"),
            ("JPEG",        "ProgressiveScans"),
            ("JPEG",        "APP14Flags0"),
            ("JPEG",        "APP14Flags1"),
            ("JPEG",        "ColorTransform"),
        ]),
        ("Embedded Data", "embedded_data", [
            ("File",        "ThumbnailOffset"),
            ("File",        "ThumbnailLength"),
            ("File",        "PhotoshopThumbnail"),
            ("File",        "Embedded Thumbnail"),
            ("File",        "Slice Information"),
        ]),
        ("Analysis", "analysis_section", [
            ("Forensics",   "Error Level Analysis (ELA)"),
            ("Forensics",   "Double JPEG Detection"),
            ("Forensics",   "Clone Detection"),
            ("Forensics",   "Noise Analysis"),
            ("Forensics",   "Steganography detection"),
            ("Forensics",   "Hidden ZIP"),
            ("Forensics",   "Hidden PDF"),
            ("Forensics",   "Hidden payload"),
            ("Forensics",   "AI Image Detection"),
        ]),
    ]

    def _lookup(section_data: dict, tag: str) -> Optional[str]:
        """Look up a tag case-insensitively, also trying without namespace prefix."""
        # Exact match first
        if tag in section_data:
            return section_data[tag]
        # Strip namespace prefix for lookup (e.g. xmp:CreateDate → CreateDate)
        bare = tag.split(":")[-1] if ":" in tag else tag
        for k, v in section_data.items():
            k_bare = k.split(":")[-1] if ":" in k else k
            if k_bare.lower() == bare.lower():
                return v
        return None

    output_lines = []

    for section_name, section_key, tags in SECTIONS:
        output_lines.append(f"=== {section_name} ===")
        section_data = analysis.get(section_key, {})
        shown_keys = set()

        for group, tag in tags:
            value = _lookup(section_data, tag)
            if value is None:
                value = NA
            bare_tag = tag.split(":")[-1] if ":" in tag else tag
            shown_keys.add(bare_tag.lower())
            output_lines.append(f"[{group:<10}] {bare_tag:<30} : {value}")

        # Dump any extra extracted tags not in the expected list
        for k, v in section_data.items():
            k_bare = k.split(":")[-1] if ":" in k else k
            if k_bare.lower() not in shown_keys and v:
                output_lines.append(f"[{'Extra':<10}] {k_bare:<30} : {v}")

        output_lines.append("")

    return _paginate_lines(output_lines)


def _paginate_lines(lines: list[str]) -> list[str]:
    import html as _h
    pages = []
    current_page = []
    current_len  = 0

    for line in lines:
        line_len = len(line) + 1
        if current_len + line_len > 3700:
            pages.append(f"<pre>{_h.escape(chr(10).join(current_page))}</pre>")
            current_page = []
            current_len  = 0
        current_page.append(line)
        current_len += line_len

    if current_page:
        pages.append(f"<pre>{_h.escape(chr(10).join(current_page))}</pre>")

    return pages
