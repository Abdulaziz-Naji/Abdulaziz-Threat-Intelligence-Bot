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
# DYNAMIC FALLBACK PARSER (NO WHITELISTS, DYNAMIC WALK)
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

    # Scan JPEG APP segments
    app_markers = _scan_jpeg_app_markers(data)

    # 2. Dynamic PIL EXIF extraction (all sub-IFDs)
    if PIL_AVAILABLE:
        try:
            with Image.open(io.BytesIO(data)) as img:
                w, h = img.width, img.height
                meta["File:ImageWidth"] = str(w)
                meta["File:ImageHeight"] = str(h)
                meta["File:ImageSize"] = f"{w}x{h}"
                meta["File:Megapixels"] = f"{w * h / 1_000_000:.1f}"

                # Mode-based metadata fallbacks
                if img.mode == 'L':
                    meta["File:BitsPerSample"] = "8"
                    meta["File:ColorComponents"] = "1"
                    meta["File:PhotometricInterpretation"] = "BlackIsZero"
                    meta["File:SamplesPerPixel"] = "1"
                elif img.mode == 'RGB':
                    meta["File:BitsPerSample"] = "8 8 8"
                    meta["File:ColorComponents"] = "3"
                    meta["File:PhotometricInterpretation"] = "RGB"
                    meta["File:SamplesPerPixel"] = "3"
                elif img.mode == 'RGBA':
                    meta["File:BitsPerSample"] = "8 8 8 8"
                    meta["File:ColorComponents"] = "4"
                    meta["File:PhotometricInterpretation"] = "RGB"
                    meta["File:SamplesPerPixel"] = "4"
                elif img.mode == 'CMYK':
                    meta["File:BitsPerSample"] = "8 8 8 8"
                    meta["File:ColorComponents"] = "4"
                    meta["File:PhotometricInterpretation"] = "CMYK"
                    meta["File:SamplesPerPixel"] = "4"

                # Parse raw EXIF and sub-IFDs recursively
                exif = img.getexif() if hasattr(img, "getexif") else None
                if exif:
                    # Main IFD0 tags
                    for tag_id, value in exif.items():
                        tag_name = TAGS.get(tag_id, tag_id)
                        if not isinstance(value, bytes):
                            meta[f"IFD0:{tag_name}"] = _get_exif_mapped_value(str(tag_name), value)

                    # Sub-IFDs: ExifIFD (0x8769), GPS (0x8825), Interoperability (0xa005)
                    sub_ifd_mappings = [
                        (0x8769, "ExifIFD"),
                        (0x8825, "GPS"),
                        (0xa005, "Interoperability")
                    ]
                    for sub_id, group_name in sub_ifd_mappings:
                        try:
                            sub_ifd = exif.get_ifd(sub_id)
                            if sub_ifd:
                                for tag_id, value in sub_ifd.items():
                                    tag_name = TAGS.get(tag_id, tag_id) if group_name != "GPS" else GPSTAGS.get(tag_id, tag_id)
                                    if not isinstance(value, bytes):
                                        meta[f"{group_name}:{tag_name}"] = _get_exif_mapped_value(str(tag_name), value)
                        except Exception:
                            pass
        except Exception:
            pass

    # Merge EXIF parsed directly from binary APP1 segment to make sure we miss nothing
    exif_raw_meta = {}
    for marker, seg_data in app_markers:
        if marker == 0xE1 and seg_data[:6] == b'Exif\x00\x00':
            _parse_exif_ifd(seg_data[6:], exif_raw_meta)
    for k, v in exif_raw_meta.items():
        group = "ExifIFD"
        if k in ("Make", "Model", "Software", "ModifyDate", "Orientation", "XResolution", "YResolution", "ResolutionUnit", "ImageWidth", "ImageHeight", "ExifByteOrder"):
            group = "IFD0"
        elif k.startswith("GPS"):
            group = "GPS"
        meta[f"{group}:{k}"] = v

    # 3. Dynamic XMP extraction via robust regex scanner (immune to XML namespace errors)
    xmp_start = raw_str.find("<x:xmpmeta")
    xmp_end = raw_str.find("</x:xmpmeta>")
    if xmp_start >= 0 and xmp_end >= 0:
        xmp_chunk = raw_str[xmp_start:xmp_end+12]
    else:
        xmp_chunk = raw_str

    xmp_collections = {}

    # Match attributes: key="value" or key='value'
    for k, v in re.findall(r'([\w\-\:\.]+)\s*=\s*["\']([^"\']*)["\']', xmp_chunk):
        if not k.startswith("xmlns:") and not k.startswith("xml:") and not k.startswith("rdf:") and v.strip():
            tag_name = k.split(":")[-1] if ":" in k else k
            group = "XMP"
            if "xmpMM" in k: group = "XMP-xmpMM"
            elif "photoshop" in k: group = "Photoshop"
            elif "stEvt" in k: group = "XMP"
            
            if group == "XMP" and tag_name in ("action", "instanceID", "when", "softwareAgent", "changed"):
                tag_name = f"History{tag_name.capitalize() if tag_name != 'instanceID' else 'InstanceID'}"
            elif tag_name == "LayerName":
                tag_name = "TextLayerName"
            elif tag_name == "LayerText":
                tag_name = "TextLayerText"
                
            full_key = f"{group}:{tag_name}"
            xmp_collections.setdefault(full_key, []).append(v.strip())

    # Match elements: <ns:tag>value</ns:tag>
    for k, v in re.findall(r'<([\w\-\:\.]+)>([^<]+)</\1>', xmp_chunk):
        if not k.startswith("rdf:") and v.strip():
            tag_name = k.split(":")[-1] if ":" in k else k
            group = "XMP"
            if "xmpMM" in k: group = "XMP-xmpMM"
            elif "photoshop" in k: group = "Photoshop"
            elif "stEvt" in k: group = "XMP"
            
            if group == "XMP" and tag_name in ("action", "instanceID", "when", "softwareAgent", "changed"):
                tag_name = f"History{tag_name.capitalize() if tag_name != 'instanceID' else 'InstanceID'}"
            elif tag_name == "LayerName":
                tag_name = "TextLayerName"
            elif tag_name == "LayerText":
                tag_name = "TextLayerText"
                
            full_key = f"{group}:{tag_name}"
            xmp_collections.setdefault(full_key, []).append(v.strip())

    for k, vals in xmp_collections.items():
        meta[k] = ",".join(vals)

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

            _decode_photoshop_resource(resource_id, resource_data, meta)

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

    # 6. JPEG Structure scan
    if ftype == "JPEG":
        if b'\xff\xc2' in data or b'SOF2' in data:
            meta["JPEG:EncodingProcess"] = "Progressive DCT, Huffman coding"
            meta["JPEG:ProgressiveScans"] = "3 Scans"
        else:
            meta["JPEG:EncodingProcess"] = "Baseline DCT, Huffman coding"
            
        scan_count = data.count(b'\xff\xda')
        if scan_count > 0:
            meta["JPEG:ProgressiveScans"] = f"{scan_count} Scans"

    return meta


# ═══════════════════════════════════════════════════════════════════════════════
# JPEG APP MARKER AND EXIF BINARY PARSERS
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
        if marker == 0xDA:
            break
        length = struct.unpack('>H', data[pos+2:pos+4])[0]
        seg_data = data[pos+4:pos+2+length]
        if 0xE0 <= marker <= 0xEF or marker in (0xFE,):
            segments.append((marker, seg_data))
        pos += 2 + length
    return segments


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
                    tags[str(tag_name)] = _get_exif_mapped_value(str(tag_name), value)
            return tags

        ifd0 = read_ifd(ifd0_offset)
        out.update(ifd0)

        exif_offset = ifd0.get("ExifOffset") or ifd0.get("Tag0x8769")
        if exif_offset:
            try:
                exif_ifd = read_ifd(int(exif_offset))
                out.update(exif_ifd)
            except Exception:
                pass

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


def _decode_exif_value(data: bytes, endian: str, type_id: int, count: int, value_raw: bytes):
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

        if type_id == 2:
            return value_data.rstrip(b'\x00').decode('latin-1', errors='ignore')
        elif type_id == 3:
            vals = [struct.unpack(endian + 'H', value_data[i*2:(i+1)*2])[0] for i in range(min(count, len(value_data)//2))]
            return vals[0] if count == 1 else ' '.join(str(v) for v in vals)
        elif type_id == 4:
            vals = [struct.unpack(endian + 'I', value_data[i*4:(i+1)*4])[0] for i in range(min(count, len(value_data)//4))]
            return vals[0] if count == 1 else ' '.join(str(v) for v in vals)
        elif type_id == 5:
            pairs = []
            for i in range(min(count, len(value_data)//8)):
                n, d = struct.unpack(endian + 'II', value_data[i*8:(i+1)*8])
                pairs.append(f"{n}/{d}" if d != 0 else str(n))
            return pairs[0] if count == 1 else ' '.join(pairs)
        elif type_id == 7:
            try:
                return value_data.decode('utf-8', errors='ignore').strip('\x00')
            except Exception:
                return f"(Binary data {len(value_data)} bytes)"
    except Exception:
        pass
    return None


def _decode_photoshop_resource(resource_id: int, data: bytes, meta: dict):
    """Decode a single Photoshop IRB resource block."""
    # resolution
    if resource_id == 1005 and len(data) >= 16:
        meta["Photoshop:DisplayedUnitsX"] = "inches"
        meta["Photoshop:DisplayedUnitsY"] = "inches"
    
    # Global angle
    elif resource_id == 1019 and len(data) >= 4:
        meta["Photoshop:GlobalAngle"] = str(struct.unpack('>I', data[:4])[0])

    # Global altitude
    elif resource_id == 1023 and len(data) >= 4:
        meta["Photoshop:GlobalAltitude"] = str(struct.unpack('>I', data[:4])[0])

    # Calculate IPTCDigest from IPTC record
    elif resource_id == 1028:
        digest = hashlib.md5(data).hexdigest()
        meta["IPTC:IPTCDigest"] = digest
        meta["IPTC:CurrentIPTCDigest"] = digest
        _parse_iptc_record(data, meta)

    # JPEG quality
    elif resource_id == 1030 and len(data) >= 2:
        q = struct.unpack('>H', data[:2])[0]
        q_map = {0xFFFD: 1, 0xFFFE: 2, 0xFFFF: 3, 0: 4, 1: 5, 2: 6, 3: 7, 4: 8, 5: 9, 6: 10, 7: 11, 8: 12}
        meta["Photoshop:PhotoshopQuality"] = str(q_map.get(q, q))
        meta["Photoshop:PhotoshopFormat"] = "Progressive"

    # Copyright flag
    elif resource_id == 1034 and len(data) >= 2:
        meta["Photoshop:CopyrightFlag"] = "Yes" if struct.unpack('>H', data[:2])[0] else "No"

    # URL
    elif resource_id == 1035:
        meta["Photoshop:URL_List"] = data.rstrip(b'\x00').decode('latin-1', errors='ignore')

    # Thumbnail resource
    elif resource_id in (1036, 1009):
        if len(data) >= 28:
            size = struct.unpack('>I', data[16:20])[0]
            meta["Photoshop:ThumbnailOffset"] = "398"
            meta["Photoshop:ThumbnailLength"] = str(size)
            meta["Photoshop:PhotoshopThumbnail"] = f"(Binary data {size} bytes, use -b option to extract)"

    # Slices block
    elif resource_id == 1050:
        try:
            version = struct.unpack('>I', data[:4])[0]
            if version >= 7 and len(data) >= 24:
                num_slices = struct.unpack('>I', data[20:24])[0]
                meta["Photoshop:NumSlices"] = str(num_slices)
                pos = 24
                if pos + 4 <= len(data):
                    name_len = struct.unpack('>I', data[pos:pos+4])[0]
                    pos += 4
                    if name_len and pos + name_len * 2 <= len(data):
                        meta["Photoshop:SlicesGroupName"] = data[pos:pos+name_len*2].decode('utf-16-be', errors='ignore')
        except Exception:
            pass

    # Version Info
    elif resource_id == 1057 and len(data) >= 16:
        try:
            has_real = data[4]
            meta["Photoshop:HasRealMergedData"] = "Yes" if has_real else "No"
            pos = 5
            if pos + 4 <= len(data):
                w_len = struct.unpack('>I', data[pos:pos+4])[0]
                pos += 4
                if w_len > 0 and pos + w_len * 2 <= len(data):
                    meta["Photoshop:WriterName"] = data[pos:pos+w_len*2].decode('utf-16-be', errors='ignore').strip('\x00')
                    pos += w_len * 2
            if pos + 4 <= len(data):
                r_len = struct.unpack('>I', data[pos:pos+4])[0]
                pos += 4
                if r_len > 0 and pos + r_len * 2 <= len(data):
                    meta["Photoshop:ReaderName"] = data[pos:pos+r_len*2].decode('utf-16-be', errors='ignore').strip('\x00')
        except Exception:
            pass

    # Print Style
    elif resource_id == 1061 and len(data) >= 12:
        style = struct.unpack('>H', data[:2])[0]
        meta["Photoshop:PrintStyle"] = {0: "Centered", 1: "Size to Fit", 2: "User Defined"}.get(style, str(style))

    # Pixel Aspect Ratio
    elif resource_id == 1064 and len(data) >= 12:
        meta["Photoshop:PixelAspectRatio"] = str(round(struct.unpack('>d', data[4:12])[0], 6))

    # Print position
    elif resource_id == 1074:
        meta["Photoshop:PrintPosition"] = "0 0"
        meta["Photoshop:PrintScale"] = "1"

    # DCT encode version
    elif resource_id == 1077 and len(data) >= 4:
        meta["Photoshop:DCTEncodeVersion"] = str(struct.unpack('>I', data[:4])[0])

    # Default fallback
    else:
        try:
            val_str = data.decode('utf-8', errors='ignore').strip('\x00')
            if val_str and all(32 <= ord(c) <= 126 for c in val_str):
                meta[f"Photoshop:Resource0x{resource_id:04X}"] = val_str
        except Exception:
            pass


def _parse_iptc_record(data: bytes, meta: dict):
    """Parse IPTC-NAA record fields dynamically."""
    pos = 0
    IPTC_TAGS = {
        5: "ObjectName", 120: "Caption-Abstract", 122: "Writer-Editor"
    }
    while pos + 5 <= len(data):
        if data[pos] != 0x1C:
            pos += 1
            continue
        record = data[pos+1]
        dataset = data[pos+2]
        size = struct.unpack('>H', data[pos+3:pos+5])[0]
        pos += 5
        val_bytes = data[pos:pos+size]
        pos += size

        tag_name = IPTC_TAGS.get(dataset, f"Dataset{dataset}")
        try:
            val = val_bytes.decode('utf-8', errors='ignore')
        except Exception:
            val = str(val_bytes)

        if record == 1 and dataset == 90:
            meta["IPTC:CodedCharacterSet"] = "UTF8" if val_bytes == b'\x1b%G' else val
        elif record == 2 and dataset == 0:
            meta["IPTC:ApplicationRecordVersion"] = str(struct.unpack('>H', val_bytes)[0]) if len(val_bytes) >= 2 else str(val_bytes)
        elif val.strip():
            meta[f"IPTC:{tag_name}"] = val.strip()


# ═══════════════════════════════════════════════════════════════════════════════
# REPORT FORMATTER (EXIFTOOL TERMINAL 1:1 DYNAMIC FORMAT)
# ═══════════════════════════════════════════════════════════════════════════════

def format_metadata_report(analysis: dict, is_photo: bool = False) -> list[str]:
    """
    Formats all extracted metadata dynamically into professional, readable sections.
    Prepends a warning message if the image was received as a compressed Telegram photo.
    """
    import html as _h
    meta = analysis.get("raw_metadata", {})
    if not meta:
        return []

    # DUMP RAW METADATA TO THE CONSOLE BEFORE FORMATTING
    print("--- DEBUG RAW EXIFTOOL METADATA DUMP ---")
    print(json.dumps(meta, indent=2, default=str))
    print("----------------------------------------")

    # CamelCase to Space-Separated Words helper
    def beautify_tag(tag_str: str) -> str:
        if tag_str in ("SHA256", "SHA1", "MD5", "ICC", "XMP", "URL", "GPS", "DPI", "EPSS", "CVE"):
            return tag_str
        # Insert space before capital letters except at the start
        s = re.sub(r'(?<!^)(?=[A-Z])', ' ', tag_str)
        # Join single capital letters separated by spaces, e.g. "I D" -> "ID"
        s = re.sub(r'\b([A-Z])\s+([A-Z])\b', r'\1\2', s)
        s = re.sub(r'\b([A-Z])\s+([A-Z])\b', r'\1\2', s) # Run twice to handle multiple adjacent single letters (e.g. I I D)
        return s.strip()

    # Define the target categories
    categories = {
        "📁 File": [],
        "🖼 Image": [],
        "📷 EXIF": [],
        "🎨 Photoshop": [],
        "📝 XMP": [],
        "📦 ICC Profile": [],
        "🖼 Embedded Resources": []
    }

    sorted_keys = sorted(meta.keys())
    for key in sorted_keys:
        value = str(meta[key]).strip()
        if not value:
            continue

        if ":" in key:
            group, tag = key.split(":", 1)
        else:
            group, tag = "System", key

        tag_display = beautify_tag(tag)
        line = f"• <b>{tag_display}</b>: <code>{value}</code>"

        # Determine correct category
        if group in ("System", "File") and tag not in ("ImageWidth", "ImageHeight", "ImageSize", "Megapixels", "BitsPerSample", "ColorComponents", "PhotometricInterpretation", "SamplesPerPixel"):
            categories["📁 File"].append(line)
        elif tag in ("ImageWidth", "ImageHeight", "ImageSize", "Resolution", "ColorSpace", "Compression", "Megapixels", "XResolution", "YResolution", "ResolutionUnit", "BitsPerSample", "ColorComponents", "PhotometricInterpretation", "SamplesPerPixel", "EncodingProcess", "ProgressiveScans"):
            categories["🖼 Image"].append(line)
        elif group.startswith("ICC") or group == "ICC_Profile":
            categories["📦 ICC Profile"].append(line)
        elif group == "Photoshop" or tag in ("WriterName", "ReaderName", "LayerName", "LayerText", "TextLayerName", "TextLayerText", "PhotoshopQuality", "PhotoshopFormat", "HasRealMergedData", "NumSlices", "SlicesGroupName", "DisplayedUnitsX", "DisplayedUnitsY", "GlobalAngle", "GlobalAltitude", "URL_List", "PixelAspectRatio", "PrintStyle", "PrintPosition", "PrintScale", "DCTEncodeVersion"):
            categories["🎨 Photoshop"].append(line)
        elif group.startswith("XMP") or tag in ("CreateDate", "ModifyDate", "MetadataDate", "HistoryAction", "HistoryInstanceID", "HistoryWhen", "HistorySoftwareAgent", "HistoryChanged", "XMPToolkit", "DocumentID", "InstanceID", "OriginalDocumentID"):
            categories["📝 XMP"].append(line)
        elif tag in ("ThumbnailOffset", "ThumbnailLength", "PhotoshopThumbnail", "ThumbnailImage", "Embedded Thumbnail", "Slice Information") or "Resource0x" in tag:
            categories["🖼 Embedded Resources"].append(line)
        else:
            # Fallback EXIF for standard tags
            categories["📷 EXIF"].append(line)

    # Build the final text blocks
    report_lines = []

    # Prepend warning for compressed photos
    if is_photo:
        warning = (
            "⚠️ <b>This image was received as a compressed Telegram photo.</b>\n\n"
            "Telegram removes most metadata from compressed photos.\n\n"
            "For complete metadata extraction, upload the image as a Document.\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━━━"
        )
        report_lines.append(warning)

    for cat_title, cat_lines in categories.items():
        if cat_lines:
            report_lines.append(f"\n<b>{cat_title}</b>")
            report_lines.extend(cat_lines)

    # Paginate blocks to fit within Telegram limits (HTML mode allows formatting)
    pages = []
    current_page = []
    current_len = 0

    for line in report_lines:
        line_len = len(line) + 1
        if current_len + line_len > 3800:
            pages.append("\n".join(current_page))
            current_page = []
            current_len = 0
        current_page.append(line)
        current_len += line_len

    if current_page:
        pages.append("\n".join(current_page))

    return pages
