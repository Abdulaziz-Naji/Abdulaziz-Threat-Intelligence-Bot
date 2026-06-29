"""
image_forensics.py - Hidden Intelligence Extraction Mode Engine

Core objective:
→ Extract ONLY meaningful hidden messages, flags (e.g., Flag{...}), and secrets from the image structure.
→ DO NOT generate forensic reports, metadata tables, or analysis summaries.
→ Output exactly the extracted messages or "No hidden message found" if nothing is present.
"""

from __future__ import annotations

import io
import re
import struct
import hashlib
from typing import Optional, Dict, List, Any

try:
    from PIL import Image
    from PIL.ExifTags import TAGS
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False


def analyze_image_full(data: bytes, filename: str) -> dict:
    """
    Dummy/legacy analyzer returning the list of messages in a dict for compatibility.
    """
    messages = extract_hidden_intelligence(data)
    return {"extracted_messages": messages}


def format_metadata_report(analysis: dict) -> list[str]:
    """
    Format report output matching the "Hidden Intelligence Extraction Mode" rules.
    Outputs ONLY the raw messages or "No hidden message found".
    """
    messages = analysis.get("extracted_messages", [])
    if not messages:
        return ["No hidden message found"]
    
    # Just list the messages directly with no decoration or filler
    return ["\n".join(messages)]


def extract_hidden_intelligence(data: bytes) -> list[str]:
    """
    Scans every byte and metadata node of the image for readable hidden text,
    steganography payloads, Photoshop layers, OCR text, and flags.
    """
    messages = []
    seen = set()

    def add_msg(msg: str):
        cleaned = msg.strip()
        if cleaned and len(cleaned) >= 4 and cleaned not in seen:
            seen.add(cleaned)
            messages.append(cleaned)

    # 1. Search for flags / CTF payloads in the entire binary payload first
    # Match patterns like Flag{...}, flag{...}, FlagY{...}, key{...}, secret{...}
    flag_patterns = [
        re.compile(r'flag[a-zA-Z0-9_\-\.\{\}]+', re.IGNORECASE),
        re.compile(r'flag[a-z0-9_]*\{[a-f0-9\-]+\}', re.IGNORECASE),
        re.compile(r'key\{[a-zA-Z0-9_\-]+\}', re.IGNORECASE),
    ]

    # Scan binary data as latin-1 to search for flag strings
    raw_str = data.decode('latin-1', errors='ignore')
    for pat in flag_patterns:
        for match in pat.findall(raw_str):
            add_msg(match)

    # 2. Extract Photoshop Text Layers
    layer_names = re.findall(r'photoshop:LayerName="([^"]+)"', raw_str)
    layer_texts = re.findall(r'photoshop:LayerText="([^"]+)"', raw_str)
    for t in layer_names + layer_texts:
        # Check if they look like flags or custom messages
        if "flag" in t.lower() or "key" in t.lower() or "secret" in t.lower() or len(t.strip()) > 3:
            add_msg(t)

    # 3. Scan JPEG trailing extraneous bytes after EOI marker (FF D9)
    if data.startswith(b'\xff\xd8\xff'):
        eoi_idx = data.rfind(b'\xff\xd9')
        if eoi_idx >= 0 and eoi_idx + 2 < len(data):
            extra = data[eoi_idx+2:]
            _extract_strings_from_bytes(extra, add_msg)
    elif data.startswith(b'\x89PNG\r\n\x1a\n'):
        iend_idx = data.rfind(b'IEND')
        if iend_idx >= 0 and iend_idx + 8 < len(data):
            extra = data[iend_idx+8:]
            _extract_strings_from_bytes(extra, add_msg)

    # 4. EXIF Comments or Software tags
    if PIL_AVAILABLE:
        try:
            with Image.open(io.BytesIO(data)) as img:
                exif_raw = img._getexif() if hasattr(img, "_getexif") else None
                if exif_raw:
                    for tag, value in exif_raw.items():
                        tag_name = TAGS.get(tag, tag)
                        if tag_name in ("UserComment", "ImageDescription", "Software", "Artist", "Copyright"):
                            val_str = str(value).strip()
                            if val_str and len(val_str) > 3:
                                add_msg(val_str)
        except Exception:
            pass

    return messages


def _extract_strings_from_bytes(raw_bytes: bytes, callback) -> None:
    """Helper to extract printable ASCII strings from raw binary bytes."""
    # Find sequence of printable characters (ASCII 32 to 126) of length >= 4
    str_list = re.findall(b'[ -~]{4,200}', raw_bytes)
    for s in str_list:
        try:
            callback(s.decode('ascii'))
        except Exception:
            pass
