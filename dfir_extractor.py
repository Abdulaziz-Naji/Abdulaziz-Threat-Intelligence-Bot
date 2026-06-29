"""
dfir_extractor.py - Recursive Archive Extractor & File Intelligence

Handles:
  - ZIP (multi-layer recursive)
  - GZIP (.gz, .tar.gz)
  - RAR (via rarfile if installed)
  - 7z (via py7zr if installed)
  - Flat file normalization

All extracted files are placed into an analysis queue:
  List[Tuple[filename: str, data: bytes, depth: int, parent: str]]

Magic byte detection supports 25+ file types.
"""
from __future__ import annotations

import io
import gzip
import hashlib
import logging
import zipfile
import struct
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# ─── Magic Byte Signatures (extended) ─────────────────────────────────────────

MAGIC_MAP: list[tuple[bytes, int, str]] = [
    # sig, offset, type
    (b"\x89PNG\r\n\x1a\n",  0, "png"),
    (b"\xff\xd8\xff",       0, "jpg"),
    (b"GIF87a",             0, "gif"),
    (b"GIF89a",             0, "gif"),
    (b"RIFF",               0, "riff"),          # may be WEBP; check offset 8
    (b"%PDF-",              0, "pdf"),
    (b"PK\x03\x04",         0, "zip"),           # ZIP / DOCX / XLSX / APK / JAR
    (b"PK\x05\x06",         0, "zip"),           # empty ZIP
    (b"Rar!\x1a\x07\x00",   0, "rar"),
    (b"Rar!\x1a\x07\x01",   0, "rar"),
    (b"7z\xbc\xaf'\x1c",   0, "7z"),
    (b"\x1f\x8b",           0, "gzip"),
    (b"BZh",                0, "bzip2"),
    (b"\xfd7zXZ\x00",       0, "xz"),
    (b"MZ",                 0, "pe"),            # EXE / DLL
    (b"\x7fELF",            0, "elf"),           # Linux binary
    (b"\xd4\xc3\xb2\xa1",  0, "pcap"),          # PCAP little-endian
    (b"\xa1\xb2\xc3\xd4",  0, "pcap"),          # PCAP big-endian
    (b"\x0a\x0d\x0d\x0a",  0, "pcapng"),        # PCAPng
    (b"\xd0\xcf\x11\xe0",  0, "ole"),           # DOC / XLS / PPT (OLE2)
    (b"CAFEBABE",           0, "java"),          # JAR class
    (b"\xca\xfe\xba\xbe",  0, "java"),
    (b"#!",                 0, "script"),        # Shell script
    (b"<?xml",              0, "xml"),
    (b"<?php",              0, "php"),
    (b"<html",              0, "html"),
    (b"<HTML",              0, "html"),
    (b"\x00\x00\x01\x00",  0, "ico"),
    (b"MSCF",               0, "cab"),           # Windows Cabinet
    (b"TVqQ",               0, "pe_b64"),        # Base64-encoded MZ
    (b"#!/",                0, "script"),
]

_EXT_FALLBACK: dict[str, str] = {
    "pdf": "pdf", "png": "png", "jpg": "jpg", "jpeg": "jpg",
    "gif": "gif", "webp": "webp", "bmp": "bmp",
    "zip": "zip", "rar": "rar", "7z": "7z", "gz": "gzip",
    "tar": "tar", "bz2": "bzip2", "xz": "xz",
    "exe": "pe", "dll": "pe", "sys": "pe", "scr": "pe",
    "elf": "elf", "so": "elf",
    "apk": "apk", "jar": "java", "dex": "dex",
    "doc": "ole", "xls": "ole", "ppt": "ole",
    "docx": "docx", "xlsx": "xlsx", "pptx": "pptx",
    "pcap": "pcap", "pcapng": "pcapng", "cap": "pcap",
    "mem": "memory", "raw": "raw", "dmp": "memory",
    "vmem": "memory", "img": "disk", "dd": "disk",
    "e01": "disk", "vhd": "disk", "vhdx": "disk", "vmdk": "disk",
    "sh": "script", "py": "script", "ps1": "script",
    "bat": "script", "vbs": "script", "js": "script",
    "xml": "xml", "html": "html", "htm": "html",
    "txt": "text", "log": "text", "csv": "text",
    "php": "php",
}

# Extension-based hints for ZIP containers
_ZIP_DOCX_MARKER = b"[Content_Types].xml"
_ZIP_APK_MARKER  = b"AndroidManifest.xml"
_ZIP_JAR_MARKER  = b"META-INF/MANIFEST.MF"


def detect_file_type(data: bytes, filename: str = "") -> str:
    """
    Identify file type using magic bytes (priority) then extension.
    Returns a normalized type string.
    """
    if not data:
        return "unknown"

    # Check magic bytes
    for sig, offset, ftype in MAGIC_MAP:
        chunk = data[offset:offset + len(sig)]
        if chunk == sig:
            # Refine ZIP sub-types
            if ftype == "zip":
                return _refine_zip_type(data, filename)
            # Refine RIFF (WEBP vs WAV)
            if ftype == "riff" and len(data) >= 12 and data[8:12] == b"WEBP":
                return "webp"
            return ftype

    # Extension fallback
    ext = Path(filename).suffix.lstrip(".").lower() if filename else ""
    if ext in _EXT_FALLBACK:
        return _EXT_FALLBACK[ext]

    # Entropy-based heuristic: if mostly binary with high entropy → likely memory/disk
    if _is_high_entropy_binary(data):
        if len(data) > 1024 * 1024:  # > 1MB binary blob
            ext_lower = filename.lower()
            if any(x in ext_lower for x in ["mem", "dmp", "raw", "vmem"]):
                return "memory"
            if any(x in ext_lower for x in ["dd", "e01", "img", "vhd", "vmdk"]):
                return "disk"
        return "binary"

    return "unknown"


def detect_file_type_path(filepath: str) -> str:
    """
    Identify file type from a disk path using magic bytes (priority) then extension.
    Avoids loading the entire file into memory.
    """
    filename = Path(filepath).name
    try:
        with open(filepath, "rb") as f:
            # Read first 1MB for signature and entropy check
            data_head = f.read(1024 * 1024)
    except Exception as e:
        logger.error(f"Failed to read file for type detection: {e}")
        return "unknown"

    if not data_head:
        return "unknown"

    # Check magic bytes
    for sig, offset, ftype in MAGIC_MAP:
        chunk = data_head[offset:offset + len(sig)]
        if chunk == sig:
            # Refine ZIP sub-types
            if ftype == "zip":
                return _refine_zip_type_path(filepath)
            # Refine RIFF (WEBP vs WAV)
            if ftype == "riff" and len(data_head) >= 12 and data_head[8:12] == b"WEBP":
                return "webp"
            return ftype

    # Extension fallback
    ext = Path(filename).suffix.lstrip(".").lower() if filename else ""
    if ext in _EXT_FALLBACK:
        return _EXT_FALLBACK[ext]

    # Entropy-based heuristic: if mostly binary with high entropy -> likely memory/disk
    if _is_high_entropy_binary(data_head):
        try:
            file_size = Path(filepath).stat().st_size
        except Exception:
            file_size = len(data_head)
            
        if file_size > 1024 * 1024:  # > 1MB binary blob
            ext_lower = filename.lower()
            if any(x in ext_lower for x in ["mem", "dmp", "raw", "vmem"]):
                return "memory"
            if any(x in ext_lower for x in ["dd", "e01", "img", "vhd", "vmdk"]):
                return "disk"
        return "binary"

    return "unknown"


def _refine_zip_type(data: bytes, filename: str) -> str:
    """Identify ZIP-based container types (DOCX, XLSX, APK, JAR)."""
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            names = zf.namelist()
            names_lower = [n.lower() for n in names]
            if "androidmanifest.xml" in names_lower:
                return "apk"
            if "meta-inf/manifest.mf" in names_lower:
                return "java"
            if "[content_types].xml" in names_lower:
                # OOXML family
                if any("word/" in n for n in names_lower):
                    return "docx"
                if any("xl/" in n for n in names_lower):
                    return "xlsx"
                if any("ppt/" in n for n in names_lower):
                    return "pptx"
                return "ooxml"
    except Exception:
        pass

    ext = Path(filename).suffix.lstrip(".").lower()
    if ext == "apk":
        return "apk"
    return "zip"


def _refine_zip_type_path(filepath: str) -> str:
    """Identify ZIP-based container types (DOCX, XLSX, APK, JAR) from a file path."""
    try:
        with zipfile.ZipFile(filepath) as zf:
            names = zf.namelist()
            names_lower = [n.lower() for n in names]
            if "androidmanifest.xml" in names_lower:
                return "apk"
            if "meta-inf/manifest.mf" in names_lower:
                return "java"
            if "[content_types].xml" in names_lower:
                # OOXML family
                if any("word/" in n for n in names_lower):
                    return "docx"
                if any("xl/" in n for n in names_lower):
                    return "xlsx"
                if any("ppt/" in n for n in names_lower):
                    return "pptx"
                return "ooxml"
    except Exception:
        pass

    filename = Path(filepath).name
    ext = Path(filename).suffix.lstrip(".").lower()
    if ext == "apk":
        return "apk"
    return "zip"


def _is_high_entropy_binary(data: bytes, sample: int = 4096) -> bool:
    """Check if data has high Shannon entropy (packed/encrypted/binary)."""
    sample_data = data[:sample]
    if not sample_data:
        return False
    freq = [0] * 256
    for b in sample_data:
        freq[b] += 1
    total = len(sample_data)
    import math
    entropy = -sum((f / total) * math.log2(f / total) for f in freq if f > 0)
    return entropy > 7.0  # Max is 8.0 for perfectly random data


def compute_hashes(data: bytes) -> dict[str, str]:
    """Return MD5, SHA1, SHA256 of data."""
    return {
        "md5":    hashlib.md5(data).hexdigest(),
        "sha1":   hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


# ─── Recursive Archive Extractor ──────────────────────────────────────────────

# Each item: (filename, bytes, depth, parent_filename)
ExtractionQueue = list[tuple[str, bytes, int, str]]

MAX_EXTRACT_DEPTH    = 4
MAX_EXTRACT_FILES    = 50
MAX_SINGLE_FILE_SIZE = 20 * 1024 * 1024   # 20 MB


def extract_all(
    data: bytes,
    filename: str,
    depth: int = 0,
    parent: str = "root",
    _counter: Optional[list] = None,
) -> ExtractionQueue:
    """
    Recursively extract all files from any supported archive.

    Returns a flat list of (filename, bytes, depth, parent) tuples.
    The caller is responsible for routing each item through the forensic engine.
    """
    if _counter is None:
        _counter = [0]

    result: ExtractionQueue = []

    if depth > MAX_EXTRACT_DEPTH:
        logger.warning(f"[extractor] Max depth {MAX_EXTRACT_DEPTH} reached at {filename}")
        return result

    if _counter[0] >= MAX_EXTRACT_FILES:
        logger.warning(f"[extractor] Max file count {MAX_EXTRACT_FILES} reached")
        return result

    ftype = detect_file_type(data, filename)

    if ftype == "zip" or ftype in ("apk", "docx", "xlsx", "pptx", "ooxml", "java"):
        result.extend(_extract_zip(data, filename, depth, parent, _counter))

    elif ftype == "gzip":
        result.extend(_extract_gzip(data, filename, depth, parent, _counter))

    elif ftype == "rar":
        result.extend(_extract_rar(data, filename, depth, parent, _counter))

    elif ftype == "7z":
        result.extend(_extract_7z(data, filename, depth, parent, _counter))

    else:
        # Leaf file — add directly to queue
        if len(data) <= MAX_SINGLE_FILE_SIZE:
            result.append((filename, data, depth, parent))
            _counter[0] += 1
        else:
            logger.warning(f"[extractor] {filename} exceeds size limit, truncating")
            result.append((filename, data[:MAX_SINGLE_FILE_SIZE], depth, parent))
            _counter[0] += 1

    return result


def _extract_zip(
    data: bytes, filename: str, depth: int, parent: str,
    _counter: list
) -> ExtractionQueue:
    result: ExtractionQueue = []
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            for info in zf.infolist():
                if _counter[0] >= MAX_EXTRACT_FILES:
                    break
                if info.file_size > MAX_SINGLE_FILE_SIZE:
                    continue
                try:
                    child_data = zf.read(info.filename)
                    child_name = Path(info.filename).name or info.filename
                    # Recurse into nested archives
                    nested = extract_all(
                        child_data, child_name,
                        depth=depth + 1, parent=filename,
                        _counter=_counter
                    )
                    result.extend(nested)
                except Exception as e:
                    logger.debug(f"[extractor] ZIP child read error {info.filename}: {e}")
    except zipfile.BadZipFile:
        logger.warning(f"[extractor] Bad ZIP: {filename}")
    except Exception as e:
        logger.warning(f"[extractor] ZIP extraction error {filename}: {e}")
    return result


def _extract_gzip(
    data: bytes, filename: str, depth: int, parent: str,
    _counter: list
) -> ExtractionQueue:
    result: ExtractionQueue = []
    try:
        decompressed = gzip.decompress(data)
        inner_name = filename.replace(".gz", "") if filename.endswith(".gz") else filename + "_extracted"
        nested = extract_all(
            decompressed, inner_name,
            depth=depth + 1, parent=filename,
            _counter=_counter
        )
        result.extend(nested)
    except Exception as e:
        logger.warning(f"[extractor] GZIP extraction error {filename}: {e}")
    return result


def _extract_rar(
    data: bytes, filename: str, depth: int, parent: str,
    _counter: list
) -> ExtractionQueue:
    result: ExtractionQueue = []
    try:
        import rarfile
        with rarfile.RarFile(io.BytesIO(data)) as rf:
            for info in rf.infolist():
                if _counter[0] >= MAX_EXTRACT_FILES:
                    break
                try:
                    child_data = rf.read(info.filename)
                    child_name = Path(info.filename).name or info.filename
                    nested = extract_all(
                        child_data, child_name,
                        depth=depth + 1, parent=filename,
                        _counter=_counter
                    )
                    result.extend(nested)
                except Exception as e:
                    logger.debug(f"[extractor] RAR child read error: {e}")
    except ImportError:
        logger.info("[extractor] rarfile not installed — RAR extraction unavailable")
        result.append((filename, data, depth, parent))
        _counter[0] += 1
    except Exception as e:
        logger.warning(f"[extractor] RAR error {filename}: {e}")
    return result


def _extract_7z(
    data: bytes, filename: str, depth: int, parent: str,
    _counter: list
) -> ExtractionQueue:
    result: ExtractionQueue = []
    try:
        import py7zr
        with py7zr.SevenZipFile(io.BytesIO(data), mode="r") as szf:
            extracted = szf.readall()
            for child_name, child_io in (extracted or {}).items():
                if _counter[0] >= MAX_EXTRACT_FILES:
                    break
                try:
                    child_data = child_io.read()
                    nested = extract_all(
                        child_data, Path(child_name).name,
                        depth=depth + 1, parent=filename,
                        _counter=_counter
                    )
                    result.extend(nested)
                except Exception as e:
                    logger.debug(f"[extractor] 7z child read error: {e}")
    except ImportError:
        logger.info("[extractor] py7zr not installed — 7z extraction unavailable")
        result.append((filename, data, depth, parent))
        _counter[0] += 1
    except Exception as e:
        logger.warning(f"[extractor] 7z error {filename}: {e}")
    return result
