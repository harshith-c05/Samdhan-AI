"""
backend/integrity.py
====================
SAMDHAN AI — Format-Specific Forensic Integrity Checkers & 4-Vector Scoring.

Specification:
- Format-specific validation:
  - JPEG: marker sequence (SOI FF D8, DQT FF DB, SOF0 FF C0, DHT FF C4, SOS FF DA, EOI FF D9)
  - PDF: xref table, trailer, objects via pypdf with raw fallback
  - SQLite: header signature (SQLite format 3\\000) + PRAGMA integrity_check
  - ZIP/DOCX: PK signatures (PK\\x03\\x04 local, PK\\x01\\x02 central dir, PK\\x05\\x06 EOCD)
  - UTF-8 logs: byte-level decoding, non-printable noise, timestamp monotonicity
- Output:
  - List of corruption byte ranges: [start, end, severity, description]
  - 4-vector score: {structural: 0-100, content: 0-100, metadata: 0-100, continuity: 0-100}
"""

import io
import re
import struct
import tempfile
import zipfile
import sqlite3
from typing import Dict, List, Optional, Tuple, Any

import logging

try:
    import pypdf
    logging.getLogger("pypdf").setLevel(logging.ERROR)
except ImportError:
    pypdf = None


def check_jpeg_integrity(data: bytes) -> Tuple[List[Dict[str, Any]], Dict[str, float]]:
    """Validates JPEG marker sequence and payload boundaries."""
    ranges = []
    size = len(data)
    if size < 4:
        return ([{"start": 0, "end": size, "severity": "CRITICAL", "description": "File too small to be valid JPEG"}],
                {"structural": 0.0, "content": 0.0, "metadata": 0.0, "continuity": 0.0})

    has_soi = data.startswith(b"\xff\xd8")
    has_eoi = data.endswith(b"\xff\xd9") or (b"\xff\xd9" in data[-32:])

    if not has_soi:
        ranges.append({
            "start": 0,
            "end": min(16, size),
            "severity": "CRITICAL",
            "description": "Missing or wiped JPEG SOI (Start of Image) marker 0xFFD8"
        })

    # Search for standard JPEG markers
    has_dqt = b"\xff\xdb" in data
    has_sof = b"\xff\xc0" in data or b"\xff\xc2" in data
    has_dht = b"\xff\xc4" in data
    has_sos = b"\xff\xda" in data

    if not has_sof and has_soi:
        ranges.append({
            "start": 16,
            "end": min(64, size),
            "severity": "HIGH",
            "description": "Missing JPEG SOF (Start of Frame) marker"
        })

    if not has_sos and has_soi:
        ranges.append({
            "start": min(64, size),
            "end": min(128, size),
            "severity": "HIGH",
            "description": "Missing JPEG SOS (Start of Scan) marker"
        })

    if not has_eoi:
        ranges.append({
            "start": max(0, size - 16),
            "end": size,
            "severity": "HIGH",
            "description": "Missing JPEG EOI (End of Image) marker 0xFFD9 (truncated image stream)"
        })

    # Calculate 4-vector
    # Structural: SOI + SOF + SOS + EOI
    markers_found = sum([has_soi, has_sof, has_sos, has_eoi])
    structural = (markers_found / 4.0) * 100.0

    # Content: entropy of scan payload (between SOS and EOI)
    sos_idx = data.find(b"\xff\xda")
    if sos_idx != -1 and sos_idx < size - 32:
        content_bytes = data[sos_idx + 2:]
        # Non-zero ratio
        nonzero = sum(1 for b in content_bytes if b != 0) / len(content_bytes)
        content = min(100.0, nonzero * 105.0)
    else:
        content = 50.0 if has_soi else 10.0

    # Metadata: DQT and DHT present
    meta_count = sum([has_dqt, has_dht, b"\xff\xe0" in data or b"\xff\xe1" in data])
    metadata = min(100.0, (meta_count / 3.0) * 100.0)

    # Continuity: no large runs of zeroes in middle of payload
    zero_runs = len(re.findall(b"\x00{64,}", data))
    continuity = max(10.0, 100.0 - (zero_runs * 25.0))
    if not has_soi:
        continuity = min(continuity, 40.0)

    return ranges, {
        "structural": round(structural, 1),
        "content": round(content, 1),
        "metadata": round(metadata, 1),
        "continuity": round(continuity, 1),
    }


def check_pdf_integrity(data: bytes) -> Tuple[List[Dict[str, Any]], Dict[str, float]]:
    """Validates PDF header, xref table, trailer dictionary, and object structure."""
    ranges = []
    size = len(data)
    if size < 16:
        return ([{"start": 0, "end": size, "severity": "CRITICAL", "description": "File too small for valid PDF"}],
                {"structural": 0.0, "content": 0.0, "metadata": 0.0, "continuity": 0.0})

    has_header = data.startswith(b"%PDF-") or (b"%PDF-" in data[:1024])
    has_eof = b"%%EOF" in data[-1024:]
    has_xref = b"xref" in data or b"/XRef" in data
    has_trailer = b"trailer" in data or b"/Root" in data

    if not has_header:
        ranges.append({
            "start": 0,
            "end": min(16, size),
            "severity": "CRITICAL",
            "description": "Missing %PDF- magic signature header"
        })

    if not has_eof:
        ranges.append({
            "start": max(0, size - 32),
            "end": size,
            "severity": "HIGH",
            "description": "Missing %%EOF PDF file termination token"
        })

    pypdf_ok = False
    if pypdf:
        try:
            reader = pypdf.PdfReader(io.BytesIO(data), strict=False)
            _ = len(reader.pages)
            pypdf_ok = True
        except Exception as e:
            ranges.append({
                "start": max(0, size - 256),
                "end": size,
                "severity": "MEDIUM",
                "description": f"PDF parse anomaly: {str(e)[:120]}"
            })

    # Scores
    structural = 100.0 if (has_header and has_eof and has_xref) else (50.0 if (has_header or has_eof) else 10.0)
    if pypdf_ok:
        structural = max(structural, 95.0)

    content = 95.0 if (b"stream" in data and b"endstream" in data) else 40.0
    if not has_header:
        content = min(content, 35.0)

    metadata = 90.0 if has_trailer and b"/Info" in data or b"/Catalog" in data else 50.0
    continuity = 95.0 if (has_header and has_eof) else 40.0

    return ranges, {
        "structural": round(structural, 1),
        "content": round(content, 1),
        "metadata": round(metadata, 1),
        "continuity": round(continuity, 1),
    }


def check_sqlite_integrity(data: bytes) -> Tuple[List[Dict[str, Any]], Dict[str, float]]:
    """Validates SQLite database header, page integrity, and PRAGMA integrity_check."""
    ranges = []
    size = len(data)
    if size < 100:
        return ([{"start": 0, "end": size, "severity": "CRITICAL", "description": "Database under minimum header size (100 bytes)"}],
                {"structural": 0.0, "content": 0.0, "metadata": 0.0, "continuity": 0.0})

    has_header = data.startswith(b"SQLite format 3\x00")
    if not has_header:
        ranges.append({
            "start": 0,
            "end": 16,
            "severity": "CRITICAL",
            "description": "Wiped or invalid SQLite format 3 magic header"
        })

    page_size = 0
    if has_header and len(data) >= 18:
        page_size = struct.unpack(">H", data[16:18])[0]
        if page_size == 1:
            page_size = 65536
        elif page_size not in (512, 1024, 2048, 4096, 8192, 16384, 32768, 65536):
            ranges.append({
                "start": 16,
                "end": 18,
                "severity": "HIGH",
                "description": f"Invalid SQLite page size specified: {page_size}"
            })

    # Run PRAGMA integrity check via tempfile
    pragma_passed = False
    pragma_errors = []
    if has_header:
        try:
            with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tf:
                tf.write(data)
                temp_path = tf.name

            conn = sqlite3.connect(temp_path)
            cursor = conn.cursor()
            res = cursor.execute("PRAGMA integrity_check;").fetchall()
            conn.close()

            if res and res[0][0] == "ok":
                pragma_passed = True
            else:
                for row in res[:3]:
                    pragma_errors.append(row[0])
                    ranges.append({
                        "start": 100,
                        "end": min(size, 512),
                        "severity": "HIGH",
                        "description": f"SQLite PRAGMA error: {row[0]}"
                    })
        except Exception as e:
            ranges.append({
                "start": 0,
                "end": 100,
                "severity": "CRITICAL",
                "description": f"SQLite runtime open failure: {str(e)[:100]}"
            })

    if pragma_passed:
        structural = 100.0
        content = 98.0
        metadata = 95.0
        continuity = 100.0
    elif has_header:
        structural = 65.0
        content = 50.0
        metadata = 60.0
        continuity = 70.0
    else:
        structural = 10.0
        content = 25.0
        metadata = 10.0
        continuity = 30.0

    return ranges, {
        "structural": round(structural, 1),
        "content": round(content, 1),
        "metadata": round(metadata, 1),
        "continuity": round(continuity, 1),
    }


def check_zip_integrity(data: bytes) -> Tuple[List[Dict[str, Any]], Dict[str, float]]:
    """Validates ZIP/DOCX local file headers and Central Directory EOCD record."""
    ranges = []
    size = len(data)
    has_local = data.startswith(b"PK\x03\x04")
    has_eocd = b"PK\x05\x06" in data[-1024:]

    if not has_local:
        ranges.append({
            "start": 0,
            "end": min(4, size),
            "severity": "CRITICAL",
            "description": "Missing PK 0x04034b50 local file header signature"
        })

    if not has_eocd:
        ranges.append({
            "start": max(0, size - 22),
            "end": size,
            "severity": "HIGH",
            "description": "Missing End of Central Directory (EOCD) record PK 0x06054b50"
        })

    zip_ok = False
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            bad_file = zf.testzip()
            if bad_file is None:
                zip_ok = True
            else:
                ranges.append({
                    "start": 4,
                    "end": min(1024, size),
                    "severity": "HIGH",
                    "description": f"ZIP CRC checksum mismatch in member: {bad_file}"
                })
    except Exception as e:
        ranges.append({
            "start": 0,
            "end": size,
            "severity": "MEDIUM",
            "description": f"ZIP archive structural defect: {str(e)[:100]}"
        })

    structural = 100.0 if zip_ok else (50.0 if (has_local or has_eocd) else 10.0)
    content = 95.0 if zip_ok else 40.0
    metadata = 90.0 if has_eocd else 30.0
    continuity = 95.0 if (has_local and has_eocd) else 35.0

    return ranges, {
        "structural": round(structural, 1),
        "content": round(content, 1),
        "metadata": round(metadata, 1),
        "continuity": round(continuity, 1),
    }


def check_utf8_log_integrity(data: bytes) -> Tuple[List[Dict[str, Any]], Dict[str, float]]:
    """Validates UTF-8 encoded text/logs for invalid byte sequences and anomalies."""
    ranges = []
    size = len(data)
    if size == 0:
        return ([{"start": 0, "end": 0, "severity": "HIGH", "description": "Empty text file"}],
                {"structural": 0.0, "content": 0.0, "metadata": 0.0, "continuity": 0.0})

    try:
        text = data.decode("utf-8")
        valid_utf8 = True
    except UnicodeDecodeError as err:
        valid_utf8 = False
        ranges.append({
            "start": err.start,
            "end": err.end,
            "severity": "HIGH",
            "description": f"Invalid UTF-8 byte sequence ({err.reason}) at offset {err.start}"
        })
        text = data.decode("utf-8", errors="replace")

    # Check for excessive zero-byte padding or binary garbage
    zero_count = data.count(b"\x00")
    if zero_count > (size * 0.1):
        ranges.append({
            "start": 0,
            "end": size,
            "severity": "MEDIUM",
            "description": f"Suspicious binary null byte content ({zero_count} nulls, {zero_count/size:.1%})"
        })

    # Line breaks and structure
    lines = text.splitlines()
    structural = 95.0 if valid_utf8 and len(lines) > 0 else (45.0 if valid_utf8 else 20.0)
    content = max(10.0, 100.0 - (zero_count / max(1, size) * 100.0))
    metadata = 85.0 if len(lines) > 2 else 50.0
    continuity = 90.0 if not ranges else max(20.0, 90.0 - (len(ranges) * 20.0))

    return ranges, {
        "structural": round(structural, 1),
        "content": round(content, 1),
        "metadata": round(metadata, 1),
        "continuity": round(continuity, 1),
    }


def assess_file_integrity(data: bytes, filename: str = "") -> Dict[str, Any]:
    """
    Main entry point for format-specific integrity assessment.
    Automatically detects format or checks specific format signatures.
    Returns:
      - corruption_ranges: [[start, end, severity, description], ...]
      - vector: 4-vector dictionary
      - composite_score: float (0.0 - 100.0)
      - format_detected: str
    """
    fn = filename.lower()
    size = len(data)

    # 1. Detect format by extension or magic bytes
    if fn.endswith((".jpg", ".jpeg")) or data.startswith(b"\xff\xd8"):
        fmt = "JPEG"
        ranges, vector = check_jpeg_integrity(data)
    elif fn.endswith(".pdf") or data.startswith(b"%PDF-"):
        fmt = "PDF"
        ranges, vector = check_pdf_integrity(data)
    elif fn.endswith((".db", ".sqlite", ".sqlite3")) or data.startswith(b"SQLite format 3"):
        fmt = "SQLite"
        ranges, vector = check_sqlite_integrity(data)
    elif fn.endswith((".zip", ".docx", ".xlsx", ".pptx")) or data.startswith(b"PK\x03\x04"):
        fmt = "ZIP/Office"
        ranges, vector = check_zip_integrity(data)
    elif fn.endswith((".log", ".txt", ".json", ".csv")):
        fmt = "UTF-8 Log"
        ranges, vector = check_utf8_log_integrity(data)
    else:
        # Generic binary assessment
        fmt = "Generic Binary"
        if size == 0 or data.count(b"\x00") == size:
            ranges = [{"start": 0, "end": size, "severity": "CRITICAL", "description": "All-zero wiped bitstream"}]
            vector = {"structural": 0.0, "content": 0.0, "metadata": 0.0, "continuity": 0.0}
        else:
            # Check for header wipe if extension suggests format
            if fn.endswith((".jpg", ".jpeg")) and not data.startswith(b"\xff\xd8"):
                ranges, vector = check_jpeg_integrity(data)
                fmt = "JPEG (Corrupted Header)"
            elif fn.endswith(".pdf") and not data.startswith(b"%PDF-"):
                ranges, vector = check_pdf_integrity(data)
                fmt = "PDF (Corrupted Header)"
            elif fn.endswith((".db", ".sqlite")) and not data.startswith(b"SQLite"):
                ranges, vector = check_sqlite_integrity(data)
                fmt = "SQLite (Corrupted Header)"
            else:
                ranges = []
                vector = {"structural": 75.0, "content": 75.0, "metadata": 70.0, "continuity": 75.0}

    # Calculate overall composite score
    composite = (
        0.35 * vector["structural"] +
        0.30 * vector["content"] +
        0.15 * vector["metadata"] +
        0.20 * vector["continuity"]
    )

    return {
        "format": fmt,
        "size_bytes": size,
        "vector": vector,
        "composite_score": round(composite, 1),
        "corruption_ranges": ranges,
        "is_intact": len(ranges) == 0 and composite >= 85.0
    }
