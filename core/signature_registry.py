"""
core/signature_registry.py
==========================
Format signature verification engine for Feature 02.
Examines raw bytes directly — never blindly trusts file extensions.
"""

from typing import Dict, Optional, Tuple


MAGIC_SIGNATURES = [
    # (magic_bytes, format_name, mime_type, offset)
    (b"\x89PNG\r\n\x1a\n", "PNG", "image/png", 0),
    (b"\xff\xd8\xff", "JPEG", "image/jpeg", 0),
    (b"%PDF", "PDF", "application/pdf", 0),
    (b"PK\x03\x04", "ZIP", "application/zip", 0),
    (b"PK\x05\x06", "ZIP", "application/zip", 0),   # Empty/spanned EOCD
    (b"PK\x07\x08", "ZIP", "application/zip", 0),   # Data descriptor
    (b"SQLite format 3\x00", "SQLITE", "application/x-sqlite3", 0),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "DOC", "application/msword", 0),
    (b"{\\rtf", "RTF", "text/rtf", 0),
    (b"GIF87a", "GIF", "image/gif", 0),
    (b"GIF89a", "GIF", "image/gif", 0),
    (b"BM", "BMP", "image/bmp", 0),
    (b"II*\x00", "TIFF", "image/tiff", 0),
    (b"MM\x00*", "TIFF", "image/tiff", 0),
    (b"\xd4\xc3\xb2\xa1", "PCAP", "application/vnd.tcpdump", 0),
    (b"\xa1\xb2\xc3\xd4", "PCAP", "application/vnd.tcpdump", 0),
    (b"ElfFile\x00", "EVTX", "application/x-ms-evtx", 0),
    (b"regf", "REGF", "application/x-windows-registry", 0),
    (b"MZ", "PE", "application/x-msdownload", 0),
]

EXTENSION_MAP = {
    "jpg": "JPEG", "jpeg": "JPEG", "jpe": "JPEG",
    "png": "PNG",
    "pdf": "PDF",
    "zip": "ZIP", "jar": "ZIP", "apk": "ZIP",
    "docx": "DOCX", "xlsx": "DOCX", "pptx": "DOCX",
    "sqlite": "SQLITE", "sqlite3": "SQLITE", "db": "SQLITE",
    "log": "LOG", "txt": "LOG", "syslog": "LOG",
    "gif": "GIF", "bmp": "BMP", "tif": "TIFF", "tiff": "TIFF",
    "exe": "PE", "dll": "PE", "sys": "PE",
}


def detect_format_from_bytes(data: bytes) -> Tuple[str, str, int]:
    """
    Detect format directly from raw bytes.
    Returns (format_name, mime_type, match_offset).
    """
    if not data:
        return "UNKNOWN", "application/octet-stream", -1

    for magic, fmt, mime, offset in MAGIC_SIGNATURES:
        if len(data) >= offset + len(magic):
            if data[offset:offset + len(magic)] == magic:
                return fmt, mime, offset

    # Secondary check: %PDF within first 1024 bytes (standard PDF spec tolerance)
    pdf_idx = data[:1024].find(b"%PDF")
    if pdf_idx != -1:
        return "PDF", "application/pdf", pdf_idx

    # Secondary check: Text/Log format
    if len(data) >= 8:
        sample = data[:min(len(data), 1024)]
        try:
            text = sample.decode("utf-8")
            if any(text.startswith(kw) for kw in ("[", "202", "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")):
                return "LOG", "text/plain", 0
        except UnicodeDecodeError:
            pass

    return "UNKNOWN", "application/octet-stream", -1


def verify_signature(
    data: bytes,
    filename: Optional[str] = None,
    claimed_format: Optional[str] = None
) -> Dict:
    """
    Examines actual bytes to verify file signature and cross-check against extension.
    
    Returns dictionary with:
      - signature_present: bool
      - signature_valid: bool
      - signature_mismatch: bool
      - signature_missing: bool
      - format_detected: str
      - mime_detected: str
      - expected_format: Optional[str]
      - conflict_details: Optional[str]
    """
    detected_fmt, detected_mime, match_offset = detect_format_from_bytes(data)

    ext = ""
    ext_fmt = "UNKNOWN"
    if filename and "." in filename:
        ext = filename.rsplit(".", 1)[-1].lower()
        ext_fmt = EXTENSION_MAP.get(ext, "UNKNOWN")

    expected_fmt = (claimed_format.upper() if claimed_format else None) or (ext_fmt if ext_fmt != "UNKNOWN" else None)

    signature_present = (detected_fmt != "UNKNOWN")
    signature_missing = (not signature_present)
    
    # Signature validity and mismatch relative to expected format
    if expected_fmt:
        # ZIP and DOCX share PK magic
        is_ooxml_zip = (expected_fmt in ("ZIP", "DOCX") and detected_fmt in ("ZIP", "DOCX"))
        if is_ooxml_zip or (detected_fmt == expected_fmt):
            signature_valid = True
            signature_mismatch = False
            conflict_details = None
        else:
            signature_valid = False
            signature_mismatch = True
            conflict_details = (
                f"Binary magic indicates {detected_fmt} (match at offset {match_offset}), "
                f"which conflicts with expected format {expected_fmt}."
            )
    else:
        # No expectation provided
        signature_valid = signature_present
        signature_mismatch = False
        conflict_details = None

    return {
        "signature_present": signature_present,
        "signature_valid": signature_valid,
        "signature_mismatch": signature_mismatch,
        "signature_missing": signature_missing,
        "format_detected": detected_fmt,
        "mime_detected": detected_mime,
        "match_offset": match_offset,
        "expected_format": expected_fmt,
        "conflict_details": conflict_details,
    }
