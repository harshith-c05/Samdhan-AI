"""
fragment_reconstruction/feature_extractor.py
============================================
Stage 2 — Fragment Feature Analysis.

Computes forensic features on every fragment:
  - Shannon entropy & byte statistics
  - Zero-byte and printable-byte ratios
  - Format identification (JPEG, PNG, PDF, ZIP)
  - Header / footer compatibility
  - Internal format markers (JFIF/EXIF/DQT/DHT/SOF/SOS, IHDR/IDAT/IEND, %PDF/obj/xref, PK)
"""

from __future__ import annotations

import hashlib
import math
import struct
from typing import Any, Dict, List, Optional, Tuple

from .models import Fragment, FormatType


def compute_entropy(data: bytes) -> float:
    """Calculate Shannon entropy [0.0 - 8.0] for a byte slice."""
    if not data:
        return 0.0
    length = len(data)
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    entropy = 0.0
    for count in counts:
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)
    return round(entropy, 4)


def compute_byte_frequencies(data: bytes) -> List[int]:
    """Calculate frequency counts for each byte value 0..255."""
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    return freq


def scan_jpeg_markers(data: bytes) -> Tuple[List[str], bool, bool]:
    """
    Scan for JPEG markers in data.
    Returns (markers_found, has_soi, has_eoi).
    """
    markers = []
    has_soi = False
    has_eoi = False
    n = len(data)

    if n >= 2 and data[:2] == b"\xff\xd8":
        has_soi = True
        markers.append("SOI")

    if n >= 2 and data[-2:] == b"\xff\xd9":
        has_eoi = True
        markers.append("EOI")

    # Scan internal markers
    pos = 0
    while pos < n - 1:
        if data[pos] == 0xFF:
            m = data[pos + 1]
            if m not in (0x00, 0xFF): # Exclude byte stuffing and padding
                name = None
                if m == 0xD8: name = "SOI"
                elif m == 0xD9: name = "EOI"
                elif m == 0xE0: name = "APP0"
                elif m == 0xE1: name = "APP1"
                elif m == 0xDB: name = "DQT"
                elif m == 0xC0: name = "SOF0"
                elif m == 0xC2: name = "SOF2"
                elif m == 0xC4: name = "DHT"
                elif m == 0xDA: name = "SOS"
                elif 0xD0 <= m <= 0xD7: name = f"RST{m - 0xD0}"

                if name and name not in markers:
                    markers.append(name)
        pos += 1

    return markers, has_soi, has_eoi


def scan_png_markers(data: bytes) -> Tuple[List[str], bool, bool]:
    """
    Scan for PNG chunks in data.
    Returns (markers_found, has_header, has_footer).
    """
    markers = []
    has_header = False
    has_footer = False
    PNG_MAGIC = b"\x89PNG\r\n\x1a\n"

    if data.startswith(PNG_MAGIC):
        has_header = True
        markers.append("PNG_MAGIC")

    if b"IEND" in data:
        has_footer = True
        markers.append("IEND")

    for chunk in [b"IHDR", b"PLTE", b"IDAT", b"tRNS", b"gAMA", b"cHRM", b"pHYs", b"tEXt", b"zTXt"]:
        if chunk in data and chunk.decode("ascii") not in markers:
            markers.append(chunk.decode("ascii"))

    return markers, has_header, has_footer


def scan_pdf_markers(data: bytes) -> Tuple[List[str], bool, bool]:
    """
    Scan for PDF tokens in data.
    Returns (markers_found, has_header, has_footer).
    """
    markers = []
    has_header = data.startswith(b"%PDF")
    if has_header:
        markers.append("%PDF")

    has_footer = b"%%EOF" in data
    if has_footer:
        markers.append("%%EOF")

    for token in [b"obj", b"endobj", b"stream", b"endstream", b"xref", b"trailer", b"startxref"]:
        if token in data and token.decode("ascii") not in markers:
            markers.append(token.decode("ascii"))

    return markers, has_header, has_footer


def scan_zip_markers(data: bytes) -> Tuple[List[str], bool, bool]:
    """
    Scan for ZIP record signatures.
    Returns (markers_found, has_header, has_footer).
    """
    markers = []
    has_header = data.startswith(b"PK\x03\x04")
    if has_header:
        markers.append("LOCAL_FILE_HEADER")

    has_footer = b"PK\x05\x06" in data
    if has_footer:
        markers.append("EOCD")

    if b"PK\x01\x02" in data and "CENTRAL_DIR" not in markers:
        markers.append("CENTRAL_DIR")

    return markers, has_header, has_footer


def analyze_fragment(
    data: bytes,
    fragment_id: str,
    source_offset: int = 0,
    cluster_index: Optional[int] = None,
    allocation_state: str = "UNKNOWN",
    source_evidence: Optional[Dict[str, Any]] = None,
) -> Fragment:
    """
    Perform complete forensic feature extraction on a raw byte fragment.
    """
    if source_evidence is None:
        source_evidence = {}

    length = len(data)
    sha256 = hashlib.sha256(data).hexdigest()
    entropy = compute_entropy(data)
    byte_freq = compute_byte_frequencies(data)

    zero_count = byte_freq[0]
    zero_ratio = round(zero_count / length, 4) if length > 0 else 0.0

    # Printable ASCII: 32..126 + whitespace \t \r \n
    printable_count = sum(byte_freq[b] for b in range(32, 127)) + byte_freq[9] + byte_freq[10] + byte_freq[13]
    printable_ratio = round(printable_count / length, 4) if length > 0 else 0.0

    first_16 = data[:16].hex() if length >= 16 else data.hex()
    last_16 = data[-16:].hex() if length >= 16 else data.hex()

    # Format-specific scans
    fmt = FormatType.UNKNOWN
    header_compat = False
    footer_compat = False
    all_markers: List[str] = []

    # 1. JPEG
    jpeg_markers, j_hdr, j_ftr = scan_jpeg_markers(data)
    if j_hdr or j_ftr or (len(jpeg_markers) >= 1 and any(m in ("SOF0", "DHT", "DQT", "SOS", "EOI") for m in jpeg_markers)):
        fmt = FormatType.JPEG
        header_compat = j_hdr
        footer_compat = j_ftr
        all_markers.extend(jpeg_markers)

    # 2. PNG
    if fmt == FormatType.UNKNOWN or not header_compat:
        png_markers, p_hdr, p_ftr = scan_png_markers(data)
        if p_hdr or p_ftr or (len(png_markers) >= 1 and any(m in ("IHDR", "IDAT", "IEND", "PLTE") for m in png_markers)):
            fmt = FormatType.PNG
            header_compat = p_hdr
            footer_compat = p_ftr
            all_markers.extend(png_markers)

    # 3. PDF
    if fmt == FormatType.UNKNOWN or not header_compat:
        pdf_markers, d_hdr, d_ftr = scan_pdf_markers(data)
        if d_hdr or d_ftr or (len(pdf_markers) >= 1 and any(m in ("obj", "stream", "xref", "trailer", "%%EOF") for m in pdf_markers)):
            fmt = FormatType.PDF
            header_compat = d_hdr
            footer_compat = d_ftr
            all_markers.extend(pdf_markers)

    # 4. ZIP
    if fmt == FormatType.UNKNOWN or not header_compat:
        zip_markers, z_hdr, z_ftr = scan_zip_markers(data)
        if z_hdr or z_ftr or (len(zip_markers) >= 1 and any(m in ("LOCAL_FILE_HEADER", "CENTRAL_DIR", "EOCD") for m in zip_markers)):
            fmt = FormatType.ZIP
            header_compat = z_hdr
            footer_compat = z_ftr
            all_markers.extend(zip_markers)

    # If still unknown but has high entropy and no text
    if fmt == FormatType.UNKNOWN:
        if entropy > 7.0 and printable_ratio < 0.2:
            all_markers.append("HIGH_ENTROPY_DATA")
        elif printable_ratio > 0.8:
            all_markers.append("TEXT_OR_SCRIPT")

    return Fragment(
        fragment_id=fragment_id,
        source_offset=source_offset,
        length=length,
        sha256=sha256,
        first_bytes=first_16,
        last_bytes=last_16,
        entropy=entropy,
        byte_frequency=byte_freq,
        zero_byte_ratio=zero_ratio,
        printable_byte_ratio=printable_ratio,
        format=fmt.value if isinstance(fmt, FormatType) else str(fmt),
        header_compatibility=header_compat,
        footer_compatibility=footer_compat,
        internal_markers=all_markers,
        cluster_index=cluster_index,
        allocation_state=allocation_state,
        source_evidence=source_evidence,
        data_bytes=data,
    )
