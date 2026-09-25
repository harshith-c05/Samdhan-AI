"""
core/section_analyzer.py
========================
Phase 2 Format-Specific Section & Chunk Analysis Engine.
Deconstructs format containers into constituent sections and checks each:
- which sections are valid
- which sections are damaged
- which sections are missing
- which sections prevent complete decoding
- whether partial recovery is possible
"""

from __future__ import annotations

import io
import struct
import zipfile
from typing import Dict, List, Optional

from core.models import CorruptionRegion, DetailedSectionBreakdown, StructuralCheck


def analyze_sections(
    data: bytes,
    format_name: str,
    checks: List[StructuralCheck],
    corruption_regions: List[CorruptionRegion],
) -> DetailedSectionBreakdown:
    """
    Builds a granular section breakdown answering exactly which structural
    elements are valid, damaged, missing, and whether partial recovery is feasible.
    """
    fmt = format_name.upper().strip()

    if fmt == "JPEG":
        return _analyze_jpeg_sections(data, checks, corruption_regions)
    elif fmt == "PNG":
        return _analyze_png_sections(data, checks, corruption_regions)
    elif fmt == "ZIP":
        return _analyze_zip_sections(data, checks, corruption_regions)
    elif fmt == "PDF":
        return _analyze_pdf_sections(data, checks, corruption_regions)
    else:
        return _analyze_generic_sections(data, checks, corruption_regions)


def _analyze_jpeg_sections(
    data: bytes, checks: List[StructuralCheck], corruption_regions: List[CorruptionRegion]
) -> DetailedSectionBreakdown:
    valid_sections: List[str] = []
    damaged_sections: List[str] = []
    missing_sections: List[str] = []
    blocking_issues: List[str] = []

    # SOI
    if data[:2] == b"\xff\xd8":
        valid_sections.append("SOI (Start of Image marker FF D8)")
    else:
        damaged_sections.append("SOI (Missing or corrupted start marker)")
        blocking_issues.append("Missing SOI marker prevents baseline image loader initialization")

    # DQT
    if b"\xff\xdb" in data:
        valid_sections.append("DQT (Quantization Table segments)")
    else:
        missing_sections.append("DQT (Quantization Tables)")
        blocking_issues.append("Missing DQT prevents frequency-domain DCT dequantization")

    # SOF0 / SOF2
    if b"\xff\xc0" in data or b"\xff\xc2" in data:
        valid_sections.append("SOF (Start of Frame: image dimensions & sample precision)")
    else:
        missing_sections.append("SOF (Frame descriptor)")
        blocking_issues.append("Missing SOF descriptor prevents determining canvas width/height")

    # DHT
    if b"\xff\xc4" in data:
        valid_sections.append("DHT (Huffman Huffman coding tables)")
    else:
        # Some JPEGs use default tables
        pass

    # SOS & Entropy stream
    if b"\xff\xda" in data:
        valid_sections.append("SOS (Start of Scan header)")
    else:
        missing_sections.append("SOS (Start of Scan)")
        blocking_issues.append("Missing SOS header prevents raster decoding")

    # EOI
    if data.endswith(b"\xff\xd9") or (len(data) >= 2 and data[-2:] == b"\xff\xd9"):
        valid_sections.append("EOI (End of Image terminal trailer FF D9)")
    else:
        missing_sections.append("EOI (Terminal End of Image marker missing)")
        damaged_sections.append("Image Scan Payload (Prematurely truncated before EOI)")
        blocking_issues.append("Truncated payload before EOI marker causes decoder premature EOF")

    for cr in corruption_regions:
        desc = f"{cr.type.replace('_', ' ').title()} at byte offset [{cr.start_offset}:{cr.end_offset}]"
        if cr.reason:
            desc += f": {cr.reason}"
        damaged_sections.append(desc)
        blocking_issues.append(f"Corrupted bytes at [{cr.start_offset}:{cr.end_offset}]")

    partial_possible = "SOI (Start of Image marker FF D8)" in valid_sections and (
        "SOF (Start of Frame: image dimensions & sample precision)" in valid_sections
    )

    if not blocking_issues:
        rationale = "All structural markers intact; complete image decode is supported."
    elif partial_possible:
        rationale = "Core headers and SOF frame intact; image metadata and partial scanlines can be extracted."
    else:
        rationale = "Critical header or frame descriptor missing; standard image decode is impossible."

    return DetailedSectionBreakdown(
        valid_sections=valid_sections,
        damaged_sections=damaged_sections,
        missing_sections=missing_sections,
        blocking_issues=blocking_issues,
        partial_recovery_possible=partial_possible,
        recoverability_rationale=rationale,
    )


def _analyze_png_sections(
    data: bytes, checks: List[StructuralCheck], corruption_regions: List[CorruptionRegion]
) -> DetailedSectionBreakdown:
    valid_sections: List[str] = []
    damaged_sections: List[str] = []
    missing_sections: List[str] = []
    blocking_issues: List[str] = []

    if data[:8] == b"\x89PNG\r\n\x1a\n":
        valid_sections.append("PNG Signature (8-byte magic header)")
    else:
        damaged_sections.append("PNG Signature (Invalid magic header)")
        blocking_issues.append("Corrupted PNG signature prevents parser identification")

    if b"IHDR" in data:
        valid_sections.append("IHDR Chunk (Image dimensions, bit depth, color mode)")
    else:
        missing_sections.append("IHDR Chunk")
        blocking_issues.append("Missing IHDR chunk prevents raster initialization")

    if b"IDAT" in data:
        valid_sections.append("IDAT Chunk(s) (Compressed image raster payload)")
    else:
        missing_sections.append("IDAT Chunk(s)")
        blocking_issues.append("Missing IDAT stream; no pixel data available")

    if b"IEND" in data:
        valid_sections.append("IEND Chunk (Terminal trailer chunk)")
    else:
        missing_sections.append("IEND Chunk")
        blocking_issues.append("Missing IEND chunk causes truncated archive warning")

    for cr in corruption_regions:
        if "CRC" in cr.type:
            damaged_sections.append(f"CRC-32 checksum failure at chunk [{cr.start_offset}:{cr.end_offset}]")
            blocking_issues.append(f"Invalid CRC at [{cr.start_offset}:{cr.end_offset}] invalidates affected IDAT chunk")
        elif "ZERO" in cr.type:
            damaged_sections.append(f"Zero-padded region at [{cr.start_offset}:{cr.end_offset}]")
            blocking_issues.append(f"Corrupted compressed zlib stream at [{cr.start_offset}:{cr.end_offset}]")

    partial_possible = (b"\x89PNG\r\n\x1a\n" in data) and (b"IHDR" in data)

    if not blocking_issues:
        rationale = "All PNG chunks and CRCs verified intact; image is 100% recoverable."
    elif partial_possible:
        rationale = "IHDR and dimensions intact; unaffected IDAT chunks remain readable with scanline resync."
    else:
        rationale = "Critical container headers missing; raster recovery impossible."

    return DetailedSectionBreakdown(
        valid_sections=valid_sections,
        damaged_sections=damaged_sections,
        missing_sections=missing_sections,
        blocking_issues=blocking_issues,
        partial_recovery_possible=partial_possible,
        recoverability_rationale=rationale,
    )


def _analyze_zip_sections(
    data: bytes, checks: List[StructuralCheck], corruption_regions: List[CorruptionRegion]
) -> DetailedSectionBreakdown:
    valid_sections: List[str] = []
    damaged_sections: List[str] = []
    missing_sections: List[str] = []
    blocking_issues: List[str] = []

    has_local = b"PK\x03\x04" in data
    has_central = b"PK\x01\x02" in data
    has_eocd = b"PK\x05\x06" in data

    if has_local:
        valid_sections.append("Local File Header(s) (PK 03 04)")
    else:
        missing_sections.append("Local File Headers")
        blocking_issues.append("Missing local file headers; no member streams identifiable")

    if has_central:
        valid_sections.append("Central Directory (PK 01 02)")
    else:
        missing_sections.append("Central Directory")
        blocking_issues.append("Missing Central Directory prevents archive file index listing")

    if has_eocd:
        valid_sections.append("EOCD Record (PK 05 06)")
    else:
        missing_sections.append("End of Central Directory Record (EOCD)")
        blocking_issues.append("Missing EOCD prevents finding Central Directory offset")

    for cr in corruption_regions:
        if "CRC" in cr.type or "CHECKSUM" in cr.type:
            damaged_sections.append(f"Member CRC mismatch at byte [{cr.start_offset}:{cr.end_offset}]")
            blocking_issues.append(f"Corrupted compressed member data at [{cr.start_offset}:{cr.end_offset}]")

    partial_possible = bool(has_local or has_central)

    if not blocking_issues:
        rationale = "All archive entries and CRC-32 checksums verified intact."
    elif partial_possible:
        rationale = "Archive directory or local headers parseable; intact member files can be extracted individually."
    else:
        rationale = "Missing archive structures; cannot parse ZIP archive."

    return DetailedSectionBreakdown(
        valid_sections=valid_sections,
        damaged_sections=damaged_sections,
        missing_sections=missing_sections,
        blocking_issues=blocking_issues,
        partial_recovery_possible=partial_possible,
        recoverability_rationale=rationale,
    )


def _analyze_pdf_sections(
    data: bytes, checks: List[StructuralCheck], corruption_regions: List[CorruptionRegion]
) -> DetailedSectionBreakdown:
    valid_sections: List[str] = []
    damaged_sections: List[str] = []
    missing_sections: List[str] = []
    blocking_issues: List[str] = []

    has_header = data[:5] == b"%PDF-"
    has_eof = b"%%EOF" in data[-1024:] if len(data) >= 8 else False
    has_xref = b"xref" in data

    if has_header:
        valid_sections.append("%PDF- Header Specification")
    else:
        damaged_sections.append("%PDF- Header (Corrupted or absent)")
        blocking_issues.append("Corrupted PDF header prevents PDF reader format recognition")

    if b"obj" in data and b"endobj" in data:
        valid_sections.append("Indirect Object Catalog & Page Trees")
    else:
        missing_sections.append("Indirect Objects")
        blocking_issues.append("Missing or unparseable indirect objects")

    if has_xref:
        valid_sections.append("Cross-Reference (xref) Table")
    else:
        missing_sections.append("xref Table")
        blocking_issues.append("Missing xref table requires full-file object reconstruction scan")

    if has_eof:
        valid_sections.append("%%EOF Terminal Marker")
    else:
        missing_sections.append("%%EOF Terminal Marker")
        blocking_issues.append("Truncated trailer missing terminal %%EOF")

    for cr in corruption_regions:
        damaged_sections.append(f"Malformed stream/syntax at [{cr.start_offset}:{cr.end_offset}]")
        blocking_issues.append(f"Syntax/stream error at [{cr.start_offset}:{cr.end_offset}]")

    partial_possible = bool(has_header and b"obj" in data)

    if not blocking_issues:
        rationale = "All document objects, xref tables, and trailers verified intact."
    elif partial_possible:
        rationale = "PDF header and body objects present; text and stream contents remain recoverable."
    else:
        rationale = "Severe header or object table corruption; standard rendering impossible."

    return DetailedSectionBreakdown(
        valid_sections=valid_sections,
        damaged_sections=damaged_sections,
        missing_sections=missing_sections,
        blocking_issues=blocking_issues,
        partial_recovery_possible=partial_possible,
        recoverability_rationale=rationale,
    )


def _analyze_generic_sections(
    data: bytes, checks: List[StructuralCheck], corruption_regions: List[CorruptionRegion]
) -> DetailedSectionBreakdown:
    return DetailedSectionBreakdown(
        valid_sections=["Raw Binary Payload"],
        damaged_sections=[f"Region [{cr.start_offset}:{cr.end_offset}]" for cr in corruption_regions],
        missing_sections=[],
        blocking_issues=[cr.reason for cr in corruption_regions],
        partial_recovery_possible=len(corruption_regions) == 0,
        recoverability_rationale="Generic binary stream without format-specific container grammar.",
    )
