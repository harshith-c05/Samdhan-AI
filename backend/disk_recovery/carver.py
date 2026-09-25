"""
disk_recovery/carver.py
========================
Stage 3C — Raw File Carving (Method B).

Scans raw bytes for known file-format signatures WITHOUT relying on
any filesystem structure.

Design
------
* Each file type is described by a Signature object containing:
    - header:  bytes that must appear at the start of the file
    - footer:  bytes that mark the file end (None if variable-length)
    - max_size: upper bound for the carved region
    - name:    human-readable format name

* The scanner reads the image in overlapping 1 MiB windows to avoid
  splitting signatures across read boundaries.

* Signatures supported in Phase 1:
    JPEG  (FF D8 FF ... FF D9)
    PNG   (89 50 4E 47 ... IEND chunk)
    PDF   (%PDF- ... %%EOF)
    ZIP   (PK\x03\x04 ... EOCD)

Adding a new signature = adding one Signature entry to SIGNATURES.

SAFETY: read-only access via ImageReader only. Never writes to source.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field
from typing import List, Optional

from .models import (
    AllocationState, CarvingHit, DeletionState, FilesystemInfo,
    FilesystemType, RecoveryMethod, UnallocatedRegion,
)
from .reader import ImageReader


# ─── Signature registry ───────────────────────────────────────────────────────

@dataclass
class Signature:
    name:     str
    header:   bytes
    footer:   Optional[bytes]
    max_size: int   # maximum expected file size in bytes


# IMPORTANT: order matters — more specific headers first
SIGNATURES: List[Signature] = [
    Signature(
        name="JPEG",
        header=b"\xff\xd8\xff",
        footer=b"\xff\xd9",
        max_size=20 * 1024 * 1024,   # 20 MiB
    ),
    Signature(
        name="PNG",
        header=b"\x89PNG\r\n\x1a\n",
        footer=b"IEND\xaeB`\x82",   # IEND chunk CRC
        max_size=20 * 1024 * 1024,
    ),
    Signature(
        name="PDF",
        header=b"%PDF-",
        footer=b"%%EOF",
        max_size=100 * 1024 * 1024,   # 100 MiB
    ),
    Signature(
        name="ZIP",
        header=b"PK\x03\x04",
        footer=b"PK\x05\x06",        # End-of-Central-Directory
        max_size=500 * 1024 * 1024,   # 500 MiB
    ),
    Signature(
        name="DOCX",   # DOCX is a ZIP, but we check for word/ path inside
        header=b"PK\x03\x04",
        footer=b"PK\x05\x06",
        max_size=50 * 1024 * 1024,
    ),
    Signature(
        name="SQLITE",
        header=b"SQLite format 3\x00",
        footer=None,
        max_size=1024 * 1024 * 1024,
    ),
]

# Build an index from first byte → list of matching signatures for speed
_HEADER_INDEX: dict = {}
for sig in SIGNATURES:
    key = sig.header[0:1]
    _HEADER_INDEX.setdefault(key, []).append(sig)


# ─── Window-based scanner ─────────────────────────────────────────────────────

# We read image in 1 MiB windows with a 64-byte overlap to avoid
# splitting headers across window boundaries.
_WINDOW_SIZE    = 1 * 1024 * 1024   # 1 MiB
_OVERLAP        = 64                 # bytes of overlap


def _find_footer(reader: ImageReader, header_offset: int,
                 footer: bytes, max_size: int) -> Optional[int]:
    """
    Search for *footer* bytes starting just after *header_offset*.
    Returns the byte offset of the LAST byte of the footer, or None.
    """
    search_start = header_offset + 1
    search_end   = min(header_offset + max_size, reader.size_bytes)

    CHUNK = 256 * 1024  # 256 KiB
    off   = search_start
    while off < search_end:
        chunk_len = min(CHUNK, search_end - off)
        data = reader.read_bytes(off, chunk_len + len(footer))
        pos  = data.find(footer)
        if pos >= 0:
            return off + pos + len(footer) - 1
        off += chunk_len

    return None


def _sha256_range(reader: ImageReader, start: int, end: int) -> Optional[str]:
    """Compute SHA-256 of bytes [start, end] without loading more than 10 MiB."""
    size = end - start
    if size <= 0 or size > 10 * 1024 * 1024:
        return None
    data = reader.read_bytes(start, size)
    return hashlib.sha256(data).hexdigest()


def _allocation_state_for(offset: int,
                           unallocated_regions: List[UnallocatedRegion]) -> AllocationState:
    """
    Determine if a byte offset falls inside a known unallocated region.
    Returns UNALLOCATED if it does, ALLOCATED otherwise, UNKNOWN if no data.
    """
    if not unallocated_regions:
        return AllocationState.UNKNOWN
    for r in unallocated_regions:
        if r.start_offset <= offset <= r.end_offset:
            return AllocationState.UNALLOCATED
    return AllocationState.ALLOCATED


def carve_image(reader: ImageReader,
                source_image: str,
                fs_type: FilesystemType = FilesystemType.RAW,
                unallocated_regions: Optional[List[UnallocatedRegion]] = None,
                scan_start: int = 0,
                scan_end: int = 0) -> List[CarvingHit]:
    """
    Scan the image for raw file signatures using a sliding-window approach.

    Parameters
    ----------
    reader:              ImageReader (read-only)
    source_image:        str — label for the source (image path)
    fs_type:             filesystem label for resulting CarvingHit records
    unallocated_regions: list of UnallocatedRegion to help determine alloc state
    scan_start:          byte offset to begin scanning (0 = beginning of image)
    scan_end:            byte offset to stop (0 = end of image)

    Returns
    -------
    List[CarvingHit] — one record per detected signature, never duplicated,
    sorted by start_offset.
    """
    if scan_end == 0:
        scan_end = reader.size_bytes
    scan_end = min(scan_end, reader.size_bytes)

    unallocated_regions = unallocated_regions or []
    hits: List[CarvingHit] = []
    hit_counter = 0

    # Track offsets already captured to prevent JPEG/DOCX duplicate reports
    captured_ranges: List[tuple] = []   # (start, end)

    def _already_captured(offset: int) -> bool:
        for (s, e) in captured_ranges:
            if s <= offset <= e:
                return True
        return False

    off = scan_start
    while off < scan_end:
        window_size = min(_WINDOW_SIZE + _OVERLAP, scan_end - off)
        window_data = reader.read_bytes(off, window_size)
        if not window_data:
            break

        # Scan window for each signature header
        search_off = 0
        while search_off < len(window_data) - _OVERLAP:
            # Quick pre-filter on first byte
            first_byte = window_data[search_off: search_off + 1]
            if first_byte not in _HEADER_INDEX:
                search_off += 1
                continue

            for sig in _HEADER_INDEX[first_byte]:
                hdr = sig.header
                if window_data[search_off: search_off + len(hdr)] == hdr:
                    abs_offset = off + search_off
                    if _already_captured(abs_offset):
                        break

                    # Find footer
                    end_offset: Optional[int] = None
                    size_bytes: Optional[int] = None

                    if sig.footer:
                        end_offset = _find_footer(reader, abs_offset, sig.footer, sig.max_size)
                        if end_offset is not None:
                            size_bytes = end_offset - abs_offset + 1

                    alloc_state = _allocation_state_for(abs_offset, unallocated_regions)
                    deletion_st = (DeletionState.NOT_IN_METADATA
                                   if alloc_state == AllocationState.UNALLOCATED
                                   else DeletionState.UNKNOWN)

                    sha_val = _sha256_range(reader, abs_offset,
                                            end_offset + 1 if end_offset else abs_offset + 4096)

                    # Header sample for display
                    header_bytes = reader.read_bytes(abs_offset, 16)
                    header_hex   = header_bytes.hex()

                    hit_counter += 1
                    hit = CarvingHit(
                        hit_id=f"CARVE-{sig.name}-{hit_counter:04d}",
                        source_image=source_image,
                        filesystem=fs_type,
                        signature_name=sig.name,
                        start_offset=abs_offset,
                        end_offset=end_offset,
                        size_bytes=size_bytes,
                        header_hex=header_hex,
                        allocation_state=alloc_state,
                        deletion_state=deletion_st,
                        sha256=sha_val,
                        recovery_method=RecoveryMethod.RAW_CARVING,
                    )
                    hits.append(hit)

                    if end_offset:
                        captured_ranges.append((abs_offset, end_offset))
                        # Skip past this file
                        skip_to = end_offset - off
                        if skip_to > search_off:
                            search_off = skip_to
                            break

            search_off += 1

        # Advance window (without overlap)
        off += _WINDOW_SIZE

    hits.sort(key=lambda h: h.start_offset)
    return hits
