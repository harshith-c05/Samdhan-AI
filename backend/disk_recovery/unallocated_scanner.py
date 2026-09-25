"""
disk_recovery/unallocated_scanner.py
=====================================
Stage 3B — Unallocated / Free Region Identification.

Identifies regions of the disk image that are:
  - not assigned to any active file (free clusters / unallocated sectors)
  - FAT32: clusters whose FAT entry == 0x00000000 (free)
  - NTFS:  sectors marked free in the $Bitmap file (Phase 2 — uses sector-level
           approximation in Phase 1)
  - Beyond filesystem boundary: remainder of the image after the volume end

These regions are NEVER MODIFIED — they are represented as read-only metadata.

Phase 1 uses coarse-grained cluster-level analysis for FAT32 and
a sector-level sweep for NTFS/unknown. Fine-grained $Bitmap walk
is Phase 2.
"""

from __future__ import annotations

import struct
import uuid
from typing import List

from .models import AllocationState, FilesystemInfo, FilesystemType, UnallocatedRegion
from .reader import ImageReader


# ─── FAT32 Unallocated Region Scanner ────────────────────────────────────────

def _fat32_free_clusters(reader: ImageReader, fs: FilesystemInfo) -> List[int]:
    """Return list of cluster numbers whose FAT entry == 0 (free)."""
    base  = fs.start_byte
    boot  = reader.read_bytes(base, 512)
    bps   = struct.unpack_from("<H", boot, 0x0B)[0] or 512
    res   = struct.unpack_from("<H", boot, 0x0E)[0]
    nfats = boot[0x10] or 2
    fsz   = struct.unpack_from("<I", boot, 0x24)[0]

    fat_offset = base + res * bps
    fat_bytes  = fsz * bps
    fat_data   = reader.read_bytes(fat_offset, fat_bytes)

    free_clusters = []
    for i in range(2, len(fat_data) // 4):
        entry = struct.unpack_from("<I", fat_data, i * 4)[0] & 0x0FFFFFFF
        if entry == 0x0000000:
            free_clusters.append(i)
    return free_clusters


def _fat32_cluster_to_byte(cluster: int, data_start: int,
                            spc: int, bps: int) -> int:
    return data_start + (cluster - 2) * spc * bps


def scan_unallocated_fat32(reader: ImageReader, fs: FilesystemInfo) -> List[UnallocatedRegion]:
    """
    Walk FAT32 free-cluster list and merge consecutive free clusters into
    contiguous UnallocatedRegion records.
    """
    base = fs.start_byte
    boot = reader.read_bytes(base, 512)
    bps  = struct.unpack_from("<H", boot, 0x0B)[0] or 512
    spc  = boot[0x0D] or 8
    res  = struct.unpack_from("<H", boot, 0x0E)[0]
    nfats = boot[0x10] or 2
    fsz  = struct.unpack_from("<I", boot, 0x24)[0]
    data_start = base + (res + nfats * fsz) * bps

    free_clusters = _fat32_free_clusters(reader, fs)
    if not free_clusters:
        return []

    regions: List[UnallocatedRegion] = []
    region_start: int = free_clusters[0]
    region_end:   int = free_clusters[0]
    counter = 0

    def flush(start: int, end: int):
        nonlocal counter
        counter += 1
        byte_start = _fat32_cluster_to_byte(start, data_start, spc, bps)
        byte_end   = _fat32_cluster_to_byte(end, data_start, spc, bps) + spc * bps
        regions.append(UnallocatedRegion(
            region_id=f"UNALLOC-FAT32-{counter:04d}",
            filesystem=FilesystemType.FAT32,
            start_offset=byte_start,
            end_offset=byte_end,
            size_bytes=byte_end - byte_start,
            allocation_state=AllocationState.UNALLOCATED,
            note=f"Free cluster range {start}–{end}",
        ))

    for c in free_clusters[1:]:
        if c == region_end + 1:
            region_end = c
        else:
            flush(region_start, region_end)
            region_start = c
            region_end   = c

    flush(region_start, region_end)
    return regions


# ─── Sector-level sweep for NTFS / unknown ───────────────────────────────────
# Phase 1: scan sectors in chunks of 128; if ALL bytes == 0x00, treat as free.
# This is a conservative heuristic — not a replacement for $Bitmap.
# Full $Bitmap parsing is Phase 2.

_ZERO_SECTOR = b"\x00" * 512


def scan_unallocated_sector_sweep(reader: ImageReader, fs: FilesystemInfo,
                                   start_sector: int = 0,
                                   end_sector: int = 0) -> List[UnallocatedRegion]:
    """
    Zero-sector sweep: contiguous runs of all-zero sectors are reported
    as unallocated candidate regions.

    For NTFS this is an approximation — zero sectors may also be
    legitimately allocated. $Bitmap parsing is Phase 2.
    """
    if end_sector == 0:
        # Approximate volume extent from filesystem info
        end_sector = (fs.start_byte // 512) + (fs.total_sectors or reader.total_sectors)
        end_sector = min(end_sector, reader.total_sectors)

    regions: List[UnallocatedRegion] = []
    counter = 0
    run_start: int = -1
    run_end:   int = -1
    BATCH = 128

    lba = start_sector
    while lba < end_sector:
        count = min(BATCH, end_sector - lba)
        raw   = reader.read_sectors(lba, count)
        for i in range(count):
            sec = raw[i * 512: (i + 1) * 512]
            is_zero = (sec == _ZERO_SECTOR or sec == b"")

            if is_zero:
                if run_start < 0:
                    run_start = lba + i
                run_end = lba + i
            else:
                if run_start >= 0 and run_end - run_start >= 7:
                    # only report runs >= 8 consecutive zero sectors (4 KiB)
                    counter += 1
                    byte_s = run_start * 512
                    byte_e = (run_end + 1) * 512
                    regions.append(UnallocatedRegion(
                        region_id=f"UNALLOC-SWEEP-{counter:04d}",
                        filesystem=fs.filesystem,
                        start_offset=byte_s,
                        end_offset=byte_e,
                        size_bytes=byte_e - byte_s,
                        allocation_state=AllocationState.UNALLOCATED,
                        note=f"Zero-sector run LBA {run_start}–{run_end} (Phase-1 heuristic)",
                    ))
                run_start = -1
                run_end   = -1
        lba += count

    if run_start >= 0 and run_end - run_start >= 7:
        counter += 1
        byte_s = run_start * 512
        byte_e = (run_end + 1) * 512
        regions.append(UnallocatedRegion(
            region_id=f"UNALLOC-SWEEP-{counter:04d}",
            filesystem=fs.filesystem,
            start_offset=byte_s,
            end_offset=byte_e,
            size_bytes=byte_e - byte_s,
            allocation_state=AllocationState.UNALLOCATED,
            note=f"Zero-sector run LBA {run_start}–{run_end} (Phase-1 heuristic)",
        ))

    return regions


# ─── Beyond-volume unallocated region ────────────────────────────────────────

def find_post_volume_region(reader: ImageReader,
                             fs: FilesystemInfo) -> List[UnallocatedRegion]:
    """
    If the image file is larger than the volume end, the trailing bytes are
    unallocated / raw space and important for carving.
    """
    if fs.total_sectors == 0:
        return []
    vol_end_byte = fs.start_byte + fs.total_sectors * fs.sector_size
    if vol_end_byte < reader.size_bytes:
        return [UnallocatedRegion(
            region_id="UNALLOC-TAIL-0001",
            filesystem=fs.filesystem,
            start_offset=vol_end_byte,
            end_offset=reader.size_bytes,
            size_bytes=reader.size_bytes - vol_end_byte,
            allocation_state=AllocationState.UNALLOCATED,
            note="Region beyond declared filesystem boundary",
        )]
    return []


# ─── Dispatcher ───────────────────────────────────────────────────────────────

def scan_unallocated(reader: ImageReader,
                     fs: FilesystemInfo) -> List[UnallocatedRegion]:
    """Main entry point — route to appropriate scanner for the filesystem."""
    regions: List[UnallocatedRegion] = []

    if fs.filesystem == FilesystemType.FAT32:
        regions += scan_unallocated_fat32(reader, fs)
    else:
        # NTFS, exFAT, UNKNOWN — use sector sweep heuristic
        start_sec = fs.start_byte // 512
        end_sec   = start_sec + (fs.total_sectors or reader.total_sectors)
        end_sec   = min(end_sec, reader.total_sectors)
        regions += scan_unallocated_sector_sweep(reader, fs, start_sec, end_sec)

    regions += find_post_volume_region(reader, fs)
    return regions
