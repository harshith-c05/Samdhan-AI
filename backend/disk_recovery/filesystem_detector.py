"""
disk_recovery/filesystem_detector.py
=====================================
Stage 2 — Filesystem Detection.

Reads the first sector(s) of a partition / image region and identifies:
  - MBR partition table (for whole-disk images)
  - FAT32   (OEM ID "FAT32   ", BPB signature 0x28/0x29, boot sig 0x55AA)
  - exFAT   (OEM ID "EXFAT   ", boot sig 0x55AA)
  - NTFS    (OEM ID "NTFS    ", boot sig 0x55AA)

Design goals
------------
* Pure-Python struct parsing — no external forensic libraries required.
* Adding a new filesystem means adding one _detect_xxx() function and
  registering it in detect_at_offset().
* No writes to the source image.
"""

from __future__ import annotations

import struct
from typing import List, Optional, Tuple

from .models import FilesystemInfo, FilesystemType, PartitionInfo
from .reader import ImageReader


# ─── MBR constants ───────────────────────────────────────────────────────────
MBR_SIGNATURE   = b"\x55\xaa"
MBR_PART_OFFSET = 446          # byte offset of first partition entry
MBR_PART_SIZE   = 16           # each entry is 16 bytes
MBR_PART_COUNT  = 4

# Partition type bytes that indicate FAT32 / exFAT / NTFS
FAT32_TYPES  = {0x0B, 0x0C}   # FAT32 CHS / FAT32 LBA
EXFAT_TYPES  = {0x07}         # shared with NTFS — need secondary check
NTFS_TYPES   = {0x07}
EXTENDED_TYPES = {0x05, 0x0F, 0x85}  # extended/logical partitions (skip)


# ─── OEM ID magic bytes ───────────────────────────────────────────────────────
OEM_FAT32 = b"FAT32   "
OEM_EXFAT = b"EXFAT   "
OEM_NTFS  = b"NTFS    "


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _read_oem_id(sector: bytes) -> bytes:
    """Bytes 3-10 of boot sector = OEM ID."""
    if len(sector) < 11:
        return b""
    return sector[3:11]


def _boot_sig_ok(sector: bytes) -> bool:
    """Last 2 bytes of a 512-byte boot sector must be 0x55 0xAA."""
    return len(sector) >= 512 and sector[510:512] == MBR_SIGNATURE


# ─── Per-filesystem detection helpers ─────────────────────────────────────────

def _detect_fat32(sector: bytes, base_byte: int) -> Optional[FilesystemInfo]:
    """
    FAT32 BPB layout (Microsoft FAT Specification 1.03):
      0x0B-0x0C  Bytes Per Sector (u16le)
      0x0D       Sectors Per Cluster (u8)
      0x0E-0x0F  Reserved Sectors (u16le)
      0x10       Number of FATs (u8)
      0x20-0x23  Total Sectors 32 (u32le)
      0x24-0x27  FAT Size 32 (u32le)
      0x42       Extended Boot Record Signature (0x28 or 0x29)
      0x52-0x59  File System Type ("FAT32   ")
    """
    if len(sector) < 90:
        return None
    if not _boot_sig_ok(sector):
        return None

    oem = _read_oem_id(sector)
    fs_type = sector[0x52:0x5A] if len(sector) >= 0x5A else b""
    ext_sig_42 = sector[0x42] if len(sector) > 0x42 else 0

    # Must be identifiable as FAT32
    is_fat32 = (
        oem == OEM_FAT32
        or b"FAT32" in fs_type
        or (ext_sig_42 in (0x28, 0x29) and (b"FAT" in oem or b"MSDOS" in oem or b"MSWIN" in oem or b"mkfs" in oem))
    )
    if not is_fat32:
        return None

    bytes_per_sector  = struct.unpack_from("<H", sector, 0x0B)[0]
    if bytes_per_sector not in (512, 1024, 2048, 4096):
        bytes_per_sector = 512
    sectors_per_clust = sector[0x0D] or 8
    reserved_sectors  = struct.unpack_from("<H", sector, 0x0E)[0]
    total_sectors_16  = struct.unpack_from("<H", sector, 0x13)[0]
    total_sectors_32  = struct.unpack_from("<I", sector, 0x20)[0]
    total_sectors     = total_sectors_32 or total_sectors_16
    fat_size_sectors  = struct.unpack_from("<I", sector, 0x24)[0]
    num_fats          = sector[0x10] or 2

    # FAT data region starts after reserved + FATs
    data_start = reserved_sectors + num_fats * fat_size_sectors
    free_approx = max(0, total_sectors - data_start)

    label_raw = sector[0x47:0x52] if len(sector) >= 0x52 else b""
    label = label_raw.decode("ascii", errors="replace").strip()

    cluster_bytes = bytes_per_sector * sectors_per_clust if sectors_per_clust else 4096

    return FilesystemInfo(
        filesystem=FilesystemType.FAT32,
        label=label or None,
        sector_size=bytes_per_sector or 512,
        cluster_size=cluster_bytes,
        total_sectors=total_sectors,
        free_sectors=free_approx,
        start_byte=base_byte,
    )


def _detect_exfat(sector: bytes, base_byte: int) -> Optional[FilesystemInfo]:
    """
    exFAT boot sector layout (Microsoft exFAT Specification):
      0x03-0x0A  OEM ID  "EXFAT   "
      0x40-0x43  Cluster Heap Offset (u32le)
      0x48-0x4B  Total Sectors (u64le at 0x48, but only u32 needed here)
      0x6C-0x6F  Sector Size Shift (u8 at 0x6C)
    """
    if len(sector) < 0x6E:
        return None
    oem = _read_oem_id(sector)
    if oem != OEM_EXFAT:
        return None

    sector_size_shift  = sector[0x6C] if len(sector) > 0x6C else 9
    cluster_size_shift = sector[0x6D] if len(sector) > 0x6D else 3
    sector_sz  = 1 << sector_size_shift
    cluster_sz = sector_sz * (1 << cluster_size_shift)
    total_sec  = struct.unpack_from("<Q", sector, 0x48)[0] if len(sector) >= 0x50 else 0

    label_raw = sector[0x78:0x88] if len(sector) >= 0x88 else b""
    label = label_raw.decode("utf-16-le", errors="replace").rstrip("\x00").strip()

    return FilesystemInfo(
        filesystem=FilesystemType.EXFAT,
        label=label or None,
        sector_size=sector_sz,
        cluster_size=cluster_sz,
        total_sectors=total_sec,
        free_sectors=0,    # would require FAT walk
        start_byte=base_byte,
    )


def _detect_ntfs(sector: bytes, base_byte: int) -> Optional[FilesystemInfo]:
    """
    NTFS boot sector layout:
      0x03-0x0A  OEM ID  "NTFS    "
      0x0B-0x0C  Bytes Per Sector (u16le)
      0x0D       Sectors Per Cluster (u8)
      0x28-0x2F  Total Sectors (u64le)
      0x30-0x37  MFT LCN (u64le) — cluster number of $MFT
    """
    if len(sector) < 64:
        return None
    oem = _read_oem_id(sector)
    if oem != OEM_NTFS:
        return None

    bytes_per_sector  = struct.unpack_from("<H", sector, 0x0B)[0] or 512
    sectors_per_clust = sector[0x0D] or 8
    total_sectors     = struct.unpack_from("<Q", sector, 0x28)[0] if len(sector) >= 0x30 else 0
    cluster_bytes = bytes_per_sector * sectors_per_clust

    return FilesystemInfo(
        filesystem=FilesystemType.NTFS,
        label=None,        # label is in $Volume metadata file — needs MFT walk
        sector_size=bytes_per_sector,
        cluster_size=cluster_bytes,
        total_sectors=total_sectors,
        free_sectors=0,    # needs $Bitmap walk
        start_byte=base_byte,
    )


# ─── MBR partition table reader ───────────────────────────────────────────────

def parse_mbr_partitions(reader: ImageReader) -> List[PartitionInfo]:
    """
    Parse the classical MBR partition table from LBA 0.
    Returns up to 4 primary partition entries (extended entries are skipped).
    """
    mbr = reader.read_sectors(0, 1)
    if len(mbr) < 512 or mbr[510:512] != MBR_SIGNATURE:
        return []

    partitions: List[PartitionInfo] = []
    for i in range(MBR_PART_COUNT):
        offset = MBR_PART_OFFSET + i * MBR_PART_SIZE
        entry  = mbr[offset: offset + MBR_PART_SIZE]
        if len(entry) < 16:
            break

        ptype     = entry[4]
        start_lba = struct.unpack_from("<I", entry, 8)[0]
        size_sec  = struct.unpack_from("<I", entry, 12)[0]

        if start_lba == 0 or size_sec == 0:
            continue           # empty partition slot
        if ptype in EXTENDED_TYPES:
            continue           # skip extended — out of scope for Phase 1

        partitions.append(PartitionInfo(
            index=i,
            start_lba=start_lba,
            size_sectors=size_sec,
            start_byte=start_lba * 512,
            size_bytes=size_sec * 512,
            partition_type=f"0x{ptype:02x}",
            filesystem=FilesystemType.UNKNOWN,
        ))

    return partitions


# ─── Primary public function ──────────────────────────────────────────────────

def detect_at_offset(reader: ImageReader, byte_offset: int = 0,
                     partition_index: Optional[int] = None) -> Optional[FilesystemInfo]:
    """
    Attempt to identify the filesystem whose boot sector begins at *byte_offset*.
    Tries FAT32, exFAT, NTFS in that order.
    Returns None if nothing is recognised.
    """
    sector = reader.read_bytes(byte_offset, 512)
    if len(sector) < 512:
        return None

    for detector in (_detect_fat32, _detect_exfat, _detect_ntfs):
        info = detector(sector, byte_offset)
        if info is not None:
            info.partition_index = partition_index
            return info

    return None


def detect_all_filesystems(reader: ImageReader) -> Tuple[List[PartitionInfo], List[FilesystemInfo]]:
    """
    Full discovery pass:
      1. Parse MBR partition table.
      2. Probe each partition's boot sector.
      3. Also probe offset 0 itself (for images with no MBR — FAT32/exFAT superfloppy).
    Returns (partitions, filesystems).
    """
    partitions = parse_mbr_partitions(reader)
    filesystems: List[FilesystemInfo] = []

    # Probe each MBR partition
    for part in partitions:
        fs = detect_at_offset(reader, part.start_byte, part.index)
        if fs:
            part.filesystem = fs.filesystem
            filesystems.append(fs)

    # Also probe the image from byte 0 (superfloppy / no-MBR images)
    if not filesystems:
        fs = detect_at_offset(reader, 0, None)
        if fs:
            filesystems.append(fs)

    return partitions, filesystems
