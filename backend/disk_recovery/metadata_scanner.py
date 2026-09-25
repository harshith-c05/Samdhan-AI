"""
disk_recovery/metadata_scanner.py
===================================
Stage 3A — Filesystem Metadata Path (Method A).

Walks filesystem metadata structures to enumerate:
  * allocated files (still live in directory entries)
  * deleted files (directory entries marked deleted, metadata partially intact)

For Phase 1 we implement:
  - FAT32  directory-entry scanner (Method A-FAT32)
  - NTFS   MFT-record scanner    (Method A-NTFS)

exFAT metadata scanning is architecturally present but marked
NOT_IMPLEMENTED — the carver (Method B) will still find exFAT files.

SAFETY: read-only access via ImageReader only.
"""

from __future__ import annotations

import hashlib
import struct
import uuid
from typing import List, Optional

from .models import (
    AllocationState, DeletionState, DiscoveredFile, FilesystemInfo,
    FilesystemType, RecoveryMethod,
)
from .reader import ImageReader


# ═══════════════════════════════════════════════════════════════════════════════
# FAT32 METADATA SCANNER
# ═══════════════════════════════════════════════════════════════════════════════

# FAT32 directory-entry layout (32 bytes per entry)
_FAT_ENTRY_SIZE = 32
_FAT_DELETED    = 0xE5     # first byte of a deleted-file entry
_FAT_FREE       = 0x00     # slot never used
_FAT_DOT        = 0x2E     # "." or ".." entries
_ATTR_LONG_NAME = 0x0F     # LFN attribute mask
_ATTR_DIRECTORY = 0x10
_ATTR_VOLUME_ID = 0x08

# FAT32 BPB offsets (relative to volume start)
_BPB_BYTES_PER_SECTOR   = 0x0B
_BPB_SECTORS_PER_CLUST  = 0x0D
_BPB_RESERVED_SECTORS   = 0x0E
_BPB_NUM_FATS           = 0x10
_BPB_FAT_SIZE32         = 0x24
_BPB_ROOT_CLUSTER       = 0x2C


def _fat32_cluster_to_byte(cluster: int, data_start_byte: int,
                            sectors_per_cluster: int, sector_size: int) -> int:
    """Convert a FAT32 cluster number to a byte offset in the image."""
    return data_start_byte + (cluster - 2) * sectors_per_cluster * sector_size


def _read_fat32_fat(reader: ImageReader, fs: FilesystemInfo) -> dict:
    """
    Read the entire FAT (File Allocation Table) into a dict {cluster: next_cluster}.
    Only reads FAT1 (primary copy).
    """
    base = fs.start_byte
    boot = reader.read_bytes(base, 512)
    bytes_per_sector  = struct.unpack_from("<H", boot, _BPB_BYTES_PER_SECTOR)[0]
    reserved_sectors  = struct.unpack_from("<H", boot, _BPB_RESERVED_SECTORS)[0]
    fat_size_sectors  = struct.unpack_from("<I", boot, _BPB_FAT_SIZE32)[0]

    fat_byte_offset = base + reserved_sectors * bytes_per_sector
    fat_size_bytes  = fat_size_sectors * bytes_per_sector
    fat_data = reader.read_bytes(fat_byte_offset, fat_size_bytes)

    fat: dict = {}
    for idx in range(len(fat_data) // 4):
        val = struct.unpack_from("<I", fat_data, idx * 4)[0] & 0x0FFFFFFF
        fat[idx] = val
    return fat


def _follow_cluster_chain(fat: dict, start_cluster: int,
                           max_clusters: int = 4096) -> List[int]:
    """Walk the FAT chain from start_cluster. Returns list of cluster numbers."""
    chain = []
    cluster = start_cluster
    seen = set()
    while cluster >= 2 and cluster < 0x0FFFFFF8:
        if cluster in seen or len(chain) >= max_clusters:
            break
        seen.add(cluster)
        chain.append(cluster)
        cluster = fat.get(cluster, 0x0FFFFFFF)
    return chain


def _parse_fat32_8dot3(entry: bytes) -> str:
    """Decode an 8.3 short filename from a FAT32 directory entry."""
    if len(entry) < 11:
        return "UNKNOWN"
    raw = entry[0:8].rstrip(b" ")
    ext = entry[8:11].rstrip(b" ")
    # first byte 0xE5 means deleted — replace with '?' for display
    if raw and raw[0] == 0x05:
        raw = b"\xe5" + raw[1:]
    name = raw.decode("ascii", errors="replace")
    if ext:
        name = name + "." + ext.decode("ascii", errors="replace")
    return name.strip()


def _fat32_timestamps(entry: bytes) -> dict:
    """Extract creation, modified, accessed timestamps from a FAT32 dir entry."""
    def fat_date(d: int) -> str:
        if d == 0:
            return "UNKNOWN"
        year  = 1980 + ((d >> 9) & 0x7F)
        month = (d >> 5) & 0x0F
        day   = d & 0x1F
        return f"{year:04d}-{month:02d}-{day:02d}"

    def fat_time(t: int) -> str:
        if t == 0:
            return "UNKNOWN"
        h = (t >> 11) & 0x1F
        m = (t >> 5) & 0x3F
        s = (t & 0x1F) * 2
        return f"{h:02d}:{m:02d}:{s:02d}"

    crt_time  = struct.unpack_from("<H", entry, 0x0E)[0] if len(entry) >= 0x10 else 0
    crt_date  = struct.unpack_from("<H", entry, 0x10)[0] if len(entry) >= 0x12 else 0
    acc_date  = struct.unpack_from("<H", entry, 0x12)[0] if len(entry) >= 0x14 else 0
    wrt_time  = struct.unpack_from("<H", entry, 0x16)[0] if len(entry) >= 0x18 else 0
    wrt_date  = struct.unpack_from("<H", entry, 0x18)[0] if len(entry) >= 0x1A else 0

    return {
        "created":  f"{fat_date(crt_date)} {fat_time(crt_time)}",
        "modified": f"{fat_date(wrt_date)} {fat_time(wrt_time)}",
        "accessed": fat_date(acc_date),
    }


def scan_fat32_metadata(reader: ImageReader, fs: FilesystemInfo,
                         source_image: str) -> List[DiscoveredFile]:
    """
    Walk the FAT32 root directory and its sub-directories.
    Finds both live and deleted entries.
    """
    results: List[DiscoveredFile] = []
    base = fs.start_byte
    boot = reader.read_bytes(base, 512)

    bytes_per_sector  = struct.unpack_from("<H", boot, _BPB_BYTES_PER_SECTOR)[0] or 512
    sectors_per_clust = boot[_BPB_SECTORS_PER_CLUST] or 8
    reserved_sectors  = struct.unpack_from("<H", boot, _BPB_RESERVED_SECTORS)[0]
    num_fats          = boot[_BPB_NUM_FATS] or 2
    fat_size_sectors  = struct.unpack_from("<I", boot, _BPB_FAT_SIZE32)[0]
    root_cluster      = struct.unpack_from("<I", boot, _BPB_ROOT_CLUSTER)[0]

    data_start_byte = (base
                       + reserved_sectors * bytes_per_sector
                       + num_fats * fat_size_sectors * bytes_per_sector)

    fat = _read_fat32_fat(reader, fs)

    # BFS over directory clusters
    dir_queue   = [(root_cluster, "/")]
    seen_dirs   = set()
    counter     = 0

    while dir_queue:
        cluster, dir_path = dir_queue.pop(0)
        if cluster in seen_dirs:
            continue
        seen_dirs.add(cluster)

        chain = _follow_cluster_chain(fat, cluster)
        lfn_parts: List[str] = []

        for c in chain:
            cluster_byte = _fat32_cluster_to_byte(
                c, data_start_byte, sectors_per_clust, bytes_per_sector)
            cluster_data = reader.read_bytes(
                cluster_byte, sectors_per_clust * bytes_per_sector)

            for slot_off in range(0, len(cluster_data), _FAT_ENTRY_SIZE):
                entry = cluster_data[slot_off: slot_off + _FAT_ENTRY_SIZE]
                if len(entry) < _FAT_ENTRY_SIZE:
                    break

                first_byte = entry[0]
                attr       = entry[0x0B]

                # Skip free slots and volume labels
                if first_byte == _FAT_FREE:
                    lfn_parts.clear()
                    continue
                if attr == _ATTR_VOLUME_ID:
                    lfn_parts.clear()
                    continue

                # LFN entry — accumulate Unicode name segments
                if attr == _ATTR_LONG_NAME:
                    try:
                        seg = (entry[1:11] + entry[14:26] + entry[28:32])
                        lfn_parts.insert(0, seg.decode("utf-16-le", errors="replace"))
                    except Exception:
                        pass
                    continue

                # Dot entries
                if first_byte in (_FAT_DOT,):
                    lfn_parts.clear()
                    continue

                # Decode 8.3 name
                short_name = _parse_fat32_8dot3(entry)

                # Use accumulated LFN if available
                if lfn_parts:
                    long_name = "".join(lfn_parts).rstrip("\x00").strip()
                    lfn_parts.clear()
                else:
                    long_name = short_name

                is_deleted = (first_byte == _FAT_DELETED)
                is_dir     = bool(attr & _ATTR_DIRECTORY)

                start_cluster_hi = struct.unpack_from("<H", entry, 0x14)[0]
                start_cluster_lo = struct.unpack_from("<H", entry, 0x1A)[0]
                start_cluster_n  = (start_cluster_hi << 16) | start_cluster_lo
                file_size        = struct.unpack_from("<I", entry, 0x1C)[0]
                timestamps       = _fat32_timestamps(entry)

                entry_byte_offset = (cluster_byte + slot_off)

                if is_dir and not is_deleted and start_cluster_n >= 2:
                    full_path = dir_path.rstrip("/") + "/" + long_name
                    dir_queue.append((start_cluster_n, full_path))

                # Try to compute SHA-256 for small readable files
                sha256_val = None
                cluster_chain = []
                if start_cluster_n >= 2:
                    cluster_chain = _follow_cluster_chain(fat, start_cluster_n)
                    if (not is_deleted) and cluster_chain and file_size > 0 and file_size < 10 * 1024 * 1024:
                        raw_data = b""
                        for cc in cluster_chain:
                            cb = _fat32_cluster_to_byte(
                                cc, data_start_byte, sectors_per_clust, bytes_per_sector)
                            raw_data += reader.read_bytes(cb, sectors_per_clust * bytes_per_sector)
                            if len(raw_data) >= file_size:
                                break
                        raw_data = raw_data[:file_size]
                        sha256_val = hashlib.sha256(raw_data).hexdigest()

                deletion_st = (DeletionState.DELETED_META_INTACT if is_deleted
                               else DeletionState.ACTIVE)
                alloc_st    = (AllocationState.UNALLOCATED if is_deleted
                               else AllocationState.ALLOCATED)

                counter += 1
                results.append(DiscoveredFile(
                    file_id=f"FAT32-META-{counter:04d}",
                    source_image=source_image,
                    filesystem=FilesystemType.FAT32,
                    filename=long_name if long_name else "UNKNOWN",
                    original_path=dir_path.rstrip("/") + "/" + long_name if long_name else "UNKNOWN",
                    file_size=file_size if not is_dir else None,
                    meta_identifier=f"dir_entry@0x{entry_byte_offset:08x}",
                    deletion_state=deletion_st,
                    allocation_state=alloc_st,
                    source_offset=_fat32_cluster_to_byte(
                        start_cluster_n, data_start_byte,
                        sectors_per_clust, bytes_per_sector) if start_cluster_n >= 2 else None,
                    cluster_chain=cluster_chain[:32],   # first 32 clusters
                    timestamps=timestamps,
                    sha256=sha256_val,
                    recovery_method=RecoveryMethod.METADATA_RECOVERY,
                    notes="Directory entry" if is_dir else "",
                ))

    return results


# ═══════════════════════════════════════════════════════════════════════════════
# NTFS MFT SCANNER
# ═══════════════════════════════════════════════════════════════════════════════

_MFT_RECORD_SIZE   = 1024  # default; can be overridden by BPB
_MFT_MAGIC         = b"FILE"
_MFT_FLAG_IN_USE   = 0x0001
_MFT_FLAG_DIRECTORY = 0x0002

# Attribute type codes
_ATTR_STANDARD_INFO = 0x10
_ATTR_FILE_NAME     = 0x30
_ATTR_DATA          = 0x80


def _ntfs_filetime_to_str(filetime: int) -> str:
    """Convert Windows FILETIME (100ns since 1601-01-01) to ISO string."""
    if filetime == 0:
        return "UNKNOWN"
    try:
        import datetime
        EPOCH_DIFF = 116444736000000000  # 100-ns intervals from 1601 to 1970
        ts = (filetime - EPOCH_DIFF) / 10_000_000
        if ts < 0 or ts > 32503680000:
            return "UNKNOWN"
        dt = datetime.datetime.utcfromtimestamp(ts)
        return dt.strftime("%Y-%m-%d %H:%M:%S") + " UTC"
    except Exception:
        return "UNKNOWN"


def _parse_ntfs_attr(record: bytes, offset: int) -> Optional[dict]:
    """Parse a single NTFS attribute header at *offset* within *record*."""
    if offset + 16 > len(record):
        return None
    attr_type = struct.unpack_from("<I", record, offset)[0]
    if attr_type == 0xFFFFFFFF:
        return None   # end-of-record sentinel
    attr_len  = struct.unpack_from("<I", record, offset + 4)[0]
    if attr_len < 8 or offset + attr_len > len(record):
        return None
    non_resident = record[offset + 8]
    name_len     = record[offset + 9]
    content_off  = struct.unpack_from("<H", record, offset + 20)[0] if not non_resident else 0
    content_len  = struct.unpack_from("<I", record, offset + 16)[0] if not non_resident else 0

    content = b""
    if not non_resident and content_off and content_len:
        s = offset + content_off
        content = record[s: s + content_len]

    return {
        "type":         attr_type,
        "length":       attr_len,
        "non_resident": bool(non_resident),
        "name_len":     name_len,
        "content":      content,
        "offset":       offset,
    }


def _parse_mft_record(data: bytes, record_no: int,
                       source_image: str) -> Optional[DiscoveredFile]:
    """
    Parse one 1024-byte MFT record.
    Returns a DiscoveredFile or None if the record is blank / corrupt.
    """
    if len(data) < _MFT_RECORD_SIZE:
        return None
    if data[:4] != _MFT_MAGIC:
        return None

    flags = struct.unpack_from("<H", data, 0x16)[0]
    is_dir     = bool(flags & _MFT_FLAG_DIRECTORY)
    in_use     = bool(flags & _MFT_FLAG_IN_USE)

    first_attr_off = struct.unpack_from("<H", data, 0x14)[0]

    filename    = "UNKNOWN"
    parent_path = "UNKNOWN"
    timestamps: dict = {}
    file_size   = None

    # Walk attributes
    off = first_attr_off
    while off < _MFT_RECORD_SIZE:
        attr = _parse_ntfs_attr(data, off)
        if attr is None:
            break

        content = attr["content"]

        if attr["type"] == _ATTR_FILE_NAME and content and len(content) >= 66:
            parent_ref = struct.unpack_from("<Q", content, 0)[0] & 0xFFFFFFFFFFFF
            fname_len  = content[64]
            if fname_len and len(content) >= 66 + fname_len * 2:
                try:
                    filename = content[66: 66 + fname_len * 2].decode("utf-16-le", errors="replace")
                except Exception:
                    filename = "UNKNOWN"
            ctime = struct.unpack_from("<Q", content, 8)[0]
            mtime = struct.unpack_from("<Q", content, 16)[0]
            atime = struct.unpack_from("<Q", content, 24)[0]
            fs_size = struct.unpack_from("<Q", content, 48)[0]
            file_size = fs_size if fs_size else file_size
            timestamps = {
                "created":  _ntfs_filetime_to_str(ctime),
                "modified": _ntfs_filetime_to_str(mtime),
                "accessed": _ntfs_filetime_to_str(atime),
            }

        if attr["type"] == _ATTR_DATA and not attr["non_resident"] and content:
            file_size = file_size or len(content)

        off += max(8, attr["length"])  # guard against zero-length inf-loop

    if filename == "UNKNOWN" and not in_use:
        return None    # blank / reallocated record with no meaningful data

    # Skip system meta-files ($MFT, $LogFile, etc.)
    if filename.startswith("$"):
        return None

    deletion_st = DeletionState.ACTIVE if in_use else DeletionState.DELETED_META_INTACT
    alloc_st    = AllocationState.ALLOCATED if in_use else AllocationState.UNALLOCATED

    return DiscoveredFile(
        file_id=f"NTFS-MFT-{record_no:06d}",
        source_image=source_image,
        filesystem=FilesystemType.NTFS,
        filename=filename,
        original_path=parent_path,   # full path needs MFT parent chain walk
        file_size=file_size,
        meta_identifier=f"MFT#{record_no}",
        deletion_state=deletion_st,
        allocation_state=alloc_st,
        source_offset=None,          # needs data-run decoding (Phase 2)
        cluster_chain=[],
        timestamps=timestamps,
        sha256=None,                 # needs data-run follow (Phase 2)
        recovery_method=RecoveryMethod.METADATA_RECOVERY,
        notes="Directory" if is_dir else "",
    )


def scan_ntfs_metadata(reader: ImageReader, fs: FilesystemInfo,
                        source_image: str) -> List[DiscoveredFile]:
    """
    Scan NTFS MFT records from the volume.
    Reads MFT location from the boot sector BPB.
    Limits scan to first 4096 records for Phase 1.
    """
    base = fs.start_byte
    boot = reader.read_bytes(base, 512)

    bytes_per_sector  = struct.unpack_from("<H", boot, 0x0B)[0] or 512
    sectors_per_clust = boot[0x0D] or 8
    cluster_bytes     = bytes_per_sector * sectors_per_clust
    mft_lcn           = struct.unpack_from("<Q", boot, 0x30)[0]

    mft_byte_offset = base + mft_lcn * cluster_bytes
    results: List[DiscoveredFile] = []

    MAX_RECORDS = 4096
    for rec_no in range(MAX_RECORDS):
        rec_offset = mft_byte_offset + rec_no * _MFT_RECORD_SIZE
        rec_data   = reader.read_bytes(rec_offset, _MFT_RECORD_SIZE)
        if not rec_data or rec_data[:4] not in (_MFT_MAGIC, b"\x00" * 4):
            if not rec_data:
                break   # past end of image
            if rec_data == b"\x00" * _MFT_RECORD_SIZE:
                continue
        parsed = _parse_mft_record(rec_data, rec_no, source_image)
        if parsed:
            results.append(parsed)

    return results


# ─── exFAT stub (architecture present, implementation deferred) ───────────────

def scan_exfat_metadata(reader: ImageReader, fs: FilesystemInfo,
                         source_image: str) -> List[DiscoveredFile]:
    """
    exFAT metadata scanning — architecture placeholder.
    exFAT directory entries use a different structure than FAT32.
    Implementation deferred to Phase 2; raw carving still finds exFAT files.
    """
    return []   # explicit empty — not a bug


# ─── Dispatcher ───────────────────────────────────────────────────────────────

def scan_metadata(reader: ImageReader, fs: FilesystemInfo,
                  source_image: str) -> List[DiscoveredFile]:
    """Route to the correct metadata scanner for the given filesystem."""
    if fs.filesystem == FilesystemType.FAT32:
        return scan_fat32_metadata(reader, fs, source_image)
    if fs.filesystem == FilesystemType.NTFS:
        return scan_ntfs_metadata(reader, fs, source_image)
    if fs.filesystem == FilesystemType.EXFAT:
        return scan_exfat_metadata(reader, fs, source_image)
    return []
