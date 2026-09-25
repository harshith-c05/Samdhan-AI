"""
disk_recovery/models.py
======================
Pydantic models and plain dataclasses shared across the entire
Phase-1 disk-recovery pipeline.

Nothing in here does any I/O or computation.
"""

from __future__ import annotations

import enum
from typing import List, Optional
from pydantic import BaseModel, Field


# ─── Enumerations ────────────────────────────────────────────────────────────

class AllocationState(str, enum.Enum):
    ALLOCATED   = "ALLOCATED"
    UNALLOCATED = "UNALLOCATED"
    UNKNOWN     = "UNKNOWN"


class DeletionState(str, enum.Enum):
    ACTIVE               = "ACTIVE"           # file is still live in the filesystem
    DELETED_META_INTACT  = "DELETED_META_INTACT"   # deleted but dir-entry still readable
    DELETED_META_PARTIAL = "DELETED_META_PARTIAL"  # dir-entry partially overwritten
    NOT_IN_METADATA      = "NOT_IN_METADATA"       # found by carving only
    UNKNOWN              = "UNKNOWN"


class RecoveryMethod(str, enum.Enum):
    METADATA_RECOVERY = "METADATA_RECOVERY"   # Method A — follow filesystem
    RAW_CARVING       = "RAW_CARVING"         # Method B — signature scan
    BOTH              = "BOTH"


class FilesystemType(str, enum.Enum):
    FAT32   = "FAT32"
    EXFAT   = "exFAT"
    NTFS    = "NTFS"
    UNKNOWN = "UNKNOWN"
    RAW     = "RAW"           # no recognisable filesystem (carve-only)


# ─── Core records ─────────────────────────────────────────────────────────────

class PartitionInfo(BaseModel):
    index:           int
    start_lba:       int
    size_sectors:    int
    start_byte:      int
    size_bytes:      int
    partition_type:  str          # hex string, e.g. "0b" for FAT32
    filesystem:      FilesystemType = FilesystemType.UNKNOWN


class FilesystemInfo(BaseModel):
    filesystem:      FilesystemType
    partition_index: Optional[int] = None   # None → whole-disk image
    label:           Optional[str] = None
    sector_size:     int = 512
    cluster_size:    int = 4096
    total_sectors:   int = 0
    free_sectors:    int = 0
    start_byte:      int = 0                # byte offset inside the image


class UnallocatedRegion(BaseModel):
    region_id:       str
    filesystem:      FilesystemType
    start_offset:    int          # byte offset from image start
    end_offset:      int
    size_bytes:      int
    allocation_state: AllocationState = AllocationState.UNALLOCATED
    note:            Optional[str] = None


class DiscoveredFile(BaseModel):
    """Represents a file found via filesystem metadata (Method A)."""
    file_id:         str
    source_image:    str
    filesystem:      FilesystemType
    filename:        str          # "UNKNOWN" when not available
    original_path:   str          # "UNKNOWN" when not available
    file_size:       Optional[int] = None
    meta_identifier: Optional[str] = None   # MFT record#, FAT dir-entry offset, etc.
    deletion_state:  DeletionState
    allocation_state: AllocationState
    source_offset:   Optional[int] = None   # first data cluster byte offset
    cluster_chain:   List[int] = Field(default_factory=list)
    timestamps:      dict = Field(default_factory=dict)
    sha256:          Optional[str] = None   # None if data couldn't be read
    recovery_method: RecoveryMethod = RecoveryMethod.METADATA_RECOVERY
    notes:           str = ""


class CarvingHit(BaseModel):
    """Represents a file-header match found by raw signature scanning (Method B)."""
    hit_id:          str
    source_image:    str
    filesystem:      FilesystemType = FilesystemType.RAW
    signature_name:  str           # e.g. "JPEG", "PDF"
    start_offset:    int
    end_offset:      Optional[int] = None    # None if end not found
    size_bytes:      Optional[int] = None
    header_hex:      str           # first 16 bytes as hex
    allocation_state: AllocationState
    deletion_state:  DeletionState = DeletionState.NOT_IN_METADATA
    sha256:          Optional[str] = None
    recovery_method: RecoveryMethod = RecoveryMethod.RAW_CARVING


class RecoveryCandidate(BaseModel):
    """
    Unified output record — every discovered file ends up here,
    regardless of which discovery path produced it.
    """
    candidate_id:    str
    source_image:    str
    filesystem:      FilesystemType
    source_offset:   Optional[int] = None
    size_bytes:      Optional[int] = None
    signature:       Optional[str] = None    # detected file signature / magic
    format:          Optional[str] = None    # e.g. "JPEG", "PDF"
    filename:        str = "UNKNOWN"
    original_path:   str = "UNKNOWN"
    allocation_state: AllocationState
    deletion_state:  DeletionState
    recovery_method: RecoveryMethod
    sha256:          Optional[str] = None
    timestamps:      dict = Field(default_factory=dict)
    meta_identifier: Optional[str] = None
    cluster_chain:   List[int] = Field(default_factory=list)
    # Evidence quality — not fabricated, derived from pipeline stages
    confidence_components: dict = Field(default_factory=dict)
    notes:           str = ""


# ─── API request / response models ───────────────────────────────────────────

class ImageSourceRequest(BaseModel):
    image_path: str = Field(..., description="Absolute path to the disk image file (read-only)")
    label:      Optional[str] = None


class ScanResponse(BaseModel):
    image_path:       str
    image_sha256:     Optional[str] = None
    image_size_bytes: int
    partitions:       List[PartitionInfo] = []
    filesystems:      List[FilesystemInfo] = []
    allocated_files:  List[RecoveryCandidate] = []
    deleted_files:    List[RecoveryCandidate] = []
    unallocated:      List[UnallocatedRegion] = []
    carving_hits:     List[RecoveryCandidate] = []
    all_candidates:   List[RecoveryCandidate] = []
    scan_duration_s:  float = 0.0
    errors:           List[str] = []
    warnings:         List[str] = []
