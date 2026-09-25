"""
disk_recovery/api.py
=====================
FastAPI router for the Phase-1 disk recovery endpoints.

Mounted onto the existing SAMDHAN AI FastAPI app (integrity_pipeline.py)
as a sub-application router — no new server process needed.

Endpoints
---------
POST /api/recovery/scan
    Full pipeline scan of a disk image.
    Body: { "image_path": "/absolute/path/to/image.img" }

GET  /api/recovery/filesystems?image_path=...
    Fast filesystem detection only (no metadata scan).

GET  /api/recovery/candidates?image_path=...
    Returns full candidate list from a cached or fresh scan.

POST /api/recovery/unallocated
    Returns unallocated regions for a given image.

GET  /api/recovery/sources
    List known test fixture images in backend/disk_recovery/test_fixtures/.

All endpoints are READ-ONLY with respect to source images.
Results are computed on-demand (no background tasks in Phase 1).
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import List, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from .models import (
    FilesystemInfo, ImageSourceRequest, PartitionInfo,
    RecoveryCandidate, ScanResponse, UnallocatedRegion,
)
from .pipeline           import run_scan
from .filesystem_detector import detect_all_filesystems
from .reader              import ImageReader
from .unallocated_scanner import scan_unallocated

router = APIRouter(prefix="/api/recovery", tags=["disk-recovery"])

# ─── Known test fixture directory ─────────────────────────────────────────────
FIXTURES_DIR = Path(__file__).parent / "test_fixtures"
FIXTURES_DIR.mkdir(exist_ok=True)


# ─── Request / Response models ────────────────────────────────────────────────

class FilesystemResponse(BaseModel):
    image_path:       str
    image_size_bytes: int
    partitions:       List[PartitionInfo]
    filesystems:      List[FilesystemInfo]


class UnallocatedRequest(BaseModel):
    image_path: str


class SourceListItem(BaseModel):
    filename: str
    path:     str
    size_bytes: int
    sha256:   Optional[str] = None


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _require_readable_image(image_path: str) -> Path:
    p = Path(image_path).resolve()
    if not p.exists():
        raise HTTPException(status_code=404, detail=f"Image not found: {p}")
    if not p.is_file():
        raise HTTPException(status_code=400, detail=f"Not a regular file: {p}")
    if not os.access(p, os.R_OK):
        raise HTTPException(status_code=403, detail=f"Image not readable: {p}")
    return p


# ─── Endpoints ────────────────────────────────────────────────────────────────

@router.post("/scan", response_model=ScanResponse)
async def full_scan(req: ImageSourceRequest):
    """
    Full Phase-1 pipeline scan:
      1. Open image (read-only)
      2. Detect filesystem(s)
      3. Scan metadata for allocated and deleted files
      4. Identify unallocated regions
      5. Raw-carve the image for file signatures
      6. Return unified RecoveryCandidate list

    The source image is NEVER modified.
    """
    p = _require_readable_image(req.image_path)
    try:
        result = run_scan(str(p))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))
    return result


@router.get("/filesystems", response_model=FilesystemResponse)
async def detect_filesystems(image_path: str = Query(..., description="Absolute path to disk image")):
    """
    Lightweight filesystem detection only — no metadata or carving.
    Use this for a quick probe before running the full scan.
    """
    p = _require_readable_image(image_path)
    try:
        with ImageReader(str(p)) as reader:
            partitions, filesystems = detect_all_filesystems(reader)
            size = reader.size_bytes
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))

    return FilesystemResponse(
        image_path=str(p),
        image_size_bytes=size,
        partitions=partitions,
        filesystems=filesystems,
    )


@router.post("/unallocated", response_model=List[UnallocatedRegion])
async def get_unallocated(req: UnallocatedRequest):
    """
    Return the list of unallocated / free regions for a disk image.
    For FAT32: uses the FAT free-cluster list.
    For NTFS/exFAT: uses zero-sector heuristic sweep (Phase 1).
    """
    p = _require_readable_image(req.image_path)
    try:
        with ImageReader(str(p)) as reader:
            _, filesystems = detect_all_filesystems(reader)
            regions: List[UnallocatedRegion] = []
            for fs in filesystems:
                regions += scan_unallocated(reader, fs)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))
    return regions


@router.get("/sources", response_model=List[SourceListItem])
async def list_sources():
    """
    List all disk image files (.img, .dd, .raw, .bin) in the
    test_fixtures directory that are ready to scan.
    """
    items: List[SourceListItem] = []
    for f in FIXTURES_DIR.iterdir():
        if f.suffix.lower() in (".img", ".dd", ".raw", ".bin") and f.is_file():
            items.append(SourceListItem(
                filename=f.name,
                path=str(f),
                size_bytes=f.stat().st_size,
            ))
    items.sort(key=lambda x: x.filename)
    return items
