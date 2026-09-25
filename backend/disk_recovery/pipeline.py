"""
disk_recovery/pipeline.py
==========================
Stage orchestrator — ties all Phase-1 stages together.

Execution order
---------------
1. Open image (read-only)
2. Compute image SHA-256
3. Parse MBR partitions
4. Detect filesystems
5. (Per filesystem) Scan metadata → DiscoveredFile list
6. (Per filesystem) Scan unallocated regions
7. Carve raw signatures across the entire image
8. Assemble unified RecoveryCandidate list
9. Return ScanResponse (never modifies source)

SAFETY: the ImageReader is always opened read-only.
        Results are assembled in-memory and returned — nothing is written
        to the source image.
"""

from __future__ import annotations

import hashlib
import time
from pathlib import Path
from typing import List, Optional

from .models import (
    AllocationState, CarvingHit, DeletionState, DiscoveredFile,
    FilesystemInfo, FilesystemType, RecoveryCandidate, RecoveryMethod,
    ScanResponse, UnallocatedRegion,
)
from .reader          import ImageReader
from .filesystem_detector  import detect_all_filesystems
from .metadata_scanner     import scan_metadata
from .unallocated_scanner  import scan_unallocated
from .carver               import carve_image


# ─── Helpers: convert to RecoveryCandidate ───────────────────────────────────

def _from_discovered_file(f: DiscoveredFile, counter: int) -> RecoveryCandidate:
    """Lift a DiscoveredFile (metadata path) into a RecoveryCandidate."""
    # Confidence: HIGH when file is active+allocated and we have sha256;
    #             MEDIUM when deleted but metadata intact;
    #             LOW otherwise
    conf: dict = {
        "metadata_available": True,
        "sha256_computed": f.sha256 is not None,
        "deletion_state": f.deletion_state.value,
        "allocation_state": f.allocation_state.value,
    }
    return RecoveryCandidate(
        candidate_id=f"CAND-META-{counter:06d}",
        source_image=f.source_image,
        filesystem=f.filesystem,
        source_offset=f.source_offset,
        size_bytes=f.file_size,
        signature=None,
        format=None,
        filename=f.filename,
        original_path=f.original_path,
        allocation_state=f.allocation_state,
        deletion_state=f.deletion_state,
        recovery_method=f.recovery_method,
        sha256=f.sha256,
        timestamps=f.timestamps,
        meta_identifier=f.meta_identifier,
        cluster_chain=f.cluster_chain,
        confidence_components=conf,
        notes=f.notes,
    )


def _from_carving_hit(h: CarvingHit, counter: int) -> RecoveryCandidate:
    """Lift a CarvingHit (raw carving path) into a RecoveryCandidate."""
    conf: dict = {
        "signature_matched": True,
        "footer_found": h.end_offset is not None,
        "sha256_computed": h.sha256 is not None,
        "allocation_state": h.allocation_state.value,
        "header_hex": h.header_hex,
    }
    return RecoveryCandidate(
        candidate_id=f"CAND-CARVE-{counter:06d}",
        source_image=h.source_image,
        filesystem=h.filesystem,
        source_offset=h.start_offset,
        size_bytes=h.size_bytes,
        signature=h.header_hex[:8],
        format=h.signature_name,
        filename="UNKNOWN",
        original_path="UNKNOWN",
        allocation_state=h.allocation_state,
        deletion_state=h.deletion_state,
        recovery_method=h.recovery_method,
        sha256=h.sha256,
        timestamps={},
        meta_identifier=None,
        cluster_chain=[],
        confidence_components=conf,
        notes=f"Raw signature: {h.signature_name}",
    )


# ─── Main pipeline entry point ────────────────────────────────────────────────

def run_scan(image_path: str,
             compute_image_hash: bool = True,
             max_carve_mb: int = 512) -> ScanResponse:
    """
    Execute the full Phase-1 recovery scan pipeline on *image_path*.

    Parameters
    ----------
    image_path         Absolute path to a flat disk image file (read-only).
    compute_image_hash If True, compute and return SHA-256 of the whole image.
    max_carve_mb       Carver will not scan beyond this many MiB.

    Returns
    -------
    ScanResponse — fully populated, source unchanged.
    """
    t_start = time.monotonic()
    errors:   List[str] = []
    warnings: List[str] = []

    # ── Stage 1: Open image (read-only) ───────────────────────────────────────
    try:
        reader = ImageReader(image_path)
    except (FileNotFoundError, ValueError) as exc:
        return ScanResponse(
            image_path=image_path,
            image_size_bytes=0,
            errors=[str(exc)],
        )

    image_sha256: Optional[str] = None
    if compute_image_hash:
        try:
            image_sha256 = reader.compute_sha256()
        except Exception as exc:
            warnings.append(f"Image SHA-256 computation failed: {exc}")

    # ── Stage 2: Partition table + filesystem detection ────────────────────────
    partitions, filesystems = detect_all_filesystems(reader)

    if not filesystems:
        warnings.append("No recognisable filesystem detected — carve-only mode.")
        filesystems = [FilesystemInfo(
            filesystem=FilesystemType.RAW,
            start_byte=0,
            total_sectors=reader.total_sectors,
            sector_size=512,
            cluster_size=512,
        )]

    # ── Stage 3A: Per-filesystem metadata scan ─────────────────────────────────
    all_discovered: List[DiscoveredFile] = []
    for fs in filesystems:
        try:
            found = scan_metadata(reader, fs, image_path)
            all_discovered.extend(found)
        except Exception as exc:
            warnings.append(f"Metadata scan failed for {fs.filesystem}: {exc}")

    # ── Stage 3B: Per-filesystem unallocated region scan ──────────────────────
    all_unallocated: List[UnallocatedRegion] = []
    for fs in filesystems:
        if fs.filesystem == FilesystemType.RAW:
            continue
        try:
            regions = scan_unallocated(reader, fs)
            all_unallocated.extend(regions)
        except Exception as exc:
            warnings.append(f"Unallocated scan failed for {fs.filesystem}: {exc}")

    # If no filesystem-level unallocated info, treat entire image as a candidate
    if not all_unallocated:
        all_unallocated.append(UnallocatedRegion(
            region_id="UNALLOC-IMAGE-FULL",
            filesystem=FilesystemType.RAW,
            start_offset=0,
            end_offset=reader.size_bytes,
            size_bytes=reader.size_bytes,
            allocation_state=AllocationState.UNALLOCATED,
            note="Entire image (no filesystem boundary info available)",
        ))

    # ── Stage 3C: Raw signature carving across whole image ─────────────────────
    carve_limit = max_carve_mb * 1024 * 1024
    fs_type_for_carver = filesystems[0].filesystem if filesystems else FilesystemType.RAW
    all_carving_hits: List[CarvingHit] = []
    try:
        all_carving_hits = carve_image(
            reader=reader,
            source_image=image_path,
            fs_type=fs_type_for_carver,
            unallocated_regions=all_unallocated,
            scan_start=0,
            scan_end=min(reader.size_bytes, carve_limit),
        )
    except Exception as exc:
        warnings.append(f"Raw carving failed: {exc}")

    # ── Stage 4: Assemble RecoveryCandidate list ──────────────────────────────
    allocated_candidates: List[RecoveryCandidate] = []
    deleted_candidates:   List[RecoveryCandidate] = []
    carving_candidates:   List[RecoveryCandidate] = []

    meta_counter = 0
    for df in all_discovered:
        meta_counter += 1
        cand = _from_discovered_file(df, meta_counter)
        if df.deletion_state == DeletionState.ACTIVE:
            allocated_candidates.append(cand)
        else:
            deleted_candidates.append(cand)

    carve_counter = 0
    for hit in all_carving_hits:
        carve_counter += 1
        carving_candidates.append(_from_carving_hit(hit, carve_counter))

    all_candidates = allocated_candidates + deleted_candidates + carving_candidates
    all_candidates.sort(key=lambda c: (c.source_offset or 0))

    reader.close()

    return ScanResponse(
        image_path=image_path,
        image_sha256=image_sha256,
        image_size_bytes=reader.size_bytes,
        partitions=partitions,
        filesystems=filesystems,
        allocated_files=allocated_candidates,
        deleted_files=deleted_candidates,
        unallocated=all_unallocated,
        carving_hits=carving_candidates,
        all_candidates=all_candidates,
        scan_duration_s=round(time.monotonic() - t_start, 3),
        errors=errors,
        warnings=warnings,
    )
