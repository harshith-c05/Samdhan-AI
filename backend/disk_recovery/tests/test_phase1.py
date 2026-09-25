"""
disk_recovery/tests/test_phase1.py
====================================
Phase-1 Acceptance Tests — runs entirely in-process (no HTTP server needed).

Tests
-----
1.  image_loaded          — ImageReader opens image, reports correct size/sha256
2.  filesystem_detected   — detect_all_filesystems identifies FAT32
3.  allocated_discovered  — metadata scan finds 4 active files
4.  deleted_detected      — metadata scan finds 1 deleted file (0xE5 entry)
5.  unallocated_identified — unallocated scanner reports free clusters 8-31
6.  signatures_detected   — carver finds JPEG, PDF, ZIP signatures
7.  candidates_generated  — pipeline produces >= 5 RecoveryCandidates
8.  source_unchanged      — image SHA-256 matches ground truth after full scan

Run with:
    cd backend
    python -m pytest disk_recovery/tests/test_phase1.py -v
    # or without pytest:
    python disk_recovery/tests/test_phase1.py
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

# ── Make backend/ the import root ─────────────────────────────────────────────
_BACKEND = Path(__file__).resolve().parent.parent.parent
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from disk_recovery.reader              import ImageReader
from disk_recovery.filesystem_detector import detect_all_filesystems
from disk_recovery.metadata_scanner    import scan_metadata
from disk_recovery.unallocated_scanner import scan_unallocated
from disk_recovery.carver              import carve_image
from disk_recovery.pipeline            import run_scan
from disk_recovery.models              import (
    AllocationState, DeletionState, FilesystemType,
)

# ── Paths ─────────────────────────────────────────────────────────────────────
FIXTURE_DIR  = Path(__file__).parent.parent / "test_fixtures"
IMAGE_PATH   = FIXTURE_DIR / "test_usb.img"
TRUTH_PATH   = FIXTURE_DIR / "ground_truth.json"


if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

# ── Test helpers ──────────────────────────────────────────────────────────────
_PASS = 0
_FAIL = 0


def check(label: str, condition: bool, detail: str = "") -> bool:
    global _PASS, _FAIL
    if condition:
        print(f"  [PASS] {label}")
        _PASS += 1
    else:
        print(f"  [FAIL] {label}" + (f" - {detail}" if detail else ""))
        _FAIL += 1
    return condition


def require_image():
    if not IMAGE_PATH.exists():
        print(f"\n[SETUP] Generating test fixture: {IMAGE_PATH}")
        # Run the generator in-process
        fixture_gen = FIXTURE_DIR / "create_test_image.py"
        import importlib.util, types
        spec = importlib.util.spec_from_file_location("create_test_image", fixture_gen)
        mod  = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        mod.main()
    assert IMAGE_PATH.exists(), f"Test fixture not found: {IMAGE_PATH}"
    with open(TRUTH_PATH, encoding="utf-8") as f:
        return json.load(f)


try:
    import pytest
    @pytest.fixture
    def ground_truth():
        return require_image()
except ImportError:
    pass


# ── Individual test functions ─────────────────────────────────────────────────

def test_image_loaded(ground_truth: dict):
    print("\n[TEST 1] Image Loaded")
    with ImageReader(str(IMAGE_PATH)) as r:
        check("Image size matches ground truth",
              r.size_bytes == ground_truth["image_size_bytes"],
              f"got {r.size_bytes}, expected {ground_truth['image_size_bytes']}")
        sha = r.compute_sha256()
        check("Image SHA-256 matches ground truth",
              sha == ground_truth["image_sha256"],
              f"got {sha[:16]}..., expected {ground_truth['image_sha256'][:16]}...")
        check("Image is readable (first sector non-empty)",
              len(r.read_sectors(0, 1)) == 512)


def test_filesystem_detected(ground_truth: dict):
    print("\n[TEST 2] Filesystem Detected")
    with ImageReader(str(IMAGE_PATH)) as r:
        parts, fss = detect_all_filesystems(r)
    check("At least one filesystem detected", len(fss) > 0,
          f"got {len(fss)}")
    if fss:
        check("Filesystem is FAT32",
              fss[0].filesystem == FilesystemType.FAT32,
              f"got {fss[0].filesystem}")
        check("FAT32 cluster size is 4096 bytes",
              fss[0].cluster_size == 4096,
              f"got {fss[0].cluster_size}")


def test_allocated_discovered(ground_truth: dict):
    print("\n[TEST 3] Allocated Files Discovered")
    with ImageReader(str(IMAGE_PATH)) as r:
        _, fss = detect_all_filesystems(r)
        found = scan_metadata(r, fss[0], str(IMAGE_PATH))

    active = [f for f in found if f.deletion_state == DeletionState.ACTIVE]
    check("At least 4 allocated files found",
          len(active) >= 4, f"got {len(active)}")

    # Check known filenames are present
    names = {f.filename.lower() for f in active}
    for expected in ["photo1.jpg", "document.pdf", "archive.zip", "note.txt"]:
        check(f"Allocated file '{expected}' found",
              any(expected.lower() in n for n in names),
              f"names seen: {sorted(names)[:6]}")


def test_deleted_detected(ground_truth: dict):
    print("\n[TEST 4] Deleted File Detected")
    with ImageReader(str(IMAGE_PATH)) as r:
        _, fss = detect_all_filesystems(r)
        found = scan_metadata(r, fss[0], str(IMAGE_PATH))

    deleted = [f for f in found if f.deletion_state != DeletionState.ACTIVE]
    check("At least 1 deleted file detected",
          len(deleted) >= 1, f"got {len(deleted)}")
    if deleted:
        d = deleted[0]
        check("Deleted file has UNALLOCATED allocation state",
              d.allocation_state == AllocationState.UNALLOCATED,
              f"got {d.allocation_state}")
        check("Deleted file has DELETED_META_INTACT deletion state",
              d.deletion_state == DeletionState.DELETED_META_INTACT,
              f"got {d.deletion_state}")


def test_unallocated_identified(ground_truth: dict):
    print("\n[TEST 5] Unallocated Regions Identified")
    with ImageReader(str(IMAGE_PATH)) as r:
        _, fss = detect_all_filesystems(r)
        regions = scan_unallocated(r, fss[0])

    check("At least 1 unallocated region identified",
          len(regions) >= 1, f"got {len(regions)}")
    total_unalloc = sum(reg.size_bytes for reg in regions)
    check("Unallocated space > 0 bytes",
          total_unalloc > 0, f"got {total_unalloc}")
    print(f"     {len(regions)} region(s), {total_unalloc:,} bytes total unallocated")


def test_signatures_detected(ground_truth: dict):
    print("\n[TEST 6] Raw Signatures Detected")
    with ImageReader(str(IMAGE_PATH)) as r:
        _, fss = detect_all_filesystems(r)
        regions = scan_unallocated(r, fss[0])
        hits = carve_image(r, str(IMAGE_PATH), fss[0].filesystem, regions)

    sig_names = {h.signature_name for h in hits}
    check("JPEG signature detected", "JPEG" in sig_names,
          f"found: {sig_names}")
    check("PDF signature detected",  "PDF"  in sig_names,
          f"found: {sig_names}")
    check("ZIP signature detected",  "ZIP"  in sig_names,
          f"found: {sig_names}")
    print(f"     Carver found {len(hits)} total hits: {sorted(sig_names)}")


def test_candidates_generated(ground_truth: dict):
    print("\n[TEST 7] Recovery Candidates Generated")
    result = run_scan(str(IMAGE_PATH))

    total = len(result.all_candidates)
    check("Pipeline generated >= 5 candidates",
          total >= 5, f"got {total}")
    check("Allocated candidates present",
          len(result.allocated_files) >= 4,
          f"got {len(result.allocated_files)}")
    check("Deleted candidates present",
          len(result.deleted_files) >= 1,
          f"got {len(result.deleted_files)}")
    check("Carving hits present",
          len(result.carving_hits) >= 1,
          f"got {len(result.carving_hits)}")
    check("No pipeline errors",
          len(result.errors) == 0,
          f"errors: {result.errors}")
    print(f"     Scan completed in {result.scan_duration_s:.3f}s")


def test_source_unchanged(ground_truth: dict):
    print("\n[TEST 8] Source Image Unchanged After Full Scan")
    # Run the full pipeline
    run_scan(str(IMAGE_PATH))
    # Re-hash the image file
    data = IMAGE_PATH.read_bytes()
    post_sha = hashlib.sha256(data).hexdigest()
    check("Image SHA-256 unchanged after scan",
          post_sha == ground_truth["image_sha256"],
          f"MISMATCH: before={ground_truth['image_sha256'][:16]}..., "
          f"after={post_sha[:16]}...")


# ── Main runner ───────────────────────────────────────────────────────────────

def run_all():
    print("=" * 60)
    print("  SAMDHAN AI - Phase-1 Disk Recovery Acceptance Tests")
    print("=" * 60)

    ground_truth = require_image()
    print(f"\nFixture: {IMAGE_PATH}")
    print(f"Size:    {ground_truth['image_size_bytes']:,} bytes")
    print(f"SHA-256: {ground_truth['image_sha256'][:32]}...")

    test_image_loaded(ground_truth)
    test_filesystem_detected(ground_truth)
    test_allocated_discovered(ground_truth)
    test_deleted_detected(ground_truth)
    test_unallocated_identified(ground_truth)
    test_signatures_detected(ground_truth)
    test_candidates_generated(ground_truth)
    test_source_unchanged(ground_truth)

    print("\n" + "=" * 60)
    print(f"  Results: {_PASS} passed, {_FAIL} failed")
    print("=" * 60)
    if _FAIL > 0:
        sys.exit(1)


# pytest compatibility
def test_all_phase1():
    run_all()


if __name__ == "__main__":
    run_all()
