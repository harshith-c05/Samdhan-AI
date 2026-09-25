"""
fragment_reconstruction/tests/test_phase2.py
============================================
Phase-2 Acceptance Test Suite: Intelligent Fragment Reconstruction.

Covers all 6 required forensic scenarios against exact ground truth:
  TEST 1: Complete shuffled fragments
  TEST 2: Deleted file with recoverable fragments
  TEST 3: Missing fragment
  TEST 4: Corrupted fragment
  TEST 5: Ambiguous ordering
  TEST 6: Unrelated bytes mixed into recovery area

Run with:
    cd backend
    python -m pytest fragment_reconstruction/tests/test_phase2.py -v
    # or standalone:
    python fragment_reconstruction/tests/test_phase2.py
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import random
import struct
import sys
import zipfile
import zlib
from pathlib import Path
from typing import Dict, List, Tuple

# Make backend/ the import root
_BACKEND = Path(__file__).resolve().parent.parent.parent
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

from fragment_reconstruction.models import (
    Fragment, ReconstructionStatus, FormatType
)
from fragment_reconstruction.feature_extractor import analyze_fragment
from fragment_reconstruction.boundary_analyzer import BoundaryAnalyzer
from fragment_reconstruction.graph import ReconstructionGraph
from fragment_reconstruction.pipeline import reconstruct_fragments, FragmentReconstructionPipeline

# ── Test Tracking Helpers ─────────────────────────────────────────────────────
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
    assert condition, f"Check failed: {label} ({detail})"
    return condition


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ── Synthetic Forensic File Builders ──────────────────────────────────────────

def build_valid_png() -> Tuple[bytes, List[bytes]]:
    """
    Build a structurally valid PNG file and split it into 4 natural fragments:
      Frag 1: PNG 8-byte magic + IHDR chunk
      Frag 2: IDAT chunk 1
      Frag 3: IDAT chunk 2
      Frag 4: IEND chunk
    """
    PNG_SIG = b"\x89PNG\r\n\x1a\n"

    # IHDR chunk: 16x16, 8-bit truecolor RGB (type 2)
    ihdr_data = struct.pack(">IIBBBBB", 16, 16, 8, 2, 0, 0, 0)
    ihdr_crc = zlib.crc32(b"IHDR" + ihdr_data) & 0xFFFFFFFF
    ihdr_chunk = struct.pack(">I", len(ihdr_data)) + b"IHDR" + ihdr_data + struct.pack(">I", ihdr_crc)
    frag1 = PNG_SIG + ihdr_chunk

    # Raw image scanlines: 16 lines, each has 1 filter byte (0) + 16 * 3 RGB bytes = 49 bytes per line
    raw_scanlines = bytearray()
    for row in range(16):
        raw_scanlines.append(0)  # Filter type 0 (None)
        for col in range(16):
            raw_scanlines.extend([(row * 15) & 0xFF, (col * 15) & 0xFF, 128])

    compressed_idat = zlib.compress(bytes(raw_scanlines), level=6)

    # Split compressed data into 2 IDAT chunks
    mid = len(compressed_idat) // 2
    idat1_payload = compressed_idat[:mid]
    idat1_crc = zlib.crc32(b"IDAT" + idat1_payload) & 0xFFFFFFFF
    frag2 = struct.pack(">I", len(idat1_payload)) + b"IDAT" + idat1_payload + struct.pack(">I", idat1_crc)

    idat2_payload = compressed_idat[mid:]
    idat2_crc = zlib.crc32(b"IDAT" + idat2_payload) & 0xFFFFFFFF
    frag3 = struct.pack(">I", len(idat2_payload)) + b"IDAT" + idat2_payload + struct.pack(">I", idat2_crc)

    # IEND chunk
    iend_crc = zlib.crc32(b"IEND") & 0xFFFFFFFF
    frag4 = struct.pack(">I", 0) + b"IEND" + struct.pack(">I", iend_crc)

    full_png = frag1 + frag2 + frag3 + frag4
    return full_png, [frag1, frag2, frag3, frag4]


def build_valid_jpeg() -> Tuple[bytes, List[bytes]]:
    """
    Build a structurally valid JPEG and split it into 4 fragments:
      Frag 1: SOI + APP0 + DQT
      Frag 2: SOF0 + DHT + SOS marker header
      Frag 3: Entropy-coded scan data (part 1)
      Frag 4: Entropy-coded scan data (part 2) + EOI
    """
    soi = b"\xff\xd8"
    app0_data = b"JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
    app0 = b"\xff\xe0" + struct.pack(">H", len(app0_data) + 2) + app0_data

    # DQT
    dqt_data = b"\x00" + bytes(range(64))
    dqt = b"\xff\xdb" + struct.pack(">H", len(dqt_data) + 2) + dqt_data
    frag1 = soi + app0 + dqt

    # SOF0
    sof0_data = struct.pack(">BHHB", 8, 8, 8, 3) + b"\x01\x11\x00\x02\x11\x01\x03\x11\x01"
    sof0 = b"\xff\xc0" + struct.pack(">H", len(sof0_data) + 2) + sof0_data

    # DHT
    dht_data = b"\x00" + b"\x00" * 16 + b"\x01\x02\x03"
    dht = b"\xff\xc4" + struct.pack(">H", len(dht_data) + 2) + dht_data

    # SOS marker
    sos_data = struct.pack(">B", 3) + b"\x01\x00\x02\x11\x03\x11" + struct.pack(">BBB", 0, 63, 0)
    sos = b"\xff\xda" + struct.pack(">H", len(sos_data) + 2) + sos_data
    frag2 = sof0 + dht + sos

    # Scan data
    entropy_payload = b"\x12\x34\x56\x78\x9a\xbc\xde\xf0" * 40
    mid = len(entropy_payload) // 2
    frag3 = entropy_payload[:mid]

    eoi = b"\xff\xd9"
    frag4 = entropy_payload[mid:] + eoi

    full_jpeg = frag1 + frag2 + frag3 + frag4
    return full_jpeg, [frag1, frag2, frag3, frag4]


def build_valid_zip() -> Tuple[bytes, List[bytes]]:
    """Build valid ZIP archive and split into 3 fragments."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("evidence.txt", "Forensic evidence record: CASE-NIGHTFALL-2026\nConfidential.")
        zf.writestr("meta.json", '{"case_id": "2026-NIGHTFALL", "integrity": "verified"}')

    zip_bytes = buf.getvalue()
    # Find offsets of local header 2 and central directory
    eocd_pos = zip_bytes.rfind(b"PK\x05\x06")
    cd_pos   = zip_bytes.rfind(b"PK\x01\x02")

    frag1 = zip_bytes[:cd_pos]
    frag2 = zip_bytes[cd_pos:eocd_pos]
    frag3 = zip_bytes[eocd_pos:]

    return zip_bytes, [frag1, frag2, frag3]


# ═══════════════════════════════════════════════════════════════════════════════
# ACCEPTANCE TESTS (1 to 6)
# ═══════════════════════════════════════════════════════════════════════════════

def test_1_complete_shuffled_fragments():
    """
    TEST 1: Complete shuffled fragments.
    Takes a 4-fragment valid PNG file, completely shuffles the fragment order
    [F3, F1, F4, F2], and verifies the graph-based pipeline reconstructs the exact
    original byte stream [F1, F2, F3, F4] matching ground truth SHA-256.
    """
    print("\n" + "=" * 60)
    print("TEST 1: Complete Shuffled Fragments (PNG)")
    print("=" * 60)

    original_bytes, frags = build_valid_png()
    gt_sha = sha(original_bytes)
    gt_len = len(original_bytes)

    # Wrap into Fragment objects
    f1 = analyze_fragment(frags[0], fragment_id="FRAG-1")
    f2 = analyze_fragment(frags[1], fragment_id="FRAG-2")
    f3 = analyze_fragment(frags[2], fragment_id="FRAG-3")
    f4 = analyze_fragment(frags[3], fragment_id="FRAG-4")

    # Present shuffled: 3, 1, 4, 2
    shuffled = [f3, f1, f4, f2]
    result = reconstruct_fragments(shuffled, target_format="PNG")

    check("Reconstruction status is COMPLETE", result.status == ReconstructionStatus.COMPLETE, str(result.status))
    check("Fragment order reconstructed correctly: [FRAG-1, FRAG-2, FRAG-3, FRAG-4]",
          result.selected_path == ["FRAG-1", "FRAG-2", "FRAG-3", "FRAG-4"],
          f"got: {result.selected_path}")
    check("Byte length matches ground truth", result.byte_coverage == gt_len,
          f"got {result.byte_coverage}, expected {gt_len}")
    check("Output SHA-256 matches ground truth exactly", result.output_sha256 == gt_sha,
          f"got {result.output_sha256}, expected {gt_sha}")
    check("Edge evidence explanations generated", len(result.edge_evidence) >= 3)
    check("Reconstructed artifact file exists on disk", Path(result.output_path).exists())


def test_2_deleted_file_with_recoverable_fragments():
    """
    TEST 2: Deleted file with recoverable fragments.
    Simulates scattered non-contiguous clusters of a deleted JPEG from unallocated space.
    Verifies that despite cluster gaps and scrambled input, the pipeline determines the
    correct sequence and recovers the exact file.
    """
    print("\n" + "=" * 60)
    print("TEST 2: Deleted File With Recoverable Fragments (JPEG)")
    print("=" * 60)

    original_bytes, frags = build_valid_jpeg()
    gt_sha = sha(original_bytes)

    # Provide fragments with scattered physical cluster indices
    # Cluster 10 (F1), Cluster 28 (F2), Cluster 45 (F3), Cluster 72 (F4)
    f1 = analyze_fragment(frags[0], fragment_id="DEL-CLUST-10", cluster_index=10, allocation_state="UNALLOCATED")
    f2 = analyze_fragment(frags[1], fragment_id="DEL-CLUST-28", cluster_index=28, allocation_state="UNALLOCATED")
    f3 = analyze_fragment(frags[2], fragment_id="DEL-CLUST-45", cluster_index=45, allocation_state="UNALLOCATED")
    f4 = analyze_fragment(frags[3], fragment_id="DEL-CLUST-72", cluster_index=72, allocation_state="UNALLOCATED")

    # Present shuffled
    shuffled = [f4, f2, f1, f3]
    result = reconstruct_fragments(shuffled, target_format="JPEG")

    check("Reconstruction status is COMPLETE", result.status == ReconstructionStatus.COMPLETE)
    check("Path correctly ordered from header to EOI",
          result.selected_path == ["DEL-CLUST-10", "DEL-CLUST-28", "DEL-CLUST-45", "DEL-CLUST-72"],
          f"got: {result.selected_path}")
    check("Reconstructed bytes match ground truth SHA-256 exactly",
          result.output_sha256 == gt_sha,
          f"got {result.output_sha256}, expected {gt_sha}")
    check("No missing fragments or corruption detected",
          len(result.missing_fragments) == 0 and len(result.corrupt_regions) == 0)


def test_3_missing_fragment():
    """
    TEST 3: Missing fragment.
    Takes 4-fragment PNG, but omits Fragment 3 (IDAT 2).
    Verifies status = PARTIAL, missing_fragments recorded, and NO bytes are fabricated.
    """
    print("\n" + "=" * 60)
    print("TEST 3: Missing Fragment Detection (Never Fabricated)")
    print("=" * 60)

    original_bytes, frags = build_valid_png()

    f1 = analyze_fragment(frags[0], fragment_id="F1", cluster_index=1)
    f2 = analyze_fragment(frags[1], fragment_id="F2", cluster_index=2)
    # F3 is MISSING (simulating overwritten/lost cluster 3)
    f4 = analyze_fragment(frags[3], fragment_id="F4", cluster_index=4)

    # Present [F1, F2, F4]
    input_frags = [f1, f2, f4]
    result = reconstruct_fragments(input_frags, target_format="PNG")

    check("Status flagged as PARTIAL", result.status == ReconstructionStatus.PARTIAL, str(result.status))
    check("Missing fragment detected and recorded", len(result.missing_fragments) >= 1)
    expected_bytes = len(frags[0]) + len(frags[1]) + len(frags[3])
    check("Zero fabrication: byte coverage equals sum of available fragments",
          result.byte_coverage == expected_bytes,
          f"got {result.byte_coverage}, expected {expected_bytes}")


def test_4_corrupted_fragment():
    """
    TEST 4: Corrupted fragment.
    Takes a 4-fragment PNG and corrupts bytes in Fragment 2 (bad CRC).
    Verifies status = CORRUPTED, damage recorded with affected range, repair_performed = False.
    """
    print("\n" + "=" * 60)
    print("TEST 4: Corrupted Fragment Detection (No Silent Repair)")
    print("=" * 60)

    original_bytes, frags = build_valid_png()

    # Corrupt payload of Fragment 2 (IDAT chunk)
    corrupted_f2_data = bytearray(frags[1])
    corrupted_f2_data[12] = (corrupted_f2_data[12] ^ 0xFF) # Flip byte inside IDAT payload
    corrupted_f2_bytes = bytes(corrupted_f2_data)

    f1 = analyze_fragment(frags[0], fragment_id="F1")
    f2 = analyze_fragment(corrupted_f2_bytes, fragment_id="F2_CORRUPT")
    f3 = analyze_fragment(frags[2], fragment_id="F3")
    f4 = analyze_fragment(frags[3], fragment_id="F4")

    result = reconstruct_fragments([f1, f2, f3, f4], target_format="PNG")

    check("Status flagged as CORRUPTED", result.status == ReconstructionStatus.CORRUPTED, str(result.status))
    check("Corrupt region identified in results", len(result.corrupt_regions) >= 1)
    if result.corrupt_regions:
        cr = result.corrupt_regions[0]
        check("Corrupt region points to F2_CORRUPT", cr.fragment_id == "F2_CORRUPT")
        check("Repair performed is False", cr.repair_performed is False)
        check("Error type is CRC32_CHECKSUM_FAILURE", cr.error_type == "CRC32_CHECKSUM_FAILURE")


def test_5_ambiguous_ordering():
    """
    TEST 5: Ambiguous ordering.
    Creates an ambiguous scenario where Frag 1 could branch into Frag 2A or Frag 2B.
    Verifies that multiple candidate paths (Candidate A and Candidate B) are generated,
    evaluated against byte-level format validation, and the structurally valid one is chosen.
    """
    print("\n" + "=" * 60)
    print("TEST 5: Ambiguous Ordering & Multi-Candidate Evaluation")
    print("=" * 60)

    original_bytes, frags = build_valid_png()
    gt_sha = sha(original_bytes)

    f1 = analyze_fragment(frags[0], fragment_id="F1")
    f2_real = analyze_fragment(frags[1], fragment_id="F2_REAL")

    # Create dummy competing branch F2_FAKE with valid PNG chunk format but wrong data
    dummy_payload = os.urandom(len(frags[1]) - 12)
    dummy_crc = zlib.crc32(b"IDAT" + dummy_payload) & 0xFFFFFFFF
    dummy_chunk = struct.pack(">I", len(dummy_payload)) + b"IDAT" + dummy_payload + struct.pack(">I", dummy_crc)
    f2_fake = analyze_fragment(dummy_chunk, fragment_id="F2_FAKE")

    f3 = analyze_fragment(frags[2], fragment_id="F3")
    f4 = analyze_fragment(frags[3], fragment_id="F4")

    # Present with ambiguity
    ambiguous_pool = [f1, f2_fake, f2_real, f3, f4]
    result = reconstruct_fragments(ambiguous_pool, target_format="PNG")

    check("Multiple candidate paths evaluated", len(result.candidates_evaluated) >= 2,
          f"evaluated: {len(result.candidates_evaluated)}")
    check("Winning path selected correct branch containing F2_REAL",
          "F2_REAL" in result.selected_path and "F2_FAKE" not in result.selected_path,
          f"selected path: {result.selected_path}")
    check("Output SHA-256 matches true ground truth", result.output_sha256 == gt_sha)


def test_6_unrelated_bytes_mixed_into_recovery_area():
    """
    TEST 6: Unrelated bytes mixed into recovery area.
    Mixes fragments of a valid ZIP file with random noise and junk sectors.
    Verifies unrelated fragments are rejected by graph filtering and the true
    file is reconstructed cleanly matching ground truth.
    """
    print("\n" + "=" * 60)
    print("TEST 6: Unrelated Bytes Mixed Into Recovery Area (ZIP)")
    print("=" * 60)

    original_bytes, frags = build_valid_zip()
    gt_sha = sha(original_bytes)

    f_zip1 = analyze_fragment(frags[0], fragment_id="ZIP-PART-1")
    f_zip2 = analyze_fragment(frags[1], fragment_id="ZIP-PART-2")
    f_zip3 = analyze_fragment(frags[2], fragment_id="ZIP-PART-3")

    # Unrelated noise fragments (garbage sectors / text / wrong format)
    noise_1 = analyze_fragment(os.urandom(512), fragment_id="NOISE-RAW-SECTOR-A")
    noise_2 = analyze_fragment(b"Random system log: kernel error at 0xdeadbeef\n" * 10, fragment_id="NOISE-LOG-B")

    mixed_pool = [noise_1, f_zip2, f_zip1, noise_2, f_zip3]
    result = reconstruct_fragments(mixed_pool, target_format="ZIP")

    check("Status is COMPLETE", result.status == ReconstructionStatus.COMPLETE)
    check("Noise fragments excluded from selected path",
          result.selected_path == ["ZIP-PART-1", "ZIP-PART-2", "ZIP-PART-3"],
          f"got: {result.selected_path}")
    check("Reconstructed ZIP matches ground truth SHA-256 exactly",
          result.output_sha256 == gt_sha,
          f"got {result.output_sha256}, expected {gt_sha}")
    check("Unused noise fragments listed in provenance report",
          "NOISE-RAW-SECTOR-A" in result.provenance.get("unused_fragments", []) and
          "NOISE-LOG-B" in result.provenance.get("unused_fragments", []))


# ── Runner ────────────────────────────────────────────────────────────────────

def run_all():
    print("=" * 60)
    print("  SAMDHAN AI - Phase-2 Fragment Reconstruction Acceptance Tests")
    print("=" * 60)

    test_1_complete_shuffled_fragments()
    test_2_deleted_file_with_recoverable_fragments()
    test_3_missing_fragment()
    test_4_corrupted_fragment()
    test_5_ambiguous_ordering()
    test_6_unrelated_bytes_mixed_into_recovery_area()

    print("\n" + "=" * 60)
    print(f"  Results: {_PASS} passed, {_FAIL} failed")
    print("=" * 60)
    if _FAIL > 0:
        sys.exit(1)


if __name__ == "__main__":
    run_all()
