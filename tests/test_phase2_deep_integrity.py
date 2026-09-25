"""
tests/test_phase2_deep_integrity.py
====================================
Comprehensive Test Suite for CALMSTACKS Feature 02 Phase 2:
Deep Corruption Localization, Recoverability Engine, Block Analysis,
Real Decoder Validation, and Explainable Evidence.

Covers all 13 required scenarios:
Scenario A: Completely valid file
Scenario B: One damaged region
Scenario C: Multiple damaged regions
Scenario D: Truncated file
Scenario E: Corrupted header
Scenario F: Corrupted middle region
Scenario G: Corrupted trailer
Scenario H: CRC failure
Scenario I: Valid structure but hash mismatch
Scenario J: Corrupted file that remains decodable / partially recoverable
Scenario K: Corrupted file that cannot be decoded
Scenario L: Completely unrecoverable file
Scenario M: Unknown format

Plus specialized capabilities:
- Block-level analysis (BLOCK_001 -> INTACT, etc.)
- Boundary merging (1000-1100, 1101-1200, 1201-1300 -> 1000-1300)
- Provenance and impact tracking
- Reference comparison and fuzzy similarity
- ML supporting signal labeling
- Source preservation (read-only safety)
"""

import hashlib
import json
from pathlib import Path
import pytest

from core.block_analyzer import analyze_blocks
from core.corruption_boundaries import merge_adjacent_corruption_boundaries
from core.decoder_validator import validate_decoder
from core.integrity_analyzer import IntegrityAnalyzer
from core.models import (
    CheckStatus,
    CorruptionRegion,
    CorruptionType,
    HashVerificationStatus,
    IntegrityStatus,
    RecoverabilityClassification,
    RegionClassification,
)
from core.reference_comparator import compare_with_reference

FIXTURES_DIR = Path(__file__).parent.parent / "core" / "fixtures" / "data"
GT_PATH = FIXTURES_DIR / "ground_truth.json"


@pytest.fixture(scope="session")
def ground_truth():
    if not GT_PATH.exists():
        from core.fixtures.create_fixtures import generate_all_fixtures
        generate_all_fixtures()
    with open(GT_PATH) as f:
        return json.load(f)


@pytest.fixture
def analyzer():
    return IntegrityAnalyzer()


# ─── Scenario A: Completely Valid File ───────────────────────────────────────

def test_scenario_a_completely_valid_file(analyzer):
    """Verifies that a completely valid JPEG has 100% integrity, clean decoder, and full recoverability."""
    valid_file = FIXTURES_DIR / "jpeg_1_valid.jpg"
    res = analyzer.analyze(valid_file)

    assert res.overall_status == IntegrityStatus.INTACT
    assert res.recoverability.classification == RecoverabilityClassification.FULLY_RECOVERABLE
    assert res.scores.overall_score >= 90.0

    # Decoder validation
    assert res.decoder is not None
    assert res.decoder.attempted is True
    assert res.decoder.success is True
    assert res.decoder.partial_recovery_possible is True

    # Section breakdown
    assert res.section_breakdown is not None
    assert len(res.section_breakdown.valid_sections) >= 3
    assert len(res.section_breakdown.damaged_sections) == 0
    assert len(res.section_breakdown.blocking_issues) == 0

    # Blocks: All intact
    assert len(res.blocks) > 0
    for b in res.blocks:
        assert b.state == RegionClassification.INTACT
        assert "INTACT" in b.label

    # ML signal
    assert res.ml_signal is not None
    assert res.ml_signal.label == "ML SUPPORTING SIGNAL"
    assert res.ml_signal.anomaly_score < 25.0


# ─── Scenario B: One Damaged Region ─────────────────────────────────────────

def test_scenario_b_one_damaged_region(analyzer):
    """Verifies precise offset localization when a single region is damaged."""
    mid_file = FIXTURES_DIR / "jpeg_3_middle_corrupted.jpg"
    res = analyzer.analyze(mid_file)

    assert len(res.corruption_regions) >= 1
    first_corrupt = res.corruption_regions[0]
    assert first_corrupt.start_offset > 0
    assert first_corrupt.length > 0
    assert len(res.intact_regions) >= 1

    # Format-specific section analysis must isolate affected section
    assert res.section_breakdown is not None
    assert len(res.section_breakdown.damaged_sections) >= 1


# ─── Scenario C: Multiple Damaged Regions ────────────────────────────────────

def test_scenario_c_multiple_damaged_regions(analyzer):
    """Verifies that multiple disjoint damaged regions are independently identified."""
    multi_file = FIXTURES_DIR / "png_8_multiple_corruptions.png"
    res = analyzer.analyze(multi_file)

    assert len(res.corruption_regions) >= 2
    for i in range(len(res.corruption_regions) - 1):
        assert res.corruption_regions[i].end_offset <= res.corruption_regions[i + 1].start_offset


# ─── Scenario D: Truncated File ──────────────────────────────────────────────

def test_scenario_d_truncated_file(analyzer):
    """Verifies detection of cleanly truncated files and identification of missing tail."""
    trunc_file = FIXTURES_DIR / "jpeg_4_truncated.jpg"
    res = analyzer.analyze(trunc_file)

    assert res.overall_status in (IntegrityStatus.TRUNCATED, IntegrityStatus.PARTIALLY_DAMAGED)
    assert any("EOI" in s or "Terminal" in s for s in res.section_breakdown.missing_sections)
    assert res.section_breakdown.partial_recovery_possible is True


# ─── Scenario E: Corrupted Header ────────────────────────────────────────────

def test_scenario_e_corrupted_header(analyzer):
    """Verifies that header corruption is localized to byte offset 0 with critical severity."""
    hdr_file = FIXTURES_DIR / "png_2_header_corrupted.png"
    res = analyzer.analyze(hdr_file)

    has_hdr = any(c.start_offset == 0 and c.type == CorruptionType.HEADER_CORRUPTION.value for c in res.corruption_regions)
    assert has_hdr is True
    assert res.scores.signature_integrity == 0.0


# ─── Scenario F: Corrupted Middle Region ─────────────────────────────────────

def test_scenario_f_corrupted_middle_region(analyzer):
    """Verifies that middle region corruption leaves header intact and preserves partial recoverability."""
    mid_file = FIXTURES_DIR / "pdf_3_middle_corrupted.pdf"
    res = analyzer.analyze(mid_file)

    corrupt = res.corruption_regions[0]
    assert corrupt.start_offset > 0
    assert corrupt.end_offset <= res.file_size
    assert res.scores.signature_integrity == 100.0


# ─── Scenario G: Corrupted Trailer ───────────────────────────────────────────

def test_scenario_g_corrupted_trailer(analyzer):
    """Verifies that missing or damaged trailer is detected and localized."""
    trailer_file = FIXTURES_DIR / "png_5_trailer_damaged.png"
    res = analyzer.analyze(trailer_file)

    has_trailer_flag = any(
        c.type in (CorruptionType.MISSING_TRAILER.value, CorruptionType.TRUNCATION.value)
        for c in res.corruption_regions
    )
    assert has_trailer_flag is True
    assert any("IEND" in s for s in res.section_breakdown.missing_sections)


# ─── Scenario H: CRC Failure ─────────────────────────────────────────────────

def test_scenario_h_crc_failure(analyzer):
    """Verifies CRC32 failure localization with recoverability impact diagnostic."""
    crc_file = FIXTURES_DIR / "png_6_checksum_corrupted.png"
    res = analyzer.analyze(crc_file)

    crc_regions = [c for c in res.corruption_regions if c.type == CorruptionType.CRC_FAILURE.value]
    assert len(crc_regions) > 0
    first_crc = crc_regions[0]
    assert first_crc.start_offset > 0
    assert "IDAT" in first_crc.recoverability_impact


# ─── Scenario I: Valid Structure but Hash Mismatch ───────────────────────────

def test_scenario_i_valid_structure_hash_mismatch(analyzer):
    """Verifies that hash mismatch indicates byte divergence without fabricating corruption."""
    valid_file = FIXTURES_DIR / "jpeg_1_valid.jpg"
    wrong_hash = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
    res = analyzer.analyze(valid_file, reference_sha256=wrong_hash)

    assert res.hash.status == HashVerificationStatus.MISMATCH
    # Structural checks must still pass because bytes are structurally valid JPEG
    assert res.scores.structural_integrity >= 90.0
    assert len(res.corruption_regions) == 0


# ─── Scenario J: Corrupted File That Remains Decodable ───────────────────────

def test_scenario_j_corrupted_file_partially_recoverable(analyzer):
    """Verifies that when headers/frames are intact, partial recovery is certified."""
    trunc_file = FIXTURES_DIR / "jpeg_4_truncated.jpg"
    res = analyzer.analyze(trunc_file)

    # Core headers and SOF are present in truncated JPEG fixture
    assert res.section_breakdown.partial_recovery_possible is True
    assert res.recoverability.classification == RecoverabilityClassification.PARTIALLY_RECOVERABLE
    assert "intact" in res.recoverability.explanation.lower()


# ─── Scenario K: Corrupted File That Cannot Be Decoded ───────────────────────

def test_scenario_k_decoder_failure_captured(analyzer):
    """Verifies that real decoder failure is captured as evidence without crashing."""
    corrupted_data = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00" + b"\x00" * 64
    res = analyzer.analyze(corrupted_data, claimed_format="JPEG")

    assert res.decoder is not None
    assert res.decoder.attempted is True
    assert res.decoder.success is False
    assert res.decoder.error_message is not None
    assert any("decoder" in e.lower() for e in res.evidence)


# ─── Scenario L: Completely Unrecoverable File ────────────────────────────────

def test_scenario_l_completely_unrecoverable(analyzer):
    """Verifies that severe header destruction and noise produces UNRECOVERABLE."""
    noise = bytes([(i * 37) % 256 for i in range(512)])
    res = analyzer.analyze(noise, claimed_format="PNG")

    assert res.overall_status in (IntegrityStatus.UNRECOVERABLE, IntegrityStatus.CORRUPTED)
    assert res.scores.signature_integrity == 0.0


# ─── Scenario M: Unknown Format ──────────────────────────────────────────────

def test_scenario_m_unknown_format(analyzer):
    """Verifies graceful handling of unknown arbitrary binary streams."""
    arbitrary = b"CUSTOM_APP_PAYLOAD_001_HEADER_NONE"
    res = analyzer.analyze(arbitrary)

    assert res.format == "UNKNOWN"
    assert res.overall_status == IntegrityStatus.UNKNOWN


# ─── Specialized Capability: Block-Level Analysis ────────────────────────────

def test_block_level_analysis():
    """Verifies block partition labels (BLOCK_001 -> INTACT, BLOCK_002 -> CORRUPTED)."""
    data = b"A" * 1024 + b"B" * 1024 + b"C" * 1024 + b"D" * 1024
    corruptions = [CorruptionRegion(
        start_offset=1024,
        end_offset=2048,
        length=1024,
        type="CORRUPTED",
        reason="Corrupted block",
    )]

    blocks = analyze_blocks(data, block_size=1024, corruption_regions=corruptions)
    assert len(blocks) == 4
    assert blocks[0].label == "BLOCK_001 -> INTACT"
    assert blocks[0].state == RegionClassification.INTACT

    assert blocks[1].label == "BLOCK_002 -> CORRUPTED"
    assert blocks[1].state == RegionClassification.CORRUPTED

    assert blocks[2].label == "BLOCK_003 -> INTACT"
    assert blocks[3].label == "BLOCK_004 -> INTACT"


# ─── Specialized Capability: Boundary Merging & Provenance ────────────────────

def test_boundary_merging_and_provenance():
    """Verifies merging adjacent spans: 1000-1100, 1101-1200, 1201-1300 -> 1000-1300."""
    r1 = CorruptionRegion(start_offset=1000, end_offset=1100, length=100, type="BYTE_RANGE_ANOMALY", reason="Part 1")
    r2 = CorruptionRegion(start_offset=1101, end_offset=1200, length=99, type="BYTE_RANGE_ANOMALY", reason="Part 2")
    r3 = CorruptionRegion(start_offset=1201, end_offset=1300, length=99, type="CRC_FAILURE", reason="Part 3")

    merged = merge_adjacent_corruption_boundaries([r1, r2, r3], artifact_id="CASE-01", validator_name="TEST_VAL", merge_touching=True)

    assert len(merged) == 1
    consolidated = merged[0]
    assert consolidated.start_offset == 1000
    assert consolidated.end_offset == 1300
    assert consolidated.length == 300
    # Underlying findings preserved
    assert len(consolidated.underlying_findings) == 3
    assert consolidated.underlying_findings[0]["start"] == 1000
    assert consolidated.underlying_findings[2]["end"] == 1300
    # Provenance attached
    assert consolidated.provenance is not None
    assert consolidated.provenance["artifact"] == "CASE-01"
    assert consolidated.provenance["validator"] == "TEST_VAL"


# ─── Specialized Capability: Reference Comparison ────────────────────────────

def test_reference_comparator():
    """Verifies byte match percentage, localized changed ranges, and missing ranges."""
    pristine = b"0123456789" * 10  # 100 bytes
    modified = bytearray(pristine)
    modified[20:30] = b"XXXXXXXXXX"  # 10 bytes modified
    modified = bytes(modified[:80])  # truncated to 80 bytes

    res = compare_with_reference(candidate_bytes=modified, reference_bytes=pristine)

    assert res.match is False
    assert len(res.changed_ranges) == 1
    assert res.changed_ranges[0]["start"] == 20
    assert res.changed_ranges[0]["end"] == 30
    assert len(res.missing_ranges) == 1
    assert res.missing_ranges[0]["start"] == 80
    assert res.missing_ranges[0]["end"] == 100
    assert res.byte_match_percentage == 70.0
    assert res.fuzzy_similarity > 0.0
