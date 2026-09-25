"""
tests/test_feature02_integrity.py
=================================
Automated acceptance test suite for CALMSTACKS Feature 02:
Data Integrity & Corruption Assessment.

Tests all 16 required capabilities against deterministic fixtures:
1. Valid file
2. Invalid signature
3. Header corruption
4. Middle corruption
5. Truncation
6. Missing trailer
7. CRC failure
8. Checksum failure
9. Structural failure
10. Corruption localization (exact offsets)
11. Intact region detection
12. Multiple corruption regions
13. SHA-256 calculation
14. Reference hash match
15. Reference hash mismatch
16. Unknown/uncertain cases
17. Safety: Read-only source preservation
"""

import hashlib
import json
from pathlib import Path
import pytest

from core.integrity_analyzer import IntegrityAnalyzer
from core.models import (
    CheckStatus,
    CorruptionType,
    HashVerificationStatus,
    IntegrityStatus,
    RecoverabilityClassification,
    RegionClassification,
)

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


# ─── 1. Valid Files ───────────────────────────────────────────────────────────

def test_1_valid_files(analyzer, ground_truth):
    """Verifies that pristine JPEG, PNG, PDF, ZIP files are classified as INTACT."""
    valid_files = [k for k, v in ground_truth.items() if v["variant"] == "VALID"]
    assert len(valid_files) == 4, "Must have 4 valid format fixtures"

    for fname in valid_files:
        path = FIXTURES_DIR / fname
        result = analyzer.analyze(path)

        assert result.overall_status == IntegrityStatus.INTACT, f"{fname} should be INTACT"
        assert len(result.corruption_regions) == 0, f"{fname} should have 0 corruption regions"
        assert len(result.intact_regions) > 0, f"{fname} should have intact regions"
        assert result.recoverability.classification == RecoverabilityClassification.FULLY_RECOVERABLE
        assert result.scores.overall_score >= 85.0, f"{fname} overall score should be >= 85"
        assert result.scores.signature_integrity == 100.0


# ─── 2. Invalid Signature ─────────────────────────────────────────────────────

def test_2_invalid_signature(analyzer):
    """Verifies detection of invalid/corrupted magic bytes."""
    corrupted_data = b"NOT_A_VALID_HEADER_FOR_ANY_KNOWN_FORMAT_DATA_STREAM"
    result = analyzer.analyze(corrupted_data, claimed_format="PNG")

    assert result.checks[0].status == CheckStatus.FAIL
    assert result.scores.signature_integrity == 0.0
    assert result.overall_status in (IntegrityStatus.UNRECOVERABLE, IntegrityStatus.CORRUPTED)


# ─── 3. Header Corruption Localization ────────────────────────────────────────

def test_3_header_corruption_localization(analyzer, ground_truth):
    """Verifies header corruption is localized to byte offset 0."""
    hdr_files = [k for k, v in ground_truth.items() if v["variant"] == "HEADER_CORRUPTED"]
    assert len(hdr_files) == 4

    for fname in hdr_files:
        path = FIXTURES_DIR / fname
        result = analyzer.analyze(path)

        has_header_corrupt = any(
            c.type == CorruptionType.HEADER_CORRUPTION.value and c.start_offset == 0
            for c in result.corruption_regions
        )
        assert has_header_corrupt, f"{fname} must localize HEADER_CORRUPTION at offset 0"
        assert result.scores.signature_integrity == 0.0


# ─── 4. Middle Corruption Localization ────────────────────────────────────────

def test_4_middle_corruption_localization(analyzer, ground_truth):
    """Verifies corruption injected in the middle is localized with non-zero start offset."""
    mid_files = [k for k, v in ground_truth.items() if v["variant"] == "MIDDLE_REGION_CORRUPTED"]
    assert len(mid_files) == 4

    for fname in mid_files:
        path = FIXTURES_DIR / fname
        result = analyzer.analyze(path)

        # Must detect corruption with start_offset > 0
        corrupt_regions = result.corruption_regions
        assert len(corrupt_regions) > 0, f"{fname} must report corruption in middle region"
        assert corrupt_regions[0].start_offset > 0, f"{fname} corruption start must be > 0"
        assert result.overall_status in (IntegrityStatus.PARTIALLY_DAMAGED, IntegrityStatus.CORRUPTED)


# ─── 5. Truncation Detection & Localization ───────────────────────────────────

def test_5_truncation_detection_and_localization(analyzer, ground_truth):
    """Verifies detection of cleanly truncated files."""
    trunc_files = [k for k, v in ground_truth.items() if v["variant"] == "TRUNCATED"]
    assert len(trunc_files) == 4

    for fname in trunc_files:
        path = FIXTURES_DIR / fname
        result = analyzer.analyze(path)

        has_trunc = any(
            c.type in (CorruptionType.TRUNCATION.value, CorruptionType.MISSING_TRAILER.value)
            for c in result.corruption_regions
        )
        assert has_trunc, f"{fname} must flag TRUNCATION or MISSING_TRAILER"
        assert result.overall_status in (IntegrityStatus.TRUNCATED, IntegrityStatus.PARTIALLY_DAMAGED)


# ─── 6. Missing Trailer Detection ─────────────────────────────────────────────

def test_6_missing_trailer_detection(analyzer, ground_truth):
    """Verifies detection when terminal marker (EOI, IEND, %%EOF, EOCD) is removed."""
    trail_files = [k for k, v in ground_truth.items() if v["variant"] == "TRAILER_DAMAGED"]
    assert len(trail_files) == 4

    for fname in trail_files:
        path = FIXTURES_DIR / fname
        result = analyzer.analyze(path)

        has_trailer_issue = any(
            c.type in (CorruptionType.MISSING_TRAILER.value, CorruptionType.TRUNCATION.value)
            for c in result.corruption_regions
        )
        assert has_trailer_issue, f"{fname} must identify missing terminal trailer"


# ─── 7. CRC Failure Localization ──────────────────────────────────────────────

def test_7_crc_failure_localization(analyzer):
    """Verifies exact detection and offset localization of PNG CRC32 mismatch."""
    png_crc_file = FIXTURES_DIR / "png_6_checksum_corrupted.png"
    assert png_crc_file.exists()

    result = analyzer.analyze(png_crc_file)
    crc_corruptions = [c for c in result.corruption_regions if c.type == CorruptionType.CRC_FAILURE.value]
    assert len(crc_corruptions) > 0, "Must detect PNG CRC_FAILURE"
    assert crc_corruptions[0].start_offset > 0
    assert result.scores.checksum_integrity < 100.0


# ─── 8. Checksum Failure Detection ────────────────────────────────────────────

def test_8_checksum_failure_detection(analyzer):
    """Verifies ZIP entry CRC-32 failure detection."""
    zip_chk_file = FIXTURES_DIR / "zip_6_checksum_corrupted.zip"
    assert zip_chk_file.exists()

    result = analyzer.analyze(zip_chk_file)
    crc_corruptions = [c for c in result.corruption_regions if c.type == CorruptionType.CRC_FAILURE.value]
    assert len(crc_corruptions) > 0, "Must detect ZIP entry CRC failure"
    assert result.scores.checksum_integrity < 100.0


# ─── 9. Structural Failure Detection ──────────────────────────────────────────

def test_9_structural_failure_detection(analyzer):
    """Verifies failed structural checks contain expected check fields."""
    corrupted_png = FIXTURES_DIR / "png_2_header_corrupted.png"
    result = analyzer.analyze(corrupted_png)

    failed_checks = [c for c in result.checks if c.status == CheckStatus.FAIL]
    assert len(failed_checks) > 0, "Must record structural check failures"
    first_fail = failed_checks[0]
    assert first_fail.location == 0
    assert first_fail.expected != ""
    assert first_fail.actual != ""


# ─── 10. Corruption Localization Exact Offsets ────────────────────────────────

def test_10_corruption_localization_exact_offsets(analyzer):
    """Verifies corruption regions contain valid, non-fabricated byte offsets."""
    pdf_mid = FIXTURES_DIR / "pdf_3_middle_corrupted.pdf"
    result = analyzer.analyze(pdf_mid)

    for c in result.corruption_regions:
        assert c.start_offset >= 0
        assert c.end_offset <= result.file_size
        assert c.length == c.end_offset - c.start_offset
        assert c.length > 0


# ─── 11. Intact Region Detection ──────────────────────────────────────────────

def test_11_intact_region_detection(analyzer):
    """Verifies intact regions are partitioned and do not overlap with corruption."""
    png_mid = FIXTURES_DIR / "png_3_middle_corrupted.png"
    result = analyzer.analyze(png_mid)

    assert len(result.intact_regions) > 0, "Should have intact regions"
    for r in result.intact_regions:
        assert r.status == RegionClassification.INTACT
        assert r.length == r.end - r.start
        # Guarantee intact region does not intersect any corruption region
        for c in result.corruption_regions:
            overlaps = max(r.start, c.start_offset) < min(r.end, c.end_offset)
            assert not overlaps, f"Intact region [{r.start}:{r.end}] overlaps corruption [{c.start_offset}:{c.end_offset}]"


# ─── 12. Multiple Corruption Regions ──────────────────────────────────────────

def test_12_multiple_corruption_regions(analyzer, ground_truth):
    """Verifies that multiple disjoint corruption regions are independently localized."""
    multi_files = [k for k, v in ground_truth.items() if v["variant"] == "MULTIPLE_CORRUPTION_REGIONS"]
    assert len(multi_files) == 4

    for fname in multi_files:
        path = FIXTURES_DIR / fname
        result = analyzer.analyze(path)

        assert len(result.corruption_regions) >= 2, f"{fname} must identify >= 2 corruption regions"
        # Check regions are in strictly increasing order
        for i in range(len(result.corruption_regions) - 1):
            curr_c = result.corruption_regions[i]
            next_c = result.corruption_regions[i + 1]
            assert curr_c.end_offset <= next_c.start_offset, "Corruption regions must be disjoint and sorted"


# ─── 13. SHA-256 Calculation ──────────────────────────────────────────────────

def test_13_sha256_calculation(analyzer):
    """Verifies accurate SHA-256 calculation over input bytes."""
    sample = b"Digital Forensic Verification Payload 2026"
    expected_sha256 = hashlib.sha256(sample).hexdigest()

    result = analyzer.analyze(sample)
    assert result.sha256 == expected_sha256
    assert result.hash.computed_sha256 == expected_sha256


# ─── 14. Reference Hash Match ─────────────────────────────────────────────────

def test_14_reference_hash_match(analyzer):
    """Verifies status MATCH when computed SHA-256 matches reference."""
    sample = b"Pristine Baseline Evidence Block"
    ref_hash = hashlib.sha256(sample).hexdigest()

    result = analyzer.analyze(sample, reference_sha256=ref_hash)
    assert result.hash.status == HashVerificationStatus.MATCH
    assert result.hash.reference_sha256 == ref_hash


# ─── 15. Reference Hash Mismatch ──────────────────────────────────────────────

def test_15_reference_hash_mismatch(analyzer):
    """Verifies status MISMATCH when computed SHA-256 differs from reference."""
    sample = b"Actual Evidence Bytes"
    wrong_ref = "0000000000000000000000000000000000000000000000000000000000000000"

    result = analyzer.analyze(sample, reference_sha256=wrong_ref)
    assert result.hash.status == HashVerificationStatus.MISMATCH
    assert result.hash.reference_sha256 == wrong_ref


# ─── 16. Unknown / Uncertain Cases ────────────────────────────────────────────

def test_16_unknown_uncertain_cases(analyzer):
    """Verifies graceful handling of empty or unidentifiable byte streams."""
    empty_bytes = b""
    result_empty = analyzer.analyze(empty_bytes)
    assert result_empty.file_size == 0

    random_noise = bytes([i % 256 for i in range(256)])
    result_noise = analyzer.analyze(random_noise)
    assert result_noise.overall_status in (IntegrityStatus.UNKNOWN, IntegrityStatus.PARTIALLY_DAMAGED)


# ─── 17. Safety: Read-Only Source Preservation ────────────────────────────────

def test_17_source_safety_read_only(analyzer):
    """Cryptographically proves source file is never modified or overwritten."""
    test_file = FIXTURES_DIR / "jpeg_1_valid.jpg"
    assert test_file.exists()

    with open(test_file, "rb") as f:
        pre_hash = hashlib.sha256(f.read()).hexdigest()

    # Run analysis
    _ = analyzer.analyze(test_file)

    with open(test_file, "rb") as f:
        post_hash = hashlib.sha256(f.read()).hexdigest()

    assert pre_hash == post_hash, "Source file SHA-256 altered! Read-only invariant violated!"
