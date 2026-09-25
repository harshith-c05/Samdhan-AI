"""
core/integrity_analyzer.py
==========================
Master format-aware, byte-level data integrity and corruption assessment engine.
Adheres strictly to CALMSTACKS Feature 02 requirements:
"Determine which portions of recovered data are intact, damaged, or corrupted."
"""

import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from core.byte_analyzer import analyze_byte_stream, calculate_hashes
from core.models import (
    CheckStatus,
    CorruptionRegion,
    CorruptionType,
    DecomposedScore,
    HashVerificationResult,
    HashVerificationStatus,
    IntegrityAssessment,
    IntegrityStatus,
    RecoverabilityAssessment,
    RecoverabilityClassification,
    RegionClassification,
    StructuralCheck,
)
from core.range_partitioner import partition_byte_ranges
from core.signature_registry import verify_signature
from core.validators import get_validator_for_format


class IntegrityAnalyzer:
    """
    Forensic Data Integrity & Corruption Assessment Analyzer.
    
    Guarantees:
    - Source artifacts are strictly READ-ONLY (never altered, repaired, or overwritten)
    - Byte-level offset localization (never fabricated)
    - Decomposed, transparent scoring (never opaque single percentages)
    - Courtroom-defensible chain of evidence
    """

    def analyze(
        self,
        artifact: Union[bytes, str, Path],
        artifact_id: Optional[str] = None,
        filename: Optional[str] = None,
        claimed_format: Optional[str] = None,
        reference_sha256: Optional[str] = None,
    ) -> IntegrityAssessment:
        """
        Executes complete 8-step forensic integrity pipeline:
        1. Input Validation & Safe Ingest (Read-Only)
        2. Pre-processing Input Hashing
        3. Byte-Level Signature Verification
        4. Format-Aware Structural Validation
        5. Deep Byte-Level & Anomaly Analysis
        6. Reference Hash Comparison
        7. Corruption & Intact Range Localization
        8. Transparent Scoring & Recoverability Assessment
        """
        # 1. Input Ingest
        if isinstance(artifact, (str, Path)):
            path = Path(artifact)
            if not path.exists():
                raise FileNotFoundError(f"Artifact not found on disk: {path}")
            if not path.is_file():
                raise ValueError(f"Path is not a regular file: {path}")
            if filename is None:
                filename = path.name
            if artifact_id is None:
                artifact_id = path.stem
            # Read strictly binary read-only
            with open(path, "rb") as f:
                data = f.read()
        elif isinstance(artifact, bytes):
            data = artifact
            if artifact_id is None:
                artifact_id = "ARTIFACT-STREAM"
            if filename is None:
                filename = f"{artifact_id}.bin"
        else:
            raise TypeError(f"Unsupported artifact input type: {type(artifact)}")

        file_size = len(data)
        evidence: List[str] = []

        # 2. Cryptographic Pre-Hashing
        hashes = calculate_hashes(data)
        computed_sha256 = hashes["sha256"]
        computed_md5 = hashes["md5"]

        # 3. Signature Verification
        sig_result = verify_signature(
            data,
            filename=filename,
            claimed_format=claimed_format,
        )
        detected_format = sig_result["format_detected"]
        format_name = detected_format if detected_format != "UNKNOWN" else (claimed_format or "UNKNOWN")

        all_checks: List[StructuralCheck] = []
        raw_corruption_regions: List[CorruptionRegion] = []
        known_damaged = []
        validator_evidence = []

        # 4. Structural Validation
        validator = get_validator_for_format(format_name)
        if validator:
            val_res = validator.validate(data)
            all_checks.extend(val_res.checks)
            raw_corruption_regions.extend(val_res.corruption_regions)
            known_damaged.extend(val_res.damaged_regions)
            validator_evidence.extend(val_res.evidence)
            struct_score = val_res.structural_integrity
            checksum_score = val_res.checksum_integrity
            decoder_score = val_res.decoder_integrity
        else:
            # Fallback for unrecognized formats
            all_checks.append(StructuralCheck(
                check="FORMAT_RECOGNITION",
                status=CheckStatus.WARNING,
                location=0,
                expected="Known binary signature",
                actual="Unrecognized byte pattern",
                description=f"Format '{format_name}' has no format-specific structural parser",
            ))
            struct_score = 50.0
            checksum_score = 100.0
            decoder_score = 50.0

        # Signature check record
        sig_status = CheckStatus.PASS if sig_result["signature_valid"] else CheckStatus.FAIL
        all_checks.insert(0, StructuralCheck(
            check=f"{format_name}_SIGNATURE",
            status=sig_status,
            location=sig_result["match_offset"] if sig_result["match_offset"] >= 0 else 0,
            expected=sig_result["expected_format"] or "Known header signature",
            actual=sig_result["format_detected"],
            description="Magic byte signature verification",
        ))

        if sig_result["conflict_details"]:
            evidence.append(sig_result["conflict_details"])
            raw_corruption_regions.append(CorruptionRegion(
                start_offset=0,
                end_offset=min(16, file_size),
                length=min(16, file_size),
                type=CorruptionType.HEADER_CORRUPTION.value,
                reason=sig_result["conflict_details"],
                severity="critical",
            ))

        # 5. Byte-Level & Anomaly Analysis
        byte_analysis = analyze_byte_stream(data, format_hint=format_name)
        entropy = byte_analysis["entropy"]
        zero_ratio = byte_analysis["zero_byte_ratio"]

        # Incorporate unexpected zero-fill runs into corruption regions
        for zr in byte_analysis["zero_filled_regions"]:
            # Only mark zero-fills as corruption if inside compressed formats
            if format_name in ("JPEG", "PNG", "ZIP", "DOCX") and zr["length"] >= 256:
                raw_corruption_regions.append(CorruptionRegion(
                    start_offset=zr["start"],
                    end_offset=zr["end"] + 1,
                    length=zr["length"],
                    type=CorruptionType.ZERO_FILLED_REGION.value,
                    reason=f"Zero-filled span ({zr['length']} null bytes) within compressed stream",
                    severity="medium",
                ))

        # 6. Reference Hash Verification
        if reference_sha256:
            ref_clean = reference_sha256.strip().lower()
            if computed_sha256 == ref_clean:
                hash_status = HashVerificationStatus.MATCH
                hash_desc = f"SHA-256 matches reference hash: {ref_clean}"
                evidence.append("Cryptographic hash verification: MATCH")
            else:
                hash_status = HashVerificationStatus.MISMATCH
                hash_desc = f"SHA-256 mismatch: computed {computed_sha256} != reference {ref_clean}"
                evidence.append(f"Cryptographic hash MISMATCH (differs from reference {ref_clean[:12]}...)")
                # Note requirement: hash mismatch proves bytes differ, does not fabricate corruption
        else:
            hash_status = HashVerificationStatus.NO_REFERENCE
            hash_desc = "No reference hash provided for comparison"

        hash_result = HashVerificationResult(
            status=hash_status,
            computed_sha256=computed_sha256,
            computed_md5=computed_md5,
            reference_sha256=reference_sha256,
            description=hash_desc,
        )

        # 7. Corruption Localization & Range Partitioning
        intact_regions, damaged_regions, consolidated_corruption = partition_byte_ranges(
            file_size=file_size,
            corruption_regions=raw_corruption_regions,
            known_intact=[],
            known_damaged=known_damaged,
        )

        total_corrupted_bytes = sum(c.length for c in consolidated_corruption)
        total_intact_bytes = sum(r.length for r in intact_regions)
        intact_ratio = round((total_intact_bytes / file_size), 4) if file_size > 0 else 0.0

        # 8. Overall Status Determination
        has_truncation = any(
            c.type in (CorruptionType.TRUNCATION.value, CorruptionType.MISSING_TRAILER.value)
            for c in consolidated_corruption
        )
        has_header_corrupt = any(
            c.type == CorruptionType.HEADER_CORRUPTION.value
            for c in consolidated_corruption
        )

        if not consolidated_corruption and all(c.status != CheckStatus.FAIL for c in all_checks):
            overall_status = IntegrityStatus.INTACT
        elif has_header_corrupt and struct_score < 20.0:
            overall_status = IntegrityStatus.UNRECOVERABLE
        elif has_truncation and intact_ratio > 0.40:
            overall_status = IntegrityStatus.TRUNCATED
        elif consolidated_corruption and intact_ratio >= 0.30:
            overall_status = IntegrityStatus.PARTIALLY_DAMAGED
        elif consolidated_corruption:
            overall_status = IntegrityStatus.CORRUPTED
        elif format_name == "UNKNOWN":
            overall_status = IntegrityStatus.UNKNOWN
        else:
            overall_status = IntegrityStatus.PARTIALLY_DAMAGED

        # Transparent Decomposed Scoring
        sig_score = 100.0 if sig_result["signature_valid"] else 0.0
        byte_score = max(0.0, round((1.0 - (total_corrupted_bytes / max(file_size, 1))) * 100.0, 1))
        meta_score = 100.0

        overall_score = round(
            0.20 * sig_score +
            0.30 * struct_score +
            0.20 * checksum_score +
            0.15 * byte_score +
            0.15 * decoder_score,
            1
        )

        scores = DecomposedScore(
            signature_integrity=round(sig_score, 1),
            structural_integrity=round(struct_score, 1),
            checksum_integrity=round(checksum_score, 1),
            byte_integrity=round(byte_score, 1),
            metadata_integrity=round(meta_score, 1),
            decoder_integrity=round(decoder_score, 1),
            overall_score=overall_score,
        )

        # Recoverability Determination
        if overall_status == IntegrityStatus.INTACT:
            rec_class = RecoverabilityClassification.FULLY_RECOVERABLE
            rec_exp = "All byte segments and structural markers intact; file is 100% usable."
        elif overall_status in (IntegrityStatus.PARTIALLY_DAMAGED, IntegrityStatus.TRUNCATED) and intact_ratio >= 0.50:
            rec_class = RecoverabilityClassification.PARTIALLY_RECOVERABLE
            rec_exp = f"{intact_ratio * 100:.1f}% of byte stream remains intact; key headers parseable."
        elif overall_status == IntegrityStatus.UNRECOVERABLE:
            rec_class = RecoverabilityClassification.UNRECOVERABLE
            rec_exp = "Container headers and payload severely damaged; impossible to parse or decode."
        else:
            rec_class = RecoverabilityClassification.CORRUPTED
            rec_exp = "Structural breakdown or critical checksum failure prevents normal operation."

        recoverability = RecoverabilityAssessment(
            classification=rec_class,
            intact_ratio=intact_ratio,
            recoverable_features=[r.description for r in intact_regions[:5]],
            unrecoverable_features=[c.reason for c in consolidated_corruption[:5]],
            explanation=rec_exp,
        )

        # Merge evidence list
        evidence.extend(validator_evidence)
        if consolidated_corruption:
            for c in consolidated_corruption:
                evidence.append(f"Localized corruption at [{c.start_offset}:{c.end_offset}] ({c.length} bytes): {c.reason}")

        return IntegrityAssessment(
            artifact_id=artifact_id,
            format=format_name,
            file_size=file_size,
            sha256=computed_sha256,
            overall_status=overall_status,
            checks=all_checks,
            corruption_regions=consolidated_corruption,
            intact_regions=intact_regions,
            damaged_regions=damaged_regions,
            hash=hash_result,
            recoverability=recoverability,
            scores=scores,
            evidence=evidence,
        )
