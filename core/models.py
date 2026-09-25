"""
core/models.py
==============
Forensic data models for Feature 02: Data Integrity & Corruption Assessment.
Strict Pydantic v2 schemas adhering to courtroom-admissible, byte-level standards.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


# ─── Status & Taxonomy Enums ──────────────────────────────────────────────────

class IntegrityStatus(str, Enum):
    INTACT = "INTACT"
    PARTIALLY_DAMAGED = "PARTIALLY_DAMAGED"
    CORRUPTED = "CORRUPTED"
    TRUNCATED = "TRUNCATED"
    UNRECOVERABLE = "UNRECOVERABLE"
    UNKNOWN = "UNKNOWN"


class RegionClassification(str, Enum):
    INTACT = "INTACT"
    DAMAGED = "DAMAGED"
    CORRUPTED = "CORRUPTED"
    UNKNOWN = "UNKNOWN"


class CorruptionType(str, Enum):
    HEADER_CORRUPTION = "HEADER_CORRUPTION"
    TRUNCATION = "TRUNCATION"
    MISSING_TRAILER = "MISSING_TRAILER"
    INVALID_MARKER = "INVALID_MARKER"
    INVALID_LENGTH = "INVALID_LENGTH"
    CHECKSUM_FAILURE = "CHECKSUM_FAILURE"
    CRC_FAILURE = "CRC_FAILURE"
    STRUCTURAL_CORRUPTION = "STRUCTURAL_CORRUPTION"
    BYTE_RANGE_ANOMALY = "BYTE_RANGE_ANOMALY"
    ZERO_FILLED_REGION = "ZERO_FILLED_REGION"
    UNEXPECTED_GAP = "UNEXPECTED_GAP"
    DECODER_FAILURE = "DECODER_FAILURE"
    METADATA_INCONSISTENCY = "METADATA_INCONSISTENCY"
    HASH_MISMATCH = "HASH_MISMATCH"
    UNKNOWN_CORRUPTION = "UNKNOWN_CORRUPTION"
    UNKNOWN = "UNKNOWN"
    UNCERTAIN = "UNCERTAIN"


class CheckStatus(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    WARNING = "WARNING"
    SKIPPED = "SKIPPED"


class HashVerificationStatus(str, Enum):
    NO_REFERENCE = "NO_REFERENCE"
    MATCH = "MATCH"
    MISMATCH = "MISMATCH"


class RecoverabilityClassification(str, Enum):
    FULLY_RECOVERABLE = "FULLY_RECOVERABLE"
    PARTIALLY_RECOVERABLE = "PARTIALLY_RECOVERABLE"
    CORRUPTED = "CORRUPTED"
    UNRECOVERABLE = "UNRECOVERABLE"
    UNKNOWN = "UNKNOWN"


# ─── Individual Check & Region Records ────────────────────────────────────────

class StructuralCheck(BaseModel):
    """Individual format check with exact byte location and expected vs actual values."""
    check: str
    status: CheckStatus
    location: int
    expected: str = ""
    actual: str = ""
    description: str = ""


class CorruptionRegion(BaseModel):
    """
    Localized corruption zone with exact byte offsets.
    Supports both start_offset/end_offset and start/end for client compatibility.
    Phase 2: Adds validator, expected, actual, recoverability_impact, evidence, provenance, and underlying_findings.
    """
    start_offset: int
    end_offset: int
    length: int
    type: str
    reason: str = ""
    severity: str = "medium"

    # Phase 2 enriched diagnostic fields
    validator: str = ""
    expected: str = ""
    actual: str = ""
    recoverability_impact: str = ""
    evidence: str = ""
    provenance: Optional[Dict[str, Any]] = None
    underlying_findings: List[Dict[str, Any]] = Field(default_factory=list)

    @property
    def start(self) -> int:
        return self.start_offset

    @property
    def end(self) -> int:
        return self.end_offset

    def model_dump(self, *args, **kwargs) -> Dict[str, Any]:
        d = super().model_dump(*args, **kwargs)
        d["start"] = self.start_offset
        d["end"] = self.end_offset
        return d


class ByteRegion(BaseModel):
    """Classified byte range within the artifact (INTACT, DAMAGED, CORRUPTED, UNKNOWN)."""
    start: int
    end: int
    length: int
    status: RegionClassification
    type: Optional[str] = None
    description: str = ""


class HashVerificationResult(BaseModel):
    """Hash verification against optional reference hash."""
    status: HashVerificationStatus
    computed_sha256: str
    computed_md5: Optional[str] = None
    reference_sha256: Optional[str] = None
    description: str = ""


class RecoverabilityAssessment(BaseModel):
    """Forensic recoverability determination."""
    classification: RecoverabilityClassification
    intact_ratio: float = 0.0
    recoverable_features: List[str] = Field(default_factory=list)
    unrecoverable_features: List[str] = Field(default_factory=list)
    explanation: str = ""


class DecomposedScore(BaseModel):
    """Decomposed, transparent integrity scores (never opaque single percentages)."""
    signature_integrity: float = 100.0
    structural_integrity: float = 100.0
    checksum_integrity: float = 100.0
    byte_integrity: float = 100.0
    metadata_integrity: float = 100.0
    decoder_integrity: float = 100.0
    overall_score: float = 100.0


# ─── Phase 2 Specialized Models ───────────────────────────────────────────────

class BlockAnalysisRecord(BaseModel):
    """
    Fixed / adaptive block analysis record.
    Represents BLOCK_001 -> INTACT, BLOCK_002 -> CORRUPTED, etc.
    """
    block_index: int
    offset_start: int
    offset_end: int
    size: int
    sha256: str
    entropy: float
    zero_ratio: float
    state: RegionClassification
    label: str = ""
    notes: str = ""


class DecoderResult(BaseModel):
    """Safe, non-modifying real decoder verification result."""
    decoder_name: str
    attempted: bool
    success: bool
    error_message: Optional[str] = None
    error_offset: Optional[int] = None
    partial_recovery_possible: bool = False
    details: Dict[str, Any] = Field(default_factory=dict)


class ReferenceComparisonResult(BaseModel):
    """Byte-level ground-truth comparison against reference bytes."""
    reference_sha256: Optional[str] = None
    match: bool = False
    byte_match_percentage: float = 0.0
    changed_ranges: List[Dict[str, int]] = Field(default_factory=list)
    missing_ranges: List[Dict[str, int]] = Field(default_factory=list)
    extra_ranges: List[Dict[str, int]] = Field(default_factory=list)
    fuzzy_similarity: Optional[float] = None
    fuzzy_note: Optional[str] = None


class MLAnomalySignal(BaseModel):
    """
    Auxiliary explainable ML supporting anomaly signal.
    Labeled explicitly as 'ML SUPPORTING SIGNAL' (never proof of corruption).
    """
    label: str = "ML SUPPORTING SIGNAL"
    anomaly_score: float = 0.0
    entropy_transition_score: float = 0.0
    byte_distribution_score: float = 0.0
    structural_failure_density: float = 0.0
    repeated_zero_score: float = 0.0
    findings: List[str] = Field(default_factory=list)
    explanation: str = ""


class DetailedSectionBreakdown(BaseModel):
    """Format-specific breakdown answering which sections are valid, damaged, or missing."""
    valid_sections: List[str] = Field(default_factory=list)
    damaged_sections: List[str] = Field(default_factory=list)
    missing_sections: List[str] = Field(default_factory=list)
    blocking_issues: List[str] = Field(default_factory=list)
    partial_recovery_possible: bool = False
    recoverability_rationale: str = ""


# ─── Master Output Model ──────────────────────────────────────────────────────

class IntegrityAssessment(BaseModel):
    """
    Complete structured forensic assessment result for an artifact.
    Matches CALMSTACKS Feature 02 output specification verbatim.
    """
    artifact_id: str
    format: str
    file_size: int
    sha256: str
    overall_status: IntegrityStatus

    checks: List[StructuralCheck] = Field(default_factory=list)
    corruption_regions: List[CorruptionRegion] = Field(default_factory=list)
    intact_regions: List[ByteRegion] = Field(default_factory=list)
    damaged_regions: List[ByteRegion] = Field(default_factory=list)

    hash: HashVerificationResult
    recoverability: RecoverabilityAssessment
    scores: DecomposedScore
    evidence: List[str] = Field(default_factory=list)

    # Phase 2 enriched forensic outputs
    blocks: List[BlockAnalysisRecord] = Field(default_factory=list)
    decoder: Optional[DecoderResult] = None
    reference_comparison: Optional[ReferenceComparisonResult] = None
    ml_signal: Optional[MLAnomalySignal] = None
    section_breakdown: Optional[DetailedSectionBreakdown] = None

