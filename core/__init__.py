"""
core/__init__.py
================
CALMSTACKS Feature 02: Data Integrity & Corruption Assessment Module.
"""

from core.models import (
    BlockAnalysisRecord,
    CheckStatus,
    CorruptionRegion,
    CorruptionType,
    DecoderResult,
    DecomposedScore,
    DetailedSectionBreakdown,
    HashVerificationResult,
    HashVerificationStatus,
    IntegrityAssessment,
    IntegrityStatus,
    MLAnomalySignal,
    RecoverabilityAssessment,
    RecoverabilityClassification,
    ReferenceComparisonResult,
    RegionClassification,
    StructuralCheck,
)

__all__ = [
    "BlockAnalysisRecord",
    "CheckStatus",
    "CorruptionRegion",
    "CorruptionType",
    "DecoderResult",
    "DecomposedScore",
    "DetailedSectionBreakdown",
    "HashVerificationResult",
    "HashVerificationStatus",
    "IntegrityAssessment",
    "IntegrityStatus",
    "MLAnomalySignal",
    "RecoverabilityAssessment",
    "RecoverabilityClassification",
    "ReferenceComparisonResult",
    "RegionClassification",
    "StructuralCheck",
]

