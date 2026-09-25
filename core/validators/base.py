"""
core/validators/base.py
=======================
Base validator class and shared data containers for format-specific validators.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from core.models import (
    ByteRegion,
    CheckStatus,
    CorruptionRegion,
    CorruptionType,
    RegionClassification,
    StructuralCheck,
)


class ValidationResult(BaseModel):
    """Container returned by each format-specific validator."""
    format_name: str
    checks: List[StructuralCheck] = Field(default_factory=list)
    corruption_regions: List[CorruptionRegion] = Field(default_factory=list)
    intact_regions: List[ByteRegion] = Field(default_factory=list)
    damaged_regions: List[ByteRegion] = Field(default_factory=list)

    structural_integrity: float = 100.0
    checksum_integrity: float = 100.0
    decoder_integrity: float = 100.0
    evidence: List[str] = Field(default_factory=list)


class BaseValidator(ABC):
    """Abstract base class for all forensic format validators."""

    @abstractmethod
    def validate(self, data: bytes) -> ValidationResult:
        """
        Parses format structure at byte level, runs verification checks,
        and localizes corruption and intact regions with exact byte offsets.
        """
        pass
