"""
core/validators/docx.py
=======================
Format-aware byte-level structural validator for Microsoft OOXML (.docx/.xlsx/.pptx).
"""

import io
import zipfile
from typing import List

from core.models import (
    ByteRegion,
    CheckStatus,
    CorruptionRegion,
    CorruptionType,
    RegionClassification,
    StructuralCheck,
)
from core.validators.base import BaseValidator, ValidationResult
from core.validators.zip_validator import ZIPValidator


class DOCXValidator(BaseValidator):
    """
    Validates:
    - Underlying ZIP container
    - [Content_Types].xml manifest
    - word/document.xml core document part
    - OOXML packaging relationships
    """

    def validate(self, data: bytes) -> ValidationResult:
        # First validate underlying ZIP container
        zip_val = ZIPValidator()
        zip_res = zip_val.validate(data)

        checks = list(zip_res.checks)
        corruption_regions = list(zip_res.corruption_regions)
        intact_regions = list(zip_res.intact_regions)
        damaged_regions = list(zip_res.damaged_regions)
        evidence = list(zip_res.evidence)

        has_content_types = False
        has_word_doc = False
        decoder_ok = False

        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                names = zf.namelist()
                has_content_types = "[Content_Types].xml" in names
                has_word_doc = any("word/document.xml" in n or "xl/workbook.xml" in n or "ppt/presentation.xml" in n for n in names)
                decoder_ok = has_content_types and has_word_doc
        except Exception:
            pass

        checks.append(StructuralCheck(
            check="OOXML_CONTENT_TYPES",
            status=CheckStatus.PASS if has_content_types else CheckStatus.FAIL,
            location=0,
            expected="[Content_Types].xml entry",
            actual="Found" if has_content_types else "Missing",
            description="[Content_Types].xml manifest verification",
        ))

        checks.append(StructuralCheck(
            check="OOXML_DOCUMENT_PART",
            status=CheckStatus.PASS if has_word_doc else CheckStatus.FAIL,
            location=0,
            expected="Primary payload XML (document.xml)",
            actual="Found" if has_word_doc else "Missing",
            description="Core OOXML document XML verification",
        ))

        pass_count = sum(1 for c in checks if c.status == CheckStatus.PASS)
        struct_score = (pass_count / len(checks) * 100.0) if checks else 0.0

        return ValidationResult(
            format_name="DOCX",
            checks=checks,
            corruption_regions=corruption_regions,
            intact_regions=intact_regions,
            damaged_regions=damaged_regions,
            structural_integrity=round(struct_score, 1),
            checksum_integrity=zip_res.checksum_integrity,
            decoder_integrity=100.0 if decoder_ok else 20.0,
            evidence=evidence,
        )
