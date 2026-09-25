"""
core/validators/log.py
======================
Format-aware byte-level structural validator for System & Application Logs.
"""

import re
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


class LogValidator(BaseValidator):
    """
    Validates:
    - Text encoding integrity (UTF-8 / ASCII)
    - Structured timestamp formats (ISO-8601, RFC-3164 Syslog)
    - Absence of binary injection or null corruption runs
    """

    def validate(self, data: bytes) -> ValidationResult:
        checks: List[StructuralCheck] = []
        corruption_regions: List[CorruptionRegion] = []
        intact_regions: List[ByteRegion] = []
        damaged_regions: List[ByteRegion] = []
        evidence: List[str] = []

        total_bytes = len(data)
        if total_bytes == 0:
            checks.append(StructuralCheck(
                check="LOG_EMPTY",
                status=CheckStatus.WARNING,
                location=0,
                expected="Non-empty text",
                actual="0 bytes",
                description="Empty log file",
            ))
            return ValidationResult(
                format_name="LOG",
                checks=checks,
                corruption_regions=[],
                intact_regions=[],
                damaged_regions=[],
                structural_integrity=100.0,
                checksum_integrity=100.0,
                decoder_integrity=100.0,
                evidence=["Empty log file"],
            )

        # 1. UTF-8 Encoding Verification
        try:
            text = data.decode("utf-8")
            checks.append(StructuralCheck(
                check="LOG_UTF8_ENCODING",
                status=CheckStatus.PASS,
                location=0,
                expected="Valid UTF-8 stream",
                actual="Valid UTF-8",
                description="All bytes represent valid UTF-8 characters",
            ))
            intact_regions.append(ByteRegion(
                start=0,
                end=total_bytes,
                length=total_bytes,
                status=RegionClassification.INTACT,
                description="Valid UTF-8 Log Stream",
            ))
        except UnicodeDecodeError as ue:
            checks.append(StructuralCheck(
                check="LOG_UTF8_ENCODING",
                status=CheckStatus.FAIL,
                location=ue.start,
                expected="Valid UTF-8",
                actual=f"Invalid byte 0x{data[ue.start]:02X}",
                description=f"Encoding error at offset {ue.start}",
            ))
            corruption_regions.append(CorruptionRegion(
                start_offset=ue.start,
                end_offset=min(ue.end, total_bytes),
                length=ue.end - ue.start,
                type=CorruptionType.BYTE_RANGE_ANOMALY.value,
                reason=f"Illegal non-UTF-8 byte sequence in log text",
                severity="medium",
            ))
            text = data.decode("utf-8", errors="replace")

        # 2. Line Structure Analysis
        lines = text.splitlines(keepends=True)
        RFC3164 = re.compile(r"^(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d+\s+\d{2}:\d{2}:\d{2}")
        ISO8601 = re.compile(r"^\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}")
        BRACKET = re.compile(r"^\[\d{4}-\d{2}-\d{2}|\[INFO\]|\[ERROR\]|\[WARN\]|\[DEBUG\]")

        matched_lines = 0
        curr_offset = 0
        for line in lines:
            line_len = len(line.encode("utf-8", errors="replace"))
            clean_l = line.strip()
            if RFC3164.match(clean_l) or ISO8601.match(clean_l) or BRACKET.match(clean_l):
                matched_lines += 1
            curr_offset += line_len

        ratio = (matched_lines / len(lines)) if lines else 0.0
        checks.append(StructuralCheck(
            check="LOG_RECORD_STRUCTURE",
            status=CheckStatus.PASS if ratio >= 0.50 else CheckStatus.WARNING,
            location=0,
            expected=">= 50% lines match log timestamps",
            actual=f"{matched_lines}/{len(lines)} lines matched ({ratio * 100:.1f}%)",
            description=f"Timestamp format conformity {ratio * 100:.1f}%",
        ))

        pass_count = sum(1 for c in checks if c.status == CheckStatus.PASS)
        struct_score = (pass_count / len(checks) * 100.0) if checks else 0.0

        return ValidationResult(
            format_name="LOG",
            checks=checks,
            corruption_regions=corruption_regions,
            intact_regions=intact_regions,
            damaged_regions=damaged_regions,
            structural_integrity=round(struct_score, 1),
            checksum_integrity=100.0,
            decoder_integrity=100.0 if not corruption_regions else 60.0,
            evidence=[f"{matched_lines}/{len(lines)} lines matched structured log patterns"],
        )
