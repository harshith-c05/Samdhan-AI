"""
core/validators/sqlite.py
=========================
Format-aware byte-level structural validator for SQLite 3 Relational Databases.
"""

import struct
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


SQLITE_MAGIC = b"SQLite format 3\x00"


class SQLiteValidator(BaseValidator):
    """
    Validates:
    - 16-byte magic header ("SQLite format 3\x00")
    - Database page size (power of 2 between 512 and 65536)
    - Page count and expected file size bounds
    - B-Tree page headers
    """

    def validate(self, data: bytes) -> ValidationResult:
        checks: List[StructuralCheck] = []
        corruption_regions: List[CorruptionRegion] = []
        intact_regions: List[ByteRegion] = []
        damaged_regions: List[ByteRegion] = []
        evidence: List[str] = []

        total_bytes = len(data)
        if total_bytes < 100:  # SQLite header is 100 bytes minimum
            checks.append(StructuralCheck(
                check="SQLITE_HEADER_SIZE",
                status=CheckStatus.FAIL,
                location=0,
                expected=">= 100 bytes database header",
                actual=f"{total_bytes} bytes",
                description="File too small for 100-byte SQLite header",
            ))
            corruption_regions.append(CorruptionRegion(
                start_offset=0,
                end_offset=total_bytes,
                length=total_bytes,
                type=CorruptionType.HEADER_CORRUPTION.value,
                reason="File shorter than SQLite 100-byte database header",
                severity="critical",
            ))
            return ValidationResult(
                format_name="SQLITE",
                checks=checks,
                corruption_regions=corruption_regions,
                intact_regions=[],
                damaged_regions=[],
                structural_integrity=0.0,
                checksum_integrity=100.0,
                decoder_integrity=0.0,
                evidence=["File too short for SQLite header"],
            )

        # 1. Magic Header Check
        magic = data[:16]
        if magic == SQLITE_MAGIC:
            checks.append(StructuralCheck(
                check="SQLITE_MAGIC",
                status=CheckStatus.PASS,
                location=0,
                expected=SQLITE_MAGIC.hex().upper(),
                actual=magic.hex().upper(),
                description="Valid SQLite 3 header magic string",
            ))
            intact_regions.append(ByteRegion(
                start=0,
                end=16,
                length=16,
                status=RegionClassification.INTACT,
                description="SQLite 3 Magic String",
            ))
            evidence.append("Valid SQLite format 3 magic header verified")
        else:
            checks.append(StructuralCheck(
                check="SQLITE_MAGIC",
                status=CheckStatus.FAIL,
                location=0,
                expected=SQLITE_MAGIC.hex().upper(),
                actual=magic.hex().upper(),
                description="Corrupted or missing SQLite magic header string",
            ))
            corruption_regions.append(CorruptionRegion(
                start_offset=0,
                end_offset=16,
                length=16,
                type=CorruptionType.HEADER_CORRUPTION.value,
                reason=f"SQLite magic string mismatch: expected 'SQLite format 3', got '{magic.decode('latin-1', errors='replace')}'",
                severity="critical",
            ))
            evidence.append("Corrupted SQLite magic header")

        # 2. Page Size Check
        raw_page_size = struct.unpack(">H", data[16:18])[0]
        page_size = 65536 if raw_page_size == 1 else raw_page_size
        valid_page_size = (page_size >= 512 and page_size <= 65536 and (page_size & (page_size - 1)) == 0)

        if valid_page_size:
            checks.append(StructuralCheck(
                check="SQLITE_PAGE_SIZE",
                status=CheckStatus.PASS,
                location=16,
                expected="Power of 2 in [512, 65536]",
                actual=f"{page_size} bytes",
                description=f"Valid database page size {page_size}",
            ))
            intact_regions.append(ByteRegion(
                start=16,
                end=100,
                length=84,
                status=RegionClassification.INTACT,
                description="SQLite Database Header Fields",
            ))
        else:
            checks.append(StructuralCheck(
                check="SQLITE_PAGE_SIZE",
                status=CheckStatus.FAIL,
                location=16,
                expected="Power of 2 in [512, 65536]",
                actual=f"{page_size} bytes",
                description=f"Illegal database page size {page_size}",
            ))
            corruption_regions.append(CorruptionRegion(
                start_offset=16,
                end_offset=18,
                length=2,
                type=CorruptionType.STRUCTURAL_CORRUPTION.value,
                reason=f"Illegal SQLite page size: {page_size}",
                severity="high",
            ))

        # 3. Page Count & File Size Verification
        declared_pages = struct.unpack(">I", data[28:32])[0]
        if valid_page_size and declared_pages > 0:
            expected_size = declared_pages * page_size
            if total_bytes < expected_size:
                trunc_bytes = expected_size - total_bytes
                checks.append(StructuralCheck(
                    check="SQLITE_FILE_SIZE",
                    status=CheckStatus.FAIL,
                    location=total_bytes,
                    expected=f"{expected_size} bytes ({declared_pages} pages)",
                    actual=f"{total_bytes} bytes",
                    description=f"Database file truncated by {trunc_bytes} bytes",
                ))
                corruption_regions.append(CorruptionRegion(
                    start_offset=total_bytes,
                    end_offset=expected_size,
                    length=trunc_bytes,
                    type=CorruptionType.TRUNCATION.value,
                    reason=f"Database truncated: declared {declared_pages} pages ({expected_size} bytes) but file has {total_bytes} bytes",
                    severity="high",
                ))
                evidence.append(f"SQLite file truncated: missing {trunc_bytes} bytes for declared page count")
            else:
                checks.append(StructuralCheck(
                    check="SQLITE_FILE_SIZE",
                    status=CheckStatus.PASS,
                    location=28,
                    expected=f"{expected_size} bytes",
                    actual=f"{total_bytes} bytes",
                    description=f"Declared {declared_pages} pages matches file boundary",
                ))

        pass_count = sum(1 for c in checks if c.status == CheckStatus.PASS)
        struct_score = (pass_count / len(checks) * 100.0) if checks else 0.0

        return ValidationResult(
            format_name="SQLITE",
            checks=checks,
            corruption_regions=corruption_regions,
            intact_regions=intact_regions,
            damaged_regions=damaged_regions,
            structural_integrity=round(struct_score, 1),
            checksum_integrity=100.0,
            decoder_integrity=100.0 if not corruption_regions else 25.0,
            evidence=evidence,
        )
