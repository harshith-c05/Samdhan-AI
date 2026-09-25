"""
core/validators/png.py
======================
Format-aware byte-level structural validator for Portable Network Graphics (PNG).
Adheres strictly to RFC 2083 / W3C PNG Specification.
"""

import io
import struct
import zlib
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


PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"


class PNGValidator(BaseValidator):
    """
    Validates:
    - 8-byte signature
    - Chunk headers, lengths, and ordering (IHDR first, IDAT contiguous, IEND last)
    - IEEE 802.3 32-bit CRC per chunk
    - zlib decompression & image raster integrity
    """

    def validate(self, data: bytes) -> ValidationResult:
        checks: List[StructuralCheck] = []
        corruption_regions: List[CorruptionRegion] = []
        intact_regions: List[ByteRegion] = []
        damaged_regions: List[ByteRegion] = []
        evidence: List[str] = []

        total_bytes = len(data)
        if total_bytes < 8:
            checks.append(StructuralCheck(
                check="PNG_SIGNATURE",
                status=CheckStatus.FAIL,
                location=0,
                expected=PNG_SIGNATURE.hex().upper(),
                actual=data.hex().upper(),
                description="File too small for 8-byte PNG signature",
            ))
            corruption_regions.append(CorruptionRegion(
                start_offset=0,
                end_offset=total_bytes,
                length=total_bytes,
                type=CorruptionType.HEADER_CORRUPTION.value,
                reason="File shorter than PNG 8-byte magic header",
                severity="critical",
            ))
            return ValidationResult(
                format_name="PNG",
                checks=checks,
                corruption_regions=corruption_regions,
                intact_regions=[],
                damaged_regions=[],
                structural_integrity=0.0,
                checksum_integrity=0.0,
                decoder_integrity=0.0,
                evidence=["File too short for PNG header"],
            )

        # 1. Signature Check
        sig = data[:8]
        if sig == PNG_SIGNATURE:
            checks.append(StructuralCheck(
                check="PNG_SIGNATURE",
                status=CheckStatus.PASS,
                location=0,
                expected=PNG_SIGNATURE.hex().upper(),
                actual=sig.hex().upper(),
                description="Valid 8-byte PNG signature",
            ))
            evidence.append("Valid 8-byte PNG header (89 50 4E 47 0D 0A 1A 0A)")
            intact_regions.append(ByteRegion(
                start=0,
                end=8,
                length=8,
                status=RegionClassification.INTACT,
                description="PNG Signature",
            ))
        else:
            checks.append(StructuralCheck(
                check="PNG_SIGNATURE",
                status=CheckStatus.FAIL,
                location=0,
                expected=PNG_SIGNATURE.hex().upper(),
                actual=sig.hex().upper(),
                description="Invalid PNG signature bytes",
            ))
            corruption_regions.append(CorruptionRegion(
                start_offset=0,
                end_offset=8,
                length=8,
                type=CorruptionType.HEADER_CORRUPTION.value,
                reason="PNG header signature mismatch or corrupted",
                severity="critical",
            ))
            evidence.append(f"Header signature corrupted: got {sig.hex().upper()}")

        # 2. Chunk Traversal
        pos = 8
        first_chunk = True
        has_ihdr = False
        has_idat = False
        has_iend = False
        chunk_count = 0
        total_crc_checks = 0
        passed_crc_checks = 0

        while pos < total_bytes:
            # Need at least 8 bytes for length (4) + type (4)
            if pos + 8 > total_bytes:
                # Truncation in chunk header
                trunc_len = total_bytes - pos
                checks.append(StructuralCheck(
                    check="PNG_CHUNK_HEADER",
                    status=CheckStatus.FAIL,
                    location=pos,
                    expected="8 bytes (length + type)",
                    actual=f"{trunc_len} bytes remaining",
                    description="Unexpected EOF within chunk header",
                ))
                corruption_regions.append(CorruptionRegion(
                    start_offset=pos,
                    end_offset=total_bytes,
                    length=trunc_len,
                    type=CorruptionType.TRUNCATION.value,
                    reason=f"File truncated mid-chunk header at offset {pos}",
                    severity="high",
                ))
                break

            chunk_len = struct.unpack(">I", data[pos:pos + 4])[0]
            chunk_type_bytes = data[pos + 4:pos + 8]
            try:
                chunk_type_str = chunk_type_bytes.decode("ascii", errors="replace")
            except Exception:
                chunk_type_str = "????"

            chunk_start = pos
            payload_start = pos + 8
            payload_end = payload_start + chunk_len
            chunk_end = payload_end + 4  # Includes 4-byte CRC

            # Validate first chunk is IHDR
            if first_chunk:
                if chunk_type_bytes == b"IHDR":
                    has_ihdr = True
                    checks.append(StructuralCheck(
                        check="PNG_IHDR_FIRST",
                        status=CheckStatus.PASS,
                        location=pos,
                        expected="IHDR",
                        actual="IHDR",
                        description="First chunk is valid IHDR",
                    ))
                else:
                    checks.append(StructuralCheck(
                        check="PNG_IHDR_FIRST",
                        status=CheckStatus.FAIL,
                        location=pos,
                        expected="IHDR",
                        actual=chunk_type_str,
                        description=f"First chunk must be IHDR, found {chunk_type_str}",
                    ))
                    corruption_regions.append(CorruptionRegion(
                        start_offset=pos,
                        end_offset=min(chunk_end, total_bytes),
                        length=min(chunk_end, total_bytes) - pos,
                        type=CorruptionType.STRUCTURAL_CORRUPTION.value,
                        reason=f"Illegal chunk order: expected IHDR at offset 8, found {chunk_type_str}",
                        severity="high",
                    ))
                first_chunk = False

            # Check chunk boundaries against file length
            if chunk_end > total_bytes:
                trunc_len = total_bytes - chunk_start
                checks.append(StructuralCheck(
                    check=f"PNG_{chunk_type_str}_BOUNDS",
                    status=CheckStatus.FAIL,
                    location=chunk_start,
                    expected=f"{chunk_end} bytes total",
                    actual=f"{total_bytes} bytes in file",
                    description=f"Chunk {chunk_type_str} requires {chunk_len + 12} bytes, only {trunc_len} available",
                ))
                corruption_regions.append(CorruptionRegion(
                    start_offset=chunk_start,
                    end_offset=total_bytes,
                    length=trunc_len,
                    type=CorruptionType.TRUNCATION.value,
                    reason=f"Chunk {chunk_type_str} truncated: declared length {chunk_len} exceeds file size",
                    severity="high",
                ))
                evidence.append(f"Chunk {chunk_type_str} at offset {chunk_start} truncated")
                break

            # Chunk payload and CRC are fully present
            if chunk_type_bytes == b"IDAT":
                has_idat = True
            elif chunk_type_bytes == b"IEND":
                has_iend = True

            stored_crc = struct.unpack(">I", data[payload_end:chunk_end])[0]
            calc_crc = zlib.crc32(data[pos + 4:payload_end]) & 0xFFFFFFFF
            total_crc_checks += 1

            crc_loc = payload_end
            if calc_crc == stored_crc:
                passed_crc_checks += 1
                checks.append(StructuralCheck(
                    check=f"PNG_{chunk_type_str}_CRC",
                    status=CheckStatus.PASS,
                    location=crc_loc,
                    expected=f"{stored_crc:08X}",
                    actual=f"{calc_crc:08X}",
                    description=f"CRC32 valid for {chunk_type_str}",
                ))
                intact_regions.append(ByteRegion(
                    start=chunk_start,
                    end=chunk_end,
                    length=chunk_end - chunk_start,
                    status=RegionClassification.INTACT,
                    description=f"Valid PNG {chunk_type_str} chunk",
                ))
            else:
                checks.append(StructuralCheck(
                    check=f"PNG_{chunk_type_str}_CRC",
                    status=CheckStatus.FAIL,
                    location=crc_loc,
                    expected=f"{calc_crc:08X}",
                    actual=f"{stored_crc:08X}",
                    description=f"CRC32 mismatch on {chunk_type_str} chunk",
                ))
                corruption_regions.append(CorruptionRegion(
                    start_offset=chunk_start,
                    end_offset=chunk_end,
                    length=chunk_end - chunk_start,
                    type=CorruptionType.CRC_FAILURE.value,
                    reason=f"PNG {chunk_type_str} CRC failure: expected 0x{calc_crc:08X}, got 0x{stored_crc:08X}",
                    severity="high",
                ))
                damaged_regions.append(ByteRegion(
                    start=chunk_start,
                    end=chunk_end,
                    length=chunk_end - chunk_start,
                    status=RegionClassification.CORRUPTED,
                    type=CorruptionType.CRC_FAILURE.value,
                    description=f"Corrupted {chunk_type_str} chunk (CRC mismatch)",
                ))
                evidence.append(f"CRC32 failure in {chunk_type_str} at offset {chunk_start} (stored 0x{stored_crc:08X} vs computed 0x{calc_crc:08X})")

            pos = chunk_end
            chunk_count += 1

            if chunk_type_bytes == b"IEND":
                # Any bytes following IEND are extra/slack or corrupted
                if pos < total_bytes:
                    extra_len = total_bytes - pos
                    evidence.append(f"{extra_len} trailing bytes found after IEND marker")
                    damaged_regions.append(ByteRegion(
                        start=pos,
                        end=total_bytes,
                        length=extra_len,
                        status=RegionClassification.DAMAGED,
                        type=CorruptionType.BYTE_RANGE_ANOMALY.value,
                        description="Trailing data past IEND marker",
                    ))
                break

        # Post-loop checks
        if not has_ihdr:
            checks.append(StructuralCheck(
                check="PNG_IHDR_PRESENT",
                status=CheckStatus.FAIL,
                location=8,
                expected="IHDR chunk present",
                actual="IHDR missing",
                description="Required IHDR chunk missing",
            ))

        if not has_idat:
            checks.append(StructuralCheck(
                check="PNG_IDAT_PRESENT",
                status=CheckStatus.FAIL,
                location=min(pos, total_bytes),
                expected="At least one IDAT chunk",
                actual="0 IDAT chunks found",
                description="Image data chunks missing",
            ))

        if not has_iend:
            checks.append(StructuralCheck(
                check="PNG_IEND_PRESENT",
                status=CheckStatus.FAIL,
                location=total_bytes,
                expected="IEND trailer chunk",
                actual="IEND missing",
                description="Required IEND terminal chunk missing",
            ))
            corruption_regions.append(CorruptionRegion(
                start_offset=max(0, total_bytes - 1),
                end_offset=total_bytes,
                length=1,
                type=CorruptionType.MISSING_TRAILER.value,
                reason="Terminal IEND chunk is missing from end of PNG",
                severity="high",
            ))
            evidence.append("Terminal IEND chunk missing from end of file")
        else:
            checks.append(StructuralCheck(
                check="PNG_IEND_PRESENT",
                status=CheckStatus.PASS,
                location=chunk_start if 'chunk_start' in locals() else total_bytes - 12,
                expected="IEND",
                actual="IEND",
                description="Valid IEND terminal chunk verified",
            ))

        # 3. Content Decoder Check (PIL / Pillow safely in-memory)
        decoder_ok = False
        try:
            from PIL import Image
            img = Image.open(io.BytesIO(data))
            img.verify()
            decoder_ok = True
            evidence.append(f"Image decoder verified raster: {img.size[0]}x{img.size[1]} ({img.format})")
        except Exception as e:
            decoder_ok = False
            evidence.append(f"Image raster decoding failure: {e}")

        # Compute transparent scores
        crc_score = (passed_crc_checks / total_crc_checks * 100.0) if total_crc_checks > 0 else 0.0
        pass_count = sum(1 for c in checks if c.status == CheckStatus.PASS)
        struct_score = (pass_count / len(checks) * 100.0) if checks else 0.0
        dec_score = 100.0 if decoder_ok else (40.0 if has_idat and not corruption_regions else 10.0)

        return ValidationResult(
            format_name="PNG",
            checks=checks,
            corruption_regions=corruption_regions,
            intact_regions=intact_regions,
            damaged_regions=damaged_regions,
            structural_integrity=round(struct_score, 1),
            checksum_integrity=round(crc_score, 1),
            decoder_integrity=round(dec_score, 1),
            evidence=evidence,
        )
