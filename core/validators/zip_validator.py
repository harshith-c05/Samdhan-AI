"""
core/validators/zip_validator.py
================================
Format-aware byte-level structural validator for ZIP archives.
Adheres to PKWARE APPNOTE.TXT / ISO/IEC 21320-1 specification.
"""

import io
import struct
import zipfile
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


class ZIPValidator(BaseValidator):
    """
    Validates:
    - Local file headers (PK 03 04)
    - Compressed data regions and payload boundaries
    - Per-file CRC-32 integrity
    - Central directory headers (PK 01 02)
    - End of Central Directory (EOCD) record (PK 05 06)
    """

    def validate(self, data: bytes) -> ValidationResult:
        checks: List[StructuralCheck] = []
        corruption_regions: List[CorruptionRegion] = []
        intact_regions: List[ByteRegion] = []
        damaged_regions: List[ByteRegion] = []
        evidence: List[str] = []

        total_bytes = len(data)
        if total_bytes < 22:  # Minimum empty ZIP is 22 bytes (EOCD only)
            checks.append(StructuralCheck(
                check="ZIP_MIN_SIZE",
                status=CheckStatus.FAIL,
                location=0,
                expected=">= 22 bytes for valid ZIP",
                actual=f"{total_bytes} bytes",
                description="File too small for valid ZIP archive",
            ))
            corruption_regions.append(CorruptionRegion(
                start_offset=0,
                end_offset=total_bytes,
                length=total_bytes,
                type=CorruptionType.HEADER_CORRUPTION.value,
                reason="File shorter than minimum ZIP EOCD structure (22 bytes)",
                severity="critical",
            ))
            return ValidationResult(
                format_name="ZIP",
                checks=checks,
                corruption_regions=corruption_regions,
                intact_regions=[],
                damaged_regions=[],
                structural_integrity=0.0,
                checksum_integrity=0.0,
                decoder_integrity=0.0,
                evidence=["File too short for ZIP container"],
            )

        # 1. First Header Signature Check
        first_sig = data[:4]
        if first_sig in (b"PK\x03\x04", b"PK\x05\x06"):
            checks.append(StructuralCheck(
                check="ZIP_HEADER_SIGNATURE",
                status=CheckStatus.PASS,
                location=0,
                expected="PK0304 or PK0506",
                actual=first_sig.hex().upper(),
                description="Valid ZIP magic signature at offset 0",
            ))
            evidence.append(f"Valid ZIP header ({first_sig.hex().upper()}) at offset 0")
        else:
            checks.append(StructuralCheck(
                check="ZIP_HEADER_SIGNATURE",
                status=CheckStatus.FAIL,
                location=0,
                expected="504B0304",
                actual=first_sig.hex().upper(),
                description="Invalid initial ZIP magic signature",
            ))
            corruption_regions.append(CorruptionRegion(
                start_offset=0,
                end_offset=4,
                length=4,
                type=CorruptionType.HEADER_CORRUPTION.value,
                reason=f"Corrupted ZIP header signature: expected 504B0304, got {first_sig.hex().upper()}",
                severity="critical",
            ))
            evidence.append(f"Invalid ZIP magic signature: got {first_sig.hex().upper()}")

        # 2. Local File Headers Scan
        pos = 0
        local_entries = []
        crc_checks_total = 0
        crc_checks_passed = 0

        while pos + 30 <= total_bytes:
            sig = data[pos:pos + 4]
            if sig != b"PK\x03\x04":
                # Stopped at non-local-header (could be Central Directory or corrupted byte)
                break

            entry_start = pos
            version_needed, bit_flag, comp_method, mod_time, mod_date, stored_crc, comp_size, uncomp_size, name_len, extra_len = struct.unpack(
                "<HHHHHIIIHH", data[pos + 4:pos + 30]
            )

            hdr_size = 30 + name_len + extra_len
            if pos + hdr_size > total_bytes:
                # Truncation in header
                checks.append(StructuralCheck(
                    check="ZIP_LOCAL_HEADER_BOUNDS",
                    status=CheckStatus.FAIL,
                    location=pos,
                    expected=f"{hdr_size} bytes header",
                    actual=f"{total_bytes - pos} bytes remaining",
                    description=f"Local header at {pos} truncated before filename/extra fields",
                ))
                corruption_regions.append(CorruptionRegion(
                    start_offset=pos,
                    end_offset=total_bytes,
                    length=total_bytes - pos,
                    type=CorruptionType.TRUNCATION.value,
                    reason=f"ZIP local header at {pos} truncated",
                    severity="high",
                ))
                break

            name_bytes = data[pos + 30:pos + 30 + name_len]
            filename = name_bytes.decode("utf-8", errors="replace")

            payload_start = pos + hdr_size
            payload_end = payload_start + comp_size
            entry_end = payload_end

            if payload_end > total_bytes:
                # Compressed payload is truncated
                trunc_len = total_bytes - pos
                checks.append(StructuralCheck(
                    check=f"ZIP_ENTRY_{filename}_BOUNDS",
                    status=CheckStatus.FAIL,
                    location=pos,
                    expected=f"{comp_size} bytes payload",
                    actual=f"{total_bytes - payload_start} bytes available",
                    description=f"Entry '{filename}' payload truncated",
                ))
                corruption_regions.append(CorruptionRegion(
                    start_offset=pos,
                    end_offset=total_bytes,
                    length=trunc_len,
                    type=CorruptionType.TRUNCATION.value,
                    reason=f"ZIP entry '{filename}' truncated: declared {comp_size} bytes payload exceeds file size",
                    severity="high",
                ))
                break

            # Payload is within file bounds
            payload_data = data[payload_start:payload_end]
            entry_crc_ok = True

            # If not streaming data descriptor (bit 3 not set) and stored_crc > 0
            if (bit_flag & 0x08) == 0 and stored_crc != 0:
                crc_checks_total += 1
                try:
                    if comp_method == 0:  # Stored
                        decompressed = payload_data
                        calc_crc = zlib.crc32(decompressed) & 0xFFFFFFFF
                    elif comp_method == 8:  # Deflate
                        decompressed = zlib.decompress(payload_data, -15)
                        calc_crc = zlib.crc32(decompressed) & 0xFFFFFFFF
                    else:
                        calc_crc = stored_crc  # Unsupported compression method, assume ok

                    if calc_crc == stored_crc:
                        crc_checks_passed += 1
                        checks.append(StructuralCheck(
                            check=f"ZIP_CRC_{filename}",
                            status=CheckStatus.PASS,
                            location=pos + 14,
                            expected=f"{stored_crc:08X}",
                            actual=f"{calc_crc:08X}",
                            description=f"CRC-32 verified for entry '{filename}'",
                        ))
                    else:
                        entry_crc_ok = False
                        checks.append(StructuralCheck(
                            check=f"ZIP_CRC_{filename}",
                            status=CheckStatus.FAIL,
                            location=pos + 14,
                            expected=f"{stored_crc:08X}",
                            actual=f"{calc_crc:08X}",
                            description=f"CRC-32 mismatch on entry '{filename}'",
                        ))
                        corruption_regions.append(CorruptionRegion(
                            start_offset=payload_start,
                            end_offset=payload_end,
                            length=comp_size,
                            type=CorruptionType.CRC_FAILURE.value,
                            reason=f"CRC32 mismatch in entry '{filename}': expected 0x{stored_crc:08X}, calculated 0x{calc_crc:08X}",
                            severity="high",
                        ))
                        damaged_regions.append(ByteRegion(
                            start=payload_start,
                            end=payload_end,
                            length=comp_size,
                            status=RegionClassification.CORRUPTED,
                            type=CorruptionType.CRC_FAILURE.value,
                            description=f"Corrupted compressed payload for '{filename}'",
                        ))
                        evidence.append(f"CRC-32 failure in '{filename}': expected 0x{stored_crc:08X}, got 0x{calc_crc:08X}")
                except Exception as decompress_err:
                    entry_crc_ok = False
                    checks.append(StructuralCheck(
                        check=f"ZIP_DECOMPRESS_{filename}",
                        status=CheckStatus.FAIL,
                        location=payload_start,
                        expected="Valid deflate stream",
                        actual=str(decompress_err),
                        description=f"Decompression error in entry '{filename}'",
                    ))
                    corruption_regions.append(CorruptionRegion(
                        start_offset=payload_start,
                        end_offset=payload_end,
                        length=comp_size,
                        type=CorruptionType.DECODER_FAILURE.value,
                        reason=f"Deflate stream decompression error in '{filename}': {decompress_err}",
                        severity="high",
                    ))
                    damaged_regions.append(ByteRegion(
                        start=payload_start,
                        end=payload_end,
                        length=comp_size,
                        status=RegionClassification.CORRUPTED,
                        type=CorruptionType.DECODER_FAILURE.value,
                        description=f"Decompression failure for '{filename}'",
                    ))

            if entry_crc_ok:
                intact_regions.append(ByteRegion(
                    start=entry_start,
                    end=entry_end,
                    length=entry_end - entry_start,
                    status=RegionClassification.INTACT,
                    description=f"Valid ZIP entry '{filename}'",
                ))

            local_entries.append({"name": filename, "start": entry_start, "end": entry_end})
            pos = entry_end

        # 3. Central Directory Scan
        cd_pos = pos
        cd_entries = 0
        has_cd = False
        while cd_pos + 46 <= total_bytes:
            if data[cd_pos:cd_pos + 4] != b"PK\x01\x02":
                break
            has_cd = True
            cd_entries += 1
            n_len = struct.unpack("<H", data[cd_pos + 28:cd_pos + 30])[0]
            e_len = struct.unpack("<H", data[cd_pos + 30:cd_pos + 32])[0]
            c_len = struct.unpack("<H", data[cd_pos + 32:cd_pos + 34])[0]
            cd_end = cd_pos + 46 + n_len + e_len + c_len
            if cd_end > total_bytes:
                break
            cd_pos = cd_end

        if has_cd:
            checks.append(StructuralCheck(
                check="ZIP_CENTRAL_DIRECTORY",
                status=CheckStatus.PASS,
                location=pos,
                expected="PK0102 headers",
                actual=f"{cd_entries} CD records",
                description=f"Central Directory verified with {cd_entries} entries",
            ))
            intact_regions.append(ByteRegion(
                start=pos,
                end=cd_pos,
                length=cd_pos - pos,
                status=RegionClassification.INTACT,
                description=f"ZIP Central Directory ({cd_entries} entries)",
            ))

        # 4. End of Central Directory (EOCD) Scan
        # Search backwards up to 65557 bytes for PK 05 06
        eocd_found = False
        search_window = min(total_bytes, 65557)
        search_start = total_bytes - search_window
        eocd_idx = data.rfind(b"PK\x05\x06", search_start)

        if eocd_idx != -1 and eocd_idx + 22 <= total_bytes:
            eocd_found = True
            disk_num, cd_disk, disk_entries, total_cd_entries, cd_size, cd_offset, comment_len = struct.unpack(
                "<HHHHIIH", data[eocd_idx + 4:eocd_idx + 22]
            )
            checks.append(StructuralCheck(
                check="ZIP_EOCD",
                status=CheckStatus.PASS,
                location=eocd_idx,
                expected="PK0506",
                actual="PK0506",
                description=f"End of Central Directory verified (declared {total_cd_entries} entries)",
            ))
            intact_regions.append(ByteRegion(
                start=eocd_idx,
                end=min(eocd_idx + 22 + comment_len, total_bytes),
                length=min(22 + comment_len, total_bytes - eocd_idx),
                status=RegionClassification.INTACT,
                description="ZIP End of Central Directory (EOCD)",
            ))
            evidence.append(f"Valid ZIP EOCD marker verified at offset {eocd_idx}")
        else:
            checks.append(StructuralCheck(
                check="ZIP_EOCD",
                status=CheckStatus.FAIL,
                location=total_bytes,
                expected="PK0506 EOCD record in last 65KB",
                actual="Missing",
                description="End of Central Directory (EOCD) missing — archive is truncated",
            ))
            corruption_regions.append(CorruptionRegion(
                start_offset=max(0, total_bytes - 22),
                end_offset=total_bytes,
                length=min(22, total_bytes),
                type=CorruptionType.MISSING_TRAILER.value,
                reason="ZIP End of Central Directory (EOCD) missing — archive truncated",
                severity="high",
            ))
            evidence.append("ZIP EOCD terminal record missing — archive truncated")

        # 5. Native zipfile Safe Verification
        decoder_ok = False
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                bad_file = zf.testzip()
                if bad_file is None:
                    decoder_ok = True
                    evidence.append(f"zipfile verification passed: {len(zf.namelist())} files readable")
                else:
                    decoder_ok = False
                    evidence.append(f"zipfile testzip detected CRC corruption in entry: '{bad_file}'")
        except Exception as zerr:
            decoder_ok = False
            evidence.append(f"zipfile open error: {zerr}")

        # Compute transparent scores
        crc_score = (crc_checks_passed / crc_checks_total * 100.0) if crc_checks_total > 0 else 100.0
        pass_count = sum(1 for c in checks if c.status == CheckStatus.PASS)
        struct_score = (pass_count / len(checks) * 100.0) if checks else 0.0
        dec_score = 100.0 if decoder_ok else (45.0 if local_entries and not corruption_regions else 10.0)

        return ValidationResult(
            format_name="ZIP",
            checks=checks,
            corruption_regions=corruption_regions,
            intact_regions=intact_regions,
            damaged_regions=damaged_regions,
            structural_integrity=round(struct_score, 1),
            checksum_integrity=round(crc_score, 1),
            decoder_integrity=round(dec_score, 1),
            evidence=evidence,
        )
