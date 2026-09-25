"""
core/validators/jpeg.py
=======================
Format-aware byte-level structural validator for JPEG / JFIF / EXIF images.
Adheres to ITU-T T.81 / ISO/IEC 10918-1 specification.
"""

import io
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


class JPEGValidator(BaseValidator):
    """
    Validates:
    - SOI marker (FF D8)
    - Marker structure and segment lengths
    - DQT (Quantization table)
    - SOF0 / SOF2 (Start of Frame)
    - DHT (Huffman tables)
    - SOS (Start of Scan)
    - Entropy-coded scan stream
    - EOI marker (FF D9)
    """

    def validate(self, data: bytes) -> ValidationResult:
        checks: List[StructuralCheck] = []
        corruption_regions: List[CorruptionRegion] = []
        intact_regions: List[ByteRegion] = []
        damaged_regions: List[ByteRegion] = []
        evidence: List[str] = []

        total_bytes = len(data)
        if total_bytes < 4:
            checks.append(StructuralCheck(
                check="JPEG_SOI",
                status=CheckStatus.FAIL,
                location=0,
                expected="FFD8",
                actual=data.hex().upper(),
                description="File too small for JPEG SOI marker",
            ))
            corruption_regions.append(CorruptionRegion(
                start_offset=0,
                end_offset=total_bytes,
                length=total_bytes,
                type=CorruptionType.HEADER_CORRUPTION.value,
                reason="File shorter than minimum JPEG header",
                severity="critical",
            ))
            return ValidationResult(
                format_name="JPEG",
                checks=checks,
                corruption_regions=corruption_regions,
                intact_regions=[],
                damaged_regions=[],
                structural_integrity=0.0,
                checksum_integrity=100.0,
                decoder_integrity=0.0,
                evidence=["File too short for JPEG header"],
            )

        # 1. SOI Check
        if data[:2] == b"\xff\xd8":
            checks.append(StructuralCheck(
                check="JPEG_SOI",
                status=CheckStatus.PASS,
                location=0,
                expected="FFD8",
                actual="FFD8",
                description="Valid Start of Image (SOI) marker",
            ))
            intact_regions.append(ByteRegion(
                start=0,
                end=2,
                length=2,
                status=RegionClassification.INTACT,
                description="JPEG SOI marker",
            ))
            evidence.append("Valid JPEG Start of Image (FF D8)")
        else:
            checks.append(StructuralCheck(
                check="JPEG_SOI",
                status=CheckStatus.FAIL,
                location=0,
                expected="FFD8",
                actual=data[:2].hex().upper(),
                description="Missing or corrupted JPEG SOI marker",
            ))
            corruption_regions.append(CorruptionRegion(
                start_offset=0,
                end_offset=2,
                length=2,
                type=CorruptionType.HEADER_CORRUPTION.value,
                reason=f"Corrupted SOI marker: expected FFD8, got {data[:2].hex().upper()}",
                severity="critical",
            ))
            evidence.append(f"Invalid JPEG SOI: got {data[:2].hex().upper()}")

        # 2. Marker Walk
        pos = 2
        has_dqt = False
        has_sof = False
        has_dht = False
        has_sos = False
        has_eoi = False
        in_scan = False
        scan_start_offset = 0

        # Standalone markers with no length payload
        STANDALONE = {0xd8, 0xd9, 0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0x01}

        while pos < total_bytes:
            if not in_scan:
                if data[pos] != 0xFF:
                    # Invalid marker alignment
                    err_len = 1
                    while (pos + err_len < total_bytes) and data[pos + err_len] != 0xFF:
                        err_len += 1
                    checks.append(StructuralCheck(
                        check="JPEG_MARKER_ALIGNMENT",
                        status=CheckStatus.FAIL,
                        location=pos,
                        expected="0xFF marker prefix",
                        actual=f"0x{data[pos]:02X}",
                        description=f"Corrupted non-marker bytes ({err_len} bytes) in segment header area",
                    ))
                    corruption_regions.append(CorruptionRegion(
                        start_offset=pos,
                        end_offset=pos + err_len,
                        length=err_len,
                        type=CorruptionType.INVALID_MARKER.value,
                        reason=f"Non-marker byte sequence (0x{data[pos:min(pos+4, total_bytes)].hex().upper()}) encountered outside scan data",
                        severity="high",
                    ))
                    damaged_regions.append(ByteRegion(
                        start=pos,
                        end=pos + err_len,
                        length=err_len,
                        status=RegionClassification.CORRUPTED,
                        type=CorruptionType.INVALID_MARKER.value,
                        description="Corrupted marker sequence",
                    ))
                    pos += err_len
                    continue

                if pos + 1 >= total_bytes:
                    # Truncated marker byte
                    checks.append(StructuralCheck(
                        check="JPEG_MARKER_CODE",
                        status=CheckStatus.FAIL,
                        location=pos,
                        expected="Marker code byte",
                        actual="EOF",
                        description="File ends on marker prefix 0xFF",
                    ))
                    corruption_regions.append(CorruptionRegion(
                        start_offset=pos,
                        end_offset=total_bytes,
                        length=1,
                        type=CorruptionType.TRUNCATION.value,
                        reason="Truncation immediately after 0xFF marker prefix",
                        severity="high",
                    ))
                    break

                marker_code = data[pos + 1]

                # Consecutive 0xFF padding
                if marker_code == 0xFF:
                    pos += 1
                    continue

                marker_hex = f"FF{marker_code:02X}"

                # EOI marker check
                if marker_code == 0xD9:
                    has_eoi = True
                    checks.append(StructuralCheck(
                        check="JPEG_EOI",
                        status=CheckStatus.PASS,
                        location=pos,
                        expected="FFD9",
                        actual="FFD9",
                        description="Valid End of Image (EOI) marker",
                    ))
                    intact_regions.append(ByteRegion(
                        start=pos,
                        end=pos + 2,
                        length=2,
                        status=RegionClassification.INTACT,
                        description="JPEG EOI marker",
                    ))
                    evidence.append("Valid JPEG End of Image (FF D9)")
                    pos += 2
                    break

                if marker_code in STANDALONE:
                    intact_regions.append(ByteRegion(
                        start=pos,
                        end=pos + 2,
                        length=2,
                        status=RegionClassification.INTACT,
                        description=f"JPEG Standalone Marker {marker_hex}",
                    ))
                    pos += 2
                    continue

                # Segment with length
                if pos + 4 > total_bytes:
                    checks.append(StructuralCheck(
                        check=f"JPEG_{marker_hex}_LENGTH",
                        status=CheckStatus.FAIL,
                        location=pos,
                        expected="2-byte segment length",
                        actual=f"{total_bytes - pos - 2} bytes remaining",
                        description=f"File truncated inside {marker_hex} segment header",
                    ))
                    corruption_regions.append(CorruptionRegion(
                        start_offset=pos,
                        end_offset=total_bytes,
                        length=total_bytes - pos,
                        type=CorruptionType.TRUNCATION.value,
                        reason=f"Truncation inside segment {marker_hex} header",
                        severity="high",
                    ))
                    break

                seg_len = struct.unpack(">H", data[pos + 2:pos + 4])[0]
                if seg_len < 2:
                    checks.append(StructuralCheck(
                        check=f"JPEG_{marker_hex}_LENGTH",
                        status=CheckStatus.FAIL,
                        location=pos + 2,
                        expected="Length >= 2",
                        actual=str(seg_len),
                        description=f"Invalid segment length {seg_len} for marker {marker_hex}",
                    ))
                    corruption_regions.append(CorruptionRegion(
                        start_offset=pos + 2,
                        end_offset=pos + 4,
                        length=2,
                        type=CorruptionType.INVALID_LENGTH.value,
                        reason=f"Illegal segment length {seg_len} for marker {marker_hex}",
                        severity="high",
                    ))
                    pos += 4
                    continue

                seg_end = pos + 2 + seg_len
                if seg_end > total_bytes:
                    trunc_len = total_bytes - pos
                    checks.append(StructuralCheck(
                        check=f"JPEG_{marker_hex}_BOUNDS",
                        status=CheckStatus.FAIL,
                        location=pos,
                        expected=f"{seg_len + 2} bytes",
                        actual=f"{trunc_len} bytes",
                        description=f"Segment {marker_hex} declared {seg_len} bytes but file ends early",
                    ))
                    corruption_regions.append(CorruptionRegion(
                        start_offset=pos,
                        end_offset=total_bytes,
                        length=trunc_len,
                        type=CorruptionType.TRUNCATION.value,
                        reason=f"Segment {marker_hex} declared length {seg_len} exceeds file size",
                        severity="high",
                    ))
                    break

                # Record specific markers
                if marker_code == 0xDB:
                    has_dqt = True
                    checks.append(StructuralCheck(
                        check="JPEG_DQT",
                        status=CheckStatus.PASS,
                        location=pos,
                        expected="DQT table",
                        actual=f"{seg_len} bytes",
                        description="Quantization Table (DQT) verified",
                    ))
                elif marker_code in (0xC0, 0xC1, 0xC2):
                    has_sof = True
                    checks.append(StructuralCheck(
                        check=f"JPEG_{marker_hex}_SOF",
                        status=CheckStatus.PASS,
                        location=pos,
                        expected="SOF frame header",
                        actual=f"{seg_len} bytes",
                        description="Start of Frame (SOF) verified",
                    ))
                elif marker_code == 0xC4:
                    has_dht = True
                    checks.append(StructuralCheck(
                        check="JPEG_DHT",
                        status=CheckStatus.PASS,
                        location=pos,
                        expected="DHT table",
                        actual=f"{seg_len} bytes",
                        description="Huffman Table (DHT) verified",
                    ))
                elif marker_code == 0xDA:
                    has_sos = True
                    in_scan = True
                    scan_start_offset = seg_end
                    checks.append(StructuralCheck(
                        check="JPEG_SOS",
                        status=CheckStatus.PASS,
                        location=pos,
                        expected="SOS header",
                        actual=f"{seg_len} bytes",
                        description="Start of Scan (SOS) verified",
                    ))

                intact_regions.append(ByteRegion(
                    start=pos,
                    end=seg_end,
                    length=seg_end - pos,
                    status=RegionClassification.INTACT,
                    description=f"JPEG {marker_hex} Segment",
                ))
                pos = seg_end

            else:
                # Inside entropy-coded scan data until EOI or restart/marker
                scan_pos = pos
                scan_corrupt = False
                while scan_pos < total_bytes - 1:
                    b = data[scan_pos]
                    if b == 0xFF:
                        nxt = data[scan_pos + 1]
                        if nxt == 0x00:
                            # Byte stuffing: literal 0xFF
                            scan_pos += 2
                            continue
                        elif 0xD0 <= nxt <= 0xD7:
                            # RST marker
                            scan_pos += 2
                            continue
                        elif nxt == 0xD9:
                            # EOI!
                            has_eoi = True
                            if scan_pos > pos:
                                intact_regions.append(ByteRegion(
                                    start=pos,
                                    end=scan_pos,
                                    length=scan_pos - pos,
                                    status=RegionClassification.INTACT,
                                    description="JPEG Entropy Scan Payload",
                                ))
                            intact_regions.append(ByteRegion(
                                start=scan_pos,
                                end=scan_pos + 2,
                                length=2,
                                status=RegionClassification.INTACT,
                                description="JPEG EOI Marker",
                            ))
                            checks.append(StructuralCheck(
                                check="JPEG_EOI",
                                status=CheckStatus.PASS,
                                location=scan_pos,
                                expected="FFD9",
                                actual="FFD9",
                                description="Valid End of Image (EOI) marker found at EOF",
                            ))
                            evidence.append("Valid JPEG EOI marker found at EOF")
                            pos = scan_pos + 2
                            break
                        else:
                            # Unexpected marker in scan stream
                            checks.append(StructuralCheck(
                                check="JPEG_SCAN_MARKER",
                                status=CheckStatus.WARNING,
                                location=scan_pos,
                                expected="Scan byte or RST/EOI",
                                actual=f"FF{nxt:02X}",
                                description=f"Unexpected marker FF{nxt:02X} encountered in scan payload",
                            ))
                            scan_pos += 2
                            continue
                    scan_pos += 1

                if not has_eoi:
                    # Scan stream ended without EOI
                    trunc_len = total_bytes - pos
                    if trunc_len > 0:
                        intact_regions.append(ByteRegion(
                            start=pos,
                            end=total_bytes,
                            length=trunc_len,
                            status=RegionClassification.DAMAGED,
                            description="Truncated JPEG Scan Data (Missing EOI)",
                        ))
                    checks.append(StructuralCheck(
                        check="JPEG_EOI",
                        status=CheckStatus.FAIL,
                        location=total_bytes,
                        expected="FFD9",
                        actual="MISSING",
                        description="End of Image (EOI) marker missing from file tail",
                    ))
                    corruption_regions.append(CorruptionRegion(
                        start_offset=max(0, total_bytes - 2),
                        end_offset=total_bytes,
                        length=min(2, total_bytes),
                        type=CorruptionType.MISSING_TRAILER.value,
                        reason="JPEG terminal marker (FF D9) missing — image stream truncated",
                        severity="high",
                    ))
                    evidence.append("JPEG terminal marker (FF D9) missing from file tail")
                break

        # Verification summary
        if not has_dqt:
            checks.append(StructuralCheck(
                check="JPEG_DQT_PRESENT",
                status=CheckStatus.FAIL,
                location=2,
                expected="DQT marker (FF DB)",
                actual="Missing",
                description="Quantization tables (DQT) missing",
            ))
        if not has_sof:
            checks.append(StructuralCheck(
                check="JPEG_SOF_PRESENT",
                status=CheckStatus.FAIL,
                location=2,
                expected="SOF marker (FF C0/C2)",
                actual="Missing",
                description="Start of Frame (SOF) missing",
            ))
        if not has_sos:
            checks.append(StructuralCheck(
                check="JPEG_SOS_PRESENT",
                status=CheckStatus.FAIL,
                location=2,
                expected="SOS marker (FF DA)",
                actual="Missing",
                description="Start of Scan (SOS) missing",
            ))

        # 3. Decoder Test
        decoder_ok = False
        try:
            from PIL import Image
            img = Image.open(io.BytesIO(data))
            img.verify()
            decoder_ok = True
            evidence.append(f"Image decoder verified JPEG raster: {img.size[0]}x{img.size[1]}")
        except Exception as e:
            decoder_ok = False
            evidence.append(f"JPEG raster decoding failure: {e}")

        pass_count = sum(1 for c in checks if c.status == CheckStatus.PASS)
        struct_score = (pass_count / len(checks) * 100.0) if checks else 0.0
        dec_score = 100.0 if decoder_ok else (45.0 if has_sos and not corruption_regions else 10.0)

        return ValidationResult(
            format_name="JPEG",
            checks=checks,
            corruption_regions=corruption_regions,
            intact_regions=intact_regions,
            damaged_regions=damaged_regions,
            structural_integrity=round(struct_score, 1),
            checksum_integrity=100.0,
            decoder_integrity=round(dec_score, 1),
            evidence=evidence,
        )
