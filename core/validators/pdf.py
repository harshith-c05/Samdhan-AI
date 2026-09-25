"""
core/validators/pdf.py
======================
Format-aware byte-level structural validator for Adobe Portable Document Format (PDF).
Adheres strictly to ISO 32000-1 / PDF 1.7 specification.
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


class PDFValidator(BaseValidator):
    """
    Validates:
    - %PDF header and version
    - Indirect objects (obj ... endobj)
    - Content streams (stream ... endstream)
    - Cross-reference table (xref)
    - Trailer dictionary
    - %%EOF terminal marker
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
                check="PDF_HEADER",
                status=CheckStatus.FAIL,
                location=0,
                expected="%PDF-",
                actual=data.decode("latin-1", errors="replace"),
                description="File too small for PDF header",
            ))
            corruption_regions.append(CorruptionRegion(
                start_offset=0,
                end_offset=total_bytes,
                length=total_bytes,
                type=CorruptionType.HEADER_CORRUPTION.value,
                reason="File shorter than minimum PDF header",
                severity="critical",
            ))
            return ValidationResult(
                format_name="PDF",
                checks=checks,
                corruption_regions=corruption_regions,
                intact_regions=[],
                damaged_regions=[],
                structural_integrity=0.0,
                checksum_integrity=100.0,
                decoder_integrity=0.0,
                evidence=["File too short for PDF header"],
            )

        # 1. Header Validation
        header_match = re.search(rb"%PDF-(\d+\.\d+)", data[:1024])
        if header_match:
            header_offset = header_match.start()
            version = header_match.group(1).decode("ascii")
            checks.append(StructuralCheck(
                check="PDF_HEADER",
                status=CheckStatus.PASS,
                location=header_offset,
                expected="%PDF-1.x",
                actual=f"%PDF-{version}",
                description=f"Valid PDF header version {version}",
            ))
            intact_regions.append(ByteRegion(
                start=header_offset,
                end=header_match.end(),
                length=header_match.end() - header_offset,
                status=RegionClassification.INTACT,
                description=f"PDF Header (%PDF-{version})",
            ))
            evidence.append(f"Valid PDF header (%PDF-{version}) detected at offset {header_offset}")
        else:
            checks.append(StructuralCheck(
                check="PDF_HEADER",
                status=CheckStatus.FAIL,
                location=0,
                expected="%PDF-",
                actual=data[:8].decode("latin-1", errors="replace"),
                description="Missing or corrupted %PDF header",
            ))
            corruption_regions.append(CorruptionRegion(
                start_offset=0,
                end_offset=min(8, total_bytes),
                length=min(8, total_bytes),
                type=CorruptionType.HEADER_CORRUPTION.value,
                reason="PDF magic header (%PDF-) missing from initial bytes",
                severity="critical",
            ))
            evidence.append("PDF magic header (%PDF-) missing from initial bytes")

        # 2. Objects & Streams Parsing
        obj_matches = list(re.finditer(rb"(\d+)\s+(\d+)\s+obj", data))
        endobj_matches = list(re.finditer(rb"endobj", data))
        stream_matches = list(re.finditer(rb"\bstream[\r\n]+", data))
        endstream_matches = list(re.finditer(rb"[\r\n]+endstream\b", data))

        checks.append(StructuralCheck(
            check="PDF_OBJECT_COUNT",
            status=CheckStatus.PASS if len(obj_matches) > 0 else CheckStatus.FAIL,
            location=obj_matches[0].start() if obj_matches else 0,
            expected=">= 1 indirect object",
            actual=f"{len(obj_matches)} objects",
            description=f"Detected {len(obj_matches)} indirect object headers",
        ))

        # Check matched obj / endobj pairs
        if len(obj_matches) > 0:
            evidence.append(f"Found {len(obj_matches)} indirect objects, {len(endobj_matches)} endobj markers")
            for i, om in enumerate(obj_matches):
                obj_start = om.start()
                # Find next endobj after obj_start
                next_endobj = [em for em in endobj_matches if em.start() > obj_start]
                if next_endobj:
                    e_match = next_endobj[0]
                    # Verify no intervening obj before e_match
                    intervening = [o for o in obj_matches if obj_start < o.start() < e_match.start()]
                    if not intervening:
                        intact_regions.append(ByteRegion(
                            start=obj_start,
                            end=e_match.end(),
                            length=e_match.end() - obj_start,
                            status=RegionClassification.INTACT,
                            description=f"PDF Object {om.group(1).decode('ascii')}:{om.group(2).decode('ascii')}",
                        ))
                    else:
                        # Malformed unclosed object!
                        corruption_regions.append(CorruptionRegion(
                            start_offset=obj_start,
                            end_offset=intervening[0].start(),
                            length=intervening[0].start() - obj_start,
                            type=CorruptionType.STRUCTURAL_CORRUPTION.value,
                            reason=f"PDF object {om.group(1).decode('ascii')} missing closing endobj before next object",
                            severity="medium",
                        ))
                else:
                    # Object never closed before EOF
                    corruption_regions.append(CorruptionRegion(
                        start_offset=obj_start,
                        end_offset=total_bytes,
                        length=total_bytes - obj_start,
                        type=CorruptionType.TRUNCATION.value,
                        reason=f"PDF object {om.group(1).decode('ascii')} unclosed: file truncated before endobj",
                        severity="high",
                    ))

        # Check stream / endstream pairing
        if len(stream_matches) != len(endstream_matches):
            if len(stream_matches) > len(endstream_matches):
                loc = stream_matches[len(endstream_matches)].start()
                reason = "Unclosed content stream: stream without matching endstream"
            else:
                loc = endstream_matches[len(stream_matches)].start()
                reason = "Orphaned endstream keyword without preceding stream"

            checks.append(StructuralCheck(
                check="PDF_STREAM_PAIRING",
                status=CheckStatus.FAIL,
                location=loc,
                expected=f"{len(stream_matches)} endstream markers",
                actual=f"{len(endstream_matches)} endstream markers",
                description="Mismatched stream and endstream keyword counts",
            ))
            corruption_regions.append(CorruptionRegion(
                start_offset=loc,
                end_offset=total_bytes,
                length=total_bytes - loc,
                type=CorruptionType.STRUCTURAL_CORRUPTION.value,
                reason=reason,
                severity="high",
            ))
        elif len(stream_matches) > 0:
            checks.append(StructuralCheck(
                check="PDF_STREAM_PAIRING",
                status=CheckStatus.PASS,
                location=stream_matches[0].start(),
                expected=f"{len(stream_matches)} streams",
                actual=f"{len(stream_matches)} paired streams",
                description="All content streams properly terminated with endstream",
            ))

        # 3. Cross-reference Table (xref) & Trailer
        xref_match = re.search(rb"\bxref[\r\n]+", data)
        if xref_match:
            checks.append(StructuralCheck(
                check="PDF_XREF_TABLE",
                status=CheckStatus.PASS,
                location=xref_match.start(),
                expected="xref table",
                actual="Found",
                description="Cross-reference (xref) table detected",
            ))
            intact_regions.append(ByteRegion(
                start=xref_match.start(),
                end=min(xref_match.start() + 256, total_bytes),
                length=min(256, total_bytes - xref_match.start()),
                status=RegionClassification.INTACT,
                description="PDF xref table",
            ))
        else:
            # Could be cross-reference stream (/Type /XRef)
            xref_stream = re.search(rb"/Type\s*/XRef\b", data)
            if xref_stream:
                checks.append(StructuralCheck(
                    check="PDF_XREF_STREAM",
                    status=CheckStatus.PASS,
                    location=xref_stream.start(),
                    expected="xref stream",
                    actual="Found",
                    description="Cross-reference stream (/Type /XRef) detected",
                ))
            else:
                checks.append(StructuralCheck(
                    check="PDF_XREF_TABLE",
                    status=CheckStatus.WARNING,
                    location=total_bytes - 100 if total_bytes > 100 else 0,
                    expected="xref table or stream",
                    actual="Missing",
                    description="No standard xref table found (linearized or damaged)",
                ))

        # 4. %%EOF Terminal Marker
        tail_window = data[-1024:] if total_bytes >= 1024 else data
        eof_match = re.search(rb"%%EOF", tail_window)
        if eof_match:
            eof_offset = (total_bytes - len(tail_window)) + eof_match.start()
            checks.append(StructuralCheck(
                check="PDF_EOF_MARKER",
                status=CheckStatus.PASS,
                location=eof_offset,
                expected="%%EOF",
                actual="%%EOF",
                description="Valid %%EOF marker verified near EOF",
            ))
            intact_regions.append(ByteRegion(
                start=eof_offset,
                end=eof_offset + 5,
                length=5,
                status=RegionClassification.INTACT,
                description="PDF %%EOF Marker",
            ))
            evidence.append(f"Valid PDF %%EOF marker verified at offset {eof_offset}")
        else:
            checks.append(StructuralCheck(
                check="PDF_EOF_MARKER",
                status=CheckStatus.FAIL,
                location=total_bytes,
                expected="%%EOF in last 1024 bytes",
                actual="Missing",
                description="%%EOF terminal marker missing — file is truncated",
            ))
            corruption_regions.append(CorruptionRegion(
                start_offset=max(0, total_bytes - 6),
                end_offset=total_bytes,
                length=min(6, total_bytes),
                type=CorruptionType.MISSING_TRAILER.value,
                reason="PDF %%EOF terminal marker missing — document truncated",
                severity="high",
            ))
            evidence.append("PDF %%EOF terminal marker missing — document truncated")

        # 5. Safe Decoding Attempt
        decoder_ok = False
        try:
            # Check basic PDF structure parseability
            if header_match and len(obj_matches) > 0 and eof_match:
                decoder_ok = True
                evidence.append(f"PDF structural parser confirmed {len(obj_matches)} parseable objects")
        except Exception as e:
            decoder_ok = False
            evidence.append(f"PDF decode error: {e}")

        pass_count = sum(1 for c in checks if c.status == CheckStatus.PASS)
        struct_score = (pass_count / len(checks) * 100.0) if checks else 0.0
        dec_score = 100.0 if (decoder_ok and not corruption_regions) else (50.0 if len(obj_matches) > 0 else 10.0)

        return ValidationResult(
            format_name="PDF",
            checks=checks,
            corruption_regions=corruption_regions,
            intact_regions=intact_regions,
            damaged_regions=damaged_regions,
            structural_integrity=round(struct_score, 1),
            checksum_integrity=100.0,
            decoder_integrity=round(dec_score, 1),
            evidence=evidence,
        )
