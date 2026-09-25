"""
fragment_reconstruction/boundary_analyzer.py
============================================
Stage 3 — Boundary Analysis & Transition Compatibility.

Evaluates candidate edge Fragment A -> Fragment B based on:
  - Format-specific continuity (JPEG markers, PNG chunk CRC, PDF stream/obj, ZIP records)
  - Parser state simulation across fragment borders
  - Cluster / block filesystem adjacency
  - Entropy distribution alignment
  - Structural contradictions
"""

from __future__ import annotations

import re
import struct
import zlib
from typing import Dict, List, Optional, Tuple

from .models import Fragment, FormatType, EdgeScoreBreakdown


class BoundaryAnalyzer:
    """
    Analyzes whether Fragment B can logically and structurally succeed Fragment A.
    """

    def __init__(
        self,
        weight_signature: float = 0.25,
        weight_continuity: float = 0.30,
        weight_structural: float = 0.25,
        weight_filesystem: float = 0.10,
        weight_entropy: float = 0.10,
    ):
        self.w_sig = weight_signature
        self.w_cont = weight_continuity
        self.w_struct = weight_structural
        self.w_fs = weight_filesystem
        self.w_ent = weight_entropy

    def evaluate_edge(self, frag_a: Fragment, frag_b: Fragment) -> EdgeScoreBreakdown:
        """
        Evaluate directed relationship frag_a -> frag_b.
        Returns explainable EdgeScoreBreakdown with reasons and decomposed scores.
        """
        reasons: List[str] = []

        # ── 1. Contradiction Pre-Check ─────────────────────────────────────────
        contradiction = 0.0

        # Self-edge is impossible
        if frag_a.fragment_id == frag_b.fragment_id:
            return EdgeScoreBreakdown(
                signature_compatibility=0.0,
                continuity_compatibility=0.0,
                structural_compatibility=0.0,
                filesystem_block_evidence=0.0,
                entropy_compatibility=0.0,
                contradiction_penalty=1.0,
                final_score=0.0,
                reasons=["Fatal: Self-loop edge is impossible"],
            )

        # Target has file header: cannot follow another fragment in the same file
        if frag_b.header_compatibility:
            contradiction = 1.0
            reasons.append(f"Fatal: Target fragment {frag_b.fragment_id} contains file header (cannot be preceded)")
            return self._build_breakdown(0.0, 0.0, 0.0, 0.0, 0.0, contradiction, reasons)

        # Source has file footer: cannot be followed by another fragment
        if frag_a.footer_compatibility:
            contradiction = 1.0
            reasons.append(f"Fatal: Source fragment {frag_a.fragment_id} contains terminal footer (cannot have successor)")
            return self._build_breakdown(0.0, 0.0, 0.0, 0.0, 0.0, contradiction, reasons)

        # Format mismatch check
        fmt_a = frag_a.format
        fmt_b = frag_b.format
        sig_compat = 0.5

        if fmt_a != FormatType.UNKNOWN and fmt_b != FormatType.UNKNOWN:
            if fmt_a == fmt_b:
                sig_compat = 0.95
                reasons.append(f"Format match: both fragments classified as {fmt_a}")
            else:
                contradiction = 0.95
                reasons.append(f"Format contradiction: {fmt_a} cannot transition to {fmt_b}")
                return self._build_breakdown(0.0, 0.0, 0.0, 0.0, 0.0, contradiction, reasons)
        elif fmt_a != FormatType.UNKNOWN:
            sig_compat = 0.75
            reasons.append(f"Partial format compatibility: source is {fmt_a}, target format unconfirmed")
        elif fmt_b != FormatType.UNKNOWN:
            sig_compat = 0.75
            reasons.append(f"Partial format compatibility: target is {fmt_b}, source format unconfirmed")
        else:
            sig_compat = 0.50

        # Raw bytes for deep boundary analysis
        data_a = frag_a.get_raw_data()
        data_b = frag_b.get_raw_data()

        # ── 2. Format-Specific Structural & Continuity Analysis ───────────────
        target_fmt = fmt_a if fmt_a != FormatType.UNKNOWN else fmt_b

        cont_score = 0.50
        struct_score = 0.50

        if target_fmt == FormatType.PNG:
            c, s, extra_reasons, penalty = self._analyze_png(data_a, data_b, frag_a, frag_b)
            cont_score = c
            struct_score = s
            reasons.extend(extra_reasons)
            if penalty > 0:
                contradiction = max(contradiction, penalty)

        elif target_fmt == FormatType.JPEG:
            c, s, extra_reasons, penalty = self._analyze_jpeg(data_a, data_b, frag_a, frag_b)
            cont_score = c
            struct_score = s
            reasons.extend(extra_reasons)
            if penalty > 0:
                contradiction = max(contradiction, penalty)

        elif target_fmt == FormatType.PDF:
            c, s, extra_reasons, penalty = self._analyze_pdf(data_a, data_b, frag_a, frag_b)
            cont_score = c
            struct_score = s
            reasons.extend(extra_reasons)
            if penalty > 0:
                contradiction = max(contradiction, penalty)

        elif target_fmt == FormatType.ZIP or target_fmt == FormatType.DOCX:
            c, s, extra_reasons, penalty = self._analyze_zip(data_a, data_b, frag_a, frag_b)
            cont_score = c
            struct_score = s
            reasons.extend(extra_reasons)
            if penalty > 0:
                contradiction = max(contradiction, penalty)

        else:
            # Generic binary continuity
            cont_score = 0.55
            struct_score = 0.50
            reasons.append("Generic binary stream: evaluated via statistical and entropy continuity")

        # ── 3. Filesystem Block / Cluster Evidence ────────────────────────────
        fs_score = 0.50
        ca = frag_a.cluster_index
        cb = frag_b.cluster_index
        if ca is not None and cb is not None:
            if cb == ca + 1:
                fs_score = 0.95
                reasons.append(f"Cluster adjacency: cluster {cb} immediately follows cluster {ca}")
            elif cb > ca:
                # Monotonically increasing clusters
                gap = cb - ca
                fs_score = max(0.60, 0.85 - (gap * 0.02))
                reasons.append(f"Cluster ordering: cluster {cb} appears after cluster {ca} (gap: {gap} clusters)")
            else:
                # Discontiguous fragmented backward reference
                fs_score = 0.35
                reasons.append(f"Non-linear cluster layout: cluster {cb} precedes cluster {ca} (fragmented run)")
        elif frag_a.source_offset > 0 and frag_b.source_offset > 0:
            if frag_b.source_offset == frag_a.source_offset + frag_a.length:
                fs_score = 0.95
                reasons.append(f"Physical sector continuity: offset {frag_b.source_offset} contiguous with {frag_a.source_offset}")
            elif frag_b.source_offset > frag_a.source_offset:
                fs_score = 0.70
                reasons.append(f"Physical offset order: {frag_b.source_offset} > {frag_a.source_offset}")
            else:
                fs_score = 0.40

        # ── 4. Entropy Compatibility ──────────────────────────────────────────
        ent_diff = abs(frag_a.entropy - frag_b.entropy)
        if ent_diff < 0.5:
            ent_score = 0.90
            reasons.append(f"Entropy alignment: |{frag_a.entropy:.2f} - {frag_b.entropy:.2f}| = {ent_diff:.2f} (homogeneous data)")
        elif ent_diff < 1.5:
            ent_score = 0.75
            reasons.append(f"Entropy compatible: delta {ent_diff:.2f}")
        else:
            ent_score = 0.50
            reasons.append(f"Entropy variance: delta {ent_diff:.2f} (possible transition between header and compressed payload)")

        return self._build_breakdown(
            sig_compat, cont_score, struct_score, fs_score, ent_score, contradiction, reasons
        )

    def _build_breakdown(
        self,
        sig: float,
        cont: float,
        struct_: float,
        fs: float,
        ent: float,
        penalty: float,
        reasons: List[str],
    ) -> EdgeScoreBreakdown:
        raw_weighted = (
            self.w_sig * sig
            + self.w_cont * cont
            + self.w_struct * struct_
            + self.w_fs * fs
            + self.w_ent * ent
        )
        final_score = round(max(0.0, raw_weighted * (1.0 - penalty)), 4)
        return EdgeScoreBreakdown(
            signature_compatibility=round(sig, 4),
            continuity_compatibility=round(cont, 4),
            structural_compatibility=round(struct_, 4),
            filesystem_block_evidence=round(fs, 4),
            entropy_compatibility=round(ent, 4),
            contradiction_penalty=round(penalty, 4),
            final_score=final_score,
            reasons=reasons,
        )

    # ──────────────────────────────────────────────────────────────────────────
    # Format-Specific Boundary Parsers
    # ──────────────────────────────────────────────────────────────────────────

    def _analyze_png(
        self, a: bytes, b: bytes, frag_a: Fragment, frag_b: Fragment
    ) -> Tuple[float, float, List[str], float]:
        reasons = []
        penalty = 0.0
        cont = 0.50
        struct_ = 0.50

        # Walk chunks in a to find state at border
        pos = 8 if a.startswith(b"\x89PNG\r\n\x1a\n") else 0
        last_chunk_pos = pos

        while pos + 8 <= len(a):
            length = struct.unpack(">I", a[pos:pos+4])[0]
            chunk_type = a[pos+4:pos+8]
            total_chunk = 12 + length
            if pos + total_chunk <= len(a):
                # Complete chunk in a
                pos += total_chunk
                last_chunk_pos = pos
            else:
                # Truncated chunk spanning across boundary!
                break

        if pos == len(a):
            # Fragment A ended exactly on a chunk boundary!
            reasons.append("PNG chunk alignment: Fragment A ends cleanly on complete chunk boundary")
            # Fragment B must start with a valid chunk length + 4 ASCII letters
            if len(b) >= 8:
                b_len = struct.unpack(">I", b[:4])[0]
                b_type = b[4:8]
                if all(65 <= x <= 122 for x in b_type):
                    type_str = b_type.decode("latin-1", errors="replace")

                    # Format-level sequencing checks
                    if b_type == b"IDAT":
                        # If A contains IHDR (beginning of PNG), the first IDAT must start with zlib stream header (0x78)
                        b_payload = b[8:8+b_len] if len(b) >= 8 + b_len else b[8:]
                        has_zlib_header = (
                            len(b_payload) >= 2
                            and b_payload[0] == 0x78
                            and ((b_payload[0] * 256 + b_payload[1]) % 31 == 0)
                        )
                        if "IHDR" in frag_a.internal_markers or a.startswith(b"\x89PNG"):
                            if has_zlib_header:
                                cont = 0.98
                                struct_ = 0.98
                                reasons.append("PNG stream start: first IDAT chunk begins with valid zlib header (0x78)")
                            else:
                                penalty = 0.85
                                reasons.append("PNG stream violation: IDAT chunk following IHDR lacks initial zlib stream header")
                        elif "IDAT" in frag_a.internal_markers:
                            # Both A and B contain IDAT: test streaming zlib decompression
                            try:
                                # Extract last IDAT payload from A and first from B
                                a_idat_pos = a.rfind(b"IDAT")
                                a_len = struct.unpack(">I", a[a_idat_pos-4:a_idat_pos])[0] if a_idat_pos >= 4 else 0
                                a_payload = a[a_idat_pos+4:a_idat_pos+4+a_len] if a_idat_pos >= 4 else b""

                                d = zlib.decompressobj()
                                d.decompress(a_payload)
                                d.decompress(b_payload)
                                cont = 0.99
                                struct_ = 0.99
                                reasons.append("PNG zlib stream continuity: IDAT chunk in B cleanly decompresses after IDAT in A")
                            except Exception as e:
                                penalty = 0.80
                                reasons.append(f"PNG zlib stream violation: IDAT in B cannot decompress after IDAT in A ({e})")
                        else:
                            cont = 0.90
                            struct_ = 0.88
                            reasons.append(f"PNG chunk continuation: Fragment B starts with chunk '{type_str}'")

                    elif b_type == b"IEND":
                        if "IDAT" in frag_a.internal_markers:
                            cont = 0.98
                            struct_ = 0.98
                            reasons.append("PNG terminal transition: IDAT payload stream successfully transitions to terminal IEND chunk")
                        elif "IHDR" in frag_a.internal_markers:
                            penalty = 0.85
                            reasons.append("PNG missing payload: transition directly from IHDR to IEND without image data")
                        else:
                            cont = 0.85
                            struct_ = 0.85
                            reasons.append("PNG terminal structure: Target fragment contains IEND chunk")
                    else:
                        cont = 0.92
                        struct_ = 0.90
                        reasons.append(f"PNG chunk continuation: Fragment B starts with valid chunk '{type_str}' (declaring {b_len} bytes)")
                else:
                    penalty = 0.80
                    reasons.append("PNG chunk violation: Fragment B does not start with valid ASCII chunk type")
        elif pos < len(a):
            # Chunk was split across A and B!
            if pos + 8 <= len(a):
                length = struct.unpack(">I", a[pos:pos+4])[0]
                chunk_type = a[pos+4:pos+8].decode("latin-1", errors="replace")
                bytes_in_a = len(a) - pos
                needed_from_b = (length + 12) - bytes_in_a

                if len(b) >= needed_from_b:
                    # Assemble the split chunk and verify its CRC32!
                    full_chunk = a[pos:] + b[:needed_from_b]
                    crc_expected = struct.unpack(">I", full_chunk[-4:])[0]
                    crc_computed = zlib.crc32(full_chunk[4:-4]) & 0xFFFFFFFF

                    if crc_computed == crc_expected:
                        cont = 0.99
                        struct_ = 0.99
                        reasons.append(f"PNG mathematical CRC32 match! Split chunk '{chunk_type}' verified across boundary")
                    else:
                        cont = 0.30
                        struct_ = 0.30
                        reasons.append(f"PNG CRC32 mismatch on boundary chunk '{chunk_type}' (expected {crc_expected:08x}, computed {crc_computed:08x})")
                else:
                    cont = 0.70
                    struct_ = 0.65
                    reasons.append(f"PNG split chunk '{chunk_type}': requires {needed_from_b} bytes, B provides {len(b)} bytes")

        # If B contains IEND, it's a strong terminal candidate
        if b"IEND" in b and "IDAT" in frag_a.internal_markers:
            struct_ = min(1.0, struct_ + 0.10)
            reasons.append("PNG terminal structure: Target fragment contains IEND chunk")

        return cont, struct_, reasons, penalty

    def _analyze_jpeg(
        self, a: bytes, b: bytes, frag_a: Fragment, frag_b: Fragment
    ) -> Tuple[float, float, List[str], float]:
        reasons = []
        penalty = 0.0
        cont = 0.50
        struct_ = 0.50

        # Walk markers in A
        pos = 2 if a.startswith(b"\xff\xd8") else 0
        in_scan = False

        while pos < len(a) - 1:
            if a[pos] == 0xFF:
                m = a[pos + 1]
                if m == 0xDA: # SOS marker
                    in_scan = True
                    pos += 2
                    if pos + 2 <= len(a):
                        sos_len = struct.unpack(">H", a[pos:pos+2])[0]
                        pos += sos_len
                    break
                elif m not in (0x00, 0xFF) and not (0xD0 <= m <= 0xD7):
                    if pos + 4 <= len(a):
                        seg_len = struct.unpack(">H", a[pos+2:pos+4])[0]
                        if pos + 2 + seg_len <= len(a):
                            pos += 2 + seg_len
                        else:
                            needed = (pos + 2 + seg_len) - len(a)
                            if len(b) >= needed:
                                cont = 0.90
                                struct_ = 0.88
                                reasons.append(f"JPEG marker segment continuation: B supplies remaining {needed} bytes for marker 0xFF{m:02X}")
                            break
                    else:
                        break
            else:
                pos += 1

        # Determine whether frag_a is strictly a pre-SOS marker header fragment
        is_pre_sos_header = (
            any(m in frag_a.internal_markers for m in ("SOI", "APP0", "APP1", "DQT", "SOF0", "SOF2", "DHT"))
            and "SOS" not in frag_a.internal_markers
            and not in_scan
        )

        if is_pre_sos_header:
            if frag_b.footer_compatibility or b[-2:] == b"\xff\xd9":
                penalty = 0.85
                reasons.append("JPEG sequence violation: terminal EOI reached before SOS scan data marker")
            elif len(b) >= 2 and b[0] == 0xFF and b[1] in (0xDB, 0xC0, 0xC2, 0xC4, 0xDA):
                cont = 0.95
                struct_ = 0.95
                reasons.append(f"JPEG marker sequence: A marker header transitions cleanly to B marker 0xFF{b[1]:02X}")
            else:
                penalty = 0.85
                reasons.append("JPEG structural violation: raw payload cannot appear before SOS (Start of Scan) marker")
        else:
            # A has SOS or is a scan payload fragment
            if frag_b.footer_compatibility or b[-2:] == b"\xff\xd9":
                cont = 0.95
                struct_ = 0.98
                reasons.append("JPEG scan-to-EOI transition: scan data successfully terminates at B's EOI marker")
            elif frag_b.entropy > 7.0 or not frag_b.internal_markers:
                cont = 0.88
                struct_ = 0.85
                reasons.append("JPEG scan continuity: scan data sequence across fragment boundary")
            else:
                cont = 0.50
                struct_ = 0.50
                reasons.append("JPEG scan continuation")

        return cont, struct_, reasons, penalty

    def _analyze_pdf(
        self, a: bytes, b: bytes, frag_a: Fragment, frag_b: Fragment
    ) -> Tuple[float, float, List[str], float]:
        reasons = []
        penalty = 0.0
        cont = 0.50
        struct_ = 0.50

        text_a = a.decode("latin-1", errors="replace")
        text_b = b.decode("latin-1", errors="replace")

        # Open stream in A
        has_open_stream = "stream" in text_a and text_a.rfind("stream") > text_a.rfind("endstream")
        if has_open_stream:
            if "endstream" in text_b:
                cont = 0.92
                struct_ = 0.90
                reasons.append("PDF stream continuity: open stream in A closed by endstream in B")
            else:
                cont = 0.70
                struct_ = 0.65
                reasons.append("PDF stream payload continuation across fragment boundary")

        # Object transitions
        if text_a.strip().endswith("endobj") or re.search(r"endobj\s*$", text_a):
            if re.search(r"^\s*\d+\s+\d+\s+obj", text_b) or "xref" in text_b:
                cont = 0.90
                struct_ = 0.88
                reasons.append("PDF object continuity: endobj in A followed by new obj/xref in B")

        # Terminal xref / trailer / %%EOF
        if "%%EOF" in text_b:
            struct_ = min(1.0, struct_ + 0.15)
            reasons.append("PDF terminal marker: B contains %%EOF terminator")

        return cont, struct_, reasons, penalty

    def _analyze_zip(
        self, a: bytes, b: bytes, frag_a: Fragment, frag_b: Fragment
    ) -> Tuple[float, float, List[str], float]:
        reasons = []
        penalty = 0.0
        cont = 0.50
        struct_ = 0.50

        has_zip_sig = (
            b.startswith(b"PK\x03\x04")
            or b.startswith(b"PK\x01\x02")
            or b.startswith(b"PK\x05\x06")
            or b"PK\x01\x02" in b
            or b"PK\x05\x06" in b
            or b"PK\x03\x04" in b
        )

        # Does A end with local file header that continues in B?
        if b"PK\x03\x04" in a:
            pk_pos = a.rfind(b"PK\x03\x04")
            if pk_pos + 30 <= len(a):
                c_size = struct.unpack("<I", a[pk_pos+18:pk_pos+22])[0]
                fn_len = struct.unpack("<H", a[pk_pos+26:pk_pos+28])[0]
                ex_len = struct.unpack("<H", a[pk_pos+28:pk_pos+30])[0]
                total_entry = 30 + fn_len + ex_len + c_size
                rem = total_entry - (len(a) - pk_pos)
                if rem > 0:
                    if len(b) >= rem:
                        cont = 0.90
                        struct_ = 0.88
                        reasons.append(f"ZIP local entry continuation: entry requires {rem} bytes, satisfied by B")
                    else:
                        cont = 0.60
                        struct_ = 0.60
                        reasons.append(f"ZIP local entry split: requires {rem} bytes, B provides {len(b)} bytes")

        # Central directory transition
        if b.startswith(b"PK\x01\x02") or b"PK\x01\x02" in b:
            cont = 0.95
            struct_ = 0.95
            reasons.append("ZIP archive directory sequence: transition to central directory in B")

        # EOCD transition
        elif b.startswith(b"PK\x05\x06") or b"PK\x05\x06" in b:
            # Check if EOCD requires central directory entries
            eocd_pos = b.rfind(b"PK\x05\x06")
            cd_entries = struct.unpack("<H", b[eocd_pos+10:eocd_pos+12])[0] if eocd_pos + 12 <= len(b) else 0
            if cd_entries > 0 and b"PK\x01\x02" not in a and not b.startswith(b"PK\x01\x02"):
                penalty = 0.80
                reasons.append(f"ZIP sequence violation: EOCD declares {cd_entries} entries but central directory missing in predecessor")
            else:
                cont = 0.98
                struct_ = 0.98
                reasons.append("ZIP archive terminal sequence: valid transition to EOCD record in B")

        elif not has_zip_sig:
            penalty = 0.85
            reasons.append("ZIP structure violation: Target fragment lacks ZIP headers, central directory, or EOCD records")

        return cont, struct_, reasons, penalty
