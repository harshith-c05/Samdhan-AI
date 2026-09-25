"""
fragment_reconstruction/reassembler.py
======================================
Stages 7, 9, 10, 11, 12 — Byte Reassembly, Format Validation & Forensic Reporting.

Performs:
  - Real byte concatenation for evaluated candidate paths
  - Format-specific structural validation (JPEG, PNG, PDF, ZIP)
  - Missing fragment detection (never fabricated)
  - Corrupt region detection (damage flagged, repair_performed=False)
  - Winning candidate selection based on actual byte evidence
  - Generates 4 required output artifacts:
      1. reconstructed.bin
      2. provenance.json
      3. validation.json
      4. reconstruction_report.json
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import re
import struct
import time
import zipfile
import zlib
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .models import (
    CandidatePath, CorruptRegion, FormatType, Fragment,
    MissingFragment, ReconstructionResult, ReconstructionStatus,
)
from .graph import ReconstructionGraph


class Reassembler:
    """
    Executes actual byte reassembly, deep structural validation,
    missing/corrupt fragment analysis, and forensic artifact generation.
    """

    def __init__(self, output_dir: Optional[Path] = None):
        self.output_dir = output_dir or (Path(__file__).parent / "output")
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def reassemble_and_validate(
        self,
        graph: ReconstructionGraph,
        candidate_paths: List[CandidatePath],
        target_format: str = "UNKNOWN",
        reconstruction_id: Optional[str] = None,
        source_metadata: Optional[Dict[str, Any]] = None,
    ) -> ReconstructionResult:
        start_time = time.time()
        rec_id = reconstruction_id or f"REC-{int(start_time * 1000)}"

        if not candidate_paths:
            # Handle empty candidate search
            return ReconstructionResult(
                reconstruction_id=rec_id,
                target_format=target_format,
                status=ReconstructionStatus.FAILED,
                total_fragments=len(graph.nodes),
                selected_path=[],
                byte_coverage=0,
                validation={"error": "No viable candidate paths could be constructed"},
                provenance={"source_metadata": source_metadata or {}},
                execution_time_s=round(time.time() - start_time, 4),
            )

        # ── 1. Evaluate Every Candidate Path With Real Byte Validation ────────
        evaluated_candidates: List[CandidatePath] = []
        assembled_data_map: Dict[str, bytes] = {}

        for candidate in candidate_paths:
            # Concatenate raw fragment bytes in exact path order
            path_bytes = b"".join(graph.nodes[fid].get_raw_data() for fid in candidate.fragment_ids)
            assembled_data_map[candidate.candidate_id] = path_bytes

            # Detect format if unknown
            fmt = target_format
            if fmt == "UNKNOWN" or not fmt:
                fmt = self._infer_format(path_bytes, graph, candidate.fragment_ids)

            # Deep format validation
            val_score, is_valid, details = self._validate_format(path_bytes, fmt)

            candidate.validation_score = val_score
            candidate.is_valid = is_valid
            candidate.validation_details = details
            evaluated_candidates.append(candidate)

        # ── 2. Select Winning Candidate Based On Actual Evidence ──────────────
        # Selection criterion: Valid paths first, highest validation_score second, fragment count third, path_score fourth
        evaluated_candidates.sort(
            key=lambda c: (c.is_valid, c.validation_score, len(c.fragment_ids), c.path_score),
            reverse=True,
        )
        winner = evaluated_candidates[0]
        winning_bytes = assembled_data_map[winner.candidate_id]
        final_fmt = target_format if target_format != "UNKNOWN" else self._infer_format(winning_bytes, graph, winner.fragment_ids)

        # ── 3. Detect Missing Fragments ───────────────────────────────────────
        missing_fragments: List[MissingFragment] = []
        all_graph_fids = set(graph.nodes.keys())
        used_fids = set(winner.fragment_ids)
        unused_fids = all_graph_fids - used_fids

        # Check for expected terminal markers
        has_clean_footer = False
        if final_fmt == FormatType.JPEG:
            has_clean_footer = winning_bytes.endswith(b"\xff\xd9")
        elif final_fmt == FormatType.PNG:
            has_clean_footer = b"IEND" in winning_bytes
        elif final_fmt == FormatType.PDF:
            has_clean_footer = b"%%EOF" in winning_bytes
        elif final_fmt == FormatType.ZIP or final_fmt == FormatType.DOCX:
            has_clean_footer = b"PK\x05\x06" in winning_bytes

        if not has_clean_footer:
            missing_fragments.append(
                MissingFragment(
                    after_fragment_id=winner.fragment_ids[-1],
                    expected_offset=len(winning_bytes),
                    estimated_size=None,
                    expected_structure=f"Terminal {final_fmt} footer marker",
                    description=f"Reassembled file does not terminate with expected {final_fmt} footer (partial stream)",
                )
            )

        # Check for gap between clusters if file is incomplete or missing terminal markers
        if not winner.is_valid or not has_clean_footer:
            for i in range(len(winner.fragment_ids) - 1):
                f_curr = graph.nodes[winner.fragment_ids[i]]
                f_next = graph.nodes[winner.fragment_ids[i + 1]]
                if f_curr.cluster_index is not None and f_next.cluster_index is not None:
                    if f_next.cluster_index > f_curr.cluster_index + 1:
                        gap_size = f_next.cluster_index - (f_curr.cluster_index + 1)
                        missing_fragments.append(
                            MissingFragment(
                                after_fragment_id=f_curr.fragment_id,
                                expected_offset=f_curr.source_offset + f_curr.length,
                                estimated_size=gap_size * 4096,
                                expected_structure="Contiguous data clusters",
                                description=f"Physical cluster gap detected between cluster {f_curr.cluster_index} and {f_next.cluster_index} ({gap_size} unreferenced cluster(s))",
                            )
                        )

        # ── 4. Detect Corrupt Regions ─────────────────────────────────────────
        corrupt_regions: List[CorruptRegion] = []
        offset_tracker = 0
        for fid in winner.fragment_ids:
            frag = graph.nodes[fid]
            f_data = frag.get_raw_data()
            frag_corrupt, err_type, err_msg, rel_start, rel_end = self._check_fragment_corruption(f_data, final_fmt)
            if frag_corrupt:
                corrupt_regions.append(
                    CorruptRegion(
                        fragment_id=fid,
                        byte_offset_start=offset_tracker + rel_start,
                        byte_offset_end=offset_tracker + rel_end,
                        error_type=err_type,
                        details=err_msg,
                        repair_performed=False,
                    )
                )
            offset_tracker += len(f_data)

        # ── 5. Determine Overall Status ───────────────────────────────────────
        if corrupt_regions:
            status = ReconstructionStatus.CORRUPTED
        elif missing_fragments:
            status = ReconstructionStatus.PARTIAL
        elif winner.is_valid:
            status = ReconstructionStatus.COMPLETE
        elif winner.validation_score >= 70.0:
            status = ReconstructionStatus.COMPLETE
        else:
            status = ReconstructionStatus.PARTIAL

        # ── 6. Write Actual Output Artifacts ──────────────────────────────────
        ext_map = {"JPEG": ".jpg", "PNG": ".png", "PDF": ".pdf", "ZIP": ".zip", "DOCX": ".docx"}
        ext = ext_map.get(final_fmt, ".bin")
        out_bin_name = f"{rec_id}_reconstructed{ext}"
        out_bin_path = self.output_dir / out_bin_name
        out_bin_path.write_bytes(winning_bytes)

        output_sha = hashlib.sha256(winning_bytes).hexdigest()

        # Provenance metadata
        provenance = {
            "reconstruction_id": rec_id,
            "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "format": final_fmt,
            "status": status.value,
            "fragment_sequence": [
                {
                    "step": idx + 1,
                    "fragment_id": fid,
                    "length": graph.nodes[fid].length,
                    "sha256": graph.nodes[fid].sha256,
                    "cluster_index": graph.nodes[fid].cluster_index,
                    "source_offset": graph.nodes[fid].source_offset,
                    "allocation_state": graph.nodes[fid].allocation_state,
                }
                for idx, fid in enumerate(winner.fragment_ids)
            ],
            "unused_fragments": list(unused_fids),
            "source_evidence": source_metadata or {},
        }
        prov_path = self.output_dir / f"{rec_id}_provenance.json"
        prov_path.write_text(json.dumps(provenance, indent=2), encoding="utf-8")

        # Validation artifact
        validation_artifact = {
            "reconstruction_id": rec_id,
            "selected_candidate": winner.candidate_id,
            "validation_score": winner.validation_score,
            "is_valid": winner.is_valid,
            "format": final_fmt,
            "checks": winner.validation_details.get("checks", []),
            "issues": winner.validation_details.get("issues", []),
            "details": winner.validation_details,
        }
        val_path = self.output_dir / f"{rec_id}_validation.json"
        val_path.write_text(json.dumps(validation_artifact, indent=2), encoding="utf-8")

        # Reconstruction report
        edges_in_path = []
        for i in range(len(winner.fragment_ids) - 1):
            src_id = winner.fragment_ids[i]
            tgt_id = winner.fragment_ids[i + 1]
            edge = graph.edges.get((src_id, tgt_id))
            if edge:
                edges_in_path.append(edge)

        report_data = {
            "reconstruction_id": rec_id,
            "target_format": final_fmt,
            "status": status.value,
            "total_fragments": len(graph.nodes),
            "selected_path": winner.fragment_ids,
            "byte_coverage": len(winning_bytes),
            "output_sha256": output_sha,
            "output_file": str(out_bin_path),
            "edge_evidence": [e.model_dump() for e in edges_in_path],
            "candidates_evaluated": [c.model_dump() for c in evaluated_candidates],
            "missing_fragments": [m.model_dump() for m in missing_fragments],
            "corrupt_regions": [c.model_dump() for c in corrupt_regions],
            "validation": validation_artifact,
            "provenance": provenance,
            "execution_time_s": round(time.time() - start_time, 4),
        }
        rep_path = self.output_dir / f"{rec_id}_reconstruction_report.json"
        rep_path.write_text(json.dumps(report_data, indent=2), encoding="utf-8")

        return ReconstructionResult(
            reconstruction_id=rec_id,
            target_format=final_fmt,
            status=status,
            total_fragments=len(graph.nodes),
            selected_path=winner.fragment_ids,
            byte_coverage=len(winning_bytes),
            output_sha256=output_sha,
            output_filename=out_bin_name,
            output_path=str(out_bin_path),
            edge_evidence=edges_in_path,
            candidates_evaluated=evaluated_candidates,
            missing_fragments=missing_fragments,
            corrupt_regions=corrupt_regions,
            validation=validation_artifact,
            provenance=provenance,
            execution_time_s=round(time.time() - start_time, 4),
        )

    # ──────────────────────────────────────────────────────────────────────────
    # Deep Format Validation
    # ──────────────────────────────────────────────────────────────────────────

    def _infer_format(self, data: bytes, graph: ReconstructionGraph, path: List[str]) -> str:
        for fid in path:
            fmt = graph.nodes[fid].format
            if fmt != FormatType.UNKNOWN and fmt != "UNKNOWN":
                return fmt
        if data.startswith(b"\xff\xd8"): return FormatType.JPEG
        if data.startswith(b"\x89PNG\r\n\x1a\n"): return FormatType.PNG
        if data.startswith(b"%PDF"): return FormatType.PDF
        if data.startswith(b"PK\x03\x04"): return FormatType.ZIP
        return "UNKNOWN"

    def _validate_format(self, data: bytes, fmt: str) -> Tuple[float, bool, Dict[str, Any]]:
        if fmt == FormatType.JPEG:
            return self._validate_jpeg(data)
        elif fmt == FormatType.PNG:
            return self._validate_png(data)
        elif fmt == FormatType.PDF:
            return self._validate_pdf(data)
        elif fmt == FormatType.ZIP or fmt == FormatType.DOCX:
            return self._validate_zip(data)
        else:
            return 50.0, False, {"checks": [], "issues": ["Unknown file format"]}

    def _validate_jpeg(self, data: bytes) -> Tuple[float, bool, Dict[str, Any]]:
        checks = []
        issues = []
        score = 100.0

        if len(data) < 4:
            return 0.0, False, {"checks": [], "issues": ["File too short (< 4 bytes)"]}

        if data[:2] == b"\xff\xd8":
            checks.append("SOI marker valid (FF D8)")
        else:
            issues.append("SOI marker missing")
            score -= 40.0

        has_eoi = data[-2:] == b"\xff\xd9"
        if has_eoi:
            checks.append("EOI marker valid (FF D9)")
        else:
            issues.append("EOI marker missing")
            score -= 30.0

        # Scan markers & segments
        pos = 2
        sos_found = False
        dqt_found = False
        sof_found = False
        markers_seen = 0

        while pos < len(data) - 1:
            if data[pos] == 0xFF:
                m = data[pos + 1]
                if m == 0xD8: # SOI
                    pos += 2
                    continue
                elif m == 0xD9: # EOI
                    pos += 2
                    break
                elif m == 0xDB: # DQT
                    dqt_found = True
                elif m in (0xC0, 0xC2): # SOF0/SOF2
                    sof_found = True
                elif m == 0xDA: # SOS
                    sos_found = True
                    pos += 2
                    if pos + 2 <= len(data):
                        sos_len = struct.unpack(">H", data[pos:pos+2])[0]
                        pos += sos_len
                    # Entropy stream continues until EOI
                    break
                elif 0xD0 <= m <= 0xD7: # RST
                    pos += 2
                    continue

                if pos + 4 <= len(data):
                    seg_len = struct.unpack(">H", data[pos+2:pos+4])[0]
                    pos += 2 + seg_len
                    markers_seen += 1
                else:
                    issues.append("Truncated marker segment header")
                    score -= 15.0
                    break
            else:
                pos += 1

        if dqt_found: checks.append("DQT (Quantization Table) found")
        if sof_found: checks.append("SOF (Frame Header) found")
        if sos_found:
            checks.append("SOS (Start of Scan) found")
        else:
            issues.append("SOS marker missing")
            score -= 20.0

        final_score = max(0.0, min(100.0, score))
        is_valid = len(issues) == 0 and has_eoi and sos_found
        return final_score, is_valid, {"checks": checks, "issues": issues, "markers_seen": markers_seen}

    def _validate_png(self, data: bytes) -> Tuple[float, bool, Dict[str, Any]]:
        checks = []
        issues = []
        score = 100.0
        PNG_SIG = b"\x89PNG\r\n\x1a\n"

        if not data.startswith(PNG_SIG):
            return 0.0, False, {"checks": [], "issues": ["PNG magic signature missing"]}
        checks.append("PNG 8-byte magic valid")

        pos = 8
        idat_seen = False
        iend_seen = False
        idat_payloads = []
        crc_errors = 0
        chunks_seen = 0

        while pos + 8 <= len(data):
            length = struct.unpack(">I", data[pos:pos+4])[0]
            chunk_type = data[pos+4:pos+8]
            total_len = 12 + length
            if pos + total_len > len(data):
                issues.append(f"Chunk {chunk_type.decode('latin-1', errors='replace')} truncated at byte {pos}")
                score -= 30.0
                break

            chunk_payload = data[pos+4:pos+8+length]
            expected_crc = struct.unpack(">I", data[pos+8+length:pos+total_len])[0]
            actual_crc = zlib.crc32(chunk_payload) & 0xFFFFFFFF

            if actual_crc != expected_crc:
                crc_errors += 1
                issues.append(f"CRC32 mismatch in chunk {chunk_type.decode('latin-1', errors='replace')} (offset {pos})")
                score -= 35.0

            if chunk_type == b"IDAT":
                idat_seen = True
                idat_payloads.append(data[pos+8:pos+8+length])
            if chunk_type == b"IEND": iend_seen = True

            pos += total_len
            chunks_seen += 1

        if idat_seen:
            checks.append("IDAT image data chunk present")
            # Mathematical verification of concatenated zlib deflation stream
            try:
                raw_pixels = zlib.decompress(b"".join(idat_payloads))
                checks.append(f"IDAT zlib stream successfully decompressed ({len(raw_pixels):,} raw scanline bytes)")
            except Exception as e:
                issues.append(f"IDAT zlib stream decompression failed: {e}")
                score -= 40.0
        else:
            issues.append("IDAT chunk missing")
            score -= 25.0

        if iend_seen: checks.append("IEND terminal chunk present")
        else: issues.append("IEND chunk missing"); score -= 25.0

        if crc_errors == 0:
            checks.append(f"All {chunks_seen} PNG chunk CRCs verified mathematically")

        final_score = max(0.0, min(100.0, score))
        is_valid = len(issues) == 0 and iend_seen and idat_seen and crc_errors == 0
        return final_score, is_valid, {"checks": checks, "issues": issues, "chunks_seen": chunks_seen, "crc_errors": crc_errors}

    def _validate_pdf(self, data: bytes) -> Tuple[float, bool, Dict[str, Any]]:
        checks = []
        issues = []
        score = 100.0

        if not data.startswith(b"%PDF"):
            return 0.0, False, {"checks": [], "issues": ["%PDF header missing"]}
        checks.append("PDF header signature valid")

        has_eof = b"%%EOF" in data
        if has_eof:
            checks.append("%%EOF terminal marker found")
        else:
            issues.append("%%EOF terminal marker missing")
            score -= 30.0

        obj_matches = len(re.findall(rb"\d+\s+\d+\s+obj", data))
        if obj_matches > 0:
            checks.append(f"{obj_matches} PDF indirect object(s) found")
        else:
            issues.append("No PDF objects found")
            score -= 35.0

        if b"xref" in data: checks.append("xref table present")
        if b"trailer" in data: checks.append("trailer dictionary present")

        final_score = max(0.0, min(100.0, score))
        is_valid = len(issues) == 0 and has_eof and obj_matches > 0
        return final_score, is_valid, {"checks": checks, "issues": issues, "objects_found": obj_matches}

    def _validate_zip(self, data: bytes) -> Tuple[float, bool, Dict[str, Any]]:
        checks = []
        issues = []
        score = 100.0

        if not data.startswith(b"PK\x03\x04"):
            return 0.0, False, {"checks": [], "issues": ["ZIP local file header missing (PK 03 04)"]}
        checks.append("ZIP local file header valid")

        if b"PK\x05\x06" in data:
            checks.append("EOCD record present (PK 05 06)")
        else:
            issues.append("EOCD record missing")
            score -= 30.0

        # Attempt in-memory zipfile parse
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                bad_file = zf.testzip()
                if bad_file is None:
                    checks.append(f"Zip archive integrity verified ({len(zf.namelist())} member file(s))")
                else:
                    issues.append(f"Zip archive file corrupted: {bad_file}")
                    score -= 40.0
        except Exception as e:
            issues.append(f"Zip parser error: {e}")
            score -= 40.0

        final_score = max(0.0, min(100.0, score))
        is_valid = len(issues) == 0
        return final_score, is_valid, {"checks": checks, "issues": issues}

    def _check_fragment_corruption(
        self, data: bytes, fmt: str
    ) -> Tuple[bool, str, str, int, int]:
        """
        Scan a single fragment for internal corruption.
        Returns (is_corrupt, error_type, details, rel_start, rel_end).
        """
        if fmt == FormatType.PNG:
            # Check if fragment contains complete PNG chunks with CRC mismatch
            pos = 8 if data.startswith(b"\x89PNG\r\n\x1a\n") else 0
            while pos + 12 <= len(data):
                length = struct.unpack(">I", data[pos:pos+4])[0]
                chunk_type = data[pos+4:pos+8]
                if pos + 12 + length <= len(data):
                    payload = data[pos+4:pos+8+length]
                    expected_crc = struct.unpack(">I", data[pos+8+length:pos+12+length])[0]
                    actual_crc = zlib.crc32(payload) & 0xFFFFFFFF
                    if actual_crc != expected_crc:
                        return (
                            True,
                            "CRC32_CHECKSUM_FAILURE",
                            f"Corrupted bytes in PNG chunk '{chunk_type.decode('latin-1', errors='replace')}': expected CRC {expected_crc:08x}, got {actual_crc:08x}",
                            pos,
                            pos + 12 + length,
                        )
                    pos += 12 + length
                else:
                    break

        elif fmt == FormatType.JPEG:
            # Check for corrupt marker lengths or illegal marker codes in header
            pos = 2 if data.startswith(b"\xff\xd8") else 0
            while pos < len(data) - 1:
                if data[pos] == 0xFF:
                    m = data[pos + 1]
                    if m == 0xDA: # SOS
                        break
                    elif m not in (0x00, 0xFF) and not (0xD0 <= m <= 0xD7) and m != 0xD9:
                        if pos + 4 <= len(data):
                            seg_len = struct.unpack(">H", data[pos+2:pos+4])[0]
                            if seg_len < 2:
                                return (
                                    True,
                                    "INVALID_JPEG_MARKER_LENGTH",
                                    f"Illegal marker segment length {seg_len} at byte {pos}",
                                    pos,
                                    pos + 4,
                                )
                            pos += 2 + seg_len
                        else:
                            break
                    else:
                        pos += 1
                else:
                    pos += 1

        return False, "", "", 0, 0
