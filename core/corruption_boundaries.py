"""
core/corruption_boundaries.py
=============================
Phase 2 Corruption Boundaries & Provenance Engine.
Merges adjacent or overlapping failed byte/block ranges into consolidated corruption
regions while strictly preserving all underlying granular findings.

Adheres to Phase 2 §4, §10, and §11 requirements:
- Merges 1000-1100, 1101-1200, 1201-1300 into 1000-1300
- Retains individual sub-findings
- Attaches exact forensic provenance and recoverability impact
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from core.models import CorruptionRegion, CorruptionType


def derive_recoverability_impact(c_type: str, format_name: str) -> str:
    """Derives domain-specific recoverability impact from the corruption type and format."""
    ct = c_type.upper()
    fmt = format_name.upper()

    if "HEADER" in ct or "SIGNATURE" in ct:
        return "CONTAINER_HEADER_LOSS_PREVENTS_STANDARD_INGEST"
    elif "CRC" in ct or "CHECKSUM" in ct:
        if fmt == "PNG":
            return "AFFECTED_IDAT_CHUNK_REQUIRES_SCANLINE_RESYNC"
        elif fmt == "ZIP":
            return "SPECIFIC_MEMBER_PAYLOAD_DAMAGED_OTHER_MEMBERS_UNAFFECTED"
        else:
            return "PAYLOAD_CHECKSUM_MISMATCH_DATA_DEGRADED"
    elif "TRUNC" in ct or "TRAILER" in ct:
        return "TERMINAL_STREAM_MISSING_PREVENTS_CLEAN_CLOSE"
    elif "ZERO" in ct:
        return "ZERO_PADDED_GAP_LOSS_OF_ENTROPY_CODED_SEGMENT"
    elif "MARKER" in ct or "STRUCTURAL" in ct:
        return "STREAM_DESYNCHRONIZATION_AT_MARKER_BOUNDARY"
    else:
        return "LOCALIZED_BYTE_ANOMALY_PARTIAL_RECOVERY_FEASIBLE"


def merge_adjacent_corruption_boundaries(
    regions: List[CorruptionRegion],
    artifact_id: str = "ARTIFACT",
    validator_name: str = "UNKNOWN",
    merge_touching: bool = False,
) -> List[CorruptionRegion]:
    """
    Consolidates and enriches corruption regions with forensic provenance and impact.
    If merge_touching is True: merges adjacent touching spans (e.g. 1000-1100, 1101-1200 -> 1000-1200).
    If merge_touching is False: merges strictly overlapping spans while keeping distinct adjacent chunks.
    Underlying granular findings are preserved in underlying_findings.
    """
    if not regions:
        return []

    # Sort strictly by start offset, then end offset
    sorted_regions = sorted(regions, key=lambda r: (r.start_offset, r.end_offset))
    now_ts = datetime.now(timezone.utc).isoformat()

    merged: List[CorruptionRegion] = []

    for r in sorted_regions:
        r_validator = r.validator or validator_name
        r_impact = r.recoverability_impact or derive_recoverability_impact(r.type, r_validator)
        r_provenance = r.provenance or {
            "artifact": artifact_id,
            "byte_range": f"{r.start_offset}:{r.end_offset}",
            "validator": r_validator,
            "timestamp": now_ts,
            "tool": "SAMDHAN AI Feature 02 Engine v2.4",
        }

        finding_dict = {
            "start": r.start_offset,
            "end": r.end_offset,
            "length": r.length,
            "type": r.type,
            "reason": r.reason,
            "severity": r.severity,
            "validator": r_validator,
            "expected": r.expected,
            "actual": r.actual,
            "recoverability_impact": r_impact,
        }

        if not merged:
            new_r = CorruptionRegion(
                start_offset=r.start_offset,
                end_offset=r.end_offset,
                length=r.length,
                type=r.type,
                reason=r.reason,
                severity=r.severity,
                validator=r_validator,
                expected=r.expected,
                actual=r.actual,
                recoverability_impact=r_impact,
                evidence=r.evidence or r.reason,
                provenance=r_provenance,
                underlying_findings=[finding_dict],
            )
            merged.append(new_r)
            continue

        prev = merged[-1]

        # Condition for merging:
        # If merge_touching: r.start_offset <= prev.end_offset + 1
        # Else: r.start_offset < prev.end_offset (strictly overlapping)
        should_merge = (r.start_offset <= (prev.end_offset + 1)) if merge_touching else (r.start_offset < prev.end_offset)

        if should_merge:
            new_end = max(prev.end_offset, r.end_offset)
            prev.end_offset = new_end
            prev.length = new_end - prev.start_offset

            if r.severity == "critical" or prev.severity == "critical":
                prev.severity = "critical"
            elif r.severity == "high" or prev.severity == "high":
                prev.severity = "high"

            if r.reason and r.reason not in prev.reason:
                prev.reason = f"{prev.reason}; {r.reason}"

            prev.underlying_findings.append(finding_dict)
            prev.provenance["byte_range"] = f"{prev.start_offset}:{prev.end_offset}"
        else:
            new_r = CorruptionRegion(
                start_offset=r.start_offset,
                end_offset=r.end_offset,
                length=r.length,
                type=r.type,
                reason=r.reason,
                severity=r.severity,
                validator=r_validator,
                expected=r.expected,
                actual=r.actual,
                recoverability_impact=r_impact,
                evidence=r.evidence or r.reason,
                provenance=r_provenance,
                underlying_findings=[finding_dict],
            )
            merged.append(new_r)

    return merged

