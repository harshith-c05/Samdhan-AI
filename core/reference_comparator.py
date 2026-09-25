"""
core/reference_comparator.py
============================
Phase 2 Reference Comparison Engine.
Compares recovered/candidate artifact bytes against reference ground-truth bytes.

SAFETY & INTEGRITY RULES:
- Reference data is for verification only.
- Never use reference comparison to manufacture or fabricate parser results.
- Structural and format validators provide the corruption evidence.
"""

from __future__ import annotations

import hashlib
from typing import Dict, List, Optional

from core.models import ReferenceComparisonResult


def compare_with_reference(
    candidate_bytes: bytes,
    reference_bytes: bytes,
    reference_sha256: Optional[str] = None,
) -> ReferenceComparisonResult:
    """
    Compares candidate artifact bytes with reference ground truth.
    Produces byte match percentage, localized changed ranges, missing ranges,
    and rolling fuzzy similarity score.
    """
    cand_len = len(candidate_bytes)
    ref_len = len(reference_bytes)

    ref_hash = hashlib.sha256(reference_bytes).hexdigest()
    cand_hash = hashlib.sha256(candidate_bytes).hexdigest()
    is_exact_match = (cand_hash.lower() == ref_hash.lower())

    if is_exact_match:
        return ReferenceComparisonResult(
            reference_sha256=ref_hash,
            match=True,
            byte_match_percentage=100.0,
            changed_ranges=[],
            missing_ranges=[],
            extra_ranges=[],
            fuzzy_similarity=100.0,
            fuzzy_note="Candidate is 100% cryptographically identical to reference.",
        )

    # Byte-by-byte alignment
    min_len = min(cand_len, ref_len)
    matching_bytes = 0

    changed_ranges: List[Dict[str, int]] = []
    in_diff = False
    diff_start = 0

    for i in range(min_len):
        if candidate_bytes[i] == reference_bytes[i]:
            matching_bytes += 1
            if in_diff:
                changed_ranges.append({
                    "start": diff_start,
                    "end": i,
                    "length": i - diff_start,
                })
                in_diff = False
        else:
            if not in_diff:
                in_diff = True
                diff_start = i

    if in_diff:
        changed_ranges.append({
            "start": diff_start,
            "end": min_len,
            "length": min_len - diff_start,
        })

    missing_ranges: List[Dict[str, int]] = []
    extra_ranges: List[Dict[str, int]] = []

    if cand_len < ref_len:
        missing_ranges.append({
            "start": cand_len,
            "end": ref_len,
            "length": ref_len - cand_len,
        })
    elif cand_len > ref_len:
        extra_ranges.append({
            "start": ref_len,
            "end": cand_len,
            "length": cand_len - ref_len,
        })

    max_len = max(cand_len, ref_len)
    byte_match_pct = round((matching_bytes / max_len) * 100.0, 2) if max_len > 0 else 0.0

    # Rolling block-level fuzzy similarity (ssdeep-equivalent pure Python score)
    block_sz = max(64, min_len // 32) if min_len > 0 else 64
    matching_blocks = 0
    total_blocks = (min_len + block_sz - 1) // block_sz if min_len > 0 else 1

    for b in range(total_blocks):
        b_start = b * block_sz
        b_end = min(b_start + block_sz, min_len)
        if candidate_bytes[b_start:b_end] == reference_bytes[b_start:b_end]:
            matching_blocks += 1

    fuzzy_sim = round((matching_blocks / total_blocks) * 100.0, 1) if total_blocks > 0 else 0.0

    if byte_match_pct >= 95.0:
        fuzzy_note = f"Candidate retains high similarity ({byte_match_pct}%) with localized alterations."
    elif byte_match_pct >= 50.0:
        fuzzy_note = f"Candidate differs from reference but retains substantial similarity ({byte_match_pct}%)."
    else:
        fuzzy_note = f"Candidate differs significantly from reference ({byte_match_pct}% match)."

    return ReferenceComparisonResult(
        reference_sha256=ref_hash,
        match=False,
        byte_match_percentage=byte_match_pct,
        changed_ranges=changed_ranges,
        missing_ranges=missing_ranges,
        extra_ranges=extra_ranges,
        fuzzy_similarity=fuzzy_sim,
        fuzzy_note=fuzzy_note,
    )
