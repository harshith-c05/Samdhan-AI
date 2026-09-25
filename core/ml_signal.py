"""
core/ml_signal.py
=================
Phase 2 Auxiliary ML / Statistical Anomaly Signal Engine.

SAFETY & COMPLIANCE CONTRACT:
- Output is EXPLICITLY labeled "ML SUPPORTING SIGNAL".
- NEVER claims to be "ML PROOF OF CORRUPTION".
- Deterministic byte and structural validators are authoritative.
- Provides fully transparent, explainable anomaly decomposition.
"""

from __future__ import annotations

import math
from typing import Dict, List, Optional

from core.models import BlockAnalysisRecord, CorruptionRegion, DecoderResult, MLAnomalySignal, StructuralCheck


def compute_ml_supporting_signal(
    data: bytes,
    format_name: str,
    structural_checks: List[StructuralCheck],
    blocks: List[BlockAnalysisRecord],
    corruption_regions: List[CorruptionRegion],
    decoder_result: Optional[DecoderResult] = None,
) -> MLAnomalySignal:
    """
    Computes an explainable auxiliary anomaly score from multi-dimensional byte signals:
    1. Entropy transition variance between adjacent blocks
    2. Byte value distribution skewness
    3. Structural check failure density
    4. Unexpected zero-fill clusters
    5. Decoder exit state
    """
    findings: List[str] = []
    total_len = len(data)

    if total_len == 0:
        return MLAnomalySignal(
            label="ML SUPPORTING SIGNAL",
            anomaly_score=100.0,
            entropy_transition_score=0.0,
            byte_distribution_score=0.0,
            structural_failure_density=100.0,
            repeated_zero_score=0.0,
            findings=["Empty byte stream — maximum anomaly signal"],
            explanation="Payload has 0 bytes.",
        )

    # 1. Entropy Transition Score
    entropy_transitions = 0.0
    if len(blocks) >= 2:
        deltas = [abs(blocks[i].entropy - blocks[i - 1].entropy) for i in range(1, len(blocks))]
        avg_delta = sum(deltas) / len(deltas)
        max_delta = max(deltas)
        # Compressed formats (JPEG, PNG, ZIP) should have relatively uniform high entropy.
        # Sudden cliff drops indicate zero-fills or uncompressed insertions.
        if format_name in ("JPEG", "PNG", "ZIP") and max_delta > 3.0:
            entropy_transitions = min(100.0, max_delta * 25.0)
            findings.append(f"Severe entropy cliff transition detected (delta: {max_delta:.2f} bits/byte)")
        else:
            entropy_transitions = min(100.0, avg_delta * 20.0)

    # 2. Byte Distribution Score (Chi-Square-like uniformity or format expectation)
    byte_counts = [0] * 256
    for b in data:
        byte_counts[b] += 1
    zero_ratio = byte_counts[0] / total_len

    byte_dist_score = 0.0
    if format_name in ("JPEG", "PNG", "ZIP") and zero_ratio > 0.15:
        # High zero ratio in compressed file is anomalous
        byte_dist_score = min(100.0, (zero_ratio - 0.15) * 200.0)
        findings.append(f"Anomalous zero-byte density for compressed {format_name}: {zero_ratio * 100:.1f}%")

    # 3. Structural Failure Density
    fail_count = sum(1 for c in structural_checks if c.status.value == "FAIL")
    warn_count = sum(1 for c in structural_checks if c.status.value == "WARNING")
    total_checks = max(1, len(structural_checks))
    fail_density = round(((fail_count + 0.5 * warn_count) / total_checks) * 100.0, 1)

    if fail_count > 0:
        findings.append(f"Structural parser failure density: {fail_density}% ({fail_count} checks failed)")

    # 4. Repeated Zero Score
    repeated_zero_score = 0.0
    large_zero_spans = sum(1 for cr in corruption_regions if "ZERO" in cr.type)
    if large_zero_spans > 0:
        repeated_zero_score = min(100.0, large_zero_spans * 40.0)
        findings.append(f"{large_zero_spans} significant zero-filled region(s) identified")

    # 5. Decoder exit penalty
    decoder_penalty = 0.0
    if decoder_result and decoder_result.attempted and not decoder_result.success:
        decoder_penalty = 40.0
        findings.append(f"Decoder execution failed: {decoder_result.error_message}")

    # Weighted composite anomaly score
    composite = (
        0.35 * fail_density +
        0.20 * entropy_transitions +
        0.15 * byte_dist_score +
        0.15 * repeated_zero_score +
        0.15 * decoder_penalty
    )
    final_score = min(100.0, round(composite, 1))

    if final_score < 15.0:
        explanation = "ML signal indicates nominal byte distribution consistent with expected format profile."
    elif final_score < 50.0:
        explanation = "ML signal indicates mild statistical anomalies correlating with localized structural issues."
    else:
        explanation = "ML signal indicates substantial byte-pattern anomalies and structural discrepancies."

    return MLAnomalySignal(
        label="ML SUPPORTING SIGNAL",
        anomaly_score=final_score,
        entropy_transition_score=round(entropy_transitions, 1),
        byte_distribution_score=round(byte_dist_score, 1),
        structural_failure_density=fail_density,
        repeated_zero_score=round(repeated_zero_score, 1),
        findings=findings,
        explanation=explanation,
    )
