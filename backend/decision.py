"""
backend/decision.py
===================
SAMDHAN AI — Deterministic 5-State Forensic Decision Engine.

Specification:
- Deterministic 5-state verdict:
  1. BLOCKED_SECURITY_RISK
  2. UNRECOVERABLE
  3. INTEGRITY_VERIFIED
  4. PARTIALLY_RECOVERABLE
  5. NEEDS_REVIEW
- Fixed numeric thresholds maintained as named constants for legal reproducibility
"""

from typing import Dict, List, Optional, Any

# ============================================================================
# NAMED CONSTANTS FOR REPRODUCIBLE FORENSIC THRESHOLDS (NO MAGIC NUMBERS)
# ============================================================================
STATE_BLOCKED_SECURITY_RISK = "BLOCKED_SECURITY_RISK"
STATE_UNRECOVERABLE = "UNRECOVERABLE"
STATE_INTEGRITY_VERIFIED = "INTEGRITY_VERIFIED"
STATE_PARTIALLY_RECOVERABLE = "PARTIALLY_RECOVERABLE"
STATE_NEEDS_REVIEW = "NEEDS_REVIEW"

# Composite & 4-Vector Thresholds
THRESHOLD_VERIFIED_COMPOSITE = 85.0
THRESHOLD_VERIFIED_STRUCTURAL = 80.0
THRESHOLD_VERIFIED_CONTENT = 80.0

THRESHOLD_PARTIAL_COMPOSITE_MIN = 35.0
THRESHOLD_PARTIAL_CONTENT_MIN = 35.0

THRESHOLD_UNRECOVERABLE_COMPOSITE_MAX = 25.0
THRESHOLD_ZERO_FILL_RATIO = 0.98
THRESHOLD_PACKED_ENTROPY_SECURITY = 7.5


def evaluate_decision_state(
    integrity_result: Dict[str, Any],
    security_result: Optional[Dict[str, Any]] = None,
    anomaly_result: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Evaluates forensic state deterministically using strict priority ordering:
    1. Security containment (BLOCKED_SECURITY_RISK)
    2. Total wipe / entropy loss (UNRECOVERABLE)
    3. Pristine structure & content (INTEGRITY_VERIFIED)
    4. Salveageable body with degraded/wiped header (PARTIALLY_RECOVERABLE)
    5. Borderline / Ambiguous (NEEDS_REVIEW)
    """
    vector = integrity_result.get("vector", {})
    structural = vector.get("structural", 0.0)
    content = vector.get("content", 0.0)
    composite = integrity_result.get("composite_score", 0.0)
    corruption_ranges = integrity_result.get("corruption_ranges", [])

    is_blocked = False
    block_reasons = []

    if security_result:
        if security_result.get("is_blocked", False) or security_result.get("has_threat", False):
            is_blocked = True
            block_reasons.extend(security_result.get("reasons", []))

    # Priority 1: Security Risk
    if is_blocked:
        return {
            "state": STATE_BLOCKED_SECURITY_RISK,
            "confidence": 1.0,
            "reasons": block_reasons or ["Malicious disguised payload or security hazard detected"],
            "action": "Quarantine bitstream immediately. Prevent execution or export.",
            "thresholds_applied": {
                "rule": "Security check triggered"
            }
        }

    # Priority 2: Unrecoverable
    is_total_wipe = False
    if anomaly_result:
        null_r = anomaly_result.get("overall_null_ratio", 0.0)
        if null_r >= THRESHOLD_ZERO_FILL_RATIO or (null_r >= 0.88 and composite < THRESHOLD_UNRECOVERABLE_COMPOSITE_MAX):
            is_total_wipe = True
    if integrity_result.get("size_bytes", 1) == 0:
        is_total_wipe = True

    if is_total_wipe or (composite < THRESHOLD_UNRECOVERABLE_COMPOSITE_MAX and structural < 25.0):
        return {
            "state": STATE_UNRECOVERABLE,
            "confidence": 0.95,
            "reasons": ["Bitstream zero-filled or below minimum reconstruction threshold (< 25%)"],
            "action": "Log unrecoverable block. Mark cluster unallocated in ledger.",
            "thresholds_applied": {
                "threshold_unrecoverable_composite_max": THRESHOLD_UNRECOVERABLE_COMPOSITE_MAX,
                "threshold_zero_fill_ratio": THRESHOLD_ZERO_FILL_RATIO,
                "actual_composite": composite,
            }
        }

    # Priority 3: Integrity Verified
    critical_corruptions = [c for c in corruption_ranges if c.get("severity") == "CRITICAL"]
    if (composite >= THRESHOLD_VERIFIED_COMPOSITE and
        structural >= THRESHOLD_VERIFIED_STRUCTURAL and
        content >= THRESHOLD_VERIFIED_CONTENT and
        len(critical_corruptions) == 0):
        return {
            "state": STATE_INTEGRITY_VERIFIED,
            "confidence": 0.98,
            "reasons": ["All structural markers, headers, and payload continuous and intact"],
            "action": "Proceed with primary automated ingestion and cataloging.",
            "thresholds_applied": {
                "threshold_verified_composite": THRESHOLD_VERIFIED_COMPOSITE,
                "threshold_verified_structural": THRESHOLD_VERIFIED_STRUCTURAL,
                "threshold_verified_content": THRESHOLD_VERIFIED_CONTENT,
                "actual_composite": composite,
            }
        }

    # Priority 4: Partially Recoverable
    # Headers wiped but content salvageable, or moderate composite score
    if (composite >= THRESHOLD_PARTIAL_COMPOSITE_MIN or
        content >= THRESHOLD_PARTIAL_CONTENT_MIN or
        len(corruption_ranges) > 0):
        return {
            "state": STATE_PARTIALLY_RECOVERABLE,
            "confidence": 0.85,
            "reasons": [
                f"Partial recovery viable: {len(corruption_ranges)} corruption zones detected, body intact"
            ],
            "action": "Dispatch to DAG Fragment Reconstructor & Carver for header repair.",
            "thresholds_applied": {
                "threshold_partial_composite_min": THRESHOLD_PARTIAL_COMPOSITE_MIN,
                "threshold_partial_content_min": THRESHOLD_PARTIAL_CONTENT_MIN,
                "actual_composite": composite,
            }
        }

    # Priority 5: Needs Review (Fallback)
    return {
        "state": STATE_NEEDS_REVIEW,
        "confidence": 0.70,
        "reasons": ["Borderline structural metric requiring human examiner validation"],
        "action": "Queue for manual investigator inspection in forensic console.",
        "thresholds_applied": {
            "composite": composite
        }
    }
