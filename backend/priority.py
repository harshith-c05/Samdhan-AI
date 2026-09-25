"""
backend/priority.py
===================
SAMDHAN AI — Multi-Factor Weighted Evidence Prioritization Engine.

Specification:
- Weighted priority score combining:
  1. Evidence Relevance (0.40) — presence of IOCs, breach window alignment, keywords
  2. Data Integrity (0.25) — 4-vector integrity score
  3. Temporal Decay (0.20) — freshness and timestamp proximity to incident window
  4. Rarity (0.15) — format scarcity, anomalous entropy, signature uniqueness
- Maps to deterministic tiers: Critical, High, Medium, Low
"""

from typing import Dict, List, Optional, Any

# Named Weight Constants
WEIGHT_EVIDENCE_RELEVANCE = 0.40
WEIGHT_INTEGRITY = 0.25
WEIGHT_TEMPORAL_DECAY = 0.20
WEIGHT_RARITY = 0.15

# Named Tier Threshold Constants
TIER_CRITICAL_THRESHOLD = 80.0
TIER_HIGH_THRESHOLD = 60.0
TIER_MEDIUM_THRESHOLD = 40.0


def calculate_evidence_relevance(ioc_summary: Dict[str, Any], has_breach_window: bool = False) -> float:
    """Calculates evidence relevance score from 0.0 to 100.0."""
    score = 20.0  # baseline

    ips = ioc_summary.get("ips_count", 0)
    wallets = ioc_summary.get("wallets_count", 0)
    darknet = ioc_summary.get("darknet_count", 0)
    keywords = ioc_summary.get("keywords_count", 0)

    if darknet > 0:
        score += 35.0
    if wallets > 0:
        score += 25.0
    if ips > 0:
        score += min(20.0, ips * 10.0)
    if keywords > 0:
        score += min(25.0, keywords * 8.0)
    if has_breach_window:
        score += 15.0

    return min(100.0, score)


def calculate_temporal_score(hours_since_incident: Optional[float] = None) -> float:
    """Calculates temporal decay score (fresher = higher score)."""
    if hours_since_incident is None:
        return 75.0  # standard default for unversioned evidence
    if hours_since_incident <= 24:
        return 95.0
    elif hours_since_incident <= 72:
        return 80.0
    elif hours_since_incident <= 168:
        return 65.0
    elif hours_since_incident <= 720:
        return 50.0
    return 30.0


def calculate_rarity_score(mime_type: str, entropy: float) -> float:
    """Calculates rarity score based on format and entropy distribution."""
    score = 50.0
    # High entropy or binary executable formats are rarer in normal artifact sets
    if entropy > 7.5 or entropy < 0.5:
        score += 25.0
    if mime_type in ("application/x-sqlite3", "application/x-dosexec", "application/x-elf"):
        score += 20.0
    elif mime_type == "text/plain":
        score -= 10.0
    return max(10.0, min(100.0, score))


def compute_priority_score(
    relevance_score: float,
    integrity_score: float,
    temporal_score: float = 75.0,
    rarity_score: float = 50.0
) -> Dict[str, Any]:
    """
    Computes overall weighted priority score and maps to tier.
    """
    rel = max(0.0, min(100.0, relevance_score))
    integ = max(0.0, min(100.0, integrity_score))
    temp = max(0.0, min(100.0, temporal_score))
    rar = max(0.0, min(100.0, rarity_score))

    total = (
        WEIGHT_EVIDENCE_RELEVANCE * rel +
        WEIGHT_INTEGRITY * integ +
        WEIGHT_TEMPORAL_DECAY * temp +
        WEIGHT_RARITY * rar
    )
    total = round(total, 1)

    if total >= TIER_CRITICAL_THRESHOLD or rel >= 90.0:
        tier = "Critical"
    elif total >= TIER_HIGH_THRESHOLD:
        tier = "High"
    elif total >= TIER_MEDIUM_THRESHOLD:
        tier = "Medium"
    else:
        tier = "Low"

    return {
        "priority_score": total,
        "priority_tier": tier,
        "weights": {
            "evidence_relevance": WEIGHT_EVIDENCE_RELEVANCE,
            "integrity": WEIGHT_INTEGRITY,
            "temporal_decay": WEIGHT_TEMPORAL_DECAY,
            "rarity": WEIGHT_RARITY,
        },
        "breakdown": {
            "relevance": round(rel, 1),
            "integrity": round(integ, 1),
            "temporal": round(temp, 1),
            "rarity": round(rar, 1),
        }
    }
