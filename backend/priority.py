"""
backend/priority.py
===================
SAMDHAN AI — Multi-Factor Weighted Evidence Prioritization & Forensic Triage Engine.

Formula (SAMDHAN Master Spec & Objective 03):
    P = w1*I + w2*R + w3*T + w4*U - w5*N

Where:
    I = Integrity Score (0.0 to 1.0) — verified by Objective 02 deep parser
    R = Relevance Score (0.0 to 1.0) — IOC matches, case keywords, incident entities
    T = Temporal Proximity (0.0 to 1.0) — proximity to incident breach window
    U = Uniqueness (0.0 to 1.0) — 1 - duplication_ratio (SSDEEP / hash clustering)
    N = Noise Penalty (0.0 to 1.0) — known OS/browser/cache junk

Default Weights:
    w1 = 0.30  (Integrity)
    w2 = 0.35  (Relevance)
    w3 = 0.20  (Temporal / Recency)
    w4 = 0.15  (Uniqueness)
    w5 = 0.10  (Noise Penalty - subtracted)

Priority Tiers:
    P >= 0.75  (or >= 80.0) -> CRITICAL
    0.50 <= P < 0.75 (or 60-80) -> HIGH
    0.25 <= P < 0.50 (or 40-60) -> MEDIUM
    P < 0.25   (or < 40.0) -> LOW

CRITICAL INVARIANT:
    Classification confidence is NEVER included in P.
    Low confidence (< 60%) triggers review_required = True independently.
"""

import math
import re
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Union

# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Default Weights & Thresholds
# ---------------------------------------------------------------------------
DEFAULT_WEIGHTS = {
    "w1_integrity": 0.30,
    "w2_relevance": 0.35,
    "w3_temporal": 0.20,
    "w4_uniqueness": 0.15,
    "w5_noise": 0.10,
    "integrity": 0.30,
    "relevance": 0.35,
    "temporal": 0.20,
    "uniqueness": 0.15,
    "noise_penalty": 0.10,
}

# Legacy weight constants preserved for backward compatibility
WEIGHT_EVIDENCE_RELEVANCE = 0.40
WEIGHT_INTEGRITY = 0.25
WEIGHT_TEMPORAL_DECAY = 0.20
WEIGHT_RARITY = 0.15

# Named Tier Constants
TIER_CRITICAL = "CRITICAL"
TIER_HIGH = "HIGH"
TIER_MEDIUM = "MEDIUM"
TIER_LOW = "LOW"

# Named Tier Threshold Constants (0-100 scale preserved for backward compatibility)
TIER_CRITICAL_THRESHOLD = 80.0
TIER_HIGH_THRESHOLD = 60.0
TIER_MEDIUM_THRESHOLD = 40.0

# Normalized 0-1 scale thresholds
TIER_CRITICAL_0_1 = 0.75
TIER_HIGH_0_1 = 0.50
TIER_MEDIUM_0_1 = 0.25


def classify_priority_tier(score: float) -> str:
    """Classifies score (0-1 or 0-100) into CRITICAL, HIGH, MEDIUM, LOW tier."""
    val = score if score <= 1.0 else score / 100.0
    if val >= 0.75:
        return TIER_CRITICAL
    elif val >= 0.50:
        return TIER_HIGH
    elif val >= 0.25:
        return TIER_MEDIUM
    return TIER_LOW


# Preset Configurations
PRESETS = {
    "standard": {
        "id": "standard",
        "name": "Standard Forensic Triage",
        "description": "Balanced baseline across all 5 dimensions",
        "weights": {
            "w1_integrity": 0.30,
            "w2_relevance": 0.35,
            "w3_temporal": 0.20,
            "w4_uniqueness": 0.15,
            "w5_noise": 0.10,
            "integrity": 0.30,
            "relevance": 0.35,
            "temporal": 0.20,
            "uniqueness": 0.15,
            "noise_penalty": 0.10,
        }
    },
    "ransomware": {
        "id": "ransomware",
        "name": "Active Ransomware Incident",
        "description": "Heavily weights IOC matches and breach window recency",
        "weights": {
            "w1_integrity": 0.20,
            "w2_relevance": 0.50,
            "w3_temporal": 0.25,
            "w4_uniqueness": 0.10,
            "w5_noise": 0.05,
            "integrity": 0.20,
            "relevance": 0.50,
            "temporal": 0.25,
            "uniqueness": 0.10,
            "noise_penalty": 0.05,
        }
    },
    "time_critical": {
        "id": "time_critical",
        "name": "Time-Critical Breach Investigation",
        "description": "Focuses on events clustered directly around the breach window",
        "weights": {
            "w1_integrity": 0.20,
            "w2_relevance": 0.30,
            "w3_temporal": 0.40,
            "w4_uniqueness": 0.10,
            "w5_noise": 0.10,
            "integrity": 0.20,
            "relevance": 0.30,
            "temporal": 0.40,
            "uniqueness": 0.10,
            "noise_penalty": 0.10,
        }
    },
    "dedup_heavy": {
        "id": "dedup_heavy",
        "name": "Deduplication & Exfiltration Recovery",
        "description": "Emphasizes unique, intact artifacts and heavily penalizes noise/duplicates",
        "weights": {
            "w1_integrity": 0.35,
            "w2_relevance": 0.25,
            "w3_temporal": 0.10,
            "w4_uniqueness": 0.25,
            "w5_noise": 0.15,
            "integrity": 0.35,
            "relevance": 0.25,
            "temporal": 0.10,
            "uniqueness": 0.25,
            "noise_penalty": 0.15,
        }
    }
}

PRIORITY_PRESETS = {
    "STANDARD": PRESETS["standard"],
    "RANSOMWARE": PRESETS["ransomware"],
    "TIME_CRITICAL": PRESETS["time_critical"],
    "DEDUP_HEAVY": PRESETS["dedup_heavy"],
    **PRESETS
}

# ---------------------------------------------------------------------------
# Noise Detection Patterns
# ---------------------------------------------------------------------------
NOISE_PATTERNS = [
    (re.compile(r"thumbs\.db$", re.IGNORECASE), 0.90, "OS-generated thumbnail cache (Thumbs.db)"),
    (re.compile(r"desktop\.ini$", re.IGNORECASE), 0.95, "Windows desktop config artifact"),
    (re.compile(r"pagefile\.sys$", re.IGNORECASE), 0.60, "OS virtual memory pagefile"),
    (re.compile(r"hiberfil\.sys$", re.IGNORECASE), 0.60, "OS hibernation memory image"),
    (re.compile(r"\.ds_store$", re.IGNORECASE), 0.95, "macOS desktop services store"),
    (re.compile(r"[/\\]cache[/\\]", re.IGNORECASE), 0.85, "Browser cache directory"),
    (re.compile(r"browserhistory[/\\]cache", re.IGNORECASE), 0.90, "Browser cache web file"),
    (re.compile(r"[/\\]appdata[/\\]local[/\\]google[/\\]chrome[/\\]", re.IGNORECASE), 0.85, "Browser cache (Chrome)"),
    (re.compile(r"[/\\]appdata[/\\]local[/\\]temp", re.IGNORECASE), 0.80, "Windows temporary directory"),
    (re.compile(r"[/\\](?:tmp|temp)[/\\]", re.IGNORECASE), 0.80, "Temporary staging directory"),
    (re.compile(r"\.(?:tmp|bak|old)$", re.IGNORECASE), 0.70, "Temporary / backup extension"),
    (re.compile(r"[/\\]\$recycle\.bin[/\\]", re.IGNORECASE), 0.50, "Recycle bin deleted container"),
]


class NoiseResult(tuple):
    """Dual-access result: can be unpacked as (penalty, reasons) and accessed as dict."""
    def __new__(cls, penalty: float, indicators: list):
        return super(NoiseResult, cls).__new__(cls, (penalty, indicators))

    @property
    def noise_penalty(self):
        return self[0]

    @property
    def noise_indicators(self):
        return self[1]

    def get(self, key, default=None):
        if key == "noise_penalty":
            return self[0]
        elif key == "noise_indicators":
            return self[1]
        elif key == "is_noise":
            return self[0] >= 0.50
        elif key == "explanation":
            return f"Marked as system noise ({', '.join(self[1])})" if self[1] else "No known system noise indicators detected"
        return default

    def __getitem__(self, item):
        if isinstance(item, str):
            val = self.get(item)
            if val is not None:
                return val
            raise KeyError(item)
        return super().__getitem__(item)


def detect_noise(filename: str = "", path: str = "", mime: str = "") -> NoiseResult:
    """
    Detects known low-value system artifacts and calculates noise penalty N in [0.0, 1.0].
    Explains exactly why an artifact received a noise penalty.
    """
    combined = f"{path}/{filename}".replace("\\", "/")
    noise_indicators = []
    max_penalty = 0.0

    for pattern, penalty, reason in NOISE_PATTERNS:
        if pattern.search(combined):
            noise_indicators.append(reason)
            max_penalty = max(max_penalty, penalty)

    return NoiseResult(round(max_penalty, 3), noise_indicators)



# ---------------------------------------------------------------------------
# Temporal Proximity Engine
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Temporal Proximity Engine
# ---------------------------------------------------------------------------
class TemporalResult(tuple):
    """Dual-access result: can be unpacked as (score, explanation) or accessed as dict."""
    def __new__(cls, score: float, explanation: str):
        return super(TemporalResult, cls).__new__(cls, (score, explanation))

    @property
    def temporal_score(self):
        return self[0] * 100.0 if self[0] <= 1.0 else self[0]

    def get(self, key, default=None):
        if key == "temporal_score":
            return self.temporal_score
        elif key == "score":
            return self[0]
        elif key == "explanation":
            return self[1]
        return default

    def __getitem__(self, item):
        if isinstance(item, str):
            val = self.get(item)
            if val is not None:
                return val
            raise KeyError(item)
        return super().__getitem__(item)


def calculate_temporal_score(
    artifact_mtime: Optional[Union[str, datetime, float]] = None,
    incident_start: Optional[Union[str, datetime]] = None,
    incident_end: Optional[Union[str, datetime]] = None,
    hours_since_incident: Optional[float] = None,
    decay_lambda: float = 0.05
) -> Any:
    """
    Calculates temporal proximity score.
    Supports:
    - Legacy API: hours_since_incident -> returns float (30.0 - 95.0)
    - Triage API: (artifact_time, t_start, t_end) -> returns TemporalResult(score, explanation)
    """
    if hours_since_incident is not None:
        if hours_since_incident <= 24:
            return 95.0
        elif hours_since_incident <= 72:
            return 80.0
        elif hours_since_incident <= 168:
            return 65.0
        elif hours_since_incident <= 720:
            return 50.0
        return 30.0

    if isinstance(artifact_mtime, (int, float)) and incident_start is None:
        return calculate_temporal_score(hours_since_incident=float(artifact_mtime))

    if artifact_mtime is None:
        return TemporalResult(0.75, "Default timestamp proximity score (no timestamp provided)")

    dt_art = None
    if isinstance(artifact_mtime, (int, float)):
        dt_art = datetime.fromtimestamp(artifact_mtime, tz=timezone.utc)
    elif isinstance(artifact_mtime, datetime):
        dt_art = artifact_mtime if artifact_mtime.tzinfo else artifact_mtime.replace(tzinfo=timezone.utc)
    elif isinstance(artifact_mtime, str):
        try:
            cleaned = artifact_mtime.replace("Z", "+00:00")
            dt_art = datetime.fromisoformat(cleaned)
            if not dt_art.tzinfo:
                dt_art = dt_art.replace(tzinfo=timezone.utc)
        except Exception:
            pass

    if not dt_art:
        return TemporalResult(0.75, "Invalid artifact timestamp format")

    default_start = datetime(2026, 9, 24, 10, 0, tzinfo=timezone.utc)
    default_end = datetime(2026, 9, 24, 18, 0, tzinfo=timezone.utc)

    dt_start = default_start
    dt_end = default_end

    if isinstance(incident_start, str):
        try:
            dt_start = datetime.fromisoformat(incident_start.replace("Z", "+00:00"))
            if not dt_start.tzinfo:
                dt_start = dt_start.replace(tzinfo=timezone.utc)
        except Exception:
            pass
    elif isinstance(incident_start, datetime):
        dt_start = incident_start if incident_start.tzinfo else incident_start.replace(tzinfo=timezone.utc)

    if isinstance(incident_end, str):
        try:
            dt_end = datetime.fromisoformat(incident_end.replace("Z", "+00:00"))
            if not dt_end.tzinfo:
                dt_end = dt_end.replace(tzinfo=timezone.utc)
        except Exception:
            pass
    elif isinstance(incident_end, datetime):
        dt_end = incident_end if incident_end.tzinfo else incident_end.replace(tzinfo=timezone.utc)

    if dt_start <= dt_art <= dt_end:
        return TemporalResult(1.0, "Inside incident window (maximum temporal proximity score)")

    if dt_art < dt_start:
        diff_sec = (dt_start - dt_art).total_seconds()
    else:
        diff_sec = (dt_art - dt_end).total_seconds()

    diff_hours = diff_sec / 3600.0
    score = math.exp(-decay_lambda * diff_hours)
    score_0_1 = max(0.01, min(0.99, round(score, 4)))
    return TemporalResult(score_0_1, f"Outside incident window by {diff_hours:.2f} hours (exponential decay applied)")


# ---------------------------------------------------------------------------
# Uniqueness & Fuzzy Hash Matching Engine
# ---------------------------------------------------------------------------
class UniquenessResult(tuple):
    """Dual-access result: can be unpacked as (score, is_dup, cluster_id, ratio) or accessed as dict."""
    def __new__(cls, score: float, is_dup: bool, cluster_id: Any, ratio: float):
        return super(UniquenessResult, cls).__new__(cls, (score, is_dup, cluster_id, ratio))

    @property
    def uniqueness_score(self):
        return self[0]

    @property
    def is_duplicate(self):
        return self[1]

    @property
    def cluster_id(self):
        return self[2]

    @property
    def duplication_ratio(self):
        return self[3]

    def get(self, key, default=None):
        if key == "uniqueness_score":
            return self[0]
        elif key == "is_duplicate":
            return self[1]
        elif key == "cluster_id":
            return self[2]
        elif key in ("duplication_ratio", "similarity"):
            return self[3]
        elif key == "explanation":
            return f"Cluster duplication ratio is {self[3] * 100:.1f}% (U = {self[0]:.2f})"
        return default

    def __getitem__(self, item):
        if isinstance(item, str):
            val = self.get(item)
            if val is not None:
                return val
            raise KeyError(item)
        return super().__getitem__(item)


def calculate_uniqueness_score(
    artifact_hash: str = "",
    cluster_members: Optional[List[Any]] = None,
    duplication_ratio: Optional[float] = None,
    is_duplicate: bool = False,
    ssdeep_similarity: float = 0.0
) -> UniquenessResult:
    """
    Computes uniqueness score U in [0.0, 1.0].
    Returns UniquenessResult unpackable as (score, is_dup, cluster_id, ratio) or as dict.
    """
    members = cluster_members if cluster_members is not None else []

    if duplication_ratio is not None:
        ratio = float(duplication_ratio)
        is_dup = ratio > 0.0 or len(members) > 1
        score = max(0.0, min(1.0, round(1.0 - ratio, 4)))
        cluster_id = f"cluster_{artifact_hash[:8]}" if is_dup else None
        return UniquenessResult(score, is_dup, cluster_id, ratio)

    if is_duplicate:
        return UniquenessResult(0.0, True, f"cluster_{artifact_hash[:8]}", 1.0)

    if ssdeep_similarity > 0.90:
        return UniquenessResult(0.10, True, f"cluster_{artifact_hash[:8]}", round(ssdeep_similarity, 3))
    elif ssdeep_similarity > 0.70:
        return UniquenessResult(0.20, False, None, round(ssdeep_similarity, 3))
    elif ssdeep_similarity > 0.40:
        return UniquenessResult(0.55, False, None, round(ssdeep_similarity, 3))

    return UniquenessResult(1.0, False, None, 0.0)


# ---------------------------------------------------------------------------
# Evidence Relevance Engine
# ---------------------------------------------------------------------------
def calculate_evidence_relevance(
    ioc_summary: Dict[str, Any],
    has_breach_window: bool = False,
    matched_indicators: Optional[List[Dict[str, Any]]] = None,
    case_keywords: Optional[List[str]] = None
) -> float:
    """Calculates evidence relevance score from 0.0 to 100.0."""
    score = 20.0

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

    if matched_indicators:
        for ind in matched_indicators:
            strength = ind.get("strength", 0.5)
            score += strength * 5.0

    return min(100.0, score)


def calculate_rarity_score(mime_type: str, entropy: float) -> float:
    """Calculates rarity score based on format and entropy distribution."""
    score = 50.0
    if entropy > 7.5 or entropy < 0.5:
        score += 25.0
    if mime_type in ("application/x-sqlite3", "application/x-dosexec", "application/x-elf"):
        score += 20.0
    elif mime_type == "text/plain":
        score -= 10.0
    return max(10.0, min(100.0, score))


# ---------------------------------------------------------------------------
# Priority Score Computation & Explainability
# ---------------------------------------------------------------------------
def calculate_priority_score(
    integrity: float = 0.0,
    relevance: float = 0.0,
    temporal: float = 0.0,
    uniqueness: float = 0.0,
    noise: float = 0.0,
    weights: Optional[Dict[str, float]] = None
) -> float:
    """
    Direct mathematical evaluation of the Priority Equation:
    P = w1*I + w2*R + w3*T + w4*U - w5*N
    """
    w = weights or DEFAULT_WEIGHTS
    w1 = w.get("w1_integrity", w.get("integrity", 0.30))
    w2 = w.get("w2_relevance", w.get("relevance", 0.35))
    w3 = w.get("w3_temporal", w.get("temporal", 0.20))
    w4 = w.get("w4_uniqueness", w.get("uniqueness", 0.15))
    w5 = w.get("w5_noise", w.get("noise_penalty", w.get("noise", 0.10)))

    # Normalize inputs to 0-1 scale if passed in 0-100 scale
    I = integrity / 100.0 if integrity > 1.0 else max(0.0, min(1.0, integrity))
    R = relevance / 100.0 if relevance > 1.0 else max(0.0, min(1.0, relevance))
    T = temporal / 100.0 if temporal > 1.0 else max(0.0, min(1.0, temporal))
    U = uniqueness / 100.0 if uniqueness > 1.0 else max(0.0, min(1.0, uniqueness))
    N = noise / 100.0 if noise > 1.0 else max(0.0, min(1.0, noise))

    raw_p = (w1 * I) + (w2 * R) + (w3 * T) + (w4 * U) - (w5 * N)
    return max(0.0, min(1.0, round(raw_p, 4)))


def compute_priority_score(
    relevance_score: float = 50.0,
    integrity_score: float = 50.0,
    temporal_score: float = 75.0,
    rarity_score: float = 50.0,
    uniqueness_score: Optional[float] = None,
    noise_penalty: float = 0.0,
    classification_confidence: float = 85.0,
    custom_weights: Optional[Dict[str, float]] = None,
    evidence_indicators: Optional[List[Dict[str, Any]]] = None,
    filename: str = ""
) -> Dict[str, Any]:
    """
    Computes transparent weighted priority score and maps to tier.
    Formula:
        P = w1*I + w2*R + w3*T + w4*U - w5*N
    """
    I = integrity_score / 100.0 if integrity_score > 1.0 else max(0.0, min(1.0, integrity_score))
    R = relevance_score / 100.0 if relevance_score > 1.0 else max(0.0, min(1.0, relevance_score))
    T = temporal_score / 100.0 if temporal_score > 1.0 else max(0.0, min(1.0, temporal_score))

    if uniqueness_score is not None:
        U = uniqueness_score / 100.0 if uniqueness_score > 1.0 else max(0.0, min(1.0, uniqueness_score))
    else:
        U = rarity_score / 100.0 if rarity_score > 1.0 else max(0.0, min(1.0, rarity_score))

    N = noise_penalty / 100.0 if noise_penalty > 1.0 else max(0.0, min(1.0, noise_penalty))

    weights = custom_weights or DEFAULT_WEIGHTS
    w_integ = weights.get("w1_integrity", weights.get("integrity", DEFAULT_WEIGHTS["integrity"]))
    w_rel = weights.get("w2_relevance", weights.get("relevance", weights.get("evidence_relevance", DEFAULT_WEIGHTS["relevance"])))
    w_temp = weights.get("w3_temporal", weights.get("temporal", weights.get("temporal_decay", DEFAULT_WEIGHTS["temporal"])))
    w_uniq = weights.get("w4_uniqueness", weights.get("uniqueness", weights.get("rarity", DEFAULT_WEIGHTS["uniqueness"])))
    w_noise = weights.get("w5_noise", weights.get("noise_penalty", DEFAULT_WEIGHTS["noise_penalty"]))

    score_0_1 = calculate_priority_score(I, R, T, U, N, weights)
    score_100 = round(score_0_1 * 100.0, 1)

    tier_raw = classify_priority_tier(score_0_1)
    tier_upper = tier_raw.upper()
    tier_title = tier_raw.title()

    conf_norm = classification_confidence / 100.0 if classification_confidence > 1.0 else classification_confidence
    review_required = conf_norm < 0.60

    reasons = []
    if R >= 0.85:
        reasons.append("High investigative relevance with identified attack/extortion indicators")
    elif R >= 0.60:
        reasons.append("Moderate investigative relevance matching case context")

    if T >= 0.90:
        reasons.append("Falls inside or in immediate temporal proximity to confirmed incident breach window")

    if U >= 0.85:
        reasons.append("Unique artifact with no duplicates in the evidence corpus")
    elif U <= 0.20:
        reasons.append("Duplicated across multiple sectors/copies; uniqueness discounted")

    if I >= 0.85:
        reasons.append("High data integrity verified by format-specific parsers")
    elif I <= 0.40:
        reasons.append("Corrupted structural regions detected; manual recovery carving advised")

    if N >= 0.50:
        reasons.append(f"Noise deduction applied (-{w_noise * N * 100:.1f} pts) due to system junk location")

    if review_required:
        reasons.append(f"Classification confidence ({conf_norm * 100:.0f}%) is below 60% threshold; requires manual analyst verification")

    if not reasons:
        reasons.append(f"Balanced scoring across standard forensic dimensions placed artifact in {tier_title} tier")

    return {
        "priority_score": score_100,
        "score": round(score_0_1, 3),
        "priority_tier": tier_title,
        "tier": tier_upper,
        "reasons": reasons,
        "review_required": review_required,
        "reviewRequired": review_required,
        "weights": {
            "w1_integrity": w_integ,
            "w2_relevance": w_rel,
            "w3_temporal": w_temp,
            "w4_uniqueness": w_uniq,
            "w5_noise": w_noise,
            "integrity": w_integ,
            "relevance": w_rel,
            "temporal": w_temp,
            "uniqueness": w_uniq,
            "noise_penalty": w_noise,
        },
        "breakdown": {
            "I": round(I, 3),
            "R": round(R, 3),
            "T": round(T, 3),
            "U": round(U, 3),
            "N": round(N, 3),
            "relevance": round(R * 100, 1),
            "integrity": round(I * 100, 1),
            "temporal": round(T * 100, 1),
            "rarity": round(U * 100, 1),
            "uniqueness": round(U * 100, 1),
            "noise": round(N * 100, 1),
            "integrity_contribution": round(w_integ * I, 4),
            "relevance_contribution": round(w_rel * R, 4),
            "temporal_contribution": round(w_temp * T, 4),
            "uniqueness_contribution": round(w_uniq * U, 4),
            "noise_deduction": round(w_noise * N, 4),
            "total_score": round(score_0_1, 4),
        },
        "explanations": reasons,
        "classification_confidence": round(conf_norm * 100, 1)
    }


calculate_priority = compute_priority_score


def recalculate_priorities(artifacts: List[Dict[str, Any]], preset_or_weights: Any) -> List[Dict[str, Any]]:
    """Recalculates priority scores across provided artifacts with custom weights or preset."""
    if isinstance(preset_or_weights, dict) and "weights" in preset_or_weights:
        weights = preset_or_weights["weights"]
    elif isinstance(preset_or_weights, dict):
        weights = preset_or_weights
    else:
        weights = DEFAULT_WEIGHTS

    rescored = []
    for a in artifacts:
        art = dict(a)
        I = art.get("integrity", 0.0)
        R = art.get("relevance", 0.0)
        T = art.get("temporal", 0.0)
        U = art.get("uniqueness", 0.0)
        N = art.get("noise", 0.0)
        score = calculate_priority_score(I, R, T, U, N, weights)
        tier = classify_priority_tier(score)
        art["priority"] = {
            "score": score,
            "tier": tier,
            "weights": weights
        }
        rescored.append(art)
    return rescored

