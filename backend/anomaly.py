"""
backend/anomaly.py
==================
SAMDHAN AI — Sliding-Window Shannon Entropy & IsolationForest Anomaly Detection.

Specification:
- Sliding-window Shannon entropy calculation across bitstream
- IsolationForest (scikit-learn) over byte-frequency and statistical features:
  - Entropy (0.0 to 8.0)
  - Null byte density (0x00)
  - Printable ASCII ratio (0x20 - 0x7E)
  - High byte ratio (0x80 - 0xFF)
  - Byte value standard deviation
- Flags suspicious regions (e.g. encrypted/packed payloads, wipe pockets, anomalous spikes)
"""

import math
import numpy as np
from typing import Dict, List, Optional, Tuple, Any

try:
    from sklearn.ensemble import IsolationForest
except ImportError:
    IsolationForest = None


def compute_entropy_for_window(window: bytes) -> float:
    """Calculates Shannon entropy for a given byte window."""
    if not window:
        return 0.0
    freq = [0] * 256
    for b in window:
        freq[b] += 1
    total = len(window)
    entropy = 0.0
    for count in freq:
        if count > 0:
            p = count / total
            entropy -= p * math.log2(p)
    return entropy


def extract_window_features(window: bytes) -> List[float]:
    """
    Extracts 5 statistical and frequency features from a byte window:
    [entropy, null_ratio, printable_ratio, high_byte_ratio, byte_std_dev]
    """
    w_len = len(window)
    if w_len == 0:
        return [0.0, 0.0, 0.0, 0.0, 0.0]

    entropy = compute_entropy_for_window(window)
    null_count = sum(1 for b in window if b == 0)
    printable_count = sum(1 for b in window if (32 <= b <= 126) or b in (9, 10, 13))
    high_count = sum(1 for b in window if b >= 128)

    arr = np.frombuffer(window, dtype=np.uint8)
    std_dev = float(np.std(arr)) if len(arr) > 0 else 0.0

    return [
        entropy,
        null_count / w_len,
        printable_count / w_len,
        high_count / w_len,
        std_dev
    ]


def detect_anomalies(
    data: bytes,
    window_size: int = 512,
    step_size: int = 128,
    contamination: float = 0.08
) -> Dict[str, Any]:
    """
    Scans data with sliding window and flags anomalous blocks using IsolationForest
    and heuristic threshold rules.
    """
    size = len(data)
    if size == 0:
        return {
            "total_bytes": 0,
            "mean_entropy": 0.0,
            "max_entropy": 0.0,
            "anomalous_regions": [],
            "anomaly_ratio": 0.0,
            "status": "EMPTY"
        }

    # Dynamic window adjustment for small files
    effective_window = min(window_size, max(32, size // 2)) if size < window_size else window_size
    effective_step = min(step_size, max(16, effective_window // 4))

    windows = []
    features = []
    offsets = []

    pos = 0
    while pos < size:
        chunk = data[pos:pos + effective_window]
        if len(chunk) < 16:  # ignore tiny trailing crumbs
            break
        windows.append(chunk)
        offsets.append((pos, pos + len(chunk)))
        features.append(extract_window_features(chunk))
        pos += effective_step

    if not features:
        # Fallback for small single block
        features = [extract_window_features(data)]
        offsets = [(0, size)]

    entropies = [f[0] for f in features]
    mean_entropy = float(np.mean(entropies))
    max_entropy = float(np.max(entropies))

    # IsolationForest ML Outlier Detection
    clf_predictions = [1] * len(features)
    anomaly_scores = [0.0] * len(features)

    if IsolationForest and len(features) >= 4:
        try:
            X = np.array(features)
            # Ensure valid variance before fitting
            if np.std(X) > 1e-4:
                clf = IsolationForest(
                    contamination=min(0.2, max(0.02, contamination)),
                    random_state=42,
                    n_estimators=50
                )
                clf.fit(X)
                clf_predictions = clf.predict(X)  # -1 for anomaly, 1 for normal
                anomaly_scores = clf.decision_function(X)  # lower = more anomalous
        except Exception:
            pass

    # Flag regions
    flagged_regions = []
    for idx, (feat, (start, end)) in enumerate(zip(features, offsets)):
        ent, null_r, print_r, high_r, std_d = feat
        reasons = []
        severity = "LOW"

        # 1. High entropy payload (possible encrypted / compressed / packed malware)
        if ent > 7.6:
            reasons.append(f"High entropy packed/encrypted payload (H={ent:.2f} > 7.6)")
            severity = "HIGH"
        elif ent > 7.2:
            reasons.append(f"Elevated entropy block (H={ent:.2f})")
            severity = "MEDIUM"

        # 2. Null fill / wipe pocket
        if null_r > 0.95:
            reasons.append(f"Zero-fill wipe cavity ({null_r:.1%} nulls)")
            severity = "CRITICAL" if null_r > 0.99 else "HIGH"

        # 3. Isolation Forest ML Outlier
        if clf_predictions[idx] == -1 and not reasons:
            reasons.append(f"Statistical byte distribution anomaly (IF score={anomaly_scores[idx]:.3f})")
            severity = "MEDIUM"

        if reasons:
            flagged_regions.append({
                "start": start,
                "end": end,
                "length": end - start,
                "entropy": round(ent, 3),
                "null_ratio": round(null_r, 3),
                "severity": severity,
                "reasons": reasons,
            })

    # Merge adjacent flagged regions of same severity
    merged = []
    for r in flagged_regions:
        if merged and merged[-1]["end"] >= r["start"] and merged[-1]["severity"] == r["severity"]:
            merged[-1]["end"] = max(merged[-1]["end"], r["end"])
            merged[-1]["length"] = merged[-1]["end"] - merged[-1]["start"]
            merged[-1]["reasons"] = list(set(merged[-1]["reasons"] + r["reasons"]))
        else:
            merged.append(r)

    total_flagged_bytes = sum(r["length"] for r in merged)
    anomaly_ratio = min(1.0, total_flagged_bytes / max(1, size))

    overall_nulls = data.count(b"\x00")
    overall_null_ratio = overall_nulls / max(1, size)

    return {
        "total_bytes": size,
        "mean_entropy": round(mean_entropy, 3),
        "max_entropy": round(max_entropy, 3),
        "overall_null_ratio": round(overall_null_ratio, 4),
        "anomalous_regions": merged,
        "anomaly_ratio": round(anomaly_ratio, 4),
        "has_high_entropy_packed": any(r.get("entropy", 0) > 7.5 for r in merged),
        "has_zero_wipe": overall_null_ratio >= 0.85 or any(r.get("null_ratio", 0) > 0.90 for r in merged),
    }
