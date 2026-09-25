"""
core/byte_analyzer.py
=====================
Byte-level forensic analysis engine for Feature 02.
Calculates cryptographic hashes, Shannon entropy, zero-fill ratios,
and localizes repeated-byte runs / anomalies without false assertions.
"""

import hashlib
import math
from typing import Any, Dict, List, Optional, Tuple


def calculate_hashes(data: bytes) -> Dict[str, str]:
    """Computes SHA-256 and MD5 hashes over raw byte stream."""
    return {
        "sha256": hashlib.sha256(data).hexdigest(),
        "md5": hashlib.md5(data).hexdigest(),
    }


def calculate_shannon_entropy(data: bytes) -> float:
    """
    Computes Shannon entropy over byte stream.
    Returns float in range [0.0, 8.0].
    """
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    total = len(data)
    entropy = 0.0
    for count in freq:
        if count > 0:
            p = count / total
            entropy -= p * math.log2(p)
    return round(entropy, 4)


def find_repeated_byte_runs(
    data: bytes,
    min_length: int = 128,
    target_bytes: Optional[List[int]] = None
) -> List[Dict[str, Any]]:
    """
    Scans for contiguous runs of identical bytes >= min_length.
    Particularly identifies zero-fill regions (0x00) and fill patterns (0xFF).
    Returns list of dicts with {start, end, length, byte_value, byte_hex}.
    """
    runs = []
    if len(data) < min_length:
        return runs

    current_byte = data[0]
    run_start = 0
    run_len = 1

    for i in range(1, len(data)):
        b = data[i]
        if b == current_byte:
            run_len += 1
        else:
            if run_len >= min_length:
                if target_bytes is None or current_byte in target_bytes:
                    runs.append({
                        "start": run_start,
                        "end": i - 1,
                        "length": run_len,
                        "byte_value": current_byte,
                        "byte_hex": f"{current_byte:02X}",
                    })
            current_byte = b
            run_start = i
            run_len = 1

    # Check terminal run
    if run_len >= min_length:
        if target_bytes is None or current_byte in target_bytes:
            runs.append({
                "start": run_start,
                "end": len(data) - 1,
                "length": run_len,
                "byte_value": current_byte,
                "byte_hex": f"{current_byte:02X}",
            })

    return runs


def analyze_byte_stream(data: bytes, format_hint: Optional[str] = None) -> Dict[str, Any]:
    """
    Performs comprehensive byte-level forensic analysis.
    
    IMPORTANT INVARIANT:
    High entropy is NOT automatically marked as corruption.
    High entropy (7.2 - 8.0) is normal in compressed media (JPEG, PNG, ZIP).
    Low entropy is normal in plaintext/sparse logs.
    Entropy anomalies are interpreted strictly in format context.
    """
    file_size = len(data)
    if file_size == 0:
        return {
            "file_size": 0,
            "sha256": hashlib.sha256(b"").hexdigest(),
            "md5": hashlib.md5(b"").hexdigest(),
            "entropy": 0.0,
            "zero_byte_ratio": 0.0,
            "repeated_runs": [],
            "zero_filled_regions": [],
            "sliding_entropy": [],
            "anomalies": ["FILE_EMPTY"],
        }

    hashes = calculate_hashes(data)
    entropy = calculate_shannon_entropy(data)
    zero_count = data.count(0x00)
    zero_ratio = round(zero_count / file_size, 4)

    # Find repeated runs of 128+ bytes
    all_runs = find_repeated_byte_runs(data, min_length=128)
    zero_runs = [r for r in all_runs if r["byte_value"] == 0x00]

    # Sliding-window entropy (window 512, step 256)
    window_size = 512
    step = 256
    sliding_entropy = []
    anomalies = []

    if file_size >= window_size:
        for offset in range(0, file_size - window_size + 1, step):
            window_data = data[offset:offset + window_size]
            win_ent = calculate_shannon_entropy(window_data)
            sliding_entropy.append({
                "offset": offset,
                "entropy": win_ent,
            })

    # Format-aware anomaly checks
    is_compressed_format = format_hint in ("JPEG", "PNG", "ZIP", "DOCX")
    if is_compressed_format and zero_runs:
        for zr in zero_runs:
            anomalies.append({
                "type": "ZERO_FILLED_REGION",
                "start": zr["start"],
                "end": zr["end"],
                "length": zr["length"],
                "description": f"Unexpected zero-fill run ({zr['length']} bytes) inside compressed {format_hint} stream",
            })

    return {
        "file_size": file_size,
        "sha256": hashes["sha256"],
        "md5": hashes["md5"],
        "entropy": entropy,
        "zero_byte_ratio": zero_ratio,
        "repeated_runs": all_runs,
        "zero_filled_regions": zero_runs,
        "sliding_entropy": sliding_entropy,
        "anomalies": anomalies,
    }
