"""
core/block_analyzer.py
======================
Phase 2 Block-Level Analysis Engine.
Divides file into fixed or adaptive analysis blocks and computes byte statistics,
cryptographic hashes, entropy, zero ratio, and corruption status per block.

SAFETY & METHODOLOGY RULES:
- Read-only operations on byte stream.
- Do NOT classify a block as corrupted solely because its entropy differs.
  Entropy is supporting diagnostic evidence only.
- Exact byte offset mapping for every block.
"""

from __future__ import annotations

import hashlib
import math
from typing import Dict, List, Optional

from core.models import BlockAnalysisRecord, CorruptionRegion, RegionClassification


def calculate_shannon_entropy(data_slice: bytes) -> float:
    """Calculates Shannon entropy in bits per byte (0.0 to 8.0)."""
    if not data_slice:
        return 0.0
    length = len(data_slice)
    counts: Dict[int, int] = {}
    for b in data_slice:
        counts[b] = counts.get(b, 0) + 1
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)


def analyze_blocks(
    data: bytes,
    block_size: int = 65536,
    corruption_regions: Optional[List[CorruptionRegion]] = None,
    adaptive_for_small: bool = True,
) -> List[BlockAnalysisRecord]:
    """
    Partitions byte stream into contiguous analysis blocks.
    For files smaller than block_size, adaptively selects a smaller block size
    (e.g., 256, 512, or 1024 bytes) so that meaningful block boundaries are evaluated.
    """
    total_len = len(data)
    if total_len == 0:
        return []

    # Adaptive block size for small files
    effective_block_size = block_size
    if adaptive_for_small and total_len < block_size:
        if total_len <= 1024:
            effective_block_size = max(128, total_len // 4) if total_len >= 256 else total_len
        elif total_len <= 8192:
            effective_block_size = max(512, total_len // 4)
        else:
            effective_block_size = max(1024, total_len // 8)

    effective_block_size = max(1, effective_block_size)

    records: List[BlockAnalysisRecord] = []
    corruption_list = corruption_regions or []

    num_blocks = (total_len + effective_block_size - 1) // effective_block_size

    for idx in range(num_blocks):
        start = idx * effective_block_size
        end = min(start + effective_block_size, total_len)
        block_bytes = data[start:end]
        b_len = len(block_bytes)

        b_sha256 = hashlib.sha256(block_bytes).hexdigest()
        b_entropy = calculate_shannon_entropy(block_bytes)
        zero_count = block_bytes.count(b"\x00")
        b_zero_ratio = round(zero_count / b_len, 4) if b_len > 0 else 0.0

        # Check whether any confirmed corruption region intersects this block
        corrupted = False
        reasons = []
        for cr in corruption_list:
            if max(start, cr.start_offset) < min(end, cr.end_offset):
                corrupted = True
                reasons.append(cr.type)

        if corrupted:
            state = RegionClassification.CORRUPTED
            notes = f"Intersects corruption: {', '.join(set(reasons))}"
        else:
            state = RegionClassification.INTACT
            notes = "No structural corruption detected within block boundary"

        label = f"BLOCK_{idx + 1:03d} -> {state.value}"

        records.append(BlockAnalysisRecord(
            block_index=idx + 1,
            offset_start=start,
            offset_end=end,
            size=b_len,
            sha256=b_sha256,
            entropy=b_entropy,
            zero_ratio=b_zero_ratio,
            state=state,
            label=label,
            notes=notes,
        ))

    return records
