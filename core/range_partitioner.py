"""
core/range_partitioner.py
=========================
Partitions the file's byte stream into disjoint, classified byte regions:
- INTACT
- CORRUPTED
- DAMAGED
- UNKNOWN

Ensures exact byte accounting across [0, file_size) without gaps or fabrications.
"""

from typing import List, Tuple

from core.models import ByteRegion, CorruptionRegion, CorruptionType, RegionClassification


SEVERITY_ORDER = {
    CorruptionType.HEADER_CORRUPTION.value: 10,
    CorruptionType.CRC_FAILURE.value: 9,
    CorruptionType.CHECKSUM_FAILURE.value: 8,
    CorruptionType.TRUNCATION.value: 7,
    CorruptionType.MISSING_TRAILER.value: 6,
    CorruptionType.STRUCTURAL_CORRUPTION.value: 5,
    CorruptionType.ZERO_FILLED_REGION.value: 4,
    CorruptionType.DECODER_FAILURE.value: 3,
    CorruptionType.BYTE_RANGE_ANOMALY.value: 2,
    CorruptionType.UNKNOWN_CORRUPTION.value: 1,
}


def pick_higher_severity_type(type1: str, type2: str) -> str:
    """Returns the corruption type with higher diagnostic severity."""
    s1 = SEVERITY_ORDER.get(type1, 0)
    s2 = SEVERITY_ORDER.get(type2, 0)
    return type1 if s1 >= s2 else type2


def merge_intervals(intervals: List[Tuple[int, int, str, str]]) -> List[Tuple[int, int, str, str]]:
    """
    Merges strictly overlapping byte intervals (cur_start < prev_end).
    Adjacent touching intervals (cur_start == prev_end) remain distinct.
    intervals: list of (start, end, type, reason)
    """
    if not intervals:
        return []

    # Sort by start offset, then by end offset
    sorted_int = sorted(intervals, key=lambda x: (x[0], x[1]))
    merged = [sorted_int[0]]

    for current in sorted_int[1:]:
        prev_start, prev_end, prev_type, prev_reason = merged[-1]
        cur_start, cur_end, cur_type, cur_reason = current

        if cur_start < prev_end:  # Strictly overlapping
            new_end = max(prev_end, cur_end)
            new_type = pick_higher_severity_type(prev_type, cur_type)
            new_reason = prev_reason if prev_reason == cur_reason else f"{prev_reason}; {cur_reason}"
            merged[-1] = (prev_start, new_end, new_type, new_reason)
        else:
            merged.append(current)

    return merged


def partition_byte_ranges(
    file_size: int,
    corruption_regions: List[CorruptionRegion],
    known_intact: List[ByteRegion],
    known_damaged: List[ByteRegion],
) -> Tuple[List[ByteRegion], List[ByteRegion], List[CorruptionRegion]]:
    """
    Partitions [0, file_size) into verified INTACT, CORRUPTED, and DAMAGED byte ranges.
    Returns (intact_regions, damaged_regions, consolidated_corruption_regions).
    """
    if file_size <= 0:
        return [], [], []

    # Extract all corruption spans
    raw_spans = [
        (c.start_offset, min(c.end_offset, file_size), c.type, c.reason)
        for c in corruption_regions
        if c.start_offset < file_size
    ]

    merged_corrupt_spans = merge_intervals(raw_spans)

    consolidated_corrupt: List[CorruptionRegion] = []
    for s, e, c_type, c_reason in merged_corrupt_spans:
        length = e - s
        if length > 0:
            consolidated_corrupt.append(CorruptionRegion(
                start_offset=s,
                end_offset=e,
                length=length,
                type=c_type,
                reason=c_reason,
                severity="critical" if "HEADER" in c_type else ("high" if "CRC" in c_type or "TRUNC" in c_type else "medium"),
            ))

    # Build complement non-corrupted spans
    non_corrupt_spans: List[Tuple[int, int]] = []
    curr = 0
    for s, e, _, _ in merged_corrupt_spans:
        if s > curr:
            non_corrupt_spans.append((curr, s))
        curr = max(curr, e)
    if curr < file_size:
        non_corrupt_spans.append((curr, file_size))

    # Classify non-corrupted spans
    final_intact: List[ByteRegion] = []
    final_damaged: List[ByteRegion] = []

    # Map known damaged spans
    damaged_intervals = [(d.start, min(d.end, file_size)) for d in known_damaged if d.start < file_size]

    for span_start, span_end in non_corrupt_spans:
        span_len = span_end - span_start
        if span_len <= 0:
            continue

        # Check if span overlaps with any known damaged region
        is_damaged = any(not (span_end <= ds or span_start >= de) for ds, de in damaged_intervals)

        if is_damaged:
            final_damaged.append(ByteRegion(
                start=span_start,
                end=span_end,
                length=span_len,
                status=RegionClassification.DAMAGED,
                type="ADJACENT_DAMAGE",
                description="Damaged or unparseable byte range following corruption",
            ))
        else:
            final_intact.append(ByteRegion(
                start=span_start,
                end=span_end,
                length=span_len,
                status=RegionClassification.INTACT,
                description="Verified intact byte stream",
            ))

    return final_intact, final_damaged, consolidated_corrupt
