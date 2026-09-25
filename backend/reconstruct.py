"""
backend/reconstruct.py
======================
SAMDHAN AI — DAG-Based Fragment Reassembly Engine.

Specification:
- Pointer/header linking (PDF obj refs, SQLite page ptrs, structural anchors)
- Bigram byte-transition probability between fragment tail and head
- Shannon entropy delta between fragments (|H_A - H_B|)
- Weighted composite score combining all three signals
- Greedy maximum-weight path traversal across the DAG to reconstruct ordering
"""

import math
import re
from typing import Dict, List, Optional, Tuple, Any


def calculate_shannon_entropy(data: bytes) -> float:
    """Calculates Shannon entropy in bits per byte (0.0 to 8.0)."""
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
    return entropy


def compute_bigram_transition_score(tail_bytes: bytes, head_bytes: bytes) -> float:
    """
    Computes byte-transition continuity across fragment boundary (tail of A -> head of B).
    Evaluates:
    1. Direct boundary byte pair transition plausibility
    2. Character class continuity (ASCII/text, binary, or structured zeroes)
    3. Bigram frequency continuity across the seam
    """
    if not tail_bytes or not head_bytes:
        return 0.5

    t_last = tail_bytes[-1]
    h_first = head_bytes[0]

    # Boundary transition score
    # 1. Text / ASCII continuity (printable -> printable, whitespace, punctuation)
    is_tail_ascii = (32 <= t_last <= 126) or t_last in (9, 10, 13)
    is_head_ascii = (32 <= h_first <= 126) or h_first in (9, 10, 13)

    if is_tail_ascii and is_head_ascii:
        # Common text transitions: word to space, space to word, letter to letter
        if (t_last == 32 and h_first != 32) or (t_last != 32 and h_first == 32):
            text_score = 0.95
        elif t_last in (10, 13):  # newline followed by printable
            text_score = 0.90
        elif (65 <= t_last <= 90 or 97 <= t_last <= 122) and (65 <= h_first <= 90 or 97 <= h_first <= 122):
            text_score = 0.85
        else:
            text_score = 0.75
    else:
        text_score = 0.30

    # 2. Bigram correlation between tail window and head window
    window_tail = tail_bytes[-min(len(tail_bytes), 32):]
    window_head = head_bytes[:min(len(head_bytes), 32)]
    combined = window_tail + window_head

    # Count zero byte continuity or pattern continuity
    tail_zeros = sum(1 for b in window_tail if b == 0) / len(window_tail)
    head_zeros = sum(1 for b in window_head if b == 0) / len(window_head)
    zero_diff = abs(tail_zeros - head_zeros)
    zero_score = max(0.0, 1.0 - zero_diff)

    # Bigram diversity
    bigrams = set(zip(combined[:-1], combined[1:]))
    ratio = len(bigrams) / max(1, len(combined) - 1)
    # Balanced bigram density
    density_score = 0.8 if 0.2 < ratio < 0.9 else 0.5

    return min(1.0, max(0.0, 0.4 * text_score + 0.3 * zero_score + 0.3 * density_score))


def check_pointer_header_link(frag_a: bytes, frag_b: bytes) -> Tuple[float, str]:
    """
    Checks for structural pointer / header references linking Frag A to Frag B.
    - PDF: obj number definitions & references (e.g. '1 0 R' referencing '1 0 obj')
    - SQLite: page pointer structures or table header pointers
    - JPEG: sequential markers (e.g., SOF0 -> DHT -> SOS)
    - JSON / Text: open/close bracket balancing or keyword chaining
    """
    # 1. PDF object references
    try:
        text_a = frag_a.decode("latin-1", errors="ignore")
        text_b = frag_b.decode("latin-1", errors="ignore")

        # Check if fragment A contains reference `X 0 R` and fragment B defines `X 0 obj`
        ref_matches = re.findall(r"(\d+)\s+0\s+R", text_a[-256:])
        obj_matches = re.findall(r"(\d+)\s+0\s+obj", text_b[:256])
        for ref in ref_matches:
            if ref in obj_matches:
                return 1.0, f"PDF Object Ref Link: obj {ref} 0 R -> {ref} 0 obj"

        # Check PDF stream continuity
        if "stream" in text_a[-128:] and "endstream" in text_b[:256]:
            return 0.90, "PDF stream to endstream link"

        if "/Pages" in text_a and "/Count" in text_b:
            return 0.85, "PDF Pages catalog dictionary link"
    except Exception:
        pass

    # 2. SQLite page pointer check
    if len(frag_a) >= 16 and len(frag_b) >= 4:
        # SQLite page headers: page 1 starts with "SQLite format 3\000"
        if frag_a.startswith(b"SQLite format 3\x00"):
            # Frag B starts with btree page header (0x02, 0x05, 0x0a, 0x0d)
            if frag_b[0] in (0x02, 0x05, 0x0A, 0x0D):
                return 0.95, f"SQLite Root to B-Tree Page Link (page_type=0x{frag_b[0]:02x})"

        # Pointer array link: check 2-byte cell pointers
        if frag_a[-2:] != b"\x00\x00" and frag_b[0] in (0x05, 0x0D):
            return 0.70, "SQLite sequential page transition"

    # 3. JPEG marker sequence
    if b"\xff\xd8" in frag_a:  # SOI in A
        if b"\xff\xc0" in frag_b or b"\xff\xc4" in frag_b or b"\xff\xdb" in frag_b:
            return 0.90, "JPEG SOI -> SOF/DHT header sequence"
    if b"\xff\xda" in frag_a and b"\xff\xd9" in frag_b:  # SOS in A -> EOI in B
        return 0.95, "JPEG SOS scan payload -> EOI terminator link"

    # 4. Text / Structure keyword continuity
    try:
        lower_a = text_a[-64:].strip()
        lower_b = text_b[:64].strip()
        if lower_a.endswith(("{", "[", "(", ",", "=", ":")) or lower_b.startswith(("}", "]", ")", ";")):
            return 0.80, "Syntax punctuation continuity link"
    except Exception:
        pass

    return 0.10, "No explicit pointer link detected"


def compute_fragment_affinity(
    frag_a: bytes,
    frag_b: bytes,
    w_ptr: float = 0.45,
    w_bigram: float = 0.35,
    w_entropy: float = 0.20
) -> Dict[str, Any]:
    """
    Computes weighted affinity score for edge (Frag A -> Frag B).
    Combines:
    - Pointer/Header linking score
    - Bigram transition probability
    - Shannon entropy delta (|H_A - H_B|)
    """
    # 1. Pointer link
    ptr_score, ptr_desc = check_pointer_header_link(frag_a, frag_b)

    # 2. Bigram transition
    tail = frag_a[-64:] if len(frag_a) >= 64 else frag_a
    head = frag_b[:64] if len(frag_b) >= 64 else frag_b
    bigram_score = compute_bigram_transition_score(tail, head)

    # 3. Entropy delta
    h_a = calculate_shannon_entropy(frag_a)
    h_b = calculate_shannon_entropy(frag_b)
    delta_h = abs(h_a - h_b)
    # 0 delta is best, 8.0 delta is worst
    entropy_score = max(0.0, 1.0 - (delta_h / 4.0))

    composite_score = (w_ptr * ptr_score) + (w_bigram * bigram_score) + (w_entropy * entropy_score)

    return {
        "score": round(composite_score, 4),
        "pointer_score": round(ptr_score, 4),
        "pointer_desc": ptr_desc,
        "bigram_score": round(bigram_score, 4),
        "entropy_score": round(entropy_score, 4),
        "entropy_a": round(h_a, 3),
        "entropy_b": round(h_b, 3),
        "delta_entropy": round(delta_h, 3),
    }


def reassemble_fragments(fragments: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    DAG-based fragment reassembly using greedy maximum-weight path.
    Each item in fragments must have:
      - 'id': str or int identifier
      - 'data': bytes
      - optional 'label': str

    Returns:
      - 'ordered_ids': list of fragment ids in optimal sequence
      - 'reassembled_data': concatenated bytes
      - 'confidence': average transition confidence
      - 'edges': details of each selected transition
    """
    n = len(fragments)
    if n == 0:
        return {"ordered_ids": [], "reassembled_data": b"", "confidence": 0.0, "edges": []}
    if n == 1:
        return {
            "ordered_ids": [fragments[0]["id"]],
            "reassembled_data": fragments[0]["data"],
            "confidence": 1.0,
            "edges": [],
        }

    # Build affinity matrix (DAG edges)
    # affinity[i][j] = score for placing fragment i before fragment j
    aff_matrix = {}
    details = {}
    for i, fi in enumerate(fragments):
        for j, fj in enumerate(fragments):
            if i == j:
                continue
            res = compute_fragment_affinity(fi["data"], fj["data"])
            aff_matrix[(i, j)] = res["score"]
            details[(i, j)] = res

    # Find starting node: node with highest score as source and lowest inbound score,
    # or starting signatures (e.g. PDF %PDF-, JPEG \xFF\xD8, SQLite "SQLite format 3")
    start_scores = [0.0] * n
    for i, fi in enumerate(fragments):
        data = fi["data"]
        # Magic bytes priority for start
        if data.startswith(b"%PDF-") or data.startswith(b"\xff\xd8\xff") or data.startswith(b"SQLite format 3"):
            start_scores[i] += 10.0
        elif data.startswith(b"PK\x03\x04") or data.startswith(b"\x89PNG\r\n\x1a\n"):
            start_scores[i] += 10.0

        # Outbound vs Inbound score differential
        out_sum = sum(aff_matrix.get((i, j), 0) for j in range(n) if j != i)
        in_sum = sum(aff_matrix.get((j, i), 0) for j in range(n) if j != i)
        start_scores[i] += (out_sum - in_sum)

    current_idx = int(max(range(n), key=lambda idx: start_scores[idx]))
    visited = {current_idx}
    path = [current_idx]
    edge_details = []

    # Greedy max-weight path traversal
    while len(visited) < n:
        best_next = None
        best_score = -1.0
        for cand in range(n):
            if cand not in visited:
                score = aff_matrix.get((current_idx, cand), 0.0)
                if score > best_score:
                    best_score = score
                    best_next = cand

        if best_next is None:
            # Fallback to remaining
            remaining = [idx for idx in range(n) if idx not in visited]
            best_next = remaining[0]
            best_score = aff_matrix.get((current_idx, best_next), 0.0)

        edge_info = details.get((current_idx, best_next), {
            "score": best_score,
            "pointer_desc": "Fallback sequence"
        })
        edge_details.append({
            "from_id": fragments[current_idx]["id"],
            "to_id": fragments[best_next]["id"],
            "score": edge_info.get("score", best_score),
            "details": edge_info
        })
        visited.add(best_next)
        path.append(best_next)
        current_idx = best_next

    ordered_ids = [fragments[i]["id"] for i in path]
    reassembled_bytes = b"".join(fragments[i]["data"] for i in path)
    avg_conf = (
        sum(e["score"] for e in edge_details) / len(edge_details)
        if edge_details else 1.0
    )

    return {
        "ordered_ids": ordered_ids,
        "reassembled_data": reassembled_bytes,
        "confidence": round(avg_conf, 4),
        "edges": edge_details,
    }
