#!/usr/bin/env python3
"""
corrupt_sample.py
=================
SAMDHAN AI — Forensic Corruption Generator for Live Integrity Demos.

Takes any clean file (JPEG, PDF, PNG, etc.) and deliberately injects controlled,
realistic forensic corruptions across specific byte blocks:
1. Zero-Fill / Wipe: Overwrites blocks with 0x00 (simulating unallocated holes or partial wiping).
2. Random Noise: Injects high-entropy pseudo-random bytes (simulating bit-rot or encryption overwrite).
3. Repeating Patterns: Injects fixed byte runs (0xFF, 0xAA, 0x90) (simulating buffer padding or hardware glitch).
4. Header Wipe (optional): Overwrites magic bytes to simulate damaged headers.

Usage:
  python corrupt_sample.py --input sample_data/intact_evidence.jpg --output sample_data/corrupted_evidence.jpg
  python corrupt_sample.py --input sample_data/intact_report.pdf --output sample_data/corrupted_report.pdf --zero-fill 25 --randomize 15
"""

import argparse
import hashlib
import os
import random
import sys
from pathlib import Path
from typing import List, Dict, Any


def print_banner():
    print("=" * 78)
    print("  SAMDHAN AI :: CONTROLLED CORRUPTION SAMPLE GENERATOR  ")
    print("  Creating Before / After Evidence Artifacts for Integrity Demos  ")
    print("=" * 78)


def inject_corruption(
    data: bytearray,
    block_size: int = 512,
    pct_zero: float = 15.0,
    pct_rand: float = 15.0,
    pct_repeat: float = 10.0,
    wipe_header: bool = False,
    wipe_footer: bool = False,
    seed: int = 42,
) -> Tuple[bytearray, List[Dict[str, Any]]]:
    """
    Injects realistic corruptions into specific blocks of the bytearray.
    Returns (corrupted_bytes, corruption_log).
    """
    random.seed(seed)
    total_len = len(data)
    num_blocks = max(1, (total_len + block_size - 1) // block_size)

    # Candidate blocks to corrupt (keep block 0 unless wipe_header is explicitly requested)
    candidate_indices = list(range(1 if not wipe_header else 0, num_blocks - 1 if not wipe_footer else num_blocks))
    random.shuffle(candidate_indices)

    log: List[Dict[str, Any]] = []

    # 1. Header wipe if requested
    if wipe_header and num_blocks > 0:
        end = min(block_size, total_len)
        data[0:end] = b"\x00" * end
        log.append({
            "block_idx": 0,
            "start": 0,
            "end": end,
            "type": "HEADER_WIPE",
            "description": "Magic header zero-wiped (file signature destroyed)",
        })

    # 2. Zero-Fill Blocks
    num_zero_blocks = int(round(num_blocks * (pct_zero / 100.0)))
    zero_targets = [candidate_indices.pop() for _ in range(min(num_zero_blocks, len(candidate_indices)))]
    for idx in zero_targets:
        start = idx * block_size
        end = min(start + block_size, total_len)
        data[start:end] = b"\x00" * (end - start)
        log.append({
            "block_idx": idx,
            "start": start,
            "end": end,
            "type": "ZERO_WIPED",
            "description": f"Sector 0x{start:04X}-0x{end:04X} zero-filled (unallocated sector or wipe)",
        })

    # 3. Random Noise Blocks
    num_rand_blocks = int(round(num_blocks * (pct_rand / 100.0)))
    rand_targets = [candidate_indices.pop() for _ in range(min(num_rand_blocks, len(candidate_indices)))]
    for idx in rand_targets:
        start = idx * block_size
        end = min(start + block_size, total_len)
        random_bytes = bytearray(random.getrandbits(8) for _ in range(end - start))
        data[start:end] = random_bytes
        log.append({
            "block_idx": idx,
            "start": start,
            "end": end,
            "type": "RANDOM_NOISE",
            "description": f"Sector 0x{start:04X}-0x{end:04X} randomized (high entropy noise / ciphertext)",
        })

    # 4. Repeating Pattern Blocks
    num_repeat_blocks = int(round(num_blocks * (pct_repeat / 100.0)))
    repeat_targets = [candidate_indices.pop() for _ in range(min(num_repeat_blocks, len(candidate_indices)))]
    repeat_patterns = [b"\xFF", b"\xAA", b"\x55", b"\x90"]
    for idx in repeat_targets:
        start = idx * block_size
        end = min(start + block_size, total_len)
        pat = random.choice(repeat_patterns)
        data[start:end] = pat * (end - start)
        log.append({
            "block_idx": idx,
            "start": start,
            "end": end,
            "type": "REPEATING_PATTERN",
            "description": f"Sector 0x{start:04X}-0x{end:04X} overwritten with pattern 0x{pat.hex().upper()} (sled / filler)",
        })

    # 5. Footer wipe if requested
    if wipe_footer and num_blocks > 1:
        last_idx = num_blocks - 1
        start = last_idx * block_size
        data[start:total_len] = b"\x00" * (total_len - start)
        log.append({
            "block_idx": last_idx,
            "start": start,
            "end": total_len,
            "type": "FOOTER_WIPE",
            "description": "Terminal EOF marker zero-wiped (truncated file structure)",
        })

    log.sort(key=lambda x: x["start"])
    return data, log


def main():
    parser = argparse.ArgumentParser(
        description="SAMDHAN AI: Deliberately corrupt a file for Data Integrity Assessment demo."
    )
    parser.add_argument(
        "--input", "-i",
        default="sample_data/intact_evidence.jpg",
        help="Input source file path (default: sample_data/intact_evidence.jpg)"
    )
    parser.add_argument(
        "--output", "-o",
        default="sample_data/demo_corrupted_evidence.jpg",
        help="Output corrupted file destination (default: sample_data/demo_corrupted_evidence.jpg)"
    )
    parser.add_argument(
        "--block-size", "-b",
        type=int,
        default=512,
        help="Block size in bytes (default: 512, standard disk sector)"
    )
    parser.add_argument(
        "--zero-fill", "-z",
        type=float,
        default=20.0,
        help="Percentage of blocks to zero-fill (default: 20%%)"
    )
    parser.add_argument(
        "--randomize", "-r",
        type=float,
        default=15.0,
        help="Percentage of blocks to randomize with noise (default: 15%%)"
    )
    parser.add_argument(
        "--repeat-bytes", "-p",
        type=float,
        default=10.0,
        help="Percentage of blocks to fill with repeating byte patterns (default: 10%%)"
    )
    parser.add_argument(
        "--wipe-header",
        action="store_true",
        help="Wipe the header magic bytes (simulating header destruction)"
    )
    parser.add_argument(
        "--wipe-footer",
        action="store_true",
        help="Wipe the footer EOF bytes (simulating truncation)"
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Random seed for reproducible corruption"
    )

    args = parser.parse_args()

    src_path = Path(args.input)
    if not src_path.exists():
        print(f"[-] Error: Source file not found: {src_path.resolve()}")
        sys.exit(1)

    dst_path = Path(args.output)
    dst_path.parent.mkdir(parents=True, exist_ok=True)

    original_bytes = src_path.read_bytes()
    orig_sha256 = hashlib.sha256(original_bytes).hexdigest()
    mutable_bytes = bytearray(original_bytes)

    print_banner()
    print(f"[*] Ingesting Original File: {src_path.name}")
    print(f"    - Size   : {len(original_bytes):,} bytes")
    print(f"    - SHA-256: {orig_sha256}")
    print(f"[*] Applying Forensic Corruptions (Sector Size: {args.block_size} B):")
    print(f"    - Zero-Fill       : {args.zero_fill}%")
    print(f"    - Random Noise    : {args.randomize}%")
    print(f"    - Repeating Filler: {args.repeat_bytes}%")
    print(f"    - Wipe Header     : {args.wipe_header}")
    print(f"    - Wipe Footer     : {args.wipe_footer}")
    print("-" * 78)

    corrupted_bytes, log = inject_corruption(
        data=mutable_bytes,
        block_size=args.block_size,
        pct_zero=args.zero_fill,
        pct_rand=args.randomize,
        pct_repeat=args.repeat_bytes,
        wipe_header=args.wipe_header,
        wipe_footer=args.wipe_footer,
        seed=args.seed,
    )

    dst_path.write_bytes(corrupted_bytes)
    corr_sha256 = hashlib.sha256(corrupted_bytes).hexdigest()

    print(f"[+] Successfully wrote corrupted artifact to: {dst_path}")
    print(f"    - Output Size: {len(corrupted_bytes):,} bytes")
    print(f"    - New SHA-256: {corr_sha256}")
    print(f"    - Sectors Corrupted: {len(log)} / {max(1, (len(original_bytes) + args.block_size - 1) // args.block_size)}")
    print("\n  CORRUPTED SECTOR MAP (GROUND TRUTH):")
    print("  " + "-" * 74)
    print(f"  {'Block':<8} {'Byte Offsets':<20} {'Corruption Type':<20} {'Description'}")
    print("  " + "-" * 74)
    for entry in log:
        offsets = f"0x{entry['start']:04X} - 0x{entry['end']:04X}"
        print(f"  #{entry['block_idx']:<7} {offsets:<20} {entry['type']:<20} {entry['description']}")
    print("  " + "-" * 74)
    print("\n[+] DEMO TIP: Drop this file into the Data Integrity Web Tool to verify detection!")
    print(f"    Target File: {dst_path.resolve()}")
    print("=" * 78)


if __name__ == "__main__":
    main()
