#!/usr/bin/env python3
"""
generate_fragments.py
=====================
SAMDHAN AI — Sample Fragment Generator for Forensic Reassembly Demo.

Takes any real file (e.g. JPEG, PDF, PNG, DOCX, ZIP) and deliberately:
1. Chops the binary bitstream into discrete fragment chunks (simulating disk clusters/sectors).
2. Shuffles the fragments to simulate out-of-order unallocated disk cluster recovery.
3. Saves raw .bin / .dat files into the target fragments folder.
4. Generates a ground_truth.json file to verify 100% hash matching after reconstruction.

Usage:
  python generate_fragments.py
  python generate_fragments.py --input sample_data/intact_evidence.jpg --output fragments/
  python generate_fragments.py --input sample_data/intact_evidence.jpg sample_data/intact_report.pdf --output sample_fragments/
  python generate_fragments.py --chunk-size 1024 --mode cluster
"""

import argparse
import hashlib
import json
import os
import random
import shutil
import sys
from pathlib import Path
from typing import List, Dict, Any


def print_banner():
    print("=" * 78)
    print("  SAMDHAN AI :: DISK CLUSTER & FILE FRAGMENT GENERATOR  ")
    print("  Simulating Unallocated Sector Recovery for Forensic Reassembly  ")
    print("=" * 78)


def generate_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def slice_file(
    file_path: Path,
    chunk_size: int = 1024,
    variable_size: bool = False
) -> List[Dict[str, Any]]:
    """
    Slices a file into chunks, recording original offset, length, and hash.
    If a file is smaller than chunk_size, dynamically partitions it into 2-3 fragments
    so it has genuine Header, Body, and Footer pieces for realistic forensic demo.
    """
    raw_data = file_path.read_bytes()
    file_sha256 = generate_sha256(raw_data)
    total_size = len(raw_data)

    # Dynamic partition if file is smaller than chunk_size
    effective_chunk_size = chunk_size
    if total_size <= chunk_size:
        # Split into 3 parts (Header, Body, Footer)
        effective_chunk_size = max(64, total_size // 3)

    fragments = []
    offset = 0
    seq = 0

    while offset < total_size:
        if variable_size:
            remaining = total_size - offset
            current_chunk = min(remaining, random.choice([512, 1024, 1536, 2048]))
        else:
            current_chunk = min(effective_chunk_size, total_size - offset)

        chunk_bytes = raw_data[offset : offset + current_chunk]
        frag_sha256 = generate_sha256(chunk_bytes)

        fragments.append({
            "seq_index": seq,
            "source_file": file_path.name,
            "source_size": total_size,
            "source_sha256": file_sha256,
            "offset_start": offset,
            "offset_end": offset + len(chunk_bytes),
            "size": len(chunk_bytes),
            "sha256": frag_sha256,
            "data": chunk_bytes,
        })

        offset += current_chunk
        seq += 1

    return fragments


def main():
    parser = argparse.ArgumentParser(
        description="SAMDHAN AI Fragment Generator: chops real files into shuffled cluster fragments."
    )
    parser.add_argument(
        "--input", "-i",
        nargs="+",
        default=None,
        help="Path to one or more files to fragment (default: sample_data/intact_evidence.jpg and intact_report.pdf)"
    )
    parser.add_argument(
        "--output", "-o",
        default="sample_fragments",
        help="Output directory to save fragments (default: sample_fragments)"
    )
    parser.add_argument(
        "--chunk-size", "-c",
        type=int,
        default=1024,
        help="Fragment chunk size in bytes (default: 1024)"
    )
    parser.add_argument(
        "--variable",
        action="store_true",
        help="Use variable cluster chunk sizes (512 - 2048 bytes)"
    )
    parser.add_argument(
        "--mode",
        choices=["cluster", "raw", "hash"],
        default="cluster",
        help="Naming convention: cluster (cluster_00142.bin), raw (frag_001.bin), or hash (chunk_a4f2.bin)"
    )
    parser.add_argument(
        "--clean",
        action="store_true",
        help="Clean output directory before creating fragments"
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Random seed for reproducible shuffling (default: 42)"
    )

    args = parser.parse_args()

    # Determine input files
    target_files: List[Path] = []
    if args.input:
        for inp in args.input:
            p = Path(inp)
            if p.is_file():
                target_files.append(p)
            elif p.is_dir():
                for f in p.glob("*.*"):
                    if f.is_file() and not f.name.endswith((".bin", ".dat", ".json")):
                        target_files.append(f)
    else:
        sample_dir = Path("sample_data")
        default_candidates = [
            sample_dir / "intact_evidence.jpg",
            sample_dir / "intact_report.pdf",
        ]
        for c in default_candidates:
            if c.exists():
                target_files.append(c)

    if not target_files:
        print("[-] Error: No input files found to fragment.")
        print("    Specify files with --input <file1> <file2> or place sample files in sample_data/")
        sys.exit(1)

    output_dir = Path(args.output)
    if args.clean and output_dir.exists():
        shutil.rmtree(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    print_banner()
    print(f"[*] Target output directory : {output_dir.resolve()}")
    print(f"[*] Base fragment chunk size: {args.chunk_size} bytes {'(variable enabled)' if args.variable else ''}")
    print(f"[*] Filename pattern mode   : {args.mode}")
    print(f"[*] Files to shatter        : {len(target_files)}")
    print("-" * 78)

    all_fragments: List[Dict[str, Any]] = []
    file_manifests: Dict[str, Any] = {}

    for fpath in target_files:
        print(f"[*] Ingesting: {fpath.name} ({fpath.stat().st_size:,} bytes)")
        frags = slice_file(fpath, chunk_size=args.chunk_size, variable_size=args.variable)
        print(f"    -> Shattered into {len(frags)} fragments (offsets 0 .. {fpath.stat().st_size:,})")
        print(f"    -> Original SHA-256: {frags[0]['source_sha256']}")
        all_fragments.extend(frags)
        file_manifests[fpath.name] = {
            "original_filename": fpath.name,
            "original_size": fpath.stat().st_size,
            "original_sha256": frags[0]["source_sha256"],
            "fragment_count": len(frags),
            "expected_sequence": [f["sha256"] for f in frags],
        }

    print("-" * 78)
    print(f"[*] Total fragments across all files: {len(all_fragments)}")
    print("[*] Shuffling fragments to simulate out-of-order unallocated sectors...")

    random.seed(args.seed)
    saved_manifest = []
    shuffled_pool = list(all_fragments)
    random.shuffle(shuffled_pool)

    base_cluster = random.randint(1000, 9000)

    curr_cluster = base_cluster
    for idx, frag in enumerate(shuffled_pool):
        if args.mode == "cluster":
            curr_cluster += random.randint(1, 4)
            cluster_num = curr_cluster
            fname = f"cluster_{cluster_num:05d}.bin"
        elif args.mode == "hash":
            fname = f"chunk_{frag['sha256'][:8]}_{idx:02d}.bin"
        else:  # raw
            fname = f"frag_{idx+1:03d}.bin"

        dest_file = output_dir / fname
        dest_file.write_bytes(frag["data"])

        saved_manifest.append({
            "saved_filename": fname,
            "source_file": frag["source_file"],
            "seq_index": frag["seq_index"],
            "offset_start": frag["offset_start"],
            "offset_end": frag["offset_end"],
            "size": frag["size"],
            "sha256": frag["sha256"],
        })

    # Save ground_truth.json
    ground_truth_path = output_dir / "ground_truth.json"
    ground_truth_data = {
        "generator": "SAMDHAN AI Fragment Generator v2.0",
        "total_fragments": len(saved_manifest),
        "chunk_size": args.chunk_size,
        "files": file_manifests,
        "fragments": saved_manifest,
    }
    ground_truth_path.write_text(json.dumps(ground_truth_data, indent=2))

    print(f"[+] Successfully wrote {len(saved_manifest)} fragment files to {output_dir}/")
    print(f"[+] Saved Ground Truth verification record: {ground_truth_path}")
    print("-" * 78)
    print("[+] DEMO DATA READY! Now run file reconstruction:")
    print(f"    python reconstruct.py --input {output_dir} --output reconstructed/")
    print("=" * 78)


if __name__ == "__main__":
    main()
