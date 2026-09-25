"""
cli/samdhan_cli.py
==================
SAMDHAN AI — Command-Line Interface for Forensic Evidence Assessment.

Commands:
  assess <file>   - Comprehensive forensic analysis of a single file
  demo            - Evaluates all fixtures in /sample_data and displays results table
"""

import os
import sys
import time
from pathlib import Path
from typing import Dict, List, Any

# Ensure project root is in sys.path
CURRENT_DIR = Path(__file__).resolve().parent
ROOT_DIR = CURRENT_DIR.parent if CURRENT_DIR.name == "cli" else CURRENT_DIR
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from backend.ingestion import ingest_file
from backend.api import run_full_pipeline
from backend.reconstruct import reassemble_fragments


def format_table_row(cols: List[str], widths: List[int]) -> str:
    """Formats an ASCII table row with padded column widths."""
    parts = []
    for c, w in zip(cols, widths):
        parts.append(str(c)[:w].ljust(w))
    return "| " + " | ".join(parts) + " |"


def print_banner():
    """Prints ASCII banner for SAMDHAN AI."""
    print("=" * 78)
    print("  SAMDHAN AI :: DETERMINISTIC FORENSIC RECOVERY & VERIFICATION ENGINE  ")
    print("  CALMSTACKS HACKATHON // ISO/IEC 27037 FORENSIC SOUNDNESS PROTOCOL     ")
    print("=" * 78)


def cmd_assess(file_path_str: str):
    """Assesses a single file and prints detailed forensic report."""
    target_path = Path(file_path_str).resolve()
    if not target_path.exists():
        print(f"[-] Error: File not found: {file_path_str}")
        sys.exit(1)

    print_banner()
    print(f"[*] Ingesting target bitstream: {target_path.name}")
    start_time = time.perf_counter()

    # Ingestion & clone
    ingest_res = ingest_file(target_path)
    raw_bytes = ingest_res["raw_bytes"]
    sha256 = ingest_res["sha256"]

    # Full pipeline
    report = run_full_pipeline(raw_bytes, target_path.name)
    elapsed = (time.perf_counter() - start_time) * 1000

    integ = report["integrity"]
    vec = integ["vector"]
    decision = report["decision"]
    prio = report["priority"]
    sec = report["security"]
    anom = report["anomaly"]
    cls = report["classification"]

    print("\n" + "-" * 78)
    print("  FORENSIC INGESTION & EVIDENCE RECORD")
    print("-" * 78)
    print(f"  Artifact ID        : {ingest_res['artifact_id']}")
    print(f"  Filename           : {ingest_res['filename']}")
    print(f"  Size (Bytes)       : {ingest_res['size_bytes']:,}")
    print(f"  SHA-256 Bitstream  : {sha256}")
    print(f"  Immutable Clone    : {ingest_res['clone_path']}")

    print("\n" + "-" * 78)
    print("  4-VECTOR DATA INTEGRITY ASSESSMENT")
    print("-" * 78)
    print(f"  Detected Format    : {integ['format']}")
    print(f"  Structural Vector  : {vec['structural']:>5.1f} / 100.0")
    print(f"  Content Vector     : {vec['content']:>5.1f} / 100.0")
    print(f"  Metadata Vector    : {vec['metadata']:>5.1f} / 100.0")
    print(f"  Continuity Vector  : {vec['continuity']:>5.1f} / 100.0")
    print(f"  Composite Score    : {integ['composite_score']:>5.1f} / 100.0")

    corruptions = integ.get("corruption_ranges", [])
    if corruptions:
        print(f"\n  [!] Flagged Corruption Ranges ({len(corruptions)} total):")
        for cr in corruptions[:5]:
            print(f"      - Offsets [{cr['start']:>6} .. {cr['end']:>6}] [{cr['severity']}] {cr['description']}")
    else:
        print("  [+] No byte-level structural corruptions detected.")

    print("\n" + "-" * 78)
    print("  SECURITY & ANOMALY ANALYSIS")
    print("-" * 78)
    print(f"  Shannon Entropy    : Mean {anom['mean_entropy']:.2f}, Max {anom['max_entropy']:.2f} bits/byte")
    print(f"  Disguise Mismatch  : {'YES [CRITICAL]' if sec['mismatch_detected'] else 'None'}")
    print(f"  Security Threat    : {sec['threat_level']}")
    if sec["reasons"]:
        for r in sec["reasons"]:
            print(f"      [SECURITY WARNING] {r}")

    print("\n" + "-" * 78)
    print("  CLASSIFICATION & IOC EXTRACTION")
    print("-" * 78)
    print(f"  MIME Type          : {cls['mime']}")
    iocs = cls.get("iocs", {})
    if iocs.get("ips"):
        print(f"  IP Addresses       : {', '.join(iocs['ips'][:4])}")
    if iocs.get("onion_domains"):
        print(f"  Darknet Endpoints  : {', '.join(iocs['onion_domains'][:3])}")
    if iocs.get("crypto_wallets"):
        print(f"  Crypto Wallets     : {', '.join(iocs['crypto_wallets'][:3])}")
    if iocs.get("attack_keywords"):
        print(f"  Attack Keywords    : {', '.join(iocs['attack_keywords'][:4])}")

    print("\n" + "=" * 78)
    print(f"  PRIORITY TIER      : [{prio['priority_tier'].upper()}] (Score: {prio['priority_score']:.1f}/100)")
    print(f"  DECISION VERDICT   : [{decision['state']}] (Conf: {decision['confidence']:.0%})")
    print(f"  Recommended Action : {decision['action']}")
    print(f"  Analysis Latency   : {elapsed:.2f} ms")
    print("=" * 78 + "\n")


def cmd_demo():
    """Evaluates all sample fixtures in /sample_data and displays results table."""
    sample_dir = ROOT_DIR / "sample_data"
    if not sample_dir.exists():
        print(f"[-] Sample directory not found: {sample_dir}")
        sys.exit(1)

    print_banner()
    print("[*] Running Live Verification Benchmark across /sample_data fixtures...")
    start_total = time.perf_counter()

    col_names = ["File Name", "Size", "Composite", "Priority", "Decision State", "Status"]
    widths = [26, 8, 10, 10, 22, 10]
    sep = "+" + "+".join(["-" * (w + 2) for w in widths]) + "+"

    print("\n" + sep)
    print(format_table_row(col_names, widths))
    print(sep)

    fixtures = sorted([p for p in sample_dir.iterdir() if p.is_file()], key=lambda x: x.name)
    results = []

    for p in fixtures:
        with open(p, "rb") as fh:
            data = fh.read()
        res = run_full_pipeline(data, p.name)
        results.append((p.name, data, res))

        fname = p.name
        size_str = f"{len(data):,} B"
        comp_str = f"{res['integrity']['composite_score']:.1f}%"
        tier_str = res["priority"]["priority_tier"]
        dec_state = res["decision"]["state"]

        status = "[OK]"
        if dec_state == "BLOCKED_SECURITY_RISK":
            status = "[BLOCKED]"
        elif dec_state == "UNRECOVERABLE":
            status = "[UNREC]"
        elif dec_state == "INTEGRITY_VERIFIED":
            status = "[VERIFIED]"
        elif dec_state == "PARTIALLY_RECOVERABLE":
            status = "[PARTIAL]"

        row = [fname, size_str, comp_str, tier_str, dec_state, status]
        print(format_table_row(row, widths))

    print(sep)

    # Demonstrate DAG fragment reassembly on fragment clusters
    frag_files = [f for f in fixtures if "fragment_cluster" in f.name]
    if len(frag_files) >= 2:
        print("\n[*] Demonstrating DAG Fragment Reassembly Engine (reconstruct.py):")
        frags = []
        for i, ff in enumerate(frag_files):
            with open(ff, "rb") as fh:
                frags.append({"id": ff.name, "data": fh.read()})
        reassembly = reassemble_fragments(frags)
        print(f"    - Input Fragments : {len(frags)}")
        print(f"    - Optimal Sequence: {' -> '.join(reassembly['ordered_ids'])}")
        print(f"    - Traversal Conf  : {reassembly['confidence']:.1%}")
        print(f"    - Reassembled Size: {len(reassembly['reassembled_data']):,} bytes")
        for edge in reassembly["edges"]:
            det = edge["details"]
            print(f"      * Edge {edge['from_id']} -> {edge['to_id']}: Score={edge['score']:.3f} | {det.get('pointer_desc', '')}")

    total_time = (time.perf_counter() - start_total) * 1000
    print("\n" + "=" * 78)
    print(f"  Total Benchmark Time : {total_time:.2f} ms ({len(fixtures)} fixtures evaluated)")
    print("  Forensic Audit Trail : Logged to samdhan_integrity.db (ISO/IEC 27037 compliant)")
    print("=" * 78 + "\n")


def main():
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python samdhan_cli.py assess <file_path>")
        print("  python samdhan_cli.py demo")
        sys.exit(0)

    cmd = sys.argv[1].lower()
    if cmd == "assess":
        if len(sys.argv) < 3:
            print("Error: Missing target file path. Usage: python samdhan_cli.py assess <file>")
            sys.exit(1)
        cmd_assess(sys.argv[2])
    elif cmd == "demo":
        cmd_demo()
    else:
        print(f"Unknown command: {cmd}. Available: assess, demo")


if __name__ == "__main__":
    main()
