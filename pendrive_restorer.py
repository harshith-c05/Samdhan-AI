"""
pendrive_restorer.py
====================
SAMDHAN AI Forensic Pendrive Recovery & Integrity Verification Engine.

Reads raw sector data from a physical or mounted USB volume (e.g., \\\\.\\E:),
locates deleted FAT32 directory entries marked with 0xE5 tombstone,
carves the underlying unallocated clusters, reconstructs the file,
and runs full byte-level format integrity assessment.

Safety Contract:
- Strictly READ-ONLY operations on the source drive (mode='rb').
- Restored files are written ONLY to local safe storage.
- Never formats, modifies, repairs, or writes to the USB volume.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import struct
import sys
from pathlib import Path
from typing import Dict, List, Optional

from core.integrity_analyzer import IntegrityAnalyzer


class PendriveRestorer:
    """Forensic FAT32 USB recovery and validation engine."""

    def __init__(self, drive_path: str = r"\\.\E:"):
        self.drive_path = drive_path
        self._fh = None
        self.bytes_per_sec = 512
        self.sec_per_clus = 16
        self.cluster_size = 8192
        self.reserved_sec = 2078
        self.num_fats = 2
        self.fat_size_32 = 15345
        self.root_cluster = 2
        self.data_start_offset = 16777216

    def open(self):
        """Open raw drive handle in strictly READ-ONLY binary mode."""
        self._fh = open(self.drive_path, "rb")
        self._parse_bpb()

    def close(self):
        if self._fh and not self._fh.closed:
            self._fh.close()

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def _parse_bpb(self):
        """Read FAT32 BIOS Parameter Block (Sector 0) to derive volume geometry."""
        self._fh.seek(0)
        boot = self._fh.read(512)
        if len(boot) < 512:
            raise ValueError(f"Unable to read sector 0 from {self.drive_path}")

        magic = boot[510:512]
        if magic != b"\x55\xaa":
            raise ValueError(f"Invalid boot sector magic: {magic.hex()}")

        self.bytes_per_sec = struct.unpack_from("<H", boot, 11)[0]
        self.sec_per_clus = boot[13]
        self.cluster_size = self.bytes_per_sec * self.sec_per_clus
        self.reserved_sec = struct.unpack_from("<H", boot, 14)[0]
        self.num_fats = boot[16]
        self.fat_size_32 = struct.unpack_from("<I", boot, 36)[0]
        self.root_cluster = struct.unpack_from("<I", boot, 44)[0]

        fat_total_bytes = self.num_fats * self.fat_size_32 * self.bytes_per_sec
        reserved_bytes = self.reserved_sec * self.bytes_per_sec
        self.data_start_offset = reserved_bytes + fat_total_bytes

    def cluster_to_byte_offset(self, cluster_num: int) -> int:
        """Convert a FAT32 cluster index (>=2) to absolute volume byte offset."""
        return self.data_start_offset + (cluster_num - 2) * self.cluster_size

    def scan_deleted_files(self) -> List[Dict]:
        """
        Scans root directory cluster for entries where byte 0 == 0xE5 (FAT deletion tombstone).
        Extracts 8.3 filename, starting cluster, and file size.
        """
        root_offset = self.cluster_to_byte_offset(self.root_cluster)
        self._fh.seek(root_offset)
        dir_data = self._fh.read(self.cluster_size)

        deleted_entries = []
        lfn_parts: List[str] = []

        for i in range(0, len(dir_data), 32):
            entry = dir_data[i : i + 32]
            if not entry or len(entry) < 32:
                break
            first_byte = entry[0]
            if first_byte == 0x00:
                break  # End of directory markers

            attr = entry[11]

            # Long File Name (LFN) entry
            if attr == 0x0F:
                # If deleted LFN entry
                if first_byte == 0xE5:
                    # Parse Unicode characters from LFN chunk
                    chars = []
                    for offset in [1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30]:
                        val = struct.unpack_from("<H", entry, offset)[0]
                        if val != 0x0000 and val != 0xFFFF:
                            chars.append(chr(val))
                    lfn_parts.append("".join(chars))
                continue

            # Standard 8.3 Directory Entry
            if first_byte == 0xE5:
                # Deleted entry!
                raw_name = entry[1:8].decode("ascii", errors="replace").strip()
                raw_ext = entry[8:11].decode("ascii", errors="replace").strip()
                short_name = f"{raw_name}.{raw_ext}".lower()

                clus_hi = struct.unpack_from("<H", entry, 20)[0]
                clus_lo = struct.unpack_from("<H", entry, 26)[0]
                cluster = (clus_hi << 16) | clus_lo
                file_size = struct.unpack_from("<I", entry, 28)[0]

                # If we collected LFN parts before this short entry, reconstruct
                if lfn_parts:
                    reconstructed_lfn = "".join(reversed(lfn_parts)).lower()
                else:
                    reconstructed_lfn = short_name

                deleted_entries.append({
                    "dir_offset": root_offset + i,
                    "short_name": short_name,
                    "reconstructed_name": reconstructed_lfn,
                    "cluster": cluster,
                    "size": file_size,
                    "cluster_byte_offset": self.cluster_to_byte_offset(cluster) if cluster >= 2 else 0,
                })
                lfn_parts = []
            else:
                lfn_parts = []

        return deleted_entries

    def restore_file(
        self,
        entry: Dict,
        destination_dir: str,
        expected_sha256: Optional[str] = None,
    ) -> Dict:
        """
        Extracts raw bytes from the deleted file's starting cluster on the drive,
        saves to local destination, and runs forensic IntegrityAnalyzer.
        """
        dest_dir = Path(destination_dir).resolve()
        dest_dir.mkdir(parents=True, exist_ok=True)

        filename = entry.get("reconstructed_name") or entry.get("short_name", "recovered_file.bin")
        clean_filename = Path(filename).name.replace(" ", "_")
        dest_file = dest_dir / f"restored_{clean_filename}"

        cluster = entry["cluster"]
        size = entry["size"]

        if cluster < 2 or size <= 0:
            raise ValueError(f"Invalid cluster ({cluster}) or size ({size}) in entry")

        byte_offset = self.cluster_to_byte_offset(cluster)
        self._fh.seek(byte_offset)
        raw_bytes = self._fh.read(size)

        with open(dest_file, "wb") as f_out:
            f_out.write(raw_bytes)

        computed_sha256 = hashlib.sha256(raw_bytes).hexdigest()

        # Run SAMDHAN AI Feature 02 byte-level integrity assessment
        analyzer = IntegrityAnalyzer()
        assessment = analyzer.analyze(
            artifact=dest_file,
            filename=clean_filename,
            reference_sha256=expected_sha256,
        )

        return {
            "saved_to": str(dest_file),
            "file_size": len(raw_bytes),
            "sha256": computed_sha256,
            "hash_matches_baseline": (computed_sha256.upper() == expected_sha256.upper()) if expected_sha256 else None,
            "integrity_status": assessment.overall_status.value,
            "overall_integrity_score": assessment.scores.overall_score,
            "format": assessment.format,
            "checks_passed": sum(1 for c in assessment.checks if c.status.value == "PASS"),
            "total_checks": len(assessment.checks),
            "recoverability": assessment.recoverability.classification.value,
        }


def main():
    parser = argparse.ArgumentParser(description="SAMDHAN AI Pendrive Recovery Tool")
    parser.add_argument("--drive", default=r"\\.\E:", help="Target raw drive path (e.g. \\\\.\\E:)")
    parser.add_argument("--out", default=r"c:\Samdhan AI\recovered_evidence", help="Output directory")
    parser.add_argument("--pattern", default="", help="Filter deleted filename pattern (e.g. evid or jpg)")
    parser.add_argument("--baseline-hash", default=None, help="Expected pre-deletion SHA-256 for verification")

    args = parser.parse_args()

    print("=" * 70)
    print(" SAMDHAN AI — FORENSIC PENDRIVE RECOVERY & INTEGRITY ENGINE")
    print("=" * 70)
    print(f"Target Volume : {args.drive} (READ-ONLY)")
    print(f"Output Path   : {args.out}")

    with PendriveRestorer(args.drive) as restorer:
        print(f"\n[+] Volume Geometry Discovered:")
        print(f"    Bytes per Sector    : {restorer.bytes_per_sec}")
        print(f"    Sectors per Cluster : {restorer.sec_per_clus} ({restorer.cluster_size} bytes/cluster)")
        print(f"    Data Area Offset    : {restorer.data_start_offset} bytes")

        print(f"\n[+] Scanning FAT32 Directory Table for Deleted File Tombstones (0xE5)...")
        deleted = restorer.scan_deleted_files()
        print(f"    Found {len(deleted)} deleted entry records in root directory.")

        for idx, entry in enumerate(deleted, 1):
            print(f"\n    [{idx}] Tombstone Entry:")
            print(f"        Short Name       : {entry['short_name']}")
            print(f"        Reconstructed LFN: {entry['reconstructed_name']}")
            print(f"        Start Cluster    : {entry['cluster']} (Offset: {entry['cluster_byte_offset']} bytes)")
            print(f"        File Length      : {entry['size']} bytes")

            # Check if this matches search pattern
            should_restore = True
            if args.pattern:
                should_restore = (
                    args.pattern.lower() in entry["short_name"].lower()
                    or args.pattern.lower() in entry["reconstructed_name"].lower()
                )

            if should_restore and entry["cluster"] >= 2 and entry["size"] > 0:
                print(f"        -> CARVING & RESTORING...")
                result = restorer.restore_file(
                    entry,
                    destination_dir=args.out,
                    expected_sha256=args.baseline_hash,
                )
                print(f"        -> Restored File : {result['saved_to']}")
                print(f"        -> SHA-256       : {result['sha256']}")
                if result['hash_matches_baseline'] is not None:
                    print(f"        -> Baseline Match: {'100% IDENTICAL (PERFECT MATCH)' if result['hash_matches_baseline'] else 'MISMATCH'}")
                print(f"        -> Forensic Status: {result['integrity_status']}")
                print(f"        -> Integrity Score: {result['overall_integrity_score']}/100.0")
                print(f"        -> Format Checks : {result['checks_passed']}/{result['total_checks']} passed")
                print(f"        -> Recoverability: {result['recoverability']}")

    print("\n" + "=" * 70)
    print(" FORENSIC RESTORATION COMPLETE")
    print("=" * 70)


if __name__ == "__main__":
    main()
