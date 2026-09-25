"""
disk_recovery/test_fixtures/create_test_image.py
=================================================
Creates a controlled FAT32 disk image for Phase-1 acceptance testing.

Image layout
------------
  MBR (1 sector)
  FAT32 boot sector + BPB
  FAT1 + FAT2
  Root directory cluster containing:
      photo1.jpg        ← valid JPEG (allocated, active)
      document.pdf      ← valid PDF  (allocated, active)
      archive.zip       ← valid ZIP  (allocated, active)
      note.txt          ← plain text (allocated, active)
      [DELETED_PHOTO]   ← directory entry for deleted_photo.jpg
                          (entry marked 0xE5, cluster chain freed in FAT)
  Data clusters:
      cluster 2  → photo1.jpg data (intact JPEG bytes)
      cluster 3  → document.pdf data
      cluster 4  → archive.zip data
      cluster 5  → note.txt data
      cluster 6  → deleted_photo.jpg data (FAT entry = 0, but raw bytes intact)
      clusters 7-31 → zero-filled (unallocated)

Ground truth (preserved separately in ground_truth.json):
  - photo1.jpg     : allocated, active, SHA-256 recorded
  - document.pdf   : allocated, active, SHA-256 recorded
  - archive.zip    : allocated, active, SHA-256 recorded
  - note.txt       : allocated, active, SHA-256 recorded
  - deleted_photo.jpg : DELETED (0xE5 entry), FAT freed, raw data intact

Usage
-----
    python create_test_image.py

Output
------
    test_fixtures/test_usb.img          ← disk image (read-only for pipeline)
    test_fixtures/ground_truth.json     ← expected pipeline results
"""

from __future__ import annotations

import hashlib
import io
import json
import struct
import sys
import zlib
from pathlib import Path

OUT_DIR = Path(__file__).parent
IMAGE_PATH = OUT_DIR / "test_usb.img"
TRUTH_PATH = OUT_DIR / "ground_truth.json"

# ── Disk geometry ─────────────────────────────────────────────────────────────
SECTOR_SIZE        = 512
SECTORS_PER_CLUST  = 8          # 4 KiB clusters
CLUSTER_SIZE       = SECTOR_SIZE * SECTORS_PER_CLUST   # 4096 bytes
NUM_RESERVED       = 4          # reserved sectors (boot sector + 3 spare)
NUM_FATS           = 2
FAT_SIZE_SECTORS   = 1          # 1 sector per FAT (supports ~128 clusters)
ROOT_CLUSTER       = 2          # root directory starts at cluster 2
DATA_CLUSTERS      = 30         # total data clusters
TOTAL_SECTORS      = (NUM_RESERVED
                      + NUM_FATS * FAT_SIZE_SECTORS
                      + DATA_CLUSTERS * SECTORS_PER_CLUST)

# Data region byte offset
DATA_REGION_BYTE   = ((NUM_RESERVED + NUM_FATS * FAT_SIZE_SECTORS)
                      * SECTOR_SIZE)


# ── File content factories ────────────────────────────────────────────────────

def make_jpeg(label: bytes = b"PHOTO1") -> bytes:
    """Minimal but structurally valid JPEG."""
    soi  = b"\xff\xd8"
    app0 = b"\xff\xe0" + struct.pack(">H", 16) + b"JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
    dqt  = b"\xff\xdb" + struct.pack(">H", 67) + b"\x00" + bytes(range(64))
    sof0 = (b"\xff\xc0" + struct.pack(">H", 17) + b"\x08"
            + struct.pack(">HH", 8, 8)
            + b"\x03\x01\x11\x00\x02\x11\x01\x03\x11\x01")
    dht  = b"\xff\xc4" + struct.pack(">H", 31) + b"\x00" + b"\x00" * 29
    sos  = b"\xff\xda" + struct.pack(">H", 12) + b"\x03\x01\x00\x02\x11\x03\x11\x00\x3f\x00"
    entropy = label * 32 + bytes(range(256)) * 2
    eoi  = b"\xff\xd9"
    return soi + app0 + dqt + sof0 + dht + sos + entropy + eoi


def make_pdf(label: str = "DOCUMENT") -> bytes:
    """Minimal valid single-page PDF."""
    body  = b"%PDF-1.4\n"
    body += b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
    body += b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
    body += (b"3 0 obj\n<< /Type /Page /Parent 2 0 R "
             b"/MediaBox [0 0 612 792] >>\nendobj\n")
    label_bytes = label.encode()
    body += (b"4 0 obj\n<< /Length " + str(len(label_bytes) + 4).encode()
             + b" >>\nstream\nBT " + label_bytes + b" ET\nendstream\nendobj\n")
    xref_pos = len(body)
    body += b"xref\n0 5\n"
    body += b"0000000000 65535 f \n" * 5
    body += b"trailer\n<< /Size 5 /Root 1 0 R >>\n"
    body += b"startxref\n" + str(xref_pos).encode() + b"\n%%EOF\n"
    return body


def make_zip(label: str = "archive") -> bytes:
    """Minimal valid ZIP with one small text file inside."""
    buf = io.BytesIO()
    import zipfile
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(f"{label}/readme.txt",
                    f"Samdhan AI test archive: {label}\nPhase-1 acceptance fixture.")
    return buf.getvalue()


def make_txt(content: str) -> bytes:
    return content.encode("utf-8")


# ── FAT32 helpers ─────────────────────────────────────────────────────────────

def _fat32_boot_sector() -> bytes:
    """Build a valid FAT32 boot/BPB sector."""
    bpb = bytearray(512)

    # Jump boot + NOP
    bpb[0:3] = b"\xeb\x58\x90"
    # OEM ID
    bpb[3:11] = b"FAT32   "
    # BPB fields
    struct.pack_into("<H", bpb, 0x0B, SECTOR_SIZE)          # bytes per sector
    bpb[0x0D] = SECTORS_PER_CLUST                            # sectors per cluster
    struct.pack_into("<H", bpb, 0x0E, NUM_RESERVED)         # reserved sectors
    bpb[0x10] = NUM_FATS                                     # number of FATs
    struct.pack_into("<H", bpb, 0x11, 0)                    # root entry count (0 for FAT32)
    struct.pack_into("<H", bpb, 0x13, 0)                    # total sectors 16 (0 = use 32-bit)
    bpb[0x15] = 0xF8                                         # media type (fixed disk)
    struct.pack_into("<H", bpb, 0x16, 0)                    # FAT size 16 (0 = use FAT32 field)
    struct.pack_into("<H", bpb, 0x18, 63)                   # sectors per track
    struct.pack_into("<H", bpb, 0x1A, 255)                  # number of heads
    struct.pack_into("<I", bpb, 0x1C, 0)                    # hidden sectors
    struct.pack_into("<I", bpb, 0x20, TOTAL_SECTORS)        # total sectors 32
    struct.pack_into("<I", bpb, 0x24, FAT_SIZE_SECTORS)     # FAT size 32
    struct.pack_into("<H", bpb, 0x28, 0)                    # ext flags
    struct.pack_into("<H", bpb, 0x2A, 0)                    # FS version
    struct.pack_into("<I", bpb, 0x2C, ROOT_CLUSTER)         # root cluster
    struct.pack_into("<H", bpb, 0x30, 1)                    # FS info sector
    struct.pack_into("<H", bpb, 0x32, 6)                    # backup boot sector
    bpb[0x40] = 0x80                                         # drive number
    bpb[0x42] = 0x29                                         # ext boot sig
    struct.pack_into("<I", bpb, 0x43, 0xDEADBEEF)          # volume serial
    bpb[0x47:0x52] = b"SAMDHAN    "                         # volume label
    bpb[0x52:0x5A] = b"FAT32   "                            # FS type
    # Boot signature
    bpb[510] = 0x55
    bpb[511] = 0xAA
    return bytes(bpb)


def _build_fat(used_clusters: dict) -> bytes:
    """
    Build a FAT sector.
    used_clusters: {cluster_no: next_cluster or 0x0FFFFFFF (EOF) or 0x00 (free)}
    """
    fat = bytearray(FAT_SIZE_SECTORS * SECTOR_SIZE)
    # Media byte in first two entries
    struct.pack_into("<I", fat, 0, 0x0FFFFFF8)  # cluster 0 (reserved)
    struct.pack_into("<I", fat, 4, 0x0FFFFFFF)  # cluster 1 (reserved)

    for cluster, next_val in used_clusters.items():
        struct.pack_into("<I", fat, cluster * 4, next_val & 0x0FFFFFFF)

    return bytes(fat)


def _dir_entry(name_8dot3: bytes, attr: int, cluster: int, size: int,
               deleted: bool = False) -> bytes:
    """Build a 32-byte FAT32 short directory entry."""
    e = bytearray(32)
    e[0:11] = name_8dot3[:11]
    if deleted:
        e[0] = 0xE5
    e[11] = attr
    # creation date 2026-09-26
    fat_date = ((2026 - 1980) << 9) | (9 << 5) | 26
    fat_time = (1 << 11) | (0 << 5) | 0    # 01:00:00
    struct.pack_into("<H", e, 0x0E, fat_time)  # creation time
    struct.pack_into("<H", e, 0x10, fat_date)  # creation date
    struct.pack_into("<H", e, 0x12, fat_date)  # last access date
    struct.pack_into("<H", e, 0x14, (cluster >> 16) & 0xFFFF)  # high cluster
    struct.pack_into("<H", e, 0x16, fat_time)  # write time
    struct.pack_into("<H", e, 0x18, fat_date)  # write date
    struct.pack_into("<H", e, 0x1A, cluster & 0xFFFF)          # low cluster
    struct.pack_into("<I", e, 0x1C, size)
    return bytes(e)


def _cluster_to_byte(cluster: int) -> int:
    return DATA_REGION_BYTE + (cluster - 2) * CLUSTER_SIZE


def _pad_to_cluster(data: bytes) -> bytes:
    """Zero-pad data to a multiple of CLUSTER_SIZE."""
    rem = len(data) % CLUSTER_SIZE
    if rem:
        data += b"\x00" * (CLUSTER_SIZE - rem)
    return data


# ── Image assembly ────────────────────────────────────────────────────────────

def build_image() -> tuple:
    """
    Assemble the complete disk image bytes and ground truth dict.
    Returns (image_bytes: bytes, ground_truth: dict).
    """
    # File contents
    jpeg1   = make_jpeg(b"PHOTO1_LIVE")
    pdf1    = make_pdf("SAMDHAN_DOC")
    zip1    = make_zip("samdhan_archive")
    txt1    = make_txt("Samdhan AI Phase-1 test fixture.\nCase: NIGHTFALL-2026.\n")
    jpeg_del = make_jpeg(b"DELETED_PHOTO")

    # SHA-256 ground truth (before image assembly)
    def sha(data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    gt_sha = {
        "photo1.jpg":       sha(jpeg1),
        "document.pdf":     sha(pdf1),
        "archive.zip":      sha(zip1),
        "note.txt":         sha(txt1),
        "deleted_photo.jpg": sha(jpeg_del),
    }

    # Cluster assignments
    # cluster 2 = root directory
    # cluster 3 = photo1.jpg
    # cluster 4 = document.pdf
    # cluster 5 = archive.zip
    # cluster 6 = note.txt
    # cluster 7 = deleted_photo.jpg (FAT freed, raw data intact)
    # clusters 8-31 = free (zero-filled)

    FAT_ENTRIES = {
        2: 0x0FFFFFFF,   # root dir (EOF)
        3: 0x0FFFFFFF,   # photo1.jpg (EOF)
        4: 0x0FFFFFFF,   # document.pdf (EOF)
        5: 0x0FFFFFFF,   # archive.zip (EOF)
        6: 0x0FFFFFFF,   # note.txt (EOF)
        7: 0x00000000,   # deleted_photo.jpg — FAT entry FREED (0)
    }
    for c in range(8, DATA_CLUSTERS + 2):
        FAT_ENTRIES[c] = 0x00000000   # free

    fat_bytes = _build_fat(FAT_ENTRIES)

    # Root directory (cluster 2)
    ATTR_ARCHIVE = 0x20
    root_dir = (
        _dir_entry(b"PHOTO1  JPG", ATTR_ARCHIVE, 3, len(jpeg1))
        + _dir_entry(b"DOCUMENTPDF", ATTR_ARCHIVE, 4, len(pdf1))
        + _dir_entry(b"ARCHIVE ZIP", ATTR_ARCHIVE, 5, len(zip1))
        + _dir_entry(b"NOTE    TXT", ATTR_ARCHIVE, 6, len(txt1))
        + _dir_entry(b"DELETED JPG", ATTR_ARCHIVE, 7, len(jpeg_del), deleted=True)
    )
    root_dir = _pad_to_cluster(root_dir)

    # Allocate image buffer
    IMAGE_SIZE = TOTAL_SECTORS * SECTOR_SIZE
    image = bytearray(IMAGE_SIZE)

    # Sector 0: boot sector
    image[0:512] = _fat32_boot_sector()

    # FAT1 at sector NUM_RESERVED
    fat1_off = NUM_RESERVED * SECTOR_SIZE
    image[fat1_off: fat1_off + len(fat_bytes)] = fat_bytes

    # FAT2 (mirror)
    fat2_off = fat1_off + FAT_SIZE_SECTORS * SECTOR_SIZE
    image[fat2_off: fat2_off + len(fat_bytes)] = fat_bytes

    # Root directory cluster (cluster 2)
    c2_off = _cluster_to_byte(2)
    image[c2_off: c2_off + len(root_dir)] = root_dir

    # Data clusters
    for cluster, data in [
        (3, _pad_to_cluster(jpeg1)),
        (4, _pad_to_cluster(pdf1)),
        (5, _pad_to_cluster(zip1)),
        (6, _pad_to_cluster(txt1)),
        (7, _pad_to_cluster(jpeg_del)),   # deleted — FAT freed but data present
    ]:
        off = _cluster_to_byte(cluster)
        image[off: off + len(data)] = data

    image_bytes = bytes(image)
    image_sha256 = sha(image_bytes)

    ground_truth = {
        "image_sha256": image_sha256,
        "image_size_bytes": len(image_bytes),
        "filesystem": "FAT32",
        "sector_size": SECTOR_SIZE,
        "cluster_size": CLUSTER_SIZE,
        "files": {
            "photo1.jpg": {
                "cluster": 3,
                "byte_offset": _cluster_to_byte(3),
                "size_bytes": len(jpeg1),
                "sha256": gt_sha["photo1.jpg"],
                "deletion_state": "ACTIVE",
                "allocation_state": "ALLOCATED",
                "format": "JPEG",
            },
            "document.pdf": {
                "cluster": 4,
                "byte_offset": _cluster_to_byte(4),
                "size_bytes": len(pdf1),
                "sha256": gt_sha["document.pdf"],
                "deletion_state": "ACTIVE",
                "allocation_state": "ALLOCATED",
                "format": "PDF",
            },
            "archive.zip": {
                "cluster": 5,
                "byte_offset": _cluster_to_byte(5),
                "size_bytes": len(zip1),
                "sha256": gt_sha["archive.zip"],
                "deletion_state": "ACTIVE",
                "allocation_state": "ALLOCATED",
                "format": "ZIP",
            },
            "note.txt": {
                "cluster": 6,
                "byte_offset": _cluster_to_byte(6),
                "size_bytes": len(txt1),
                "sha256": gt_sha["note.txt"],
                "deletion_state": "ACTIVE",
                "allocation_state": "ALLOCATED",
                "format": "TXT",
            },
            "deleted_photo.jpg": {
                "cluster": 7,
                "byte_offset": _cluster_to_byte(7),
                "size_bytes": len(jpeg_del),
                "sha256": gt_sha["deleted_photo.jpg"],
                "deletion_state": "DELETED_META_INTACT",
                "allocation_state": "UNALLOCATED",
                "format": "JPEG",
                "note": "FAT entry freed (0x00), dir entry marked 0xE5, raw bytes intact — recoverable by carving",
            },
        },
        "acceptance_checks": [
            "disk image loaded successfully",
            "FAT32 filesystem detected",
            "4 allocated files discovered via metadata",
            "1 deleted file detected via 0xE5 directory entry",
            "unallocated clusters 8-31 identified",
            "raw JPEG/PDF/ZIP signatures detected by carver",
            "recovery candidates generated for all 5 files",
            "image SHA-256 matches ground truth (source unchanged)",
        ],
    }

    return image_bytes, ground_truth


def main():
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except Exception:
            pass

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    print(f"Building test disk image -> {IMAGE_PATH}")
    image_bytes, ground_truth = build_image()

    IMAGE_PATH.write_bytes(image_bytes)
    print(f"  Image written: {len(image_bytes):,} bytes")
    print(f"  Image SHA-256: {ground_truth['image_sha256']}")

    TRUTH_PATH.write_text(json.dumps(ground_truth, indent=2), encoding="utf-8")
    print(f"  Ground truth -> {TRUTH_PATH}")

    # Verify read-back
    read_back = IMAGE_PATH.read_bytes()
    assert hashlib.sha256(read_back).hexdigest() == ground_truth["image_sha256"], \
        "SHA-256 mismatch after write!"
    print("  SHA-256 verified [OK]")

    print("\nFiles in image:")
    for fname, info in ground_truth["files"].items():
        state = info["deletion_state"]
        marker = "[DELETED]" if "DELETED" in state else "[ACTIVE] "
        print(f"  {marker}  {fname:30s}  {info['size_bytes']:6d} B  "
              f"cluster={info['cluster']}  sha256={info['sha256'][:16]}...")

    print(f"\nAcceptance checks ({len(ground_truth['acceptance_checks'])} items):")
    for chk in ground_truth["acceptance_checks"]:
        print(f"  * {chk}")

    print(f"\nDone. Run the pipeline scan:\n"
          f"  POST /api/recovery/scan  {{ \"image_path\": \"{IMAGE_PATH}\" }}")


if __name__ == "__main__":
    main()
