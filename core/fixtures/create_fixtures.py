"""
core/fixtures/create_fixtures.py
================================
Generates deterministic test fixtures for Feature 02:
4 Formats (JPEG, PNG, PDF, ZIP) x 8 Variants = 32 Test Fixtures.

Variants:
1. VALID: Clean, 100% intact specimen
2. HEADER_CORRUPTED: Flipped magic bytes at offset 0
3. MIDDLE_REGION_CORRUPTED: Damaged middle bytes / markers
4. TRUNCATED: Cut off before completion
5. TRAILER_DAMAGED: Terminal marker removed/corrupted
6. CHECKSUM_CORRUPTED: Explicit CRC32 / checksum mismatch
7. ZERO_FILLED_REGION: Injected null bytes run
8. MULTIPLE_CORRUPTION_REGIONS: Two or more distinct corruption zones
"""

import io
import json
import os
import struct
import zipfile
import zlib
from pathlib import Path
from PIL import Image

FIXTURES_DIR = Path(__file__).parent / "data"
FIXTURES_DIR.mkdir(parents=True, exist_ok=True)


def build_pristine_png() -> bytes:
    """Creates a real 64x64 RGBA PNG with 2 IDAT chunks."""
    img = Image.new("RGBA", (64, 64))
    for x in range(64):
        for y in range(64):
            img.putpixel((x, y), (x * 4 % 256, y * 4 % 256, (x + y) * 2 % 256, 255))
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    raw = buf.getvalue()

    # Split single IDAT into two IDAT chunks for multi-region testing
    idat_pos = raw.find(b"IDAT")
    if idat_pos != -1:
        full_len = struct.unpack(">I", raw[idat_pos - 4:idat_pos])[0]
        payload = raw[idat_pos + 4:idat_pos + 4 + full_len]
        mid = len(payload) // 2
        p1, p2 = payload[:mid], payload[mid:]
        c1 = struct.pack(">I", len(p1)) + b"IDAT" + p1 + struct.pack(">I", zlib.crc32(b"IDAT" + p1) & 0xFFFFFFFF)
        c2 = struct.pack(">I", len(p2)) + b"IDAT" + p2 + struct.pack(">I", zlib.crc32(b"IDAT" + p2) & 0xFFFFFFFF)
        return raw[:idat_pos - 4] + c1 + c2 + raw[idat_pos + 4 + full_len + 4:]
    return raw


def build_pristine_jpeg() -> bytes:
    """Creates a real 64x64 RGB JPEG in memory."""
    img = Image.new("RGB", (64, 64))
    for x in range(64):
        for y in range(64):
            img.putpixel((x, y), (x * 4 % 256, y * 4 % 256, (x * y) % 256))
    buf = io.BytesIO()
    img.save(buf, format="JPEG", quality=85)
    return buf.getvalue()


def build_pristine_pdf() -> bytes:
    """Creates a minimal valid PDF 1.4 document with multiple objects."""
    content = b"BT /F1 12 Tf 72 712 Td (Samdhan AI Forensic Evidence Specimen) Tj ET"
    stream_len = len(content)
    pdf = (
        b"%PDF-1.4\n"
        b"1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n"
        b"2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj\n"
        b"3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >> endobj\n"
        b"4 0 obj << /Length " + str(stream_len).encode("ascii") + b" >>\nstream\n"
        + content + b"\nendstream\nendobj\n"
        b"5 0 obj << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> endobj\n"
        b"xref\n"
        b"0 6\n"
        b"0000000000 65535 f \n"
        b"0000000009 00000 n \n"
        b"0000000058 00000 n \n"
        b"0000000115 00000 n \n"
        b"0000000244 00000 n \n"
        b"0000000350 00000 n \n"
        b"trailer << /Size 6 /Root 1 0 R >>\n"
        b"startxref\n"
        b"425\n"
        b"%%EOF\n"
    )
    return pdf


def build_pristine_zip() -> bytes:
    """Creates a valid ZIP archive with 2 distinct files."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("evidence_01.txt", b"First forensic payload data stream for testing integrity verification.")
        zf.writestr("evidence_02.txt", b"Second forensic payload data stream for testing integrity verification.")
    return buf.getvalue()


def generate_all_fixtures() -> dict:
    """Generates all 32 fixtures and outputs ground_truth.json."""
    ground_truth = {}

    pristine_generators = {
        "PNG": (build_pristine_png, ".png"),
        "JPEG": (build_pristine_jpeg, ".jpg"),
        "PDF": (build_pristine_pdf, ".pdf"),
        "ZIP": (build_pristine_zip, ".zip"),
    }

    for fmt, (gen_fn, ext) in pristine_generators.items():
        pristine = gen_fn()
        p_len = len(pristine)

        # 1. VALID
        f_valid = f"{fmt.lower()}_1_valid{ext}"
        (FIXTURES_DIR / f_valid).write_bytes(pristine)
        ground_truth[f_valid] = {
            "format": fmt,
            "variant": "VALID",
            "size": p_len,
            "expected_status": "INTACT",
            "corruptions": [],
        }

        # 2. HEADER_CORRUPTED (corrupt byte 0..4)
        f_hdr = f"{fmt.lower()}_2_header_corrupted{ext}"
        corrupt_hdr = bytearray(pristine)
        corrupt_hdr[0:4] = b"\x00\x00\x00\x00"
        (FIXTURES_DIR / f_hdr).write_bytes(corrupt_hdr)
        ground_truth[f_hdr] = {
            "format": fmt,
            "variant": "HEADER_CORRUPTED",
            "size": p_len,
            "expected_status": "UNRECOVERABLE",
            "corruptions": [{"start": 0, "end": 4, "type": "HEADER_CORRUPTION"}],
        }

        # 3. MIDDLE_REGION_CORRUPTED
        f_mid = f"{fmt.lower()}_3_middle_corrupted{ext}"
        corrupt_mid = bytearray(pristine)

        if fmt == "JPEG":
            # Corrupt DQT marker prefix in middle
            dqt_pos = pristine.find(b"\xff\xdb")
            mid_start = dqt_pos
            mid_end = dqt_pos + 2
            corrupt_mid[mid_start:mid_end] = b"\xde\xad"
        elif fmt == "PNG":
            # Corrupt CRC of first IDAT chunk
            idat_pos = pristine.find(b"IDAT")
            chunk_len = struct.unpack(">I", pristine[idat_pos - 4:idat_pos])[0]
            mid_start = idat_pos + 4 + chunk_len
            mid_end = mid_start + 4
            corrupt_mid[mid_start:mid_end] = b"\x00\x00\x00\x00"
        elif fmt == "PDF":
            # Corrupt endstream keyword in Object 4
            stream_pos = pristine.find(b"endstream")
            mid_start = stream_pos
            mid_end = stream_pos + 9
            corrupt_mid[mid_start:mid_end] = b"xxxxxxxxx"
        elif fmt == "ZIP":
            # Corrupt CRC of first entry
            mid_start = 14
            mid_end = 18
            corrupt_mid[mid_start:mid_end] = b"\xde\xad\xbe\xef"

        (FIXTURES_DIR / f_mid).write_bytes(corrupt_mid)
        ground_truth[f_mid] = {
            "format": fmt,
            "variant": "MIDDLE_REGION_CORRUPTED",
            "size": p_len,
            "expected_status": "PARTIALLY_DAMAGED",
            "corruptions": [{"start": mid_start, "end": mid_end, "type": "CORRUPTED"}],
        }

        # 4. TRUNCATED (cut off at 60%)
        f_trunc = f"{fmt.lower()}_4_truncated{ext}"
        trunc_len = int(p_len * 0.6)
        corrupt_trunc = pristine[:trunc_len]
        (FIXTURES_DIR / f_trunc).write_bytes(corrupt_trunc)
        ground_truth[f_trunc] = {
            "format": fmt,
            "variant": "TRUNCATED",
            "size": trunc_len,
            "expected_status": "TRUNCATED",
            "corruptions": [{"start": trunc_len, "end": p_len, "type": "TRUNCATION"}],
        }

        # 5. TRAILER_DAMAGED (remove exact terminal marker)
        f_trail = f"{fmt.lower()}_5_trailer_damaged{ext}"
        if fmt == "PNG":
            # Strip 12-byte IEND chunk
            corrupt_trail = pristine[:-12]
        elif fmt == "JPEG":
            # Strip 2-byte EOI (FF D9)
            corrupt_trail = pristine[:-2]
        elif fmt == "PDF":
            # Strip %%EOF
            corrupt_trail = pristine[:-6]
        elif fmt == "ZIP":
            # Strip 22-byte EOCD
            corrupt_trail = pristine[:-22]

        (FIXTURES_DIR / f_trail).write_bytes(corrupt_trail)
        ground_truth[f_trail] = {
            "format": fmt,
            "variant": "TRAILER_DAMAGED",
            "size": len(corrupt_trail),
            "expected_status": "TRUNCATED",
            "corruptions": [{"start": len(corrupt_trail), "end": p_len, "type": "MISSING_TRAILER"}],
        }

        # 6. CHECKSUM_CORRUPTED
        f_chk = f"{fmt.lower()}_6_checksum_corrupted{ext}"
        corrupt_chk = bytearray(pristine)
        if fmt == "PNG":
            # Corrupt CRC of first IDAT
            idat_pos = pristine.find(b"IDAT")
            chunk_len = struct.unpack(">I", pristine[idat_pos - 4:idat_pos])[0]
            crc_loc = idat_pos + 4 + chunk_len
            corrupt_chk[crc_loc:crc_loc + 4] = b"\x12\x34\x56\x78"
            chk_corruption = [{"start": idat_pos - 4, "end": crc_loc + 4, "type": "CRC_FAILURE"}]
        elif fmt == "ZIP":
            # Corrupt CRC-32 in first local header
            corrupt_chk[14:18] = b"\xaa\xbb\xcc\xdd"
            chk_corruption = [{"start": 14, "end": 18, "type": "CRC_FAILURE"}]
        elif fmt == "JPEG":
            # Corrupt DQT length byte to trigger segment length failure
            dqt_pos = pristine.find(b"\xff\xdb")
            corrupt_chk[dqt_pos + 2:dqt_pos + 4] = b"\x00\x01"  # Invalid length < 2
            chk_corruption = [{"start": dqt_pos + 2, "end": dqt_pos + 4, "type": "INVALID_LENGTH"}]
        elif fmt == "PDF":
            # Corrupt xref table
            xref_pos = pristine.find(b"xref")
            corrupt_chk[xref_pos:xref_pos + 4] = b"xxxx"
            chk_corruption = [{"start": xref_pos, "end": xref_pos + 4, "type": "STRUCTURAL_CORRUPTION"}]

        (FIXTURES_DIR / f_chk).write_bytes(corrupt_chk)
        ground_truth[f_chk] = {
            "format": fmt,
            "variant": "CHECKSUM_CORRUPTED",
            "size": p_len,
            "expected_status": "PARTIALLY_DAMAGED",
            "corruptions": chk_corruption,
        }

        # 7. ZERO_FILLED_REGION (inject 256 null bytes in middle)
        f_zero = f"{fmt.lower()}_7_zero_filled{ext}"
        z_start = p_len // 3
        z_len = 256
        if p_len < z_start + z_len:
            corrupt_zero = bytearray(pristine) + bytearray(z_len)
        else:
            corrupt_zero = bytearray(pristine)
            corrupt_zero[z_start:z_start + z_len] = b"\x00" * z_len

        (FIXTURES_DIR / f_zero).write_bytes(corrupt_zero)
        ground_truth[f_zero] = {
            "format": fmt,
            "variant": "ZERO_FILLED_REGION",
            "size": len(corrupt_zero),
            "expected_status": "PARTIALLY_DAMAGED",
            "corruptions": [{"start": z_start, "end": z_start + z_len, "type": "ZERO_FILLED_REGION"}],
        }

        # 8. MULTIPLE_CORRUPTION_REGIONS (two separate corrupted zones)
        f_multi = f"{fmt.lower()}_8_multiple_corruptions{ext}"
        corrupt_multi = bytearray(pristine)

        if fmt == "PNG":
            # Corrupt CRC of IDAT 1 AND CRC of IDAT 2
            idat1 = pristine.find(b"IDAT")
            len1 = struct.unpack(">I", pristine[idat1 - 4:idat1])[0]
            crc1 = idat1 + 4 + len1
            corrupt_multi[crc1:crc1 + 4] = b"\x00\x00\x00\x00"

            idat2 = pristine.find(b"IDAT", crc1 + 4)
            len2 = struct.unpack(">I", pristine[idat2 - 4:idat2])[0]
            crc2 = idat2 + 4 + len2
            corrupt_multi[crc2:crc2 + 4] = b"\x00\x00\x00\x00"

            ground_truth[f_multi] = {
                "format": fmt,
                "variant": "MULTIPLE_CORRUPTION_REGIONS",
                "size": p_len,
                "expected_status": "PARTIALLY_DAMAGED",
                "corruptions": [
                    {"start": idat1 - 4, "end": crc1 + 4, "type": "CRC_FAILURE"},
                    {"start": idat2 - 4, "end": crc2 + 4, "type": "CRC_FAILURE"},
                ],
            }
        elif fmt == "ZIP":
            # Corrupt Entry 1 CRC (at 14) and Entry 2 CRC
            e2 = pristine.find(b"PK\x03\x04", 30)
            corrupt_multi[14:18] = b"\x11\x11\x11\x11"
            corrupt_multi[e2 + 14:e2 + 18] = b"\x22\x22\x22\x22"
            ground_truth[f_multi] = {
                "format": fmt,
                "variant": "MULTIPLE_CORRUPTION_REGIONS",
                "size": p_len,
                "expected_status": "PARTIALLY_DAMAGED",
                "corruptions": [
                    {"start": 14, "end": 18, "type": "CRC_FAILURE"},
                    {"start": e2 + 14, "end": e2 + 18, "type": "CRC_FAILURE"},
                ],
            }
        elif fmt == "PDF":
            # Corrupt endobj 1 and endobj 2 to produce unclosed objects
            e1 = pristine.find(b"endobj")
            e2 = pristine.find(b"endobj", e1 + 6)
            corrupt_multi[e1:e1 + 6] = b"xxxxxx"
            corrupt_multi[e2:e2 + 6] = b"xxxxxx"
            ground_truth[f_multi] = {
                "format": fmt,
                "variant": "MULTIPLE_CORRUPTION_REGIONS",
                "size": p_len,
                "expected_status": "PARTIALLY_DAMAGED",
                "corruptions": [
                    {"start": e1, "end": e1 + 6, "type": "STRUCTURAL_CORRUPTION"},
                    {"start": e2, "end": e2 + 6, "type": "STRUCTURAL_CORRUPTION"},
                ],
            }
        elif fmt == "JPEG":
            # Corrupt DQT length and inject bad marker before SOS
            dqt_pos = pristine.find(b"\xff\xdb")
            corrupt_multi[dqt_pos:dqt_pos + 2] = b"\xde\xad"
            dht_pos = pristine.find(b"\xff\xc4")
            corrupt_multi[dht_pos:dht_pos + 2] = b"\xbe\xef"
            ground_truth[f_multi] = {
                "format": fmt,
                "variant": "MULTIPLE_CORRUPTION_REGIONS",
                "size": p_len,
                "expected_status": "PARTIALLY_DAMAGED",
                "corruptions": [
                    {"start": dqt_pos, "end": dqt_pos + 2, "type": "INVALID_MARKER"},
                    {"start": dht_pos, "end": dht_pos + 2, "type": "INVALID_MARKER"},
                ],
            }

        (FIXTURES_DIR / f_multi).write_bytes(corrupt_multi)

    # Save ground_truth.json
    gt_path = FIXTURES_DIR / "ground_truth.json"
    with open(gt_path, "w") as f:
        json.dump(ground_truth, f, indent=2)

    print(f"Generated {len(ground_truth)} deterministic fixtures in {FIXTURES_DIR}")
    return ground_truth


if __name__ == "__main__":
    generate_all_fixtures()
