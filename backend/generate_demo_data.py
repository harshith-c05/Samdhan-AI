"""
SAMDHAN AI — Demo Data Generator (S21)
Generates synthetic reconstructed artifacts covering all 15 variants from the spec.
Run: python generate_demo_data.py
"""

import io
import json
import os
import struct
import zipfile
from pathlib import Path

DEMO_DIR = Path(__file__).parent / "demo_data" / "reconstructed"
FIXTURES_DIR = Path(__file__).parent / "demo_data" / "fixtures"
DEMO_DIR.mkdir(parents=True, exist_ok=True)
FIXTURES_DIR.mkdir(parents=True, exist_ok=True)

# ─── Helpers ─────────────────────────────────────────────────────────────────

def make_jpeg(corrupted_middle=False, missing_tail=False) -> bytes:
    """Build a minimal valid/partially-valid JPEG."""
    soi = b"\xff\xd8"
    # APP0 JFIF header
    app0 = b"\xff\xe0" + struct.pack(">H", 16) + b"JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
    # Quantization table (minimal)
    dqt  = b"\xff\xdb" + struct.pack(">H", 67) + b"\x00" + bytes(range(64))
    # Start of frame
    sof0 = b"\xff\xc0" + struct.pack(">H", 17) + b"\x08" + struct.pack(">HH", 80, 60) + b"\x03\x01\x11\x00\x02\x11\x01\x03\x11\x01"
    # Huffman table (empty placeholder)
    dht  = b"\xff\xc4" + struct.pack(">H", 31) + b"\x00" + b"\x00" * 29
    # SOS marker + fake entropy data
    sos  = b"\xff\xda" + struct.pack(">H", 12) + b"\x03\x01\x00\x02\x11\x03\x11\x00\x3f\x00"
    entropy = bytes([i % 256 for i in range(1024)])  # Fake image entropy data
    eoi  = b"\xff\xd9"

    if corrupted_middle:
        # Replace middle of entropy data with zero-fill (Type C corruption)
        entropy = entropy[:256] + b"\x00" * 512 + entropy[768:]

    data = soi + app0 + dqt + sof0 + dht + sos + entropy
    if not missing_tail:
        data += eoi
    else:
        # Truncate without EOI (Type A: Missing Data)
        data = data[:len(data) - 200]
    return data


def make_png(missing_iend=False) -> bytes:
    """Build a minimal PNG."""
    import zlib
    PNG_SIG = b"\x89PNG\r\n\x1a\n"
    def chunk(name, data):
        import struct, zlib
        c = struct.pack(">I", len(data)) + name + data
        crc = struct.pack(">I", zlib.crc32(name + data) & 0xFFFFFFFF)
        return c + crc

    width, height = 4, 4
    ihdr_data = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    ihdr = chunk(b"IHDR", ihdr_data)

    raw_rows = b"".join(b"\x00" + b"\xff\x00\x00" * width for _ in range(height))
    idat_data = zlib.compress(raw_rows)
    idat = chunk(b"IDAT", idat_data)
    iend = chunk(b"IEND", b"")

    data = PNG_SIG + ihdr + idat
    if not missing_iend:
        data += iend
    return data


def make_pdf(damaged_object=False, missing_page=False) -> bytes:
    """Build a minimal PDF."""
    body = b"%PDF-1.7\n"
    body += b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
    body += b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
    body += b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\n"
    if damaged_object:
        body += b"4 0 obj\n<< /BROKEN" + b"\x00" * 128 + b">>\nendobj\n"
    if not missing_page:
        body += b"xref\n0 4\n0000000000 65535 f\n0000000015 00000 n\n0000000068 00000 n\n0000000125 00000 n\n"
    body += b"trailer\n<< /Size 4 /Root 1 0 R >>\nstartxref\n200\n%%EOF\n"
    return body


def make_docx(broken_zip=False, damaged_xml=False) -> bytes:
    """Build a minimal DOCX (ZIP container)."""
    if broken_zip:
        return b"PK\x03\x04" + b"\x00" * 128 + b"CORRUPT_CENTRAL_DIR" + b"\x00" * 64
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml",
            '<?xml version="1.0"?>'
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
            '<Override PartName="/word/document.xml" '
            'ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
            '</Types>')
        zf.writestr("_rels/.rels",
            '<?xml version="1.0"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument"'
            ' Target="word/document.xml"/>'
            '</Relationships>')
        doc_xml = ('<?xml version="1.0"?>'
                   '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
                   '<w:body><w:p><w:r><w:t>CONFIDENTIAL — Demo Document</w:t></w:r></w:p></w:body>'
                   '</w:document>')
        if damaged_xml:
            doc_xml = doc_xml[:len(doc_xml) // 2] + "<!-- CORRUPT -->"
        zf.writestr("word/document.xml", doc_xml)
    return buf.getvalue()


def make_sqlite(damaged_page=False, missing_records=False) -> bytes:
    """Write to a real temp SQLite file then read bytes."""
    import sqlite3, tempfile, os
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        tmp_path = tmp.name
    conn = sqlite3.connect(tmp_path)
    conn.execute("CREATE TABLE auth_log (id INTEGER PRIMARY KEY, user TEXT, action TEXT, ts TEXT)")
    for i in range(20):
        conn.execute("INSERT INTO auth_log VALUES (?,?,?,?)",
                     (i, f"user_{i}", "LOGIN" if i % 3 else "PRIV_ESC", f"2026-09-24T{i:02d}:00:00Z"))
    conn.commit(); conn.close()
    data = open(tmp_path, "rb").read()
    os.unlink(tmp_path)
    if damaged_page:
        # Corrupt page 2 header (B-Tree leaf)
        if len(data) > 4096:
            data = data[:4096] + b"\xde\xad\xbe\xef" * 64 + data[4096 + 256:]
    if missing_records:
        data = data[:len(data) // 2]  # Truncate — simulates missing tail pages
    return data


def make_log(missing_lines=False, malformed=False) -> bytes:
    lines = []
    for i in range(50):
        lines.append(f"Sep 24 {i % 24:02d}:00:{i % 60:02d} srv-01 sshd[{1000+i}]: Accepted publickey for admin")
    if missing_lines:
        lines = lines[:30]  # Remove last 40%
    if malformed:
        # Insert corrupted / non-parseable records
        for i in range(0, 50, 7):
            lines[i] = f"\x00\xff CORRUPT_RECORD_{i} BROKEN DATA"
    return "\n".join(lines).encode("utf-8")


# ─── S21 Demo Artifact Definitions ───────────────────────────────────────────

ARTIFACTS = [
    # ID      Filename                              Type      Builder           kwargs
    ("ART-001", "art001_jpeg_intact.jpg",           "JPEG",   make_jpeg,        {}),
    ("ART-002", "art002_jpeg_missing_tail.jpg",     "JPEG",   make_jpeg,        {"missing_tail": True}),
    ("ART-003", "art003_jpeg_corrupted_mid.jpg",    "JPEG",   make_jpeg,        {"corrupted_middle": True}),
    ("ART-004", "art004_pdf_intact.pdf",            "PDF",    make_pdf,         {}),
    ("ART-005", "art005_pdf_damaged_obj.pdf",       "PDF",    make_pdf,         {"damaged_object": True}),
    ("ART-006", "art006_pdf_missing_page.pdf",      "PDF",    make_pdf,         {"missing_page": True}),
    ("ART-007", "art007_docx_intact.docx",          "DOCX",   make_docx,        {}),
    ("ART-008", "art008_docx_damaged_xml.docx",     "DOCX",   make_docx,        {"damaged_xml": True}),
    ("ART-009", "art009_docx_broken_zip.docx",      "DOCX",   make_docx,        {"broken_zip": True}),
    ("ART-010", "art010_sqlite_intact.db",          "SQLite", make_sqlite,      {}),
    ("ART-011", "art011_sqlite_damaged_page.db",    "SQLite", make_sqlite,      {"damaged_page": True}),
    ("ART-012", "art012_sqlite_missing_records.db", "SQLite", make_sqlite,      {"missing_records": True}),
    ("ART-013", "art013_log_complete.log",          "LOG",    make_log,         {}),
    ("ART-014", "art014_log_missing_lines.log",     "LOG",    make_log,         {"missing_lines": True}),
    ("ART-015", "art015_log_malformed.log",         "LOG",    make_log,         {"malformed": True}),
]

# ─── S3.1 Input Fixtures ─────────────────────────────────────────────────────

FIXTURE_METADATA = {
    "ART-001": {"reconstruction_confidence": 0.98, "fragments_used": [
        {"fragment_id": "F001", "offset": 0,    "length": 512,  "confidence": 0.98},
        {"fragment_id": "F002", "offset": 512,  "length": 512,  "confidence": 0.97},
    ], "missing_ranges": []},
    "ART-002": {"reconstruction_confidence": 0.87, "fragments_used": [
        {"fragment_id": "F010", "offset": 0,    "length": 800,  "confidence": 0.95},
    ], "missing_ranges": [{"start": 800, "end": 999}]},
    "ART-003": {"reconstruction_confidence": 0.82, "fragments_used": [
        {"fragment_id": "F020", "offset": 0,    "length": 512,  "confidence": 0.95},
        {"fragment_id": "F021", "offset": 512,  "length": 512,  "confidence": 0.61},
    ], "missing_ranges": []},
    "ART-004": {"reconstruction_confidence": 0.99, "fragments_used": [
        {"fragment_id": "F030", "offset": 0,    "length": 2048, "confidence": 0.99},
    ], "missing_ranges": []},
    "ART-005": {"reconstruction_confidence": 0.85, "fragments_used": [
        {"fragment_id": "F040", "offset": 0,    "length": 1024, "confidence": 0.90},
        {"fragment_id": "F041", "offset": 1024, "length": 512,  "confidence": 0.72},
    ], "missing_ranges": []},
    "ART-006": {"reconstruction_confidence": 0.79, "fragments_used": [
        {"fragment_id": "F050", "offset": 0,    "length": 800,  "confidence": 0.88},
    ], "missing_ranges": [{"start": 800, "end": 1200}]},
    "ART-007": {"reconstruction_confidence": 0.99, "fragments_used": [
        {"fragment_id": "F060", "offset": 0,    "length": 4096, "confidence": 0.99},
    ], "missing_ranges": []},
    "ART-008": {"reconstruction_confidence": 0.71, "fragments_used": [
        {"fragment_id": "F070", "offset": 0,    "length": 2048, "confidence": 0.85},
        {"fragment_id": "F071", "offset": 2048, "length": 1024, "confidence": 0.55},
    ], "missing_ranges": []},
    "ART-009": {"reconstruction_confidence": 0.52, "fragments_used": [
        {"fragment_id": "F080", "offset": 0,    "length": 128,  "confidence": 0.60},
    ], "missing_ranges": [{"start": 128, "end": 4096}]},
    "ART-010": {"reconstruction_confidence": 0.99, "fragments_used": [
        {"fragment_id": "F090", "offset": 0,    "length": 8192, "confidence": 0.99},
    ], "missing_ranges": []},
    "ART-011": {"reconstruction_confidence": 0.77, "fragments_used": [
        {"fragment_id": "F100", "offset": 0,    "length": 4096, "confidence": 0.90},
        {"fragment_id": "F101", "offset": 4096, "length": 2048, "confidence": 0.58},
    ], "missing_ranges": []},
    "ART-012": {"reconstruction_confidence": 0.88, "fragments_used": [
        {"fragment_id": "F110", "offset": 0,    "length": 4096, "confidence": 0.95},
    ], "missing_ranges": [{"start": 4096, "end": 8191}]},
    "ART-013": {"reconstruction_confidence": 0.99, "fragments_used": [
        {"fragment_id": "F120", "offset": 0,    "length": 2048, "confidence": 0.99},
    ], "missing_ranges": []},
    "ART-014": {"reconstruction_confidence": 0.82, "fragments_used": [
        {"fragment_id": "F130", "offset": 0,    "length": 1200, "confidence": 0.92},
    ], "missing_ranges": [{"start": 1200, "end": 1800}]},
    "ART-015": {"reconstruction_confidence": 0.76, "fragments_used": [
        {"fragment_id": "F140", "offset": 0,    "length": 2048, "confidence": 0.88},
    ], "missing_ranges": []},
}


def generate():
    fixtures = []
    for artifact_id, filename, file_type, builder, kwargs in ARTIFACTS:
        data = builder(**kwargs)
        out_path = DEMO_DIR / filename
        out_path.write_bytes(data)

        meta = FIXTURE_METADATA.get(artifact_id, {})
        fixture = {
            "artifact_id":               artifact_id,
            "filename":                  filename,
            "claimed_file_type":         file_type,
            "original_size":             int(len(data) * 1.1),  # Simulate 10% never recovered
            "reconstructed_size":        len(data),
            "fragments_used":            meta.get("fragments_used", []),
            "missing_ranges":            meta.get("missing_ranges", []),
            "header_status":             "valid",
            "reconstruction_confidence": meta.get("reconstruction_confidence", 0.85),
            "source_hash_sha256":        None,
            "reconstructed_hash_sha256": None,
            "filesystem_metadata": {
                "created":  "2026-09-18T09:20:00Z",
                "modified": "2026-09-24T10:30:00Z",
                "accessed": None
            },
            "embedded_metadata": {},
            "reconstructed_path":        str(DEMO_DIR / filename),
        }
        fixtures.append(fixture)
        print(f"  OK {artifact_id}: {filename} ({len(data):,} bytes)")

    (FIXTURES_DIR / "all_fixtures.json").write_text(
        json.dumps(fixtures, indent=2), encoding="utf-8")
    print(f"\nDemo data -> {DEMO_DIR}")
    print(f"Fixtures  -> {FIXTURES_DIR / 'all_fixtures.json'}")
    return fixtures


if __name__ == "__main__":
    print("Generating S21 Demo Dataset (15 synthetic artifacts)...")
    generate()
    print("Done.")
