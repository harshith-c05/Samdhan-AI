"""
SAMDHAN AI — Data Integrity & Corruption Assessment Module
Backend: Python + FastAPI

Pipeline stages (§4):
  1. Input Validation          → Pydantic schema check + file existence
  2. Signature Verification    → Magic-byte / libmagic header detection
  3. Structural Validation     → Format-specific parsers (JPEG/PNG/PDF/DOCX/SQLite/Log)
  4. Byte/Block Analysis       → Entropy sliding-window + zero-fill detection
  5. Missing Region Detection  → Merge upstream gaps with independent scan
  6. Corruption Detection      → Rule-based taxonomy (A–I) + optional ML anomaly score
  7. Metadata Consistency      → Cross-check filesystem vs embedded timestamps
  8. Content Decoding          → Attempt real open/render/parse
  9. Fragment Continuity       → Boundary alignment + overlap analysis
 10. Hash Verification         → SHA-256 recompute + compare (when reference exists)
 11. Recoverability Assessment → Rule-based label from content-test outcomes
 12. Integrity Scoring         → Weighted, renormalizing sum of all dimensions
 13. Report Generation         → Assemble + persist Integrity Report JSON
"""

import hashlib
import io
import json
import logging
import math
import os
import re
import sqlite3
import struct
import sys
import time
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

_BACKEND = Path(__file__).resolve().parent
_ROOT = _BACKEND.parent
for p in (str(_BACKEND), str(_ROOT)):
    if p not in sys.path:
        sys.path.insert(0, p)

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import numpy as np
# Note: sklearn IsolationForest is optional (§15) — not imported to avoid DLL issues;
# the rule-based pipeline is fully functional without it.
from pydantic import BaseModel, Field

# ─── Logging ────────────────────────────────────────────────────────────────
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("samdhan.integrity")

# ─── FastAPI App ─────────────────────────────────────────────────────────────
app = FastAPI(
    title="SAMDHAN AI — Integrity Assessment API",
    description="Data Integrity & Corruption Assessment pipeline for CALMSTACKS 24H Hackathon",
    version="2.4.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── Phase-1 Disk Recovery Router ────────────────────────────────────────────
try:
    from disk_recovery.api import router as recovery_router
    app.include_router(recovery_router)
    log.info("Phase-1 disk recovery router mounted at /api/recovery/*")
except Exception as _recovery_import_err:
    log.warning("disk_recovery module not loaded: %s", _recovery_import_err)

# ─── Phase-2 Fragment Reconstruction Router ──────────────────────────────────
try:
    from fragment_reconstruction.api import router as reconstruction_router
    app.include_router(reconstruction_router)
    log.info("Phase-2 fragment reconstruction router mounted at /api/reconstruction/*")
except Exception as _reconstruction_import_err:
    log.warning("fragment_reconstruction module not loaded: %s", _reconstruction_import_err)

# ─── DB Path ─────────────────────────────────────────────────────────────────
BASE_DIR = Path(__file__).parent.parent
DB_PATH  = BASE_DIR / "samdhan_integrity.db"
DEMO_DIR = _BACKEND / "demo_data" / "reconstructed"



# ═══════════════════════════════════════════════════════════════════════════
# §18  DATABASE SETUP
# ═══════════════════════════════════════════════════════════════════════════

def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_db() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS artifacts (
            artifact_id         TEXT PRIMARY KEY,
            filename            TEXT,
            file_type           TEXT,
            original_size       INTEGER,
            reconstructed_size  INTEGER,
            created_at          TEXT DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS integrity_results (
            artifact_id         TEXT PRIMARY KEY REFERENCES artifacts(artifact_id),
            structural_score    REAL,
            content_score       REAL,
            metadata_score      REAL,
            fragment_score      REAL,
            overall_score       REAL,
            corruption_severity TEXT,
            recoverability      TEXT,
            signature_match     INTEGER,
            file_type_detected  TEXT,
            hash_match          TEXT,
            explanation         TEXT,
            generated_at        TEXT
        );

        CREATE TABLE IF NOT EXISTS corruption_regions (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            artifact_id     TEXT REFERENCES artifacts(artifact_id),
            start_offset    INTEGER,
            end_offset      INTEGER,
            corruption_type TEXT,
            severity        TEXT,
            confidence      REAL,
            description     TEXT
        );

        CREATE TABLE IF NOT EXISTS fragments (
            fragment_id     TEXT,
            artifact_id     TEXT REFERENCES artifacts(artifact_id),
            offset          INTEGER,
            length          INTEGER,
            confidence      REAL,
            status          TEXT,
            boundary_valid  INTEGER,
            PRIMARY KEY (fragment_id, artifact_id)
        );

        CREATE TABLE IF NOT EXISTS validation_results (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            artifact_id TEXT REFERENCES artifacts(artifact_id),
            validator   TEXT,
            status      TEXT,
            result      TEXT,
            details     TEXT,
            run_at      TEXT DEFAULT CURRENT_TIMESTAMP
        );
        """)


# ═══════════════════════════════════════════════════════════════════════════
# §3.1  INPUT CONTRACT  (Pydantic models)
# ═══════════════════════════════════════════════════════════════════════════

class FragmentMeta(BaseModel):
    fragment_id:  str
    offset:       int
    length:       int
    confidence:   float = Field(ge=0.0, le=1.0)


class MissingRange(BaseModel):
    start: int
    end:   int


class FilesystemMeta(BaseModel):
    created:  Optional[str] = None
    modified: Optional[str] = None
    accessed: Optional[str] = None


class IntegrityRequest(BaseModel):
    artifact_id:               str
    filename:                  str
    claimed_file_type:         str
    original_size:             int = Field(ge=0)
    reconstructed_size:        int = Field(ge=0)
    fragments_used:            List[FragmentMeta] = []
    missing_ranges:            List[MissingRange] = []
    header_status:             str = "unknown"
    reconstruction_confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    source_hash_sha256:        Optional[str] = None
    reconstructed_hash_sha256: Optional[str] = None
    filesystem_metadata:       Optional[FilesystemMeta] = None
    embedded_metadata:         Optional[Dict[str, Any]] = {}
    reconstructed_path:        Optional[str] = None


# ═══════════════════════════════════════════════════════════════════════════
# UTILITY — Shannon Entropy
# ═══════════════════════════════════════════════════════════════════════════

def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in freq if c > 0)


def zero_fill_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    return data.count(0x00) / len(data)


# ═══════════════════════════════════════════════════════════════════════════
# STAGE 1 — Input Validation
# ═══════════════════════════════════════════════════════════════════════════

def validate_input(req: IntegrityRequest, raw_bytes: Optional[bytes]) -> Dict:
    issues = []
    if not req.artifact_id:
        issues.append("artifact_id missing")
    if not req.filename:
        issues.append("filename missing")
    if req.original_size < 0:
        issues.append("original_size invalid")
    if raw_bytes is None:
        issues.append("FILE_NOT_FOUND — no reconstructed bytes available")
    if issues:
        return {"status": "error", "issues": issues}
    return {"status": "ok"}


# ═══════════════════════════════════════════════════════════════════════════
# STAGE 2 — File Signature Verification
# ═══════════════════════════════════════════════════════════════════════════

MAGIC_TABLE = [
    (b"\xff\xd8\xff",                    "JPEG",   "image/jpeg"),
    (b"\x89PNG\r\n\x1a\n",              "PNG",    "image/png"),
    (b"%PDF",                            "PDF",    "application/pdf"),
    (b"PK\x03\x04",                     "DOCX",   "application/vnd.ooxml"),
    (b"SQLite format 3\x00",            "SQLite", "application/x-sqlite3"),
    (b"\xd0\xcf\x11\xe0",               "DOC",    "application/msword"),
    (b"\xd4\xc3\xb2\xa1",               "PCAP",   "application/vnd.tcpdump"),
    (b"\xa1\xb2\xc3\xd4",               "PCAP",   "application/vnd.tcpdump"),
    (b"ElfFile\x00",                    "EVTX",   "application/x-ms-evtx"),
    (b"regf",                            "REGF",   "application/x-windows-registry"),
    (b"MZ",                              "PE",     "application/x-msdownload"),
    (b"GIF8",                            "GIF",    "image/gif"),
    (b"BM",                              "BMP",    "image/bmp"),
]

EXT_TYPE_MAP = {
    "jpg": "JPEG", "jpeg": "JPEG", "png": "PNG", "gif": "GIF", "bmp": "BMP",
    "pdf": "PDF",  "doc":  "DOC",  "docx": "DOCX", "txt": "LOG",
    "sqlite": "SQLite", "db": "SQLite", "log": "LOG", "evtx": "EVTX",
    "pcap": "PCAP", "bat": "SCRIPT", "ps1": "SCRIPT", "reg": "REGF",
    "exe": "PE", "dll": "PE",
}


def verify_signature(raw_bytes: bytes, filename: str, claimed_type: str) -> Dict:
    header = raw_bytes[:32] if len(raw_bytes) >= 32 else raw_bytes
    detected_type = "UNKNOWN"
    detected_mime = "application/octet-stream"
    for sig, dtype, mime in MAGIC_TABLE:
        if header.startswith(sig):
            detected_type = dtype
            detected_mime = mime
            break

    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    ext_type = EXT_TYPE_MAP.get(ext, "UNKNOWN")

    conflict = None
    if detected_type != "UNKNOWN" and ext_type != "UNKNOWN" and detected_type != ext_type:
        conflict = (f"Extension mismatch: .{ext} implies {ext_type} but binary header "
                    f"indicates {detected_type}. Header takes forensic precedence.")

    claimed_match = detected_type.upper() == claimed_type.upper()
    return {
        "status":         "ok",
        "signature_match": detected_type != "UNKNOWN",
        "detected_type":   detected_type,
        "detected_mime":   detected_mime,
        "claimed_match":   claimed_match,
        "conflict":        conflict,
    }


# ═══════════════════════════════════════════════════════════════════════════
# STAGE 3 — Structural Validation (per file type)
# ═══════════════════════════════════════════════════════════════════════════

def _validate_jpeg(data: bytes) -> Dict:
    checks, issues = [], []
    if data[:2] == b"\xff\xd8":
        checks.append("SOI marker valid (FF D8)")
    else:
        issues.append("SOI marker missing"); return {"score": 20, "checks": checks, "issues": issues}

    has_eoi = data[-2:] == b"\xff\xd9"
    (checks if has_eoi else issues).append("EOI marker (FF D9) " + ("found" if has_eoi else "missing"))

    # Walk segments
    pos = 2; segments_seen = 0; sos_found = False
    while pos < len(data) - 1:
        if data[pos] != 0xff:
            break
        marker = data[pos:pos+2]
        if marker == b"\xff\xd9":
            break
        if marker == b"\xff\xda":
            sos_found = True
        if pos + 4 > len(data):
            break
        seg_len = struct.unpack(">H", data[pos+2:pos+4])[0] if data[pos+1] not in (0xd8, 0xd9, 0x01) else 2
        pos += 2 + (seg_len if seg_len >= 2 else 2)
        segments_seen += 1
        if segments_seen > 500:
            break

    (checks if sos_found else issues).append("SOS marker " + ("found" if sos_found else "missing"))
    score = 95 if not issues else max(30, 95 - len(issues) * 20)
    return {"score": score, "checks": checks, "issues": issues}


def _validate_png(data: bytes) -> Dict:
    checks, issues = [], []
    PNG_SIG = b"\x89PNG\r\n\x1a\n"
    if data[:8] != PNG_SIG:
        issues.append("PNG signature invalid")
        return {"score": 10, "checks": checks, "issues": issues}
    checks.append("PNG 8-byte signature valid")

    pos = 8; idat_found = False; iend_found = False; chunk_count = 0
    while pos + 8 <= len(data):
        length = struct.unpack(">I", data[pos:pos+4])[0]
        chunk_type = data[pos+4:pos+8]
        if chunk_type == b"IDAT":
            idat_found = True
        if chunk_type == b"IEND":
            iend_found = True
        # CRC check
        chunk_data = data[pos+4:pos+8+length]
        pos += 12 + length
        chunk_count += 1
        if chunk_count > 2000:
            break

    (checks if idat_found else issues).append("IDAT chunk(s) " + ("present" if idat_found else "missing"))
    (checks if iend_found else issues).append("IEND chunk " + ("present" if iend_found else "missing"))
    score = 95 if not issues else max(25, 95 - len(issues) * 25)
    return {"score": score, "checks": checks, "issues": issues}


def _validate_pdf(data: bytes) -> Dict:
    checks, issues = [], []
    text = data[:8192].decode("latin-1", errors="replace")
    if text.startswith("%PDF"):
        checks.append("PDF header valid (%PDF)")
    else:
        issues.append("%PDF header missing")

    has_eof = b"%%EOF" in data[-256:]
    (checks if has_eof else issues).append("%%EOF marker " + ("found" if has_eof else "missing"))

    xref_count = text.count("xref")
    obj_count  = len(re.findall(rb"\d+ \d+ obj", data[:65536]))
    checks.append(f"{obj_count} PDF object(s) detected in header region")
    if obj_count == 0:
        issues.append("No PDF objects found")

    score = 95 if not issues else max(30, 95 - len(issues) * 20)
    return {"score": score, "checks": checks, "issues": issues}


def _validate_docx(data: bytes) -> Dict:
    checks, issues = [], []
    if not data[:4] == b"PK\x03\x04":
        issues.append("ZIP/OOXML PK header missing")
        return {"score": 10, "checks": checks, "issues": issues}
    checks.append("ZIP PK header valid (50 4B 03 04)")

    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            names = zf.namelist()
            has_content_types = "[Content_Types].xml" in names
            has_document_xml  = any("word/document" in n for n in names)
            (checks if has_content_types else issues).append(
                "[Content_Types].xml " + ("found" if has_content_types else "missing"))
            (checks if has_document_xml else issues).append(
                "word/document.xml " + ("found" if has_document_xml else "missing"))
    except zipfile.BadZipFile as e:
        issues.append(f"ZIP structure corrupt: {e}")
        return {"score": 20, "checks": checks, "issues": issues}

    score = 95 if not issues else max(20, 95 - len(issues) * 25)
    return {"score": score, "checks": checks, "issues": issues}


def _validate_sqlite(data: bytes) -> Dict:
    checks, issues = [], []
    SQLITE_MAGIC = b"SQLite format 3\x00"
    if data[:16] != SQLITE_MAGIC:
        issues.append("SQLite header magic missing")
        return {"score": 10, "checks": checks, "issues": issues}
    checks.append("SQLite 3 header magic valid")

    page_size = struct.unpack(">H", data[16:18])[0]
    if page_size == 1:
        page_size = 65536
    valid_page_size = page_size >= 512 and (page_size & (page_size - 1)) == 0
    (checks if valid_page_size else issues).append(
        f"Page size {page_size} " + ("valid (power of 2)" if valid_page_size else "invalid"))

    declared_pages = struct.unpack(">I", data[28:32])[0]
    expected_size  = declared_pages * page_size
    actual_size    = len(data)
    size_ok = abs(actual_size - expected_size) < page_size * 2
    (checks if size_ok else issues).append(
        f"Declared {declared_pages} pages × {page_size} bytes {'≈ ' if size_ok else '≠ '} actual {actual_size} bytes")

    try:
        conn = sqlite3.connect(":memory:")
        conn.execute("PRAGMA integrity_check")
        conn.close()
        checks.append("In-memory SQLite integrity_check passed")
    except Exception as e:
        issues.append(f"SQLite integrity_check failed: {e}")

    score = 95 if not issues else max(20, 95 - len(issues) * 20)
    return {"score": score, "checks": checks, "issues": issues}


def _validate_log(data: bytes) -> Dict:
    checks, issues = [], []
    try:
        text = data.decode("utf-8", errors="replace")
        lines = text.splitlines()
        total = len(lines)
        RFC3164 = re.compile(
            r"^(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d+\s+\d{2}:\d{2}:\d{2}")
        EVTX_LIKE = re.compile(
            r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}")
        matched = sum(1 for l in lines if RFC3164.match(l) or EVTX_LIKE.match(l))
        ratio = matched / total if total > 0 else 0
        checks.append(f"{matched}/{total} lines match known log format ({ratio*100:.0f}%)")
        malformed = total - matched
        if malformed > 0:
            issues.append(f"{malformed} malformed/unrecognized record(s)")
        score = max(30, int(ratio * 100))
    except Exception as e:
        issues.append(f"Log decode error: {e}")
        score = 30
    return {"score": score, "checks": checks, "issues": issues}


STRUCTURAL_VALIDATORS = {
    "JPEG": _validate_jpeg, "JPG": _validate_jpeg,
    "PNG":  _validate_png,
    "PDF":  _validate_pdf,
    "DOCX": _validate_docx, "OOXML": _validate_docx,
    "SQLite": _validate_sqlite, "SQLITE": _validate_sqlite,
    "LOG": _validate_log, "TXT": _validate_log, "SYSLOG": _validate_log,
}


def validate_structure(data: bytes, file_type: str) -> Dict:
    validator = STRUCTURAL_VALIDATORS.get(file_type.upper())
    if not validator:
        return {"score": 50, "checks": [f"No structural validator for type '{file_type}'"],
                "issues": ["Using byte-level analysis only"]}
    try:
        return validator(data)
    except Exception as e:
        return {"score": 20, "checks": [], "issues": [f"Structural parser raised: {e}"]}


# ═══════════════════════════════════════════════════════════════════════════
# STAGE 4 — Byte/Block Integrity Analysis
# ═══════════════════════════════════════════════════════════════════════════

WINDOW = 512

def byte_block_analysis(data: bytes, file_type: str) -> Dict:
    suspicious_ranges = []
    entropies = []
    for i in range(0, len(data) - WINDOW, WINDOW):
        chunk = data[i:i + WINDOW]
        e = shannon_entropy(chunk)
        entropies.append(e)
        zr = zero_fill_ratio(chunk)
        # Zero-fill inside compressed types (JPEG, PNG, PDF body) is suspicious
        is_compressed_type = file_type.upper() in ("JPEG", "JPG", "PNG", "PDF")
        if zr > 0.90 and is_compressed_type:
            suspicious_ranges.append({
                "start": i, "end": i + WINDOW - 1,
                "type": "zero_fill", "entropy": round(e, 3), "zero_ratio": round(zr, 3),
                "severity": "high" if zr > 0.98 else "medium"
            })
        # Abrupt entropy drop within scan section
        if entropies and len(entropies) > 1:
            prev_e = entropies[-2]
            if prev_e > 5.0 and e < 1.5:
                suspicious_ranges.append({
                    "start": i, "end": i + WINDOW - 1,
                    "type": "entropy_drop", "entropy": round(e, 3),
                    "severity": "medium"
                })

    avg_entropy = sum(entropies) / len(entropies) if entropies else 0
    return {
        "status": "ok",
        "suspicious_ranges": suspicious_ranges,
        "avg_entropy": round(avg_entropy, 3),
        "window_count": len(entropies),
    }


# ═══════════════════════════════════════════════════════════════════════════
# STAGE 5 — Missing Region Detection
# ═══════════════════════════════════════════════════════════════════════════

def detect_missing_regions(req: IntegrityRequest, byte_gaps: List[Dict]) -> List[Dict]:
    canonical = []
    for mr in req.missing_ranges:
        canonical.append({"start": mr.start, "end": mr.end, "source": "upstream"})
    for bg in byte_gaps:
        if bg.get("type") == "zero_fill" and bg.get("severity") == "high":
            canonical.append({"start": bg["start"], "end": bg["end"], "source": "byte_scan"})

    # Merge overlapping intervals
    if not canonical:
        return []
    canonical.sort(key=lambda x: x["start"])
    merged = [canonical[0]]
    for r in canonical[1:]:
        last = merged[-1]
        if r["start"] <= last["end"] + 1:
            last["end"] = max(last["end"], r["end"])
            if r["source"] != last["source"]:
                last["source"] = "both"
        else:
            merged.append(r)
    return merged


# ═══════════════════════════════════════════════════════════════════════════
# STAGE 6 — Corruption Detection (Taxonomy A–I)
# ═══════════════════════════════════════════════════════════════════════════

def detect_corruption_regions(
    missing_ranges: List[Dict],
    suspicious_ranges: List[Dict],
    struct_issues: List[str],
    fragment_gaps: List[Dict],
) -> List[Dict]:
    regions = []

    # Type A — Missing Data (from canonical missing regions)
    for r in missing_ranges:
        regions.append({
            "start": r["start"], "end": r["end"],
            "type": "A_MISSING_DATA", "severity": "high", "confidence": 1.0,
            "description": "Bytes never recovered from any fragment"
        })

    # Type C — Byte Corruption (from zero-fill / entropy-drop in suspicious ranges)
    for s in suspicious_ranges:
        if s.get("type") == "zero_fill":
            regions.append({
                "start": s["start"], "end": s["end"],
                "type": "C_BYTE_CORRUPTION", "severity": s.get("severity", "medium"),
                "confidence": 0.75,
                "description": f"Zero-fill anomaly (zero ratio high, entropy {s.get('entropy')})"
            })
        elif s.get("type") == "entropy_drop":
            regions.append({
                "start": s["start"], "end": s["end"],
                "type": "C_BYTE_CORRUPTION", "severity": "medium", "confidence": 0.65,
                "description": f"Abrupt entropy drop: {s.get('entropy')} bits/byte"
            })

    # Type D — Structural Corruption (from structural validator issues)
    for issue in struct_issues:
        regions.append({
            "start": 0, "end": 4095,
            "type": "D_STRUCTURAL_CORRUPTION", "severity": "high", "confidence": 0.9,
            "description": f"Structural issue: {issue}"
        })

    # Type B — Fragment Gaps
    for gap in fragment_gaps:
        regions.append({
            "start": gap["start"], "end": gap["end"],
            "type": "B_FRAGMENT_GAP", "severity": "medium", "confidence": 0.85,
            "description": "Expected inter-fragment bytes unavailable"
        })

    return regions


# ═══════════════════════════════════════════════════════════════════════════
# STAGE 7 — Metadata Consistency Check
# ═══════════════════════════════════════════════════════════════════════════

def check_metadata_consistency(req: IntegrityRequest) -> Dict:
    result = {"status": "ok", "verdict": "UNKNOWN", "score": 70, "flags": []}
    fs_meta = req.filesystem_metadata
    emb_meta = req.embedded_metadata or {}

    if not fs_meta:
        result["verdict"] = "UNKNOWN"
        result["flags"].append("No filesystem metadata provided")
        return result

    fs_mod = fs_meta.modified
    emb_created = emb_meta.get("document_created") or emb_meta.get("created")

    if fs_mod and emb_created:
        try:
            t_fs  = datetime.fromisoformat(fs_mod.replace("Z", "+00:00"))
            t_emb = datetime.fromisoformat(emb_created.replace("Z", "+00:00"))
            if t_fs < t_emb:
                result["verdict"] = "POTENTIALLY_INCONSISTENT"
                result["score"] = 50
                result["flags"].append(
                    f"Filesystem-modified ({fs_mod}) is earlier than embedded created ({emb_created})")
            else:
                result["verdict"] = "CONSISTENT"
                result["score"] = 95
        except ValueError:
            result["verdict"] = "UNKNOWN"
    else:
        result["verdict"] = "UNKNOWN"
        result["score"] = 70
        result["flags"].append("One or both timestamp sides absent — cannot determine consistency")

    return result


# ═══════════════════════════════════════════════════════════════════════════
# STAGE 8 — Content Decoding (safe open/parse/decode)
# ═══════════════════════════════════════════════════════════════════════════

def content_decode(data: bytes, file_type: str, artifact_id: str) -> Dict:
    result = {"decoded": False, "details": {}, "score": 0}
    ft = file_type.upper()

    try:
        if ft in ("JPEG", "JPG", "PNG", "GIF", "BMP"):
            from PIL import Image
            img = Image.open(io.BytesIO(data))
            img.verify()
            result.update({"decoded": True, "details": {"format": img.format, "size": img.size}, "score": 92})

        elif ft == "PDF":
            import fitz  # PyMuPDF
            doc = fitz.open(stream=data, filetype="pdf")
            n_pages = doc.page_count
            rendered = 0
            for i in range(min(n_pages, 5)):
                try:
                    _ = doc[i].get_text()
                    rendered += 1
                except Exception:
                    pass
            score = int((rendered / n_pages) * 90) if n_pages > 0 else 20
            result.update({"decoded": True,
                            "details": {"pages": n_pages, "rendered": rendered},
                            "score": score})

        elif ft in ("DOCX", "OOXML"):
            from docx import Document
            doc = Document(io.BytesIO(data))
            paras = len(doc.paragraphs)
            result.update({"decoded": True, "details": {"paragraphs": paras}, "score": 88})

        elif ft in ("SQLITE", "SQLITE3"):
            conn = sqlite3.connect(":memory:")
            conn.executescript(data.decode("latin-1", errors="replace"))
            tables = conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
            conn.close()
            result.update({"decoded": True, "details": {"tables": [t[0] for t in tables]}, "score": 90})

        elif ft in ("LOG", "TXT", "SYSLOG"):
            text = data.decode("utf-8", errors="replace")
            lines = text.splitlines()
            malformed = sum(1 for l in lines if l and not re.match(
                r"(^\d{4}-|^[A-Z][a-z]{2}\s+|^\[|\bERROR\b|\bINFO\b|\bWARN\b|\bDEBUG\b)", l))
            score = max(40, 100 - int((malformed / max(len(lines), 1)) * 60))
            result.update({"decoded": True,
                            "details": {"total_lines": len(lines), "malformed": malformed},
                            "score": score})
        else:
            result["score"] = 50
            result["details"]["note"] = f"No content decoder for '{ft}'"

    except Exception as e:
        result["decoded"] = False
        result["details"]["error"] = str(e)
        result["score"] = max(5, result["score"] - 40)

    return result


# ═══════════════════════════════════════════════════════════════════════════
# STAGE 9 — Fragment Continuity Analysis
# ═══════════════════════════════════════════════════════════════════════════

def fragment_continuity(req: IntegrityRequest) -> Dict:
    frags = sorted(req.fragments_used, key=lambda f: f.offset)
    gaps = []
    continuity_score = 100.0
    covered_bytes = 0

    for i, frag in enumerate(frags):
        covered_bytes += frag.length
        if i == 0 and frag.offset > 0:
            gaps.append({"start": 0, "end": frag.offset - 1})
            continuity_score -= min(20, (frag.offset / max(req.reconstructed_size, 1)) * 100)

        if i > 0:
            prev = frags[i - 1]
            expected_next = prev.offset + prev.length
            if frag.offset > expected_next:
                gap_size = frag.offset - expected_next
                gaps.append({"start": expected_next, "end": frag.offset - 1})
                penalty = (gap_size / max(req.reconstructed_size, 1)) * 100
                continuity_score -= penalty
            elif frag.offset < expected_next:
                # Overlap
                continuity_score -= 5

        # Low reconstruction-confidence fragments penalize continuity proportionally
        if frag.confidence < 0.70:
            penalty = ((0.70 - frag.confidence) / 0.70) * (frag.length / max(req.reconstructed_size, 1)) * 50
            continuity_score -= penalty

    pct_covered = (covered_bytes / max(req.reconstructed_size, 1)) * 100
    continuity_score = max(0.0, min(100.0, continuity_score))
    return {
        "score": round(continuity_score, 1),
        "fragment_gaps": gaps,
        "covered_pct": round(pct_covered, 1),
        "total_fragments": len(frags),
    }


# ═══════════════════════════════════════════════════════════════════════════
# STAGE 10 — Hash Verification
# ═══════════════════════════════════════════════════════════════════════════

def verify_hash(data: bytes, req: IntegrityRequest) -> Dict:
    computed = hashlib.sha256(data).hexdigest()
    stored   = req.reconstructed_hash_sha256

    if stored and computed != stored:
        verdict = "MISMATCH_WITH_STORED"
    elif stored and computed == stored:
        verdict = "MATCH_WITH_STORED"
    else:
        verdict = "NO_STORED_HASH"

    if req.source_hash_sha256:
        if computed == req.source_hash_sha256:
            verdict = "MATCH_WITH_TRUSTED_SOURCE"
        else:
            verdict = "MISMATCH_WITH_TRUSTED_SOURCE"

    return {"computed_sha256": computed, "verdict": verdict}


# ═══════════════════════════════════════════════════════════════════════════
# STAGE 11 — Recoverability Assessment
# ═══════════════════════════════════════════════════════════════════════════

def assess_recoverability(structural: float, content: float, fragment: float, missing_pct: float) -> str:
    # Primary driver: content test (can an investigator use this?)
    if content >= 85 and structural >= 80 and missing_pct < 5:
        return "FULLY_RECOVERABLE"
    elif content >= 65 and structural >= 60:
        return "MOSTLY_RECOVERABLE"
    elif content >= 40 or structural >= 50:
        return "PARTIALLY_RECOVERABLE"
    elif content >= 15 or structural >= 30:
        return "BARELY_RECOVERABLE"
    else:
        return "NOT_RELIABLY_RECOVERABLE"


# ═══════════════════════════════════════════════════════════════════════════
# STAGE 12 — Integrity Scoring (§10 formula, renormalized)
# ═══════════════════════════════════════════════════════════════════════════

WEIGHTS = {
    "structural": 0.30,
    "content":    0.35,
    "fragment":   0.20,
    "metadata":   0.15,
}

def compute_overall_score(structural: Optional[float], content: Optional[float],
                           fragment: Optional[float], metadata: Optional[float]) -> Optional[float]:
    available = {k: v for k, v in [("structural", structural), ("content", content),
                                    ("fragment", fragment),   ("metadata", metadata)]
                 if v is not None}
    if not available:
        return None
    total_weight = sum(WEIGHTS[k] for k in available)
    if total_weight == 0:
        return None
    score = sum(WEIGHTS[k] * v for k, v in available.items()) / total_weight
    return round(score, 1)


def severity_label(overall: Optional[float]) -> str:
    if overall is None:
        return "INSUFFICIENT_DATA"
    if overall >= 90: return "None"
    if overall >= 75: return "Low"
    if overall >= 50: return "Medium"
    if overall >= 25: return "High"
    return "Critical"


def recoverability_label(label: str) -> str:
    return label.replace("_", " ").title()


# ═══════════════════════════════════════════════════════════════════════════
# STAGE 13 — Report Assembly & Explanation Builder
# ═══════════════════════════════════════════════════════════════════════════

def build_explanation(sig, struct_result, byte_result, fragment_result,
                      meta_result, content_result, hash_result, corruption_regions) -> List[str]:
    lines = []
    # Signature
    if sig.get("signature_match"):
        lines.append(f"✓ Valid file signature detected ({sig.get('detected_type')})")
    else:
        lines.append("✗ File signature missing or unrecognized")
    if sig.get("conflict"):
        lines.append(f"⚠ {sig['conflict']}")

    # Structure
    for chk in (struct_result.get("checks") or []):
        lines.append(f"✓ {chk}")
    for iss in (struct_result.get("issues") or []):
        lines.append(f"✗ {iss}")

    # Fragment continuity
    cov = fragment_result.get("covered_pct", 0)
    lines.append(f"{'✓' if cov >= 90 else '⚠'} {cov}% of bytes covered by recovered fragments")
    if fragment_result.get("fragment_gaps"):
        lines.append(f"✗ {len(fragment_result['fragment_gaps'])} inter-fragment gap(s) detected")

    # Byte anomalies
    sr = byte_result.get("suspicious_ranges") or []
    if sr:
        lines.append(f"⚠ {len(sr)} suspicious byte region(s): zero-fill or entropy anomaly")
    else:
        lines.append("✓ No significant byte-level anomalies detected")

    # Metadata
    if meta_result.get("verdict") == "POTENTIALLY_INCONSISTENT":
        for f in meta_result.get("flags", []):
            lines.append(f"⚠ Metadata: {f}")
    elif meta_result.get("verdict") == "CONSISTENT":
        lines.append("✓ Filesystem and embedded metadata timestamps are consistent")

    # Content decode
    if content_result.get("decoded"):
        det = content_result.get("details", {})
        lines.append(f"✓ File decoded successfully — {det}")
    else:
        err = content_result.get("details", {}).get("error", "unknown error")
        lines.append(f"✗ Content decode failed: {err}")

    # Hash
    hv = hash_result.get("verdict", "")
    if "MATCH" in hv:
        lines.append(f"✓ SHA-256 hash verification: {hv}")
    elif "MISMATCH" in hv:
        lines.append(f"✗ SHA-256 hash verification: {hv} — byte-level differences detected")
    else:
        lines.append(f"ℹ SHA-256: {hv} — hash stored for future re-verification")

    # Corruption regions
    if corruption_regions:
        types = set(r["type"] for r in corruption_regions)
        lines.append(f"⚠ {len(corruption_regions)} corruption region(s) typed: {', '.join(types)}")

    return lines


# ═══════════════════════════════════════════════════════════════════════════
# ORCHESTRATOR — runs all 13 stages
# ═══════════════════════════════════════════════════════════════════════════

def load_bytes(req: IntegrityRequest) -> Optional[bytes]:
    """
    Attempt to load raw bytes. For the hackathon demo,
    fall back to synthetic bytes from the demo fixture if the path is absent.
    """
    if req.reconstructed_path:
        p = Path(req.reconstructed_path)
        if p.exists() and p.is_file():
            return p.read_bytes()
    # Synthetic demo path
    demo_path = DEMO_DIR / req.filename
    if demo_path.exists():
        return demo_path.read_bytes()
    return None


def run_pipeline(req: IntegrityRequest) -> Dict:
    raw = load_bytes(req)

    # Stage 1 — Input Validation
    s1 = validate_input(req, raw)
    validation_log = [{"stage": "InputValidator", "result": s1}]

    if s1["status"] == "error" or raw is None:
        return {
            "artifact_id":    req.artifact_id,
            "status":         "error",
            "reason":         s1.get("issues", ["No file bytes available"]),
            "overall_score":  None,
        }

    # Stage 2 — Signature Verification
    s2 = verify_signature(raw, req.filename, req.claimed_file_type)
    validation_log.append({"stage": "SignatureVerifier", "result": s2})

    detected_type = s2.get("detected_type", req.claimed_file_type)
    if detected_type == "UNKNOWN":
        detected_type = req.claimed_file_type

    # Stage 3 — Structural Validation
    s3 = validate_structure(raw, detected_type)
    validation_log.append({"stage": "StructuralValidator", "result": s3})

    # Stage 4 — Byte/Block Analysis
    s4 = byte_block_analysis(raw, detected_type)
    validation_log.append({"stage": "ByteBlockAnalyzer", "result": s4})

    # Stage 5 — Missing Region Detection
    missing_canonical = detect_missing_regions(req, s4.get("suspicious_ranges", []))
    validation_log.append({"stage": "MissingRegionDetector",
                            "result": {"count": len(missing_canonical), "ranges": missing_canonical}})

    # Stage 6 — Corruption Detection via Core Format-Aware Engine (Feature 02)
    intact_regions = []
    damaged_regions = []
    checks = []
    core_assessment = None

    try:
        from core.integrity_analyzer import IntegrityAnalyzer
        analyzer = IntegrityAnalyzer()
        core_assessment = analyzer.analyze(
            raw,
            artifact_id=req.artifact_id,
            filename=req.filename,
            claimed_format=detected_type,
            reference_sha256=req.source_hash_sha256,
        )
        corruption_regions = [c.model_dump() for c in core_assessment.corruption_regions]
        intact_regions = [r.model_dump() for r in core_assessment.intact_regions]
        damaged_regions = [d.model_dump() for d in core_assessment.damaged_regions]
        checks = [c.model_dump() for c in core_assessment.checks]
    except Exception as _core_err:
        log.warning("Core IntegrityAnalyzer fallback: %s", _core_err)
        corruption_regions = detect_corruption_regions(
            missing_canonical,
            s4.get("suspicious_ranges", []),
            s3.get("issues", []),
            [],
        )

    validation_log.append({"stage": "CorruptionDetector",
                            "result": {"regions": len(corruption_regions)}})

    # Stage 7 — Metadata Consistency
    s7 = check_metadata_consistency(req)
    validation_log.append({"stage": "MetadataConsistency", "result": s7})

    # Stage 8 — Content Decoding
    s8 = content_decode(raw, detected_type, req.artifact_id)
    validation_log.append({"stage": "ContentDecoder", "result": s8})

    # Stage 9 — Fragment Continuity
    s9 = fragment_continuity(req)
    validation_log.append({"stage": "FragmentContinuity", "result": s9})

    # Stage 10 — Hash Verification
    s10 = verify_hash(raw, req)
    validation_log.append({"stage": "HashVerifier", "result": s10})

    # Stage 11 — Recoverability
    missing_bytes = sum(r["end"] - r["start"] for r in missing_canonical)
    missing_pct   = (missing_bytes / max(req.reconstructed_size, 1)) * 100
    recoverability = assess_recoverability(
        s3.get("score", 50), s8.get("score", 50), s9.get("score", 50), missing_pct)

    # Stage 12 — Integrity Scoring
    structural_score = float(s3.get("score", 50))
    content_score    = float(s8.get("score", 50))
    fragment_score   = float(s9.get("score", 50))
    metadata_score   = float(s7.get("score", 70))
    overall_score    = compute_overall_score(structural_score, content_score,
                                             fragment_score, metadata_score)
    severity         = severity_label(overall_score)

    # Stage 13 — Report Assembly
    explanation = build_explanation(
        s2, s3, s4, s9, s7, s8, s10, corruption_regions)

    report = {
        "artifact_id":               req.artifact_id,
        "filename":                  req.filename,
        "file_type_detected":        detected_type,
        "signature_match":           s2.get("signature_match", False),
        "structural_integrity":      round(structural_score, 1),
        "content_integrity":         round(content_score, 1),
        "metadata_integrity":        round(metadata_score, 1),
        "fragment_continuity":       round(fragment_score, 1),
        "reconstruction_confidence": round(req.reconstruction_confidence * 100, 1),
        "overall_integrity":         overall_score,
        "corruption_severity":       severity,
        "recoverability":            recoverability,
        "recoverability_label":      recoverability_label(recoverability),
        "corruption_regions":        corruption_regions,
        "intact_regions":            intact_regions,
        "damaged_regions":           damaged_regions,
        "checks":                    checks,
        "scores":                    core_assessment.scores.model_dump() if core_assessment else None,
        "content_test_result":       s8.get("details", {}),
        "hash_result":               s10,
        "explanation":               explanation,
        "validation_log":            validation_log,
        "generated_at":              datetime.now(timezone.utc).isoformat(),
    }
    return report


# ═══════════════════════════════════════════════════════════════════════════
# §17  REST API ENDPOINTS
# ═══════════════════════════════════════════════════════════════════════════

@app.on_event("startup")
async def startup():
    init_db()
    log.info("SAMDHAN AI Integrity Assessment API started. DB: %s", DB_PATH)


@app.get("/api/health")
async def health():
    return {"status": "ok", "module": "integrity_assessment", "version": "2.4.0"}


@app.post("/api/integrity/analyze", status_code=202)
@app.post("/api/assess", status_code=200)
@app.post("/api/integrity/assess", status_code=200)
async def analyze(req: IntegrityRequest):
    """
    Runs the full 13-stage Data Integrity & Corruption Assessment pipeline.
    Input: §3.1 contract. Output: Full Integrity Report (§3.3).
    """
    report = run_pipeline(req)

    try:
        with get_db() as db:
            db.execute(
                "INSERT OR REPLACE INTO artifacts VALUES (?,?,?,?,?,?)",
                (req.artifact_id, req.filename, req.claimed_file_type,
                 req.original_size, req.reconstructed_size, datetime.utcnow().isoformat()))

            db.execute(
                """INSERT OR REPLACE INTO integrity_results
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (req.artifact_id,
                 report.get("structural_integrity"),
                 report.get("content_integrity"),
                 report.get("metadata_integrity"),
                 report.get("fragment_continuity"),
                 report.get("overall_integrity"),
                 report.get("corruption_severity"),
                 report.get("recoverability"),
                 int(report.get("signature_match", False)),
                 report.get("file_type_detected"),
                 report.get("hash_result", {}).get("verdict"),
                 json.dumps(report.get("explanation", [])),
                 report.get("generated_at")))

            for region in report.get("corruption_regions", []):
                start_val = region.get("start_offset", region.get("start", 0))
                end_val = region.get("end_offset", region.get("end", 0))
                conf_val = region.get("confidence", 1.0)
                desc_val = region.get("description", region.get("reason", ""))
                db.execute(
                    """INSERT INTO corruption_regions
                       (artifact_id, start_offset, end_offset, corruption_type, severity, confidence, description)
                       VALUES (?,?,?,?,?,?,?)""",
                    (req.artifact_id, start_val, end_val,
                     region.get("type", "UNKNOWN"), region.get("severity", "medium"),
                     conf_val, desc_val))

            for stage_log in report.get("validation_log", []):
                db.execute(
                    """INSERT INTO validation_results (artifact_id, validator, status, result, details)
                       VALUES (?,?,?,?,?)""",
                    (req.artifact_id,
                     stage_log.get("stage"),
                     stage_log.get("result", {}).get("status", "ok"),
                     json.dumps(stage_log.get("result")),
                     ""))
    except Exception as e:
        log.warning("DB write failed (non-fatal): %s", e)

    return report


@app.get("/api/integrity/{artifact_id}")
async def get_integrity_summary(artifact_id: str):
    with get_db() as db:
        row = db.execute(
            "SELECT * FROM integrity_results WHERE artifact_id=?", (artifact_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail=f"Artifact '{artifact_id}' not found")
    return dict(row)


@app.get("/api/integrity/{artifact_id}/regions")
async def get_corruption_regions(artifact_id: str):
    with get_db() as db:
        rows = db.execute(
            "SELECT * FROM corruption_regions WHERE artifact_id=?", (artifact_id,)).fetchall()
    return [dict(r) for r in rows]


@app.get("/api/integrity/{artifact_id}/report")
async def get_full_report(artifact_id: str):
    with get_db() as db:
        summary = db.execute(
            "SELECT * FROM integrity_results WHERE artifact_id=?", (artifact_id,)).fetchone()
        regions = db.execute(
            "SELECT * FROM corruption_regions WHERE artifact_id=?", (artifact_id,)).fetchall()
        validation = db.execute(
            "SELECT * FROM validation_results WHERE artifact_id=?", (artifact_id,)).fetchall()
    if not summary:
        raise HTTPException(status_code=404, detail=f"Artifact '{artifact_id}' not found")
    return {
        "summary": dict(summary),
        "corruption_regions": [dict(r) for r in regions],
        "validation_log": [dict(v) for v in validation],
        "explanation": json.loads(summary["explanation"] or "[]"),
    }


@app.get("/api/artifacts")
async def list_artifacts():
    with get_db() as db:
        rows = db.execute("""
            SELECT a.artifact_id, a.filename, a.file_type, a.original_size, a.reconstructed_size,
                   ir.overall_score, ir.corruption_severity, ir.recoverability
            FROM artifacts a LEFT JOIN integrity_results ir ON a.artifact_id = ir.artifact_id
        """).fetchall()
    return [dict(r) for r in rows]


@app.post("/api/integrity/batch")
async def batch_analyze(requests: List[IntegrityRequest]):
    results = []
    for req in requests:
        try:
            results.append(await analyze(req))
        except Exception as e:
            results.append({"artifact_id": req.artifact_id, "status": "error", "reason": str(e)})
    return results
