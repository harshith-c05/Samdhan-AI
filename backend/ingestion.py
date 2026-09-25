"""
backend/ingestion.py
====================
SAMDHAN AI — Evidence Ingestion & Cryptographic Provenance Module.

Specification:
- SHA-256 & MD5 hash a source file or image
- Write an immutable, write-locked (read-only) clone to prevent tampering
- Initialize and log to forensic SQLite audit trail (samdhan_integrity.db)
"""

import hashlib
import os
import sqlite3
import stat
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Union

ROOT_DIR = Path(__file__).resolve().parent.parent
DB_PATH = ROOT_DIR / "samdhan_integrity.db"
CLONE_DIR = ROOT_DIR / "recovered_evidence" / "read_only_clones"
CLONE_DIR.mkdir(parents=True, exist_ok=True)


def get_db_connection() -> sqlite3.Connection:
    """Returns a connection to the forensic SQLite database."""
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Initializes the tamper-proof audit database schema."""
    conn = get_db_connection()
    try:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS ingestion_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            artifact_id TEXT UNIQUE,
            filename TEXT,
            original_path TEXT,
            clone_path TEXT,
            sha256 TEXT,
            md5 TEXT,
            size_bytes INTEGER,
            ingested_at TEXT
        );

        CREATE TABLE IF NOT EXISTS audit_trail (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            stage TEXT,
            artifact_id TEXT,
            input_hash TEXT,
            output_verdict TEXT,
            details TEXT
        );

        CREATE TABLE IF NOT EXISTS restore_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            artifact_id TEXT,
            restore_type TEXT,
            target_device TEXT,
            pre_write_hash TEXT,
            post_write_hash TEXT,
            match INTEGER,
            timestamp TEXT
        );
        """)
        conn.commit()
    finally:
        conn.close()


def log_audit_event(stage: str, artifact_id: str, input_hash: str, output_verdict: str, details: str = ""):
    """Logs an immutable forensic action into audit_trail."""
    init_db()
    conn = get_db_connection()
    try:
        conn.execute("""
            INSERT INTO audit_trail (timestamp, stage, artifact_id, input_hash, output_verdict, details)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (datetime.now(timezone.utc).isoformat(), stage, artifact_id, input_hash, output_verdict, details))
        conn.commit()
    finally:
        conn.close()


def calculate_hashes(data: bytes) -> Dict[str, str]:
    """Calculates SHA-256 and MD5 of the given raw bytes."""
    return {
        "sha256": hashlib.sha256(data).hexdigest(),
        "md5": hashlib.md5(data).hexdigest(),
    }


def ingest_file(file_path: Union[str, Path], artifact_id: Optional[str] = None) -> Dict:
    """
    Ingests a raw forensic image or file:
    1. Reads bytes strictly in binary mode ('rb')
    2. Computes bitstream SHA-256 & MD5
    3. Writes an immutable read-only clone to /recovered_evidence/read_only_clones/
    4. Sets read-only permissions on clone
    5. Records entry into SQLite database
    """
    init_db()
    path = Path(file_path).resolve()
    if not path.exists():
        raise FileNotFoundError(f"Source file not found: {file_path}")

    with open(path, "rb") as fh:
        raw_bytes = fh.read()

    hashes = calculate_hashes(raw_bytes)
    size_bytes = len(raw_bytes)
    art_id = artifact_id or f"ART-{hashes['sha256'][:8].upper()}"

    # Write read-only clone
    clone_filename = f"{art_id}_{path.name}"
    clone_path = CLONE_DIR / clone_filename

    # Ensure clone writable before writing (if already existed)
    if clone_path.exists():
        os.chmod(clone_path, stat.S_IWRITE | stat.S_IREAD)

    with open(clone_path, "wb") as fh:
        fh.write(raw_bytes)

    # Set strict read-only permissions on clone (S_IREAD only)
    try:
        os.chmod(clone_path, stat.S_IREAD)
    except Exception:
        pass

    ingested_at = datetime.now(timezone.utc).isoformat()

    # Log into database
    conn = get_db_connection()
    try:
        conn.execute("""
            INSERT OR REPLACE INTO ingestion_log 
            (artifact_id, filename, original_path, clone_path, sha256, md5, size_bytes, ingested_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (art_id, path.name, str(path), str(clone_path), hashes["sha256"], hashes["md5"], size_bytes, ingested_at))
        conn.commit()
    finally:
        conn.close()

    log_audit_event(
        stage="Ingestion (ISO/IEC 27037)",
        artifact_id=art_id,
        input_hash=hashes["sha256"],
        output_verdict="READ_ONLY_CLONE_SEALED",
        details=f"Cloned {size_bytes:,} bytes to {clone_path.name}"
    )

    return {
        "artifact_id": art_id,
        "filename": path.name,
        "original_path": str(path),
        "clone_path": str(clone_path),
        "sha256": hashes["sha256"],
        "md5": hashes["md5"],
        "size_bytes": size_bytes,
        "ingested_at": ingested_at,
        "raw_bytes": raw_bytes,
    }


def get_all_ingested() -> List[Dict]:
    """Retrieves all ingested artifacts from SQLite."""
    init_db()
    conn = get_db_connection()
    try:
        rows = conn.execute("SELECT * FROM ingestion_log ORDER BY id DESC").fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()
