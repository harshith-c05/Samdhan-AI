"""
backend/api.py
==============
SAMDHAN AI — Unified FastAPI Forensic Intelligence API.

Serves complete endpoints wrapping all 9 forensic modules:
- /api/ingest
- /api/reconstruct
- /api/integrity
- /api/anomaly
- /api/classify
- /api/priority
- /api/decision
- /api/security
- /api/usb/drives
- /api/usb/restore
- /api/assess (End-to-End Analysis)
- /api/samples
- /api/audit-trail
"""

import os
from pathlib import Path
from typing import Dict, List, Optional, Any

from fastapi import FastAPI, File, UploadFile, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, FileResponse
from pydantic import BaseModel

from backend.ingestion import ingest_file, get_all_ingested, get_db_connection, init_db
from backend.reconstruct import reassemble_fragments
from backend.integrity import assess_file_integrity
from backend.anomaly import detect_anomalies
from backend.classify import classify_artifact
from backend.priority import compute_priority_score, calculate_evidence_relevance, calculate_rarity_score
from backend.decision import evaluate_decision_state
from backend.security_scan import scan_file_security
from backend.usb_restore import detect_usb_drives, restore_artifact_verified

ROOT_DIR = Path(__file__).resolve().parent.parent
SAMPLE_DIR = ROOT_DIR / "sample_data"
FRONTEND_DIR = ROOT_DIR / "frontend"

from contextlib import asynccontextmanager

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield

app = FastAPI(
    title="SAMDHAN AI — Digital Forensic Recovery & Reassembly Platform",
    description="Deterministic AI-Assisted Evidence Recovery, Fragment Reconstruction & Integrity Assessment API",
    version="2.0.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------
class FragmentModel(BaseModel):
    id: str
    data_hex: str


class ReconstructRequest(BaseModel):
    fragments: List[FragmentModel]


class PriorityRequest(BaseModel):
    relevance_score: float
    integrity_score: float
    temporal_score: float = 75.0
    rarity_score: float = 50.0


class RestoreRequest(BaseModel):
    filename: str
    data_hex: str
    target_dir: str = "recovered_evidence/restored_exports"
    artifact_id: str = "RESTORED-EXPORT"


# ---------------------------------------------------------------------------
# Core Pipeline Helper
# ---------------------------------------------------------------------------
def run_full_pipeline(data: bytes, filename: str) -> Dict[str, Any]:
    """Runs the unified 9-module forensic assessment pipeline on raw bytes."""
    # 1. Integrity Assessment (4-Vector + Format-specific corruption ranges)
    integrity = assess_file_integrity(data, filename)

    # 2. Anomaly Detection (Sliding-window entropy + IsolationForest)
    anomaly = detect_anomalies(data)

    # 3. Security Scan (Extension mismatch, entropy > 7.5, malicious streams)
    security = scan_file_security(data, filename)

    # 4. Classification & IOC Extraction
    classification = classify_artifact(data, filename)

    # 5. Deterministic Decision Engine
    decision = evaluate_decision_state(
        integrity_result=integrity,
        security_result=security,
        anomaly_result=anomaly
    )

    # 6. Priority Scoring
    relevance = calculate_evidence_relevance(classification.get("ioc_summary", {}))
    rarity = calculate_rarity_score(classification.get("mime", ""), anomaly.get("mean_entropy", 0.0))
    priority = compute_priority_score(
        relevance_score=relevance,
        integrity_score=integrity.get("composite_score", 0.0),
        temporal_score=75.0,
        rarity_score=rarity
    )

    return {
        "filename": filename,
        "size_bytes": len(data),
        "integrity": integrity,
        "anomaly": anomaly,
        "security": security,
        "classification": classification,
        "priority": priority,
        "decision": decision,
    }


# ---------------------------------------------------------------------------
@app.get("/", response_class=HTMLResponse)
def serve_dashboard_root():
    index_file = FRONTEND_DIR / "index.html"
    if index_file.exists():
        return FileResponse(index_file)
    return HTMLResponse("<h1>SAMDHAN AI Backend Online</h1><p>Visit <a href='/docs'>/docs</a></p>")


@app.get("/dashboard", response_class=HTMLResponse)
def serve_dashboard():
    index_file = FRONTEND_DIR / "index.html"
    if index_file.exists():
        return FileResponse(index_file)
    return HTMLResponse("<h1>SAMDHAN AI Dashboard</h1>")


@app.get("/api/health")
def health_check():
    return {"status": "ok", "service": "SAMDHAN AI", "version": "2.0.0"}


@app.post("/api/assess")
async def assess_upload(file: UploadFile = File(...)):
    """Assess an uploaded file through the entire forensic pipeline."""
    contents = await file.read()
    results = run_full_pipeline(contents, file.filename or "unknown_file")
    return results


@app.get("/api/samples")
def list_samples():
    """Lists pre-seeded sample data fixtures."""
    files = []
    if SAMPLE_DIR.exists():
        for p in SAMPLE_DIR.iterdir():
            if p.is_file():
                files.append({
                    "name": p.name,
                    "size_bytes": p.stat().st_size,
                    "path": str(p)
                })
    return {"samples": sorted(files, key=lambda x: x["name"])}


@app.get("/api/samples/assess/{filename}")
def assess_sample(filename: str):
    """Assesses one of the pre-seeded sample data files."""
    file_path = SAMPLE_DIR / filename
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="Sample fixture not found")
    with open(file_path, "rb") as fh:
        data = fh.read()
    return run_full_pipeline(data, filename)


@app.post("/api/reconstruct")
def reconstruct_endpoint(req: ReconstructRequest):
    """Reassembles fragmented clusters using DAG edge scoring."""
    frags = []
    for f in req.fragments:
        frags.append({
            "id": f.id,
            "data": bytes.fromhex(f.data_hex)
        })
    result = reassemble_fragments(frags)
    return {
        "ordered_ids": result["ordered_ids"],
        "reassembled_hex": result["reassembled_data"].hex()[:500] + "...",
        "total_bytes": len(result["reassembled_data"]),
        "confidence": result["confidence"],
        "edges": result["edges"]
    }


@app.post("/api/priority")
def priority_endpoint(req: PriorityRequest):
    """Computes weighted multi-factor priority tier."""
    return compute_priority_score(
        relevance_score=req.relevance_score,
        integrity_score=req.integrity_score,
        temporal_score=req.temporal_score,
        rarity_score=req.rarity_score
    )


@app.get("/api/usb/drives")
def get_usb_drives():
    """Detects available USB / removable drives."""
    return {"drives": detect_usb_drives()}


@app.post("/api/usb/restore")
def restore_usb_endpoint(req: RestoreRequest):
    """Executes verified write-then-reread forensic restoration."""
    data = bytes.fromhex(req.data_hex)
    result = restore_artifact_verified(
        data=data,
        target_directory=req.target_dir,
        filename=req.filename,
        artifact_id=req.artifact_id
    )
    return result


@app.get("/api/audit-trail")
def get_audit_trail(limit: int = 50):
    """Returns recent tamper-proof forensic audit events."""
    with get_db_connection() as conn:
        rows = conn.execute("SELECT * FROM audit_trail ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    return {"audit_trail": [dict(r) for r in rows]}
