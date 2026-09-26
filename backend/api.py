"""
backend/api.py
==============
SAMDHAN AI — Unified FastAPI Forensic Intelligence API.

Serves complete endpoints wrapping all forensic modules:
- /api/ingest
- /api/reconstruct
- /api/integrity
- /api/anomaly
- /api/classify (Objective 03)
- /api/priority / /api/prioritize (Objective 03)
- /api/triage (Objective 03 Consolidated Engine)
- /api/artifacts (Objective 03 Ranked Evidence Retrieval)
- /api/priority-summary & /api/priority-distribution
- /api/classification-summary
- /api/priority/recalculate
- /api/decision (Objective 04)
- /api/security (Feature 6)
- /api/usb/drives & /api/usb/restore (Feature 5)
- /api/assess (End-to-End Analysis)
- /api/samples
- /api/audit-trail
"""

import hashlib
import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Any, Union

from fastapi import FastAPI, File, UploadFile, HTTPException, Query, Body
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, FileResponse
from pydantic import BaseModel

from backend.ingestion import ingest_file, get_all_ingested, get_db_connection, init_db, log_audit_event
from backend.reconstruct import reassemble_fragments
from backend.integrity import assess_file_integrity
from backend.anomaly import detect_anomalies
from backend.classify import (
    classify_artifact,
    classify_mime_format,
    extract_iocs_and_entities,
    ALL_CATEGORIES,
    CAT_DOCUMENTS,
    CAT_DATABASE_LOGS,
    CAT_PHOTOS,
    CAT_SYSTEM_TRACES,
    CAT_NETWORK_CAPTURES,
    CAT_REGISTRY_HIVES,
    CAT_EXECUTABLES
)
from backend.priority import (
    compute_priority_score,
    calculate_evidence_relevance,
    calculate_temporal_score,
    calculate_uniqueness_score,
    detect_noise,
    calculate_rarity_score,
    DEFAULT_WEIGHTS,
    PRESETS,
    TIER_CRITICAL_THRESHOLD,
    TIER_HIGH_THRESHOLD,
    TIER_MEDIUM_THRESHOLD
)
from backend.decision import evaluate_decision_state
from backend.security_scan import scan_file_security
from backend.usb_restore import detect_usb_drives, restore_artifact_verified
from backend.fragment_reconstruction.api import router as reconstruction_router
from backend.disk_recovery.api import router as disk_recovery_router

ROOT_DIR = Path(__file__).resolve().parent.parent
SAMPLE_DIR = ROOT_DIR / "sample_data"
FRONTEND_DIR = ROOT_DIR / "frontend"


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(
    title="SAMDHAN AI — Digital Forensic Recovery & Reassembly Platform",
    description="Deterministic AI-Assisted Evidence Recovery, Fragment Reconstruction, Classification & Priority Triage API",
    version="3.0.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(reconstruction_router)
app.include_router(disk_recovery_router)



# ---------------------------------------------------------------------------
# Request & Response Models
# ---------------------------------------------------------------------------
class FragmentModel(BaseModel):
    id: str
    data_hex: str


class ReconstructRequest(BaseModel):
    fragments: List[FragmentModel]


class PriorityRequest(BaseModel):
    artifact_id: Optional[str] = None
    integrity: Optional[float] = None
    relevance: Optional[float] = None
    temporal: Optional[float] = None
    uniqueness: Optional[float] = None
    noise: Optional[float] = None
    weights: Optional[Dict[str, float]] = None
    relevance_score: Optional[float] = None
    integrity_score: Optional[float] = None
    temporal_score: Optional[float] = None
    rarity_score: Optional[float] = None
    uniqueness_score: Optional[float] = None
    noise_penalty: Optional[float] = None
    classification_confidence: Optional[float] = 85.0
    custom_weights: Optional[Dict[str, float]] = None
    filename: Optional[str] = ""


class ClassifyRequest(BaseModel):
    artifact_id: Optional[str] = None
    filename: str = ""
    data_hex: Optional[str] = None
    hex_header: Optional[str] = None
    content: Optional[str] = None
    text_preview: Optional[str] = None


class TriageRequest(BaseModel):
    case_id: Optional[str] = "CASE-2026-NIGHTFALL"
    incident_start: Optional[str] = "2026-09-24T10:00:00Z"
    incident_end: Optional[str] = "2026-09-24T18:00:00Z"
    case_keywords: Optional[List[str]] = None
    custom_weights: Optional[Dict[str, float]] = None
    artifacts: Optional[List[Dict[str, Any]]] = None


class RecalculateRequest(BaseModel):
    artifacts: Optional[List[Dict[str, Any]]] = None
    weights: Dict[str, float]


class RestoreRequest(BaseModel):
    filename: str
    data_hex: str
    target_dir: str = "recovered_evidence/restored_exports"
    artifact_id: str = "RESTORED-EXPORT"


# ---------------------------------------------------------------------------
# Core Pipeline Helpers
# ---------------------------------------------------------------------------
def run_full_pipeline(data: bytes, filename: str, case_context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Runs the unified 9-module forensic assessment pipeline on raw bytes."""
    # 1. Integrity Assessment (Objective 02)
    integrity = assess_file_integrity(data, filename)

    # 2. Anomaly Detection
    anomaly = detect_anomalies(data)

    # 3. Security Scan
    security = scan_file_security(data, filename)

    # 4. Classification & IOC Extraction (Objective 03)
    classification = classify_artifact(data, filename)

    # 5. Deterministic Decision Engine (Objective 04)
    decision = evaluate_decision_state(
        integrity_result=integrity,
        security_result=security,
        anomaly_result=anomaly
    )

    # 6. Priority Scoring (Objective 03)
    # Calculate factors
    relevance_val = calculate_evidence_relevance(
        classification.get("ioc_summary", {}),
        has_breach_window=bool(case_context and case_context.get("incident_start")),
        matched_indicators=classification.get("semantic_indicators", [])
    )

    noise_res = detect_noise(filename=filename, mime=classification.get("mime", ""))

    temporal_res = calculate_temporal_score(
        artifact_mtime=datetime.now(timezone.utc),
        incident_start=case_context.get("incident_start") if case_context else None,
        incident_end=case_context.get("incident_end") if case_context else None
    )
    temporal_val = temporal_res if isinstance(temporal_res, (int, float)) else temporal_res.get("temporal_score", 75.0)

    rarity_val = calculate_rarity_score(classification.get("mime", ""), anomaly.get("mean_entropy", 0.0))

    priority = compute_priority_score(
        relevance_score=relevance_val,
        integrity_score=integrity.get("composite_score", 0.0),
        temporal_score=temporal_val,
        rarity_score=rarity_val,
        uniqueness_score=rarity_val,
        noise_penalty=noise_res["noise_penalty"] * 100.0,
        classification_confidence=classification.get("confidence", 0.85) * 100.0,
        filename=filename
    )

    return {
        "filename": filename,
        "size_bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "integrity": integrity,
        "anomaly": anomaly,
        "security": security,
        "classification": classification,
        "priority": priority,
        "decision": decision,
        "noise": noise_res,
        "temporal": temporal_res
    }


def triage_evidence_corpus(
    case_id: str = "CASE-2026-NIGHTFALL",
    incident_start: str = "2026-09-24T10:00:00Z",
    incident_end: str = "2026-09-24T18:00:00Z",
    case_keywords: Optional[List[str]] = None,
    custom_weights: Optional[Dict[str, float]] = None
) -> Dict[str, Any]:
    """
    Consolidated Objective 03 Triage Engine.
    Processes all available evidence fixtures through real classification,
    integrity, temporal, uniqueness, and noise assessment.
    """
    files_to_process = []
    if SAMPLE_DIR.exists():
        for p in sorted(SAMPLE_DIR.iterdir()):
            if p.is_file():
                try:
                    with open(p, "rb") as fh:
                        b = fh.read()
                    mtime = datetime.fromtimestamp(p.stat().st_mtime, tz=timezone.utc).isoformat()
                    files_to_process.append({
                        "filename": p.name,
                        "path": str(p),
                        "data": b,
                        "mtime": mtime,
                        "size": len(b)
                    })
                except Exception:
                    pass

    # Hash table for duplicate detection across evidence set
    hash_counts = {}
    for f in files_to_process:
        h = hashlib.sha256(f["data"]).hexdigest()
        f["sha256"] = h
        hash_counts[h] = hash_counts.get(h, 0) + 1

    artifacts = []
    category_counts = {cat: 0 for cat in ALL_CATEGORIES}
    tier_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    conflict_count = 0
    review_required_count = 0

    for idx, f in enumerate(files_to_process):
        art_id = f"ART-{idx + 1:03d}"
        filename = f["filename"]
        data = f["data"]
        sha256 = f["sha256"]

        # Objective 02 Integrity Assessment
        integrity = assess_file_integrity(data, filename)
        comp_integrity = integrity.get("composite_score", 0.0)

        # Objective 03 Classification & IOC Extraction
        classification = classify_artifact(data, filename)
        cat = classification.get("category", CAT_DOCUMENTS)
        if cat in category_counts:
            category_counts[cat] += 1

        if classification.get("conflict"):
            conflict_count += 1

        # Relevance Calculation
        relevance_score = calculate_evidence_relevance(
            classification.get("ioc_summary", {}),
            has_breach_window=True,
            matched_indicators=classification.get("semantic_indicators", []),
            case_keywords=case_keywords
        )

        # Temporal Proximity Calculation
        temp_info = calculate_temporal_score(
            artifact_mtime=f["mtime"],
            incident_start=incident_start,
            incident_end=incident_end
        )
        temporal_score = temp_info if isinstance(temp_info, (int, float)) else temp_info.get("temporal_score", 75.0)

        # Uniqueness Calculation
        is_dup = hash_counts[sha256] > 1
        uniq_info = calculate_uniqueness_score(is_duplicate=is_dup)
        uniqueness_score = uniq_info["uniqueness_score"] * 100.0

        # Noise Detection
        noise_info = detect_noise(filename=filename, path=f["path"], mime=classification.get("mime", ""))
        noise_penalty = noise_info["noise_penalty"] * 100.0

        # Objective 03 Priority Computation
        priority_res = compute_priority_score(
            relevance_score=relevance_score,
            integrity_score=comp_integrity,
            temporal_score=temporal_score,
            uniqueness_score=uniqueness_score,
            noise_penalty=noise_penalty,
            classification_confidence=classification.get("confidence", 0.85) * 100.0,
            custom_weights=custom_weights,
            filename=filename
        )

        tier = priority_res["priority_tier"]
        tier_counts[tier] = tier_counts.get(tier, 0) + 1

        if priority_res.get("review_required") or classification.get("review_required"):
            review_required_count += 1

        artifact_doc = {
            "artifact_id": art_id,
            "id": art_id,
            "filename": filename,
            "path": f["path"],
            "size": f["size"],
            "sha256": sha256,
            "mtime": f["mtime"],
            "classification": {
                "category": cat,
                "subtype": classification.get("subtype", classification.get("format", "")),
                "format": classification.get("format", ""),
                "mime": classification.get("mime", ""),
                "confidence": classification.get("confidence", 0.90),
                "method": classification.get("method", "MAGIC_BYTES"),
                "detected_signature": classification.get("detected_signature", ""),
            },
            "category": cat,
            "type": cat,
            "mime": classification.get("mime", ""),
            "confidence": classification.get("confidence", 0.90),
            "classificationConfidence": round(classification.get("confidence", 0.90) * 100, 1),
            "semantic": classification.get("semantic_analysis", {}),
            "semantic_indicators": classification.get("semantic_indicators", []),
            "iocs": classification.get("iocs", {}),
            "ioc_summary": classification.get("ioc_summary", {}),
            "conflicts": classification.get("conflicts", []),
            "conflict": classification.get("conflict", False),
            "conflict_type": classification.get("conflict_type"),
            "forensic_message": classification.get("forensic_message"),
            "integrity": round(comp_integrity / 100.0, 3),
            "overallIntegrity": round(comp_integrity, 1),
            "integrity_score": comp_integrity,
            "relevance": round(relevance_score / 100.0, 3),
            "evidenceRelevance": round(relevance_score, 1),
            "temporal": round(temporal_score / 100.0, 3),
            "uniqueness": round(uniqueness_score / 100.0, 3),
            "noise": round(noise_penalty / 100.0, 3),
            "noisePenalty": round(noise_penalty / 100.0, 3),
            "duplicate": is_dup,
            "priority": {
                "score": priority_res["score"],
                "score_100": priority_res["priority_score"],
                "tier": tier,
                "breakdown": priority_res["breakdown"],
                "explanations": priority_res["explanations"]
            },
            "priorityScore": priority_res["score"],
            "priorityTier": tier,
            "reviewRequired": priority_res["review_required"] or classification.get("review_required", False),
            "review_required": priority_res["review_required"] or classification.get("review_required", False),
            "reason": "; ".join(priority_res["explanations"][:2]),
            "explanations": priority_res["explanations"],
            "noise_info": noise_info,
            "temporal_info": temp_info if isinstance(temp_info, dict) else {},
            "raw_hex_preview": data[:64].hex() if len(data) >= 64 else data.hex()
        }
        artifacts.append(artifact_doc)

    # Sort descending by priority score
    artifacts.sort(key=lambda a: a["priorityScore"], reverse=True)
    for r_idx, a in enumerate(artifacts):
        a["rank"] = r_idx + 1

    return {
        "case_context": {
            "case_id": case_id,
            "incident_start": incident_start,
            "incident_end": incident_end,
            "total_artifacts": len(artifacts)
        },
        "artifacts": artifacts,
        "classification_summary": {
            "categories": category_counts,
            "conflicts_count": conflict_count,
            "review_required_count": review_required_count
        },
        "priority_summary": {
            "critical": tier_counts.get("Critical", 0),
            "high": tier_counts.get("High", 0),
            "medium": tier_counts.get("Medium", 0),
            "low": tier_counts.get("Low", 0),
            "needs_review": review_required_count
        },
        "weights": custom_weights or DEFAULT_WEIGHTS,
        "tiers": {
            "critical_threshold": TIER_CRITICAL_THRESHOLD,
            "high_threshold": TIER_HIGH_THRESHOLD,
            "medium_threshold": TIER_MEDIUM_THRESHOLD
        },
        "statistics": {
            "total": len(artifacts),
            "avg_integrity": round(sum(a["overallIntegrity"] for a in artifacts) / len(artifacts), 1) if artifacts else 0,
            "avg_relevance": round(sum(a["evidenceRelevance"] for a in artifacts) / len(artifacts), 1) if artifacts else 0,
        }
    }


# ---------------------------------------------------------------------------
# API Endpoints
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
    return {"status": "ok", "service": "SAMDHAN AI", "version": "3.0.0"}


# ---------------------------------------------------------------------------
# Objective 03: Classification & Prioritization Endpoints
# ---------------------------------------------------------------------------
@app.post("/api/classify")
def classify_endpoint(req: ClassifyRequest):
    """
    Objective 03: Classifies raw bytes or content into one of 7 forensic categories.
    Detects binary signatures, MIME types, extension conflicts, and extracts semantic IOCs.
    """
    hex_data = req.data_hex or req.hex_header
    if hex_data:
        raw_bytes = bytes.fromhex(hex_data)
    elif req.content or req.text_preview:
        raw_bytes = (req.content or req.text_preview).encode("utf-8")
    else:
        raw_bytes = b""

    result = classify_artifact(raw_bytes, req.filename)
    log_audit_event(
        stage="Classification (Objective 03)",
        artifact_id=req.artifact_id or req.filename or "HEX_PAYLOAD",
        input_hash=hashlib.sha256(raw_bytes).hexdigest() if raw_bytes else "",
        output_verdict=result.get("category", CAT_DOCUMENTS),
        details=f"Classified as {result.get('format')} (Method: {result.get('method')})"
    )
    return result


@app.post("/api/prioritize")
@app.post("/api/priority")
def priority_endpoint(req: PriorityRequest):
    """
    Objective 03: Computes multi-factor weighted priority score and maps to tier.
    Formula: P = w1*I + w2*R + w3*T + w4*U - w5*N.
    """
    I = req.integrity if req.integrity is not None else (req.integrity_score if req.integrity_score is not None else 50.0)
    R = req.relevance if req.relevance is not None else (req.relevance_score if req.relevance_score is not None else 50.0)
    T = req.temporal if req.temporal is not None else (req.temporal_score if req.temporal_score is not None else 75.0)
    U = req.uniqueness if req.uniqueness is not None else (req.uniqueness_score if req.uniqueness_score is not None else (req.rarity_score if req.rarity_score is not None else 50.0))
    N = req.noise if req.noise is not None else (req.noise_penalty if req.noise_penalty is not None else 0.0)
    w = req.weights or req.custom_weights

    result = compute_priority_score(
        relevance_score=R,
        integrity_score=I,
        temporal_score=T,
        rarity_score=U,
        uniqueness_score=U,
        noise_penalty=N,
        classification_confidence=req.classification_confidence or 85.0,
        custom_weights=w,
        filename=req.filename or ""
    )
    return result


@app.post("/api/triage")
def triage_endpoint(req: Optional[TriageRequest] = Body(default=None)):
    """
    Objective 03 Consolidated Triage Endpoint:
    Processes and ranks all ingested and sample artifacts using real forensic evidence.
    """
    r = req or TriageRequest()
    result = triage_evidence_corpus(
        case_id=r.case_id or "CASE-2026-NIGHTFALL",
        incident_start=r.incident_start or "2026-09-24T10:00:00Z",
        incident_end=r.incident_end or "2026-09-24T18:00:00Z",
        case_keywords=r.case_keywords,
        custom_weights=r.custom_weights
    )
    log_audit_event(
        stage="Forensic Triage (Objective 03)",
        artifact_id=r.case_id or "ALL",
        input_hash="",
        output_verdict="TRIAGE_COMPLETE",
        details=f"Triaged {len(result['artifacts'])} artifacts into priority tiers"
    )
    return result


@app.get("/api/artifacts")
def get_artifacts_endpoint():
    """Returns all triaged and ranked evidence artifacts."""
    return triage_evidence_corpus()


@app.get("/api/artifacts/{artifact_id}")
def get_single_artifact(artifact_id: str):
    """Returns detailed forensic metadata and priority breakdown for a single artifact."""
    corpus = triage_evidence_corpus()
    for art in corpus["artifacts"]:
        if art["artifact_id"] == artifact_id or art["id"] == artifact_id or art["filename"] == artifact_id:
            return art
    raise HTTPException(status_code=404, detail=f"Artifact {artifact_id} not found")


@app.get("/api/priority-summary")
def get_priority_summary():
    """Returns priority tier counts and distribution."""
    corpus = triage_evidence_corpus()
    sum_tiers = corpus["priority_summary"]
    return {
        "CRITICAL": sum_tiers.get("critical", 0),
        "HIGH": sum_tiers.get("high", 0),
        "MEDIUM": sum_tiers.get("medium", 0),
        "LOW": sum_tiers.get("low", 0),
        "critical": sum_tiers.get("critical", 0),
        "high": sum_tiers.get("high", 0),
        "medium": sum_tiers.get("medium", 0),
        "low": sum_tiers.get("low", 0),
        "priority_summary": sum_tiers,
        "statistics": corpus["statistics"],
        "total": len(corpus["artifacts"])
    }


@app.get("/api/priority-distribution")
def get_priority_distribution():
    """Returns priority distribution chart data for dashboard visualization."""
    corpus = triage_evidence_corpus()
    tiers = corpus["priority_summary"]
    dist = [
        {"name": "Critical", "count": tiers.get("critical", 0), "fill": "#ef4444"},
        {"name": "High", "count": tiers.get("high", 0), "fill": "#f97316"},
        {"name": "Medium", "count": tiers.get("medium", 0), "fill": "#eab308"},
        {"name": "Low", "count": tiers.get("low", 0), "fill": "#71717a"},
    ]
    return {
        "distribution": dist,
        "tier_distribution": dist,
        "category_distribution": [
            {"category": cat, "count": count}
            for cat, count in corpus["classification_summary"]["categories"].items()
        ]
    }


@app.get("/api/classification-summary")
def get_classification_summary():
    """Returns summary of classification categories, conflicts, and review flags."""
    corpus = triage_evidence_corpus()
    return corpus["classification_summary"]


@app.post("/api/priority/recalculate")
def recalculate_priority(req: RecalculateRequest):
    """
    Recalculates priority scores across provided artifacts with custom weights.
    Deterministic local recalculation.
    """
    corpus = triage_evidence_corpus()
    target_artifacts = req.artifacts if req.artifacts is not None else corpus["artifacts"]
    rescored = []
    w = req.weights
    for art in target_artifacts:
        scored = compute_priority_score(
            relevance_score=art.get("evidenceRelevance", art.get("relevance", 50.0)),
            integrity_score=art.get("overallIntegrity", art.get("integrity", 50.0)),
            temporal_score=art.get("temporal", 75.0),
            uniqueness_score=art.get("uniqueness", 85.0),
            noise_penalty=art.get("noisePenalty", art.get("noise", 0.0)),
            classification_confidence=art.get("classificationConfidence", art.get("confidence", 85.0)),
            custom_weights=w,
            filename=art.get("filename", "")
        )
        updated = {
            **art,
            "priorityScore": scored["score"],
            "priorityTier": scored["priority_tier"],
            "reviewRequired": scored["review_required"],
            "priority": {
                "score": scored["score"],
                "score_100": scored["priority_score"],
                "tier": scored["priority_tier"],
                "breakdown": scored["breakdown"],
                "explanations": scored["explanations"]
            }
        }
        rescored.append(updated)

    rescored.sort(key=lambda a: a["priorityScore"], reverse=True)
    for idx, a in enumerate(rescored):
        a["rank"] = idx + 1

    return {
        "artifacts": rescored,
        "weights": w,
        "weights_applied": w
    }


# ---------------------------------------------------------------------------
# Assessment & Analysis Endpoints
# ---------------------------------------------------------------------------
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


# ---------------------------------------------------------------------------
# Mount Extended Integrity, Recovery & Security Endpoints
# ---------------------------------------------------------------------------
try:
    from backend.integrity_pipeline import app as integrity_app
    _existing_paths = {r.path for r in app.routes}
    for _route in integrity_app.routes:
        if _route.path not in _existing_paths:
            app.routes.append(_route)
            _existing_paths.add(_route.path)
except Exception as _e:
    pass
