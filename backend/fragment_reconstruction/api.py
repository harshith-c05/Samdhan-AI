"""
fragment_reconstruction/api.py
===============================
FastAPI router for Intelligent Fragment Reconstruction (Phase 2).
Mounted onto the existing FastAPI app at /api/reconstruction/*.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException, Query, Response
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from .models import (
    EdgeScoreBreakdown, Fragment, ReconstructionResult,
    ReconstructionStatus,
)
from .feature_extractor import analyze_fragment
from .boundary_analyzer import BoundaryAnalyzer
from .pipeline import FragmentReconstructionPipeline

router = APIRouter(prefix="/api/reconstruction", tags=["fragment-reconstruction"])
pipeline = FragmentReconstructionPipeline()


class FragmentInputModel(BaseModel):
    fragment_id: str
    data_hex: str
    source_offset: int = 0
    cluster_index: Optional[int] = None
    allocation_state: str = "UNKNOWN"
    source_evidence: Dict[str, Any] = Field(default_factory=dict)


class ReconstructRequest(BaseModel):
    reconstruction_id: Optional[str] = None
    target_format: str = "UNKNOWN"
    fragments: List[FragmentInputModel]
    source_metadata: Dict[str, Any] = Field(default_factory=dict)


class BoundaryScoreRequest(BaseModel):
    fragment_a: FragmentInputModel
    fragment_b: FragmentInputModel


@router.post("/reconstruct", response_model=ReconstructionResult)
async def api_reconstruct_fragments(req: ReconstructRequest):
    """
    Run end-to-end intelligent fragment reconstruction:
      1. Feature extraction on fragments
      2. Boundary compatibility scoring (explainable edges)
      3. Graph construction & multi-candidate path search
      4. Actual byte reassembly & validation
      5. Generates reconstructed.bin, provenance.json, validation.json, report.json
    """
    if not req.fragments:
        raise HTTPException(status_code=400, detail="No fragments provided")

    fragment_objects: List[Fragment] = []
    for item in req.fragments:
        try:
            raw_bytes = bytes.fromhex(item.data_hex)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid data_hex for fragment {item.fragment_id}")

        frag = analyze_fragment(
            data=raw_bytes,
            fragment_id=item.fragment_id,
            source_offset=item.source_offset,
            cluster_index=item.cluster_index,
            allocation_state=item.allocation_state,
            source_evidence=item.source_evidence,
        )
        fragment_objects.append(frag)

    result = pipeline.run(
        fragments_input=fragment_objects,
        target_format=req.target_format,
        reconstruction_id=req.reconstruction_id,
        source_metadata=req.source_metadata,
    )
    return result


@router.post("/analyze-fragment", response_model=Fragment)
async def api_analyze_fragment(item: FragmentInputModel):
    """Compute complete forensic feature model on a single fragment."""
    try:
        raw_bytes = bytes.fromhex(item.data_hex)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid data_hex")

    return analyze_fragment(
        data=raw_bytes,
        fragment_id=item.fragment_id,
        source_offset=item.source_offset,
        cluster_index=item.cluster_index,
        allocation_state=item.allocation_state,
        source_evidence=item.source_evidence,
    )


@router.post("/boundary-score", response_model=EdgeScoreBreakdown)
async def api_boundary_score(req: BoundaryScoreRequest):
    """
    Compute explainable edge score between Fragment A and Fragment B.
    Returns decomposed score breakdown and human-readable reasons.
    """
    try:
        bytes_a = bytes.fromhex(req.fragment_a.data_hex)
        bytes_b = bytes.fromhex(req.fragment_b.data_hex)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid data_hex in input fragments")

    frag_a = analyze_fragment(
        data=bytes_a,
        fragment_id=req.fragment_a.fragment_id,
        source_offset=req.fragment_a.source_offset,
        cluster_index=req.fragment_a.cluster_index,
        allocation_state=req.fragment_a.allocation_state,
    )
    frag_b = analyze_fragment(
        data=bytes_b,
        fragment_id=req.fragment_b.fragment_id,
        source_offset=req.fragment_b.source_offset,
        cluster_index=req.fragment_b.cluster_index,
        allocation_state=req.fragment_b.allocation_state,
    )

    analyzer = BoundaryAnalyzer()
    return analyzer.evaluate_edge(frag_a, frag_b)


@router.get("/report/{reconstruction_id}")
async def api_get_report(reconstruction_id: str):
    """Retrieve saved reconstruction report by ID."""
    report_file = pipeline.output_dir / f"{reconstruction_id}_reconstruction_report.json"
    if not report_file.exists():
        raise HTTPException(status_code=404, detail=f"Reconstruction report '{reconstruction_id}' not found")
    data = json.loads(report_file.read_text(encoding="utf-8"))
    return data


@router.get("/download/{reconstruction_id}")
async def api_download_reconstructed(reconstruction_id: str):
    """Download the actual reassembled byte artifact."""
    matching = list(pipeline.output_dir.glob(f"{reconstruction_id}_reconstructed*"))
    if not matching:
        raise HTTPException(status_code=404, detail=f"Reconstructed binary for '{reconstruction_id}' not found")
    bin_file = matching[0]
    return FileResponse(
        path=str(bin_file),
        filename=bin_file.name,
        media_type="application/octet-stream",
    )
