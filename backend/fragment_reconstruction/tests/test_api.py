"""
fragment_reconstruction/tests/test_api.py
=========================================
FastAPI endpoint tests for Phase-2 Intelligent Fragment Reconstruction.
"""

import sys
from pathlib import Path
from fastapi.testclient import TestClient

_BACKEND = Path(__file__).resolve().parent.parent.parent
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from integrity_pipeline import app
from fragment_reconstruction.tests.test_phase2 import build_valid_png

client = TestClient(app)


def test_analyze_fragment_endpoint():
    png_bytes, frags = build_valid_png()
    res = client.post(
        "/api/reconstruction/analyze-fragment",
        json={
            "fragment_id": "TEST-F1",
            "data_hex": frags[0].hex(),
            "source_offset": 0,
            "cluster_index": 5,
        },
    )
    assert res.status_code == 200
    data = res.json()
    assert data["fragment_id"] == "TEST-F1"
    assert data["format"] == "PNG"
    assert data["header_compatibility"] is True
    assert "PNG_MAGIC" in data["internal_markers"]


def test_boundary_score_endpoint():
    png_bytes, frags = build_valid_png()
    res = client.post(
        "/api/reconstruction/boundary-score",
        json={
            "fragment_a": {
                "fragment_id": "F1",
                "data_hex": frags[0].hex(),
            },
            "fragment_b": {
                "fragment_id": "F2",
                "data_hex": frags[1].hex(),
            },
        },
    )
    assert res.status_code == 200
    data = res.json()
    assert data["final_score"] > 0.70
    assert len(data["reasons"]) > 0
    assert "signature_compatibility" in data
    assert "continuity_compatibility" in data
    assert "structural_compatibility" in data


def test_reconstruct_endpoint():
    png_bytes, frags = build_valid_png()
    # Send shuffled fragments
    shuffled = [
        {"fragment_id": "F3", "data_hex": frags[2].hex()},
        {"fragment_id": "F1", "data_hex": frags[0].hex()},
        {"fragment_id": "F4", "data_hex": frags[3].hex()},
        {"fragment_id": "F2", "data_hex": frags[1].hex()},
    ]

    res = client.post(
        "/api/reconstruction/reconstruct",
        json={
            "reconstruction_id": "API-TEST-REC-01",
            "target_format": "PNG",
            "fragments": shuffled,
        },
    )
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "COMPLETE"
    assert data["selected_path"] == ["F1", "F2", "F3", "F4"]
    assert data["byte_coverage"] == len(png_bytes)
    assert len(data["candidates_evaluated"]) >= 1

    # Test report retrieval endpoint
    rep_res = client.get("/api/reconstruction/report/API-TEST-REC-01")
    assert rep_res.status_code == 200
    rep_data = rep_res.json()
    assert rep_data["reconstruction_id"] == "API-TEST-REC-01"

    # Test download endpoint
    dl_res = client.get("/api/reconstruction/download/API-TEST-REC-01")
    assert dl_res.status_code == 200
    assert dl_res.content == png_bytes
