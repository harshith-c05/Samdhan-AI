"""
disk_recovery/tests/test_api.py
================================
Tests for FastAPI recovery endpoints (/api/recovery/*).
Uses TestClient to test in-process without requiring an external server.
"""

import sys
from pathlib import Path
from fastapi.testclient import TestClient

_BACKEND = Path(__file__).resolve().parent.parent.parent
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from integrity_pipeline import app

client = TestClient(app)
FIXTURE_PATH = "disk_recovery/test_fixtures/test_usb.img"


def test_sources_endpoint():
    res = client.get("/api/recovery/sources")
    assert res.status_code == 200
    data = res.json()
    assert isinstance(data, list)
    assert any(item["filename"] == "test_usb.img" for item in data)


def test_scan_endpoint():
    res = client.post("/api/recovery/scan", json={"image_path": FIXTURE_PATH})
    assert res.status_code == 200
    data = res.json()
    assert len(data["filesystems"]) >= 1
    assert data["filesystems"][0]["filesystem"] == "FAT32"
    assert len(data["allocated_files"]) >= 4
    assert len(data["deleted_files"]) >= 1
    assert len(data["carving_hits"]) >= 1
    assert len(data["all_candidates"]) >= 5
    assert len(data["errors"]) == 0


def test_filesystems_endpoint():
    res = client.get(f"/api/recovery/filesystems?image_path={FIXTURE_PATH}")
    assert res.status_code == 200
    data = res.json()
    assert len(data["filesystems"]) >= 1
    assert data["filesystems"][0]["filesystem"] == "FAT32"


def test_unallocated_endpoint():
    res = client.post("/api/recovery/unallocated", json={"image_path": FIXTURE_PATH})
    assert res.status_code == 200
    data = res.json()
    assert len(data) >= 1
    assert data[0]["size_bytes"] > 0
