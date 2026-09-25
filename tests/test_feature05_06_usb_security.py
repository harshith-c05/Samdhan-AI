"""
test_feature05_06_usb_security.py
==================================
Integration and unit tests for:
- Feature 5: Pendrive / USB Restore (device discovery, write, post-write hash verification, audit logging)
- Feature 6: Malicious File Detection & Security Scan (mismatch, blocklist hash, entropy, embedded threats)
"""

import hashlib
import json
import tempfile
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from backend.integrity_pipeline import app, init_db, KNOWN_MALICIOUS_HASHES


@pytest.fixture(scope="module")
def client():
    init_db()
    with TestClient(app) as test_client:
        yield test_client


def test_usb_discovery_endpoint(client):
    """Test GET /api/v1/discovery/usb-devices returns a list of devices."""
    res = client.get("/api/v1/discovery/usb-devices")
    assert res.status_code == 200
    data = res.json()
    assert "devices" in data
    assert isinstance(data["devices"], list)
    assert len(data["devices"]) >= 1
    # Check device structure
    dev = data["devices"][0]
    assert "letter" in dev
    assert "label" in dev
    assert "type" in dev


def test_pendrive_restore_success(client):
    """Test POST /api/v1/restore/pendrive write + verification match."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create a mock source reconstructed file
        src_path = Path(tmpdir) / "source.pdf"
        content = b"%PDF-1.7 mock content for restore"
        src_path.write_bytes(content)
        expected_hash = hashlib.sha256(content).hexdigest()

        # Target drive simulated as tmpdir
        res = client.post("/api/v1/restore/pendrive", json={
            "artifact_id": "TEST-RESTORE-001",
            "filename": "document.pdf",
            "reconstructed_path": str(src_path),
            "target_device": tmpdir,
            "pre_write_hash": expected_hash,
        })

        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "SUCCESS"
        assert data["match"] is True
        assert data["pre_write_hash"] == expected_hash
        assert data["post_write_hash"] == expected_hash

        # Verify audit log entry was stored
        log_res = client.get("/api/v1/restore/log/TEST-RESTORE-001")
        assert log_res.status_code == 200
        logs = log_res.json()
        assert len(logs) >= 1
        assert logs[0]["match"] == 1


def test_pendrive_restore_hash_mismatch_security_deletion(client):
    """Test that a post-write hash mismatch triggers file deletion to prevent corruption."""
    with tempfile.TemporaryDirectory() as tmpdir:
        src_path = Path(tmpdir) / "source.pdf"
        content = b"%PDF-1.7 actual content"
        src_path.write_bytes(content)

        # Send deliberate wrong pre_write_hash
        tampered_hash = "0" * 64
        res = client.post("/api/v1/restore/pendrive", json={
            "artifact_id": "TEST-RESTORE-FAIL",
            "filename": "tampered.pdf",
            "reconstructed_path": str(src_path),
            "target_device": tmpdir,
            "pre_write_hash": tampered_hash,
        })

        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "HASH_MISMATCH"
        assert data["match"] is False

        # Verify file was deleted from target directory
        dest_file = Path(tmpdir) / "SAMDHAN_RECOVERED" / "tampered.pdf"
        assert not dest_file.exists()


def test_security_scan_clean_artifact(client):
    """Test security scan on a clean benign document."""
    res = client.post("/api/v1/security/scan", json={
        "artifact_id": "TEST-CLEAN-001",
        "filename": "report.pdf",
        "sha256": "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        "declared_type": "application/pdf",
    })
    assert res.status_code == 200
    data = res.json()
    assert data["verdict"] == "CLEAN"
    assert len(data["reasons"]) == 0


def test_security_scan_extension_mismatch_pe_in_jpg(client):
    """Test security scan flags invoice.jpg containing MZ Windows PE header as MALICIOUS."""
    res = client.post("/api/v1/security/scan", json={
        "artifact_id": "BENCH-005",
        "filename": "invoice.jpg",
        "declared_type": "image/jpeg",
    })
    assert res.status_code == 200
    data = res.json()
    assert data["verdict"] == "MALICIOUS"
    assert "extension_signature_mismatch" in data["reasons"]
    assert "known_hash_match" in data["reasons"]


def test_security_scan_blocklist_endpoint(client):
    """Test GET /api/v1/security/blocklist returns the threat blocklist."""
    res = client.get("/api/v1/security/blocklist")
    assert res.status_code == 200
    data = res.json()
    assert data["count"] >= 3
    assert "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" in data["blocklist"]


def test_security_scan_persisted_results(client):
    """Test that scan results are stored and queryable via GET."""
    # First scan
    scan_res = client.post("/api/v1/security/scan", json={
        "artifact_id": "TEST-PERSIST-001",
        "filename": "malware.exe",
        "sha256": "deadbeefcafebabedeadbeefcafebabedeadbeefcafebabedeadbeefcafebabe",
    })
    assert scan_res.status_code == 200

    # Query stored result
    get_res = client.get("/api/v1/security/results/TEST-PERSIST-001")
    assert get_res.status_code == 200
    stored = get_res.json()
    assert stored["artifact_id"] == "TEST-PERSIST-001"
    assert stored["verdict"] == "MALICIOUS"
    assert stored["hash_blocklist_match"] == 1
