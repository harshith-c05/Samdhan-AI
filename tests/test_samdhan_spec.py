"""
tests/test_samdhan_spec.py
==========================
Comprehensive Pytest Test Suite verifying all 10 SAMDHAN AI modules and fixtures.

Coverage:
- backend/ingestion.py (SHA-256, read-only clone, SQLite audit trail)
- backend/reconstruct.py (DAG fragment reassembly, bigrams, entropy delta, greedy path)
- backend/integrity.py (JPEG, PDF, SQLite, ZIP, UTF-8 logs, 4-vector score)
- backend/anomaly.py (Sliding-window entropy, IsolationForest, zero wipe)
- backend/classify.py (13 MIME formats, IOC NER: IPs, darknet, wallets, keywords)
- backend/priority.py (Multi-factor weighted priority score & tiers)
- backend/decision.py (Deterministic 5-state engine with named numeric constants)
- backend/usb_restore.py (Win32 USB detection, write-then-reread, auto-delete on tamper)
- backend/security_scan.py (Disguised PE in JPG, entropy > 7.5, active streams)
- backend/api.py (FastAPI test client endpoints)
- sample_data fixtures end-to-end evaluation
"""

import os
import shutil
import tempfile
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from backend.ingestion import ingest_file, calculate_hashes, init_db, get_db_connection
from backend.reconstruct import (
    calculate_shannon_entropy,
    compute_bigram_transition_score,
    check_pointer_header_link,
    compute_fragment_affinity,
    reassemble_fragments
)
from backend.integrity import (
    check_jpeg_integrity,
    check_pdf_integrity,
    check_sqlite_integrity,
    check_zip_integrity,
    check_utf8_log_integrity,
    assess_file_integrity
)
from backend.anomaly import (
    compute_entropy_for_window,
    extract_window_features,
    detect_anomalies
)
from backend.classify import (
    classify_mime_format,
    extract_iocs_and_entities,
    classify_artifact,
    FORMAT_SIGNATURES
)
from backend.priority import (
    compute_priority_score,
    calculate_evidence_relevance,
    calculate_temporal_score,
    calculate_rarity_score,
    WEIGHT_EVIDENCE_RELEVANCE,
    WEIGHT_INTEGRITY,
    WEIGHT_TEMPORAL_DECAY,
    WEIGHT_RARITY,
    TIER_CRITICAL_THRESHOLD,
    TIER_HIGH_THRESHOLD,
    TIER_MEDIUM_THRESHOLD
)
from backend.decision import (
    evaluate_decision_state,
    STATE_BLOCKED_SECURITY_RISK,
    STATE_UNRECOVERABLE,
    STATE_INTEGRITY_VERIFIED,
    STATE_PARTIALLY_RECOVERABLE,
    STATE_NEEDS_REVIEW,
    THRESHOLD_VERIFIED_COMPOSITE,
    THRESHOLD_VERIFIED_STRUCTURAL,
    THRESHOLD_PARTIAL_COMPOSITE_MIN,
    THRESHOLD_UNRECOVERABLE_COMPOSITE_MAX,
    THRESHOLD_ZERO_FILL_RATIO
)
from backend.usb_restore import (
    detect_usb_drives,
    read_sectors_readonly,
    restore_artifact_verified
)
from backend.security_scan import (
    check_extension_magic_mismatch,
    scan_embedded_malicious_streams,
    scan_file_security,
    ENTROPY_PACKED_THRESHOLD
)
from backend.api import app, run_full_pipeline

SAMPLE_DIR = Path(__file__).resolve().parent.parent / "sample_data"
client = TestClient(app)


# ============================================================================
# 1. INGESTION MODULE TESTS
# ============================================================================
class TestIngestion:
    def test_calculate_hashes(self):
        data = b"SAMDHAN AI ISO 27037 FORENSIC BITSTREAM TEST"
        hashes = calculate_hashes(data)
        assert len(hashes["sha256"]) == 64
        assert len(hashes["md5"]) == 32
        assert hashes["sha256"] == "681dc3de29ec3d4dbf407b40327eba3dfe26cd19f471c7f5b9d959fb720c87a4"

    def test_ingest_file_read_only_clone(self, tmp_path):
        src_file = tmp_path / "evidence_sector.raw"
        src_file.write_bytes(b"\xaa\xbb\xcc\xdd" * 128)

        res = ingest_file(src_file)
        assert res["size_bytes"] == 512
        assert Path(res["clone_path"]).exists()

        # Verify audit log entry exists in SQLite
        with get_db_connection() as conn:
            row = conn.execute("SELECT * FROM ingestion_log WHERE sha256 = ?", (res["sha256"],)).fetchone()
            assert row is not None
            assert row["filename"] == "evidence_sector.raw"

    def test_missing_file_raises_error(self):
        with pytest.raises(FileNotFoundError):
            ingest_file("C:/non_existent_image_12345.raw")


# ============================================================================
# 2. RECONSTRUCTION MODULE TESTS (DAG & SIGNALS)
# ============================================================================
class TestReconstruction:
    def test_shannon_entropy_calculation(self):
        zeroes = b"\x00" * 256
        assert calculate_shannon_entropy(zeroes) == 0.0

        # Uniform distribution across all 256 bytes has theoretical max entropy 8.0
        all_bytes = bytes(range(256))
        assert abs(calculate_shannon_entropy(all_bytes) - 8.0) < 1e-6

    def test_bigram_transition_score(self):
        tail = b"This is the start of forensic "
        head = b"evidence documentation."
        score = compute_bigram_transition_score(tail, head)
        assert score > 0.60

    def test_pointer_header_link_pdf(self):
        frag_a = b"1 0 obj\n<< /Pages 2 0 R >>\nendobj\n"
        frag_b = b"2 0 obj\n<< /Type /Pages /Count 1 >>\nendobj\n"
        score, desc = check_pointer_header_link(frag_a, frag_b)
        assert score >= 0.85
        assert "PDF" in desc

    def test_pointer_header_link_sqlite(self):
        frag_a = b"SQLite format 3\x00\x10\x00\x01\x01\x00"
        frag_b = b"\x0d\x00\x00\x00\x01\x0f\xf0\x00"
        score, desc = check_pointer_header_link(frag_a, frag_b)
        assert score >= 0.90
        assert "SQLite" in desc

    def test_dag_reassemble_two_fragments(self):
        p1 = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
        p2 = b"2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n%%EOF"

        # Pass in reverse order
        fragments = [{"id": "frag_B", "data": p2}, {"id": "frag_A", "data": p1}]
        reassembly = reassemble_fragments(fragments)

        assert reassembly["ordered_ids"] == ["frag_A", "frag_B"]
        assert reassembly["reassembled_data"].startswith(b"%PDF-1.4")
        assert reassembly["reassembled_data"].endswith(b"%%EOF")


# ============================================================================
# 3. INTEGRITY ASSESSMENT & 4-VECTOR TESTS
# ============================================================================
class TestIntegrity:
    def test_jpeg_intact_validation(self):
        data = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00\xff\xdb\x00\x43\x00" + (b"\x11" * 64) + b"\xff\xc0\x00\x0b\x08\x00\x10\x00\x10\x01\x01\x11\x00\xff\xda\x00\x08\x01\x01\x00\x00\x3f\x00" + (b"\x7f" * 128) + b"\xff\xd9"
        ranges, vec = check_jpeg_integrity(data)
        assert vec["structural"] == 100.0
        assert vec["content"] >= 90.0
        assert len(ranges) == 0

    def test_jpeg_wiped_header(self):
        # Header wiped with zeroes
        data = (b"\x00" * 32) + b"\xff\xdb\x00\x43\x00" + (b"\x11" * 64) + b"\xff\xc0\x00\x0b\x08\x00\x10\x00\x10\x01\x01\x11\x00\xff\xda" + (b"\x7f" * 64) + b"\xff\xd9"
        ranges, vec = check_jpeg_integrity(data)
        assert vec["structural"] < 100.0
        assert any(r["severity"] == "CRITICAL" for r in ranges)

    def test_pdf_intact_validation(self):
        data = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n2 0 obj\n<< /Type /Pages /Count 0 >>\nendobj\nxref\n0 3\ntrailer\n<< /Root 1 0 R >>\nstartxref\n99\n%%EOF"
        ranges, vec = check_pdf_integrity(data)
        assert vec["structural"] >= 90.0
        assert vec["continuity"] >= 90.0

    def test_sqlite_intact_validation(self):
        # 100-byte valid SQLite header with page size 4096 (0x1000)
        hdr = bytearray(b"SQLite format 3\x00" + (b"\x00" * 84))
        hdr[16] = 0x10
        hdr[17] = 0x00
        hdr[18] = 0x01
        hdr[19] = 0x01
        ranges, vec = check_sqlite_integrity(bytes(hdr))
        assert vec["structural"] >= 65.0

    def test_zip_intact_validation(self, tmp_path):
        import zipfile, io
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("evidence.txt", "Forensic Data")
        zip_bytes = buf.getvalue()

        ranges, vec = check_zip_integrity(zip_bytes)
        assert vec["structural"] == 100.0
        assert len(ranges) == 0

    def test_utf8_log_validation(self):
        valid_log = b"2026-09-24 10:00:00 [INFO] System boot verified.\n2026-09-24 10:00:01 [AUTH] User login: admin\n"
        ranges, vec = check_utf8_log_integrity(valid_log)
        assert vec["structural"] >= 90.0
        assert len(ranges) == 0

    def test_utf8_log_with_binary_noise(self):
        bad_log = b"2026-09-24 10:00:00 \xff\xfe\x99\x88 corrupt UTF-8 sequence"
        ranges, vec = check_utf8_log_integrity(bad_log)
        assert any(r["severity"] == "HIGH" for r in ranges)


# ============================================================================
# 4. ANOMALY DETECTION TESTS (ISOLATION FOREST & ENTROPY)
# ============================================================================
class TestAnomaly:
    def test_window_features(self):
        window = b"ABCDEF\x00\x00\x00" * 10
        feats = extract_window_features(window)
        assert len(feats) == 5
        assert feats[0] > 0.0  # entropy
        assert feats[1] > 0.0  # null ratio

    def test_detect_anomalies_zero_wipe(self):
        wipe_data = b"\x00" * 2048
        res = detect_anomalies(wipe_data)
        assert res["has_zero_wipe"] is True
        assert res["overall_null_ratio"] == 1.0

    def test_detect_anomalies_high_entropy_block(self):
        import os
        random_bytes = os.urandom(1024)
        res = detect_anomalies(random_bytes)
        assert res["max_entropy"] > 7.5


# ============================================================================
# 5. CLASSIFICATION & IOC NER TESTS
# ============================================================================
class TestClassification:
    def test_13_format_table_signatures(self):
        assert len(FORMAT_SIGNATURES) == 13

    def test_classify_jpeg(self):
        d = b"\xff\xd8\xff\xe0" + (b"\x00" * 10)
        res = classify_mime_format(d, "test.jpg")
        assert res["mime"] == "image/jpeg"
        assert res["extension_mismatch"] is False

    def test_classify_mismatch_mz_in_jpg(self):
        d = b"MZ\x90\x00\x03\x00\x00\x00" + (b"\x00" * 64)
        res = classify_mime_format(d, "photo.jpg")
        assert res["mime"] == "application/x-dosexec"
        assert res["is_pe"] is True
        assert res["extension_mismatch"] is True

    def test_extract_iocs(self):
        payload = (
            b"Threat actor connected from 198.51.100.24 to exfil.darkmesh.onion "
            b"demanding ransom to Bitcoin wallet bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh "
            b"and deployed mimikatz for credential dumping."
        )
        iocs = extract_iocs_and_entities(payload)
        assert "198.51.100.24" in iocs["ips"]
        assert "exfil.darkmesh.onion" in iocs["onion_domains"]
        assert "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh" in iocs["crypto_wallets"]
        assert "mimikatz" in iocs["attack_keywords"]


# ============================================================================
# 6. PRIORITY ENGINE TESTS
# ============================================================================
class TestPriority:
    def test_weights_sum_to_one(self):
        total_w = WEIGHT_EVIDENCE_RELEVANCE + WEIGHT_INTEGRITY + WEIGHT_TEMPORAL_DECAY + WEIGHT_RARITY
        assert abs(total_w - 1.0) < 1e-6

    def test_critical_priority_tier(self):
        res = compute_priority_score(
            relevance_score=95.0,
            integrity_score=90.0,
            temporal_score=85.0,
            rarity_score=80.0
        )
        assert res["priority_tier"] == "Critical"
        assert res["priority_score"] >= TIER_CRITICAL_THRESHOLD

    def test_low_priority_tier(self):
        res = compute_priority_score(
            relevance_score=10.0,
            integrity_score=20.0,
            temporal_score=30.0,
            rarity_score=10.0
        )
        assert res["priority_tier"] == "Low"
        assert res["priority_score"] < TIER_MEDIUM_THRESHOLD


# ============================================================================
# 7. DETERMINISTIC DECISION ENGINE TESTS
# ============================================================================
class TestDecisionEngine:
    def test_state_blocked_security_risk(self):
        sec = {"is_blocked": True, "has_threat": True, "reasons": ["Disguised PE in JPG"]}
        integ = {"composite_score": 90.0, "vector": {"structural": 90, "content": 90}}
        dec = evaluate_decision_state(integ, security_result=sec)
        assert dec["state"] == STATE_BLOCKED_SECURITY_RISK
        assert dec["confidence"] == 1.0

    def test_state_unrecoverable(self):
        integ = {"composite_score": 0.0, "size_bytes": 1024, "vector": {"structural": 0.0, "content": 0.0}}
        anom = {"overall_null_ratio": 1.0, "has_zero_wipe": True}
        dec = evaluate_decision_state(integ, anomaly_result=anom)
        assert dec["state"] == STATE_UNRECOVERABLE

    def test_state_integrity_verified(self):
        integ = {
            "composite_score": 95.0,
            "vector": {"structural": 95.0, "content": 95.0, "metadata": 90.0, "continuity": 95.0},
            "corruption_ranges": []
        }
        dec = evaluate_decision_state(integ)
        assert dec["state"] == STATE_INTEGRITY_VERIFIED

    def test_state_partially_recoverable(self):
        integ = {
            "composite_score": 65.0,
            "vector": {"structural": 40.0, "content": 85.0, "metadata": 50.0, "continuity": 60.0},
            "corruption_ranges": [{"start": 0, "end": 16, "severity": "HIGH", "description": "Wiped header"}]
        }
        dec = evaluate_decision_state(integ)
        assert dec["state"] == STATE_PARTIALLY_RECOVERABLE


# ============================================================================
# 8. SECURITY SCAN TESTS
# ============================================================================
class TestSecurityScan:
    def test_disguised_mz_in_jpeg(self):
        pe_header = b"MZ\x90\x00" + (b"\x00" * 128)
        res = scan_file_security(pe_header, "malicious.jpg")
        assert res["is_blocked"] is True
        assert res["mismatch_detected"] is True
        assert res["threat_level"] == "CRITICAL"

    def test_pdf_javascript_stream_flagged(self):
        mal_pdf = b"%PDF-1.4\n1 0 obj\n<< /JavaScript (app.alert('pwned')) >>\nendobj\n%%EOF"
        res = scan_file_security(mal_pdf, "statement.pdf")
        assert res["is_blocked"] is True
        assert res["active_stream_count"] > 0


# ============================================================================
# 9. USB RESTORE & VERIFICATION TESTS
# ============================================================================
class TestUSBRestore:
    def test_detect_usb_drives(self):
        drives = detect_usb_drives()
        assert isinstance(drives, list)
        assert len(drives) > 0

    def test_restore_success_verified(self, tmp_path):
        data = b"FORENSIC_EXPORT_CLUSTER_BYTE_STREAM_VERIFIED"
        res = restore_artifact_verified(data, str(tmp_path), "verified_export.bin")
        assert res["status"] == "VERIFIED_SUCCESS"
        assert res["hash_match"] is True
        assert res["purged"] is False
        assert (tmp_path / "verified_export.bin").exists()

    def test_restore_tamper_mismatch_auto_purged(self, tmp_path):
        data = b"FORENSIC_EXPORT_ORIGINAL"
        res = restore_artifact_verified(data, str(tmp_path), "tampered_export.bin", force_tamper_test=True)
        assert res["status"] == "FAILED_MISMATCH_PURGED"
        assert res["hash_match"] is False
        assert res["purged"] is True
        # File must be automatically unlinked/deleted from disk upon hash mismatch!
        assert not (tmp_path / "tampered_export.bin").exists()


# ============================================================================
# 10. FASTAPI API ENDPOINT TESTS
# ============================================================================
class TestFastAPI:
    def test_health_endpoint(self):
        res = client.get("/api/health")
        assert res.status_code == 200
        assert res.json()["status"] == "ok"

    def test_samples_endpoint(self):
        res = client.get("/api/samples")
        assert res.status_code == 200
        data = res.json()
        assert "samples" in data
        assert len(data["samples"]) >= 8

    def test_priority_endpoint(self):
        payload = {
            "relevance_score": 90.0,
            "integrity_score": 85.0,
            "temporal_score": 80.0,
            "rarity_score": 70.0
        }
        res = client.post("/api/priority", json=payload)
        assert res.status_code == 200
        assert res.json()["priority_tier"] in ("Critical", "High")


# ============================================================================
# 11. END-TO-END SPEC SAMPLE DATA EVALUATIONS
# ============================================================================
class TestSpecFixturesE2E:
    @pytest.fixture(autouse=True)
    def check_samples(self):
        assert SAMPLE_DIR.exists(), f"Sample directory missing: {SAMPLE_DIR}"

    def test_intact_jpeg(self):
        p = SAMPLE_DIR / "intact_evidence.jpg"
        res = run_full_pipeline(p.read_bytes(), p.name)
        assert res["decision"]["state"] == STATE_INTEGRITY_VERIFIED
        assert res["integrity"]["composite_score"] >= 85.0

    def test_intact_pdf(self):
        p = SAMPLE_DIR / "intact_report.pdf"
        res = run_full_pipeline(p.read_bytes(), p.name)
        assert res["decision"]["state"] == STATE_INTEGRITY_VERIFIED
        assert res["integrity"]["composite_score"] >= 85.0

    def test_wiped_header_jpeg(self):
        p = SAMPLE_DIR / "wiped_header_photo.jpg"
        res = run_full_pipeline(p.read_bytes(), p.name)
        assert res["decision"]["state"] == STATE_PARTIALLY_RECOVERABLE
        assert any(r["severity"] == "CRITICAL" for r in res["integrity"]["corruption_ranges"])

    def test_wiped_header_pdf(self):
        p = SAMPLE_DIR / "wiped_header_doc.pdf"
        res = run_full_pipeline(p.read_bytes(), p.name)
        assert res["decision"]["state"] == STATE_PARTIALLY_RECOVERABLE

    def test_zero_filled_unrecoverable(self):
        p = SAMPLE_DIR / "zero_filled_wipe.raw"
        res = run_full_pipeline(p.read_bytes(), p.name)
        assert res["decision"]["state"] == STATE_UNRECOVERABLE
        assert res["integrity"]["composite_score"] < 10.0

    def test_disguised_pe_security_risk(self):
        p = SAMPLE_DIR / "invoice.jpg"
        res = run_full_pipeline(p.read_bytes(), p.name)
        assert res["decision"]["state"] == STATE_BLOCKED_SECURITY_RISK
        assert res["security"]["is_blocked"] is True

    def test_sqlite_breach_window_iocs(self):
        p = SAMPLE_DIR / "incident_audit.db"
        res = run_full_pipeline(p.read_bytes(), p.name)
        assert res["decision"]["state"] == STATE_INTEGRITY_VERIFIED
        assert res["priority"]["priority_tier"] in ("Critical", "High")
        assert len(res["classification"]["iocs"]["ips"]) > 0
        assert len(res["classification"]["iocs"]["crypto_wallets"]) > 0

    def test_fragment_cluster_reassembly(self):
        f1 = (SAMPLE_DIR / "fragment_cluster_01.bin").read_bytes()
        f2 = (SAMPLE_DIR / "fragment_cluster_02.bin").read_bytes()
        res = reassemble_fragments([
            {"id": "cluster_02", "data": f2},
            {"id": "cluster_01", "data": f1}
        ])
        assert len(res["ordered_ids"]) == 2
        assert len(res["reassembled_data"]) == 1024
