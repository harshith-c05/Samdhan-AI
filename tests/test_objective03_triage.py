"""
test_objective03_triage.py
==========================
Comprehensive tests for SAMDHAN AI Objective 03:
Classification & Prioritization Engine.

Covers:
- Deterministic magic byte classification for 7 categories (JPEG, PDF, SQLite, DOCX, EVTX, PCAP, PE/EXE)
- Forensic conflict detection: EXTENSION_SIGNATURE_MISMATCH (e.g. invoice.jpg with MZ header)
- Unknown / headerless fragments with review_required flag
- Semantic text extraction and IOC matching (IPs, domains, attack keywords)
- Incident window temporal proximity scoring
- Duplicate detection & uniqueness calculation
- Noise penalty detection
- Multi-factor Priority Equation: P = w1*I + w2*R + w3*T + w4*U - w5*N
- Invariant: Classification confidence is strictly excluded from priority score P
- Priority tier classification (CRITICAL, HIGH, MEDIUM, LOW)
- Dynamic weight recalculation and presets
- FastAPI API endpoints (/api/classify, /api/prioritize, /api/triage, /api/priority-summary, etc.)
"""

import pytest
import math
from datetime import datetime, timezone, timedelta
from fastapi.testclient import TestClient

from backend.classify import (
    classify_artifact,
    extract_semantic_indicators,
    calculate_relevance,
    ALL_SIGNATURES,
    FORMAT_SIGNATURES
)
from backend.priority import (
    calculate_priority,
    calculate_priority_score,
    calculate_temporal_score,
    calculate_uniqueness_score,
    detect_noise,
    recalculate_priorities,
    DEFAULT_WEIGHTS,
    PRIORITY_PRESETS,
    TIER_CRITICAL,
    TIER_HIGH,
    TIER_MEDIUM,
    TIER_LOW,
    classify_priority_tier
)
from backend.api import app

client = TestClient(app)


# =========================================================================
# 1. Deterministic Magic Byte Classification for All 7 Categories
# =========================================================================

class TestDeterministicClassification:

    def test_valid_jpeg(self):
        # JPEG: FF D8 FF E0
        header = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x01" + b"\x00" * 50
        res = classify_artifact(header, "photo.jpg")
        assert res["detected_format"] == "JPEG"
        assert res["category"] in ("PHOTOS", "Photos")
        assert res["confidence"] >= 0.90
        assert res["conflict"] is False

    def test_valid_pdf(self):
        # PDF: %PDF-1.7
        header = b"%PDF-1.7\r\n1 0 obj\r\n<<>>\r\nendobj"
        res = classify_artifact(header, "statement.pdf")
        assert res["detected_format"] == "PDF"
        assert res["category"] in ("DOCUMENTS", "Documents")
        assert res["confidence"] >= 0.90
        assert res["conflict"] is False

    def test_valid_sqlite(self):
        # SQLite: SQLite format 3\x00
        header = b"SQLite format 3\x00" + b"\x00" * 40
        res = classify_artifact(header, "messages.db")
        assert res["detected_format"] == "SQLITE"
        assert res["category"] in ("DATABASE_LOGS", "Database Logs", "DATABASE")
        assert res["confidence"] >= 0.90
        assert res["conflict"] is False

    def test_valid_docx(self):
        # DOCX is a zip container: PK\x03\x04 + [Content_Types].xml
        header = b"PK\x03\x04\x14\x00\x00\x00\x08\x00" + b"A" * 20 + b"[Content_Types].xml"
        res = classify_artifact(header, "memo.docx")
        assert res["detected_format"] in ("DOCX", "ZIP")
        assert res["category"] in ("DOCUMENTS", "Documents", "SYSTEM_TRACES")
        assert res["confidence"] >= 0.85

    def test_valid_evtx(self):
        # EVTX: ElfFile\x00
        header = b"ElfFile\x00" + b"\x00" * 100
        res = classify_artifact(header, "Security.evtx")
        assert res["detected_format"] == "EVTX"
        assert res["category"] in ("SYSTEM_TRACES", "System Traces")
        assert res["confidence"] >= 0.90
        assert res["conflict"] is False

    def test_valid_pcap(self):
        # PCAP: \xd4\xc3\xb2\xa1
        header = b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00" + b"\x00" * 50
        res = classify_artifact(header, "traffic.pcap")
        assert res["detected_format"] == "PCAP"
        assert res["category"] in ("NETWORK_CAPTURES", "Network Captures")
        assert res["confidence"] >= 0.90
        assert res["conflict"] is False

    def test_valid_pe_executable(self):
        # PE / EXE: MZ header
        header = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00" + b"\x00" * 100
        res = classify_artifact(header, "malware.exe")
        assert res["detected_format"] in ("EXE", "PE")
        assert res["category"] in ("EXECUTABLES", "Executables")
        assert res["confidence"] >= 0.90
        assert res["conflict"] is False


# =========================================================================
# 2. Forensic Conflict Detection (Extension vs Magic Byte Mismatch)
# =========================================================================

class TestForensicConflictDetection:

    def test_invoice_jpg_with_pe_binary_header(self):
        """
        CRITICAL FORENSIC REQUIREMENT:
        Filename is invoice.jpg, but magic bytes indicate MZ (PE Executable).
        Engine must:
        - NEVER classify as JPEG
        - Detect as EXECUTABLES / PE
        - Set conflict = True and extension_mismatch = True
        - Flag EXTENSION_SIGNATURE_MISMATCH
        - Set review_required = True
        """
        header = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00" + b"\x00" * 100
        res = classify_artifact(header, "invoice.jpg")
        
        assert res["detected_format"] in ("EXE", "PE")
        assert res["category"] in ("EXECUTABLES", "Executables")
        assert res["extension_mismatch"] is True
        assert res["conflict"] is True
        
        conflict_types = [c.get("conflict_type") for c in res.get("forensic_conflicts", [])]
        assert "EXTENSION_SIGNATURE_MISMATCH" in conflict_types
        assert res["review_required"] is True

    def test_fake_pdf_with_zip_header(self):
        # file named report.pdf, but starts with PK\x03\x04
        header = b"PK\x03\x04\x14\x00\x00\x00" + b"\x00" * 50
        res = classify_artifact(header, "confidential.pdf")
        assert res["extension_mismatch"] is True
        assert res["conflict"] is True
        assert res["review_required"] is True


# =========================================================================
# 3. Unknown / Headerless Fragment Handling
# =========================================================================

class TestUnknownFragmentHandling:

    def test_unknown_headerless_fragment(self):
        # Raw random bytes
        header = bytes([i % 256 for i in range(128)])
        res = classify_artifact(header, "fragment_chunk_082.raw")
        
        assert res["detected_format"] == "UNKNOWN_FRAGMENT"
        assert res["confidence"] < 0.50
        assert res["review_required"] is True


# =========================================================================
# 4. Semantic Text Extraction & IOC Matching
# =========================================================================

class TestSemanticAnalysis:

    def test_ioc_and_keyword_extraction(self):
        text = """
        ATTENTION: Your files have been encrypted by BlackCat ransom.
        Send 5 BTC to bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq.
        C2 server at 10.20.30.40 and domain evil-ransomware.onion.
        Admin ran mimikatz and powershell -enc Invoke-Mimikatz.
        DROP TABLE audit_trail; shadowcopy delete;
        """
        indicators = extract_semantic_indicators(text)
        
        indicator_terms = [ind["term"] for ind in indicators]
        indicator_types = [ind["type"] for ind in indicators]
        
        # Check IP extraction
        assert "10.20.30.40" in indicator_terms
        assert "IP" in indicator_types
        
        # Check crypto wallet extraction
        assert any(ind["type"] == "CRYPTO_WALLET" for ind in indicators)
        
        # Check attack keyword extraction
        assert any(k in indicator_terms for k in ["ransom", "mimikatz", "powershell", "DROP TABLE", "shadowcopy delete"])

    def test_relevance_calculation(self):
        incident_context = {
            "keywords": ["ransom", "decrypt", "blackcat"],
            "iocs": ["10.20.30.40", "evil-ransomware.onion"],
            "target_usernames": ["Admin", "root"]
        }
        
        # High relevance content
        high_rel_text = "Urgent: contact C2 10.20.30.40 to decrypt files ransom note for Admin"
        high_rel = calculate_relevance(high_rel_text, incident_context, "DOCUMENT")
        
        # Low relevance content
        low_rel_text = "Meeting minutes for the quarterly gardening committee discussion."
        low_rel = calculate_relevance(low_rel_text, incident_context, "DOCUMENT")
        
        assert high_rel["score"] > low_rel["score"]
        assert high_rel["score"] >= 0.70
        assert len(high_rel["matched_indicators"]) >= 2


# =========================================================================
# 5. Temporal Proximity Scoring (Incident Window)
# =========================================================================

class TestTemporalProximity:

    def test_inside_incident_window(self):
        t_start = "2026-09-24T10:00:00Z"
        t_end = "2026-09-24T12:00:00Z"
        artifact_time = "2026-09-24T11:30:00Z"
        
        score, explanation = calculate_temporal_score(artifact_time, t_start, t_end)
        assert score == 1.0
        assert "Inside incident window" in explanation

    def test_outside_incident_window_exponential_decay(self):
        t_start = "2026-09-24T10:00:00Z"
        t_end = "2026-09-24T12:00:00Z"
        # 1 hour after window
        artifact_time = "2026-09-24T13:00:00Z"
        
        score, explanation = calculate_temporal_score(artifact_time, t_start, t_end)
        assert 0.0 < score < 1.0
        
        # 24 hours after window should have lower score
        artifact_later = "2026-09-25T12:00:00Z"
        score_later, _ = calculate_temporal_score(artifact_later, t_start, t_end)
        assert score_later < score


# =========================================================================
# 6. Uniqueness & Duplicate Cluster Detection
# =========================================================================

class TestUniquenessAndDuplicates:

    def test_unique_artifact(self):
        score, is_dup, cluster_id, ratio = calculate_uniqueness_score(
            artifact_hash="3a7b...",
            cluster_members=[],
            duplication_ratio=0.0
        )
        assert score == 1.0
        assert is_dup is False
        assert ratio == 0.0

    def test_duplicate_cluster_penalty(self):
        # 3 copies of an image
        cluster = ["art_01", "art_02", "art_03"]
        score, is_dup, cluster_id, ratio = calculate_uniqueness_score(
            artifact_hash="3a7b...",
            cluster_members=cluster,
            duplication_ratio=0.67
        )
        assert is_dup is True
        assert score < 0.50
        assert math.isclose(score, 1.0 - 0.67, rel_tol=1e-2)


# =========================================================================
# 7. Noise Detection
# =========================================================================

class TestNoiseDetection:

    def test_browser_cache_and_thumbs_db(self):
        penalty, reasons = detect_noise("Thumbs.db", r"C:\Users\User\Pictures\Thumbs.db")
        assert penalty >= 0.60
        assert any("OS-generated thumbnail" in r for r in reasons)

        penalty_cache, reasons_cache = detect_noise("data_0", r"C:\Users\User\AppData\Local\Google\Chrome\User Data\Default\Cache\Cache_Data\data_0")
        assert penalty_cache >= 0.70
        assert any("Browser cache" in r for r in reasons_cache)

    def test_genuine_evidence_has_zero_noise(self):
        penalty, reasons = detect_noise("ransom_note.txt", r"C:\Users\Admin\Desktop\ransom_note.txt")
        assert penalty == 0.0
        assert len(reasons) == 0


# =========================================================================
# 8. Priority Equation & Invariant: Confidence Excluded
# =========================================================================

class TestPriorityEquationAndInvariants:

    def test_priority_mathematical_formula(self):
        """
        Verify: P = w1*I + w2*R + w3*T + w4*U - w5*N
        With default weights: w1=0.30, w2=0.35, w3=0.20, w4=0.15, w5=0.10
        """
        I, R, T, U, N = 0.94, 0.98, 1.00, 0.91, 0.00
        expected = (0.30 * I) + (0.35 * R) + (0.20 * T) + (0.15 * U) - (0.10 * N)
        # 0.282 + 0.343 + 0.200 + 0.1365 - 0.0 = 0.9615
        
        actual = calculate_priority_score(I, R, T, U, N, DEFAULT_WEIGHTS)
        assert math.isclose(actual, round(expected, 4), rel_tol=1e-3)

    def test_classification_confidence_strictly_excluded_from_priority(self):
        """
        CRITICAL ARCHITECTURAL INVARIANT:
        Classification confidence MUST NEVER influence priority score P.
        Artifact A: confidence = 0.99, relevance = 0.20
        Artifact B: confidence = 0.45, relevance = 0.95
        Artifact B must receive significantly higher priority than Artifact A!
        """
        weights = DEFAULT_WEIGHTS
        
        # Artifact A: High confidence format, low relevance
        score_a = calculate_priority_score(
            integrity=0.90, relevance=0.20, temporal=0.50, uniqueness=0.80, noise=0.0, weights=weights
        )
        
        # Artifact B: Uncertain format, high investigative relevance
        score_b = calculate_priority_score(
            integrity=0.90, relevance=0.95, temporal=0.90, uniqueness=0.80, noise=0.0, weights=weights
        )
        
        assert score_b > score_a
        assert score_b >= 0.75  # Should be CRITICAL
        assert score_a < 0.60   # Should be significantly lower than score_b

    def test_priority_tier_thresholds(self):
        # 0-1 scale thresholds
        assert classify_priority_tier(0.90) == "CRITICAL"
        assert classify_priority_tier(0.75) == "CRITICAL"
        assert classify_priority_tier(0.74) == "HIGH"
        assert classify_priority_tier(0.50) == "HIGH"
        assert classify_priority_tier(0.49) == "MEDIUM"
        assert classify_priority_tier(0.25) == "MEDIUM"
        assert classify_priority_tier(0.24) == "LOW"
        assert classify_priority_tier(0.05) == "LOW"


# =========================================================================
# 9. Dynamic Weight Recalculation & Presets
# =========================================================================

class TestWeightRecalculation:

    def test_recalculate_priorities_with_preset(self):
        artifacts = [
            {
                "artifact_id": "art_1",
                "integrity": 0.50,
                "relevance": 0.95,
                "temporal": 1.00,
                "uniqueness": 0.80,
                "noise": 0.00,
            },
            {
                "artifact_id": "art_2",
                "integrity": 0.95,
                "relevance": 0.30,
                "temporal": 0.20,
                "uniqueness": 0.40,
                "noise": 0.00,
            }
        ]
        
        # Recalculate with RANSOMWARE preset (high relevance weight = 0.50)
        recalculated = recalculate_priorities(artifacts, PRIORITY_PRESETS["RANSOMWARE"])
        
        art1_recalc = next(a for a in recalculated if a["artifact_id"] == "art_1")
        art2_recalc = next(a for a in recalculated if a["artifact_id"] == "art_2")
        
        assert art1_recalc["priority"]["score"] > art2_recalc["priority"]["score"]
        assert art1_recalc["priority"]["tier"] in ("CRITICAL", "HIGH")


# =========================================================================
# 10. FastAPI API Endpoints
# =========================================================================

class TestFastApiObjective03Endpoints:

    def test_api_classify_endpoint(self):
        payload = {
            "artifact_id": "test_pe_01",
            "filename": "invoice.jpg",
            "hex_header": "4d5a90000300000004000000ffff0000",  # "MZ..."
            "text_preview": "This looks like an invoice"
        }
        res = client.post("/api/classify", json=payload)
        assert res.status_code == 200
        data = res.json()
        assert data["category"] in ("EXECUTABLES", "Executables")
        assert data["conflict"] is True
        assert data["review_required"] is True

    def test_api_prioritize_endpoint(self):
        payload = {
            "artifact_id": "test_art_01",
            "integrity": 0.95,
            "relevance": 0.92,
            "temporal": 1.00,
            "uniqueness": 0.85,
            "noise": 0.00,
            "weights": {
                "w1_integrity": 0.30,
                "w2_relevance": 0.35,
                "w3_temporal": 0.20,
                "w4_uniqueness": 0.15,
                "w5_noise": 0.10
            }
        }
        res = client.post("/api/prioritize", json=payload)
        assert res.status_code == 200
        data = res.json()
        assert data["score"] >= 0.75
        assert data["tier"] == "CRITICAL"
        assert len(data["reasons"]) > 0

    def test_api_triage_endpoint(self):
        res = client.post("/api/triage", json={})
        assert res.status_code == 200
        data = res.json()
        assert "artifacts" in data
        assert "classification_summary" in data
        assert "priority_summary" in data
        assert "weights" in data
        assert "tiers" in data
        assert len(data["artifacts"]) > 0

    def test_api_priority_summary_and_distribution(self):
        summary_res = client.get("/api/priority-summary")
        assert summary_res.status_code == 200
        sum_data = summary_res.json()
        assert "CRITICAL" in sum_data
        assert "HIGH" in sum_data
        assert "MEDIUM" in sum_data
        assert "LOW" in sum_data

        dist_res = client.get("/api/priority-distribution")
        assert dist_res.status_code == 200
        dist_data = dist_res.json()
        assert "distribution" in dist_data

    def test_api_recalculate_endpoint(self):
        payload = {
            "weights": {
                "w1_integrity": 0.10,
                "w2_relevance": 0.60,
                "w3_temporal": 0.15,
                "w4_uniqueness": 0.10,
                "w5_noise": 0.05
            }
        }
        res = client.post("/api/priority/recalculate", json=payload)
        assert res.status_code == 200
        data = res.json()
        assert "artifacts" in data
        assert "weights_applied" in data
