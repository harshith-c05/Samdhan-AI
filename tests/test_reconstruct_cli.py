"""
tests/test_reconstruct_cli.py
=============================
Regression tests for CLI fragment generator and reconstruction engine.
"""

import hashlib
import io
import shutil
from pathlib import Path
import pytest

import hashlib
import importlib.util
import io
import shutil
import sys
from pathlib import Path
import pytest

ROOT = Path(__file__).resolve().parent.parent

# Load root generate_fragments.py
gen_spec = importlib.util.spec_from_file_location("generate_fragments", str(ROOT / "generate_fragments.py"))
gen_mod = importlib.util.module_from_spec(gen_spec)
gen_spec.loader.exec_module(gen_mod)
slice_file = gen_mod.slice_file

# Load root reconstruct.py
rec_spec = importlib.util.spec_from_file_location("root_reconstruct", str(ROOT / "reconstruct.py"))
rec_mod = importlib.util.module_from_spec(rec_spec)
rec_spec.loader.exec_module(rec_mod)

detect_fragment_role = rec_mod.detect_fragment_role
compute_seam_affinity = rec_mod.compute_seam_affinity
validate_reconstruction = rec_mod.validate_reconstruction
FragmentItem = rec_mod.FragmentItem
group_fragments = rec_mod.group_fragments
order_stream_fragments = rec_mod.order_stream_fragments


def test_slice_file():
    sample_jpg = Path("sample_data/intact_evidence.jpg")
    assert sample_jpg.exists()

    frags = slice_file(sample_jpg, chunk_size=1024)
    assert len(frags) >= 4
    # Check that concatenating fragments reproduces original file
    recombined = b"".join(f["data"] for f in frags)
    assert recombined == sample_jpg.read_bytes()
    assert hashlib.sha256(recombined).hexdigest() == frags[0]["source_sha256"]


def test_detect_fragment_role_jpeg():
    sample_jpg = Path("sample_data/intact_evidence.jpg").read_bytes()
    header_chunk = sample_jpg[:512]
    footer_chunk = sample_jpg[-512:]
    body_chunk = sample_jpg[1024:1536]

    fmt_h, role_h, _ = detect_fragment_role(header_chunk)
    assert fmt_h == "JPEG"
    assert role_h == "HEADER"

    fmt_f, role_f, _ = detect_fragment_role(footer_chunk)
    assert fmt_f == "JPEG"
    assert role_f == "FOOTER"

    fmt_b, role_b, _ = detect_fragment_role(body_chunk)
    assert fmt_b == "JPEG"
    assert role_b == "BODY"


def test_detect_fragment_role_pdf():
    sample_pdf = Path("sample_data/intact_report.pdf").read_bytes()
    header_chunk = sample_pdf[:150]
    footer_chunk = sample_pdf[-150:]

    fmt_h, role_h, _ = detect_fragment_role(header_chunk)
    assert fmt_h == "PDF"
    assert role_h == "HEADER"

    fmt_f, role_f, _ = detect_fragment_role(footer_chunk)
    assert fmt_f == "PDF"
    assert role_f == "FOOTER"


def test_validate_reconstruction():
    jpg_data = Path("sample_data/intact_evidence.jpg").read_bytes()
    status, conf, details = validate_reconstruction(jpg_data, "JPEG")
    assert status == "COMPLETE"
    assert conf >= 95.0

    pdf_data = Path("sample_data/intact_report.pdf").read_bytes()
    status_pdf, conf_pdf, _ = validate_reconstruction(pdf_data, "PDF")
    assert status_pdf == "COMPLETE"
    assert conf_pdf >= 95.0


def test_end_to_end_reconstruction_pipeline(tmp_path):
    # Slice JPEG and PDF into temporary directory
    jpg_path = Path("sample_data/intact_evidence.jpg")
    pdf_path = Path("sample_data/intact_report.pdf")

    jpg_frags = slice_file(jpg_path, chunk_size=1024)
    pdf_frags = slice_file(pdf_path, chunk_size=200)

    frag_files = []
    for idx, f in enumerate(jpg_frags):
        p = tmp_path / f"cluster_{idx+100:05d}.bin"
        p.write_bytes(f["data"])
        frag_files.append(p)

    for idx, f in enumerate(pdf_frags):
        p = tmp_path / f"cluster_{idx+500:05d}.bin"
        p.write_bytes(f["data"])
        frag_files.append(p)

    # Ingest into reconstruct
    items = [FragmentItem(p) for p in frag_files]
    streams = group_fragments(items)

    assert len(streams) == 2
    formats = {s["format"] for s in streams}
    assert "JPEG" in formats
    assert "PDF" in formats

    for s in streams:
        ordered = order_stream_fragments(s)
        assembled = b"".join(x.data for x in ordered)
        status, conf, _ = validate_reconstruction(assembled, s["format"])
        assert status == "COMPLETE"
        assert conf >= 95.0
