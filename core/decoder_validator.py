"""
core/decoder_validator.py
=========================
Phase 2 Real Decoder Validation Engine.
Attempts non-destructive decoding using actual format decoders (PIL, zlib, zipfile)
without modifying or repairing the source byte stream.
Decoder failure or warning is captured as courtroom-defensible forensic evidence.
"""

from __future__ import annotations

import io
import struct
import zipfile
import zlib
from typing import Any, Dict, Optional

from core.models import DecoderResult


def validate_decoder(
    data: bytes,
    format_name: str,
    artifact_id: str = "ARTIFACT",
) -> DecoderResult:
    """
    Attempts actual real-world decoder execution on the raw byte stream.
    Strictly read-only; never repairs, patches, or fabricates missing bytes.
    """
    fmt = format_name.upper().strip()

    if fmt == "JPEG":
        return _decode_jpeg(data)
    elif fmt == "PNG":
        return _decode_png(data)
    elif fmt == "ZIP":
        return _decode_zip(data)
    elif fmt == "PDF":
        return _decode_pdf(data)
    else:
        return DecoderResult(
            decoder_name=f"Generic/{fmt}",
            attempted=False,
            success=False,
            error_message=f"No decoder validator available for format '{fmt}'",
            partial_recovery_possible=False,
            details={},
        )


def _decode_jpeg(data: bytes) -> DecoderResult:
    """Validates JPEG using PIL Image decoder."""
    has_soi = data[:2] == b"\xff\xd8"
    has_sof = b"\xff\xc0" in data or b"\xff\xc2" in data

    try:
        from PIL import Image, ImageFile
        # Strict mode — do not truncate silently
        ImageFile.LOAD_TRUNCATED_IMAGES = False

        bio = io.BytesIO(data)
        with Image.open(bio) as img:
            img.verify()

        # Reopen to load pixels
        bio.seek(0)
        with Image.open(bio) as img:
            img.load()
            width, height = img.size
            mode = img.mode

        return DecoderResult(
            decoder_name="PIL/JPEG",
            attempted=True,
            success=True,
            error_message=None,
            partial_recovery_possible=True,
            details={"width": width, "height": height, "mode": mode, "verified": True},
        )
    except Exception as e:
        err_msg = str(e)
        # Even if decoder fails, if header/SOF exists, partial features are recoverable
        partial_ok = bool(has_soi and has_sof)
        return DecoderResult(
            decoder_name="PIL/JPEG",
            attempted=True,
            success=False,
            error_message=err_msg,
            partial_recovery_possible=partial_ok,
            details={
                "has_soi": has_soi,
                "has_sof": has_sof,
                "diagnostic": "Decoder encountered invalid/truncated scan or marker stream",
            },
        )


def _decode_png(data: bytes) -> DecoderResult:
    """Validates PNG using PIL Image decoder and zlib decompression."""
    has_sig = data[:8] == b"\x89PNG\r\n\x1a\n"
    has_ihdr = b"IHDR" in data

    try:
        from PIL import Image, ImageFile
        ImageFile.LOAD_TRUNCATED_IMAGES = False

        bio = io.BytesIO(data)
        with Image.open(bio) as img:
            img.verify()

        bio.seek(0)
        with Image.open(bio) as img:
            img.load()
            width, height = img.size
            mode = img.mode

        return DecoderResult(
            decoder_name="PIL/PNG",
            attempted=True,
            success=True,
            error_message=None,
            partial_recovery_possible=True,
            details={"width": width, "height": height, "mode": mode, "verified": True},
        )
    except Exception as e:
        err_msg = str(e)
        partial_ok = bool(has_sig and has_ihdr)
        return DecoderResult(
            decoder_name="PIL/PNG",
            attempted=True,
            success=False,
            error_message=err_msg,
            partial_recovery_possible=partial_ok,
            details={
                "has_signature": has_sig,
                "has_ihdr": has_ihdr,
                "diagnostic": "Decoder encountered corrupted chunk or zlib decompression error",
            },
        )


def _decode_zip(data: bytes) -> DecoderResult:
    """Validates ZIP archive by reading central directory and executing testzip()."""
    bio = io.BytesIO(data)
    try:
        with zipfile.ZipFile(bio, "r") as zf:
            file_list = zf.namelist()
            # testzip() reads every member and verifies CRC-32!
            bad_member = zf.testzip()

            if bad_member is not None:
                # One member has CRC failure, but other members may be recoverable!
                return DecoderResult(
                    decoder_name="zipfile/ZIP",
                    attempted=True,
                    success=False,
                    error_message=f"CRC check failed in member: {bad_member}",
                    partial_recovery_possible=True,
                    details={
                        "total_members": len(file_list),
                        "members": file_list,
                        "corrupted_member": bad_member,
                        "recoverable_members": [m for m in file_list if m != bad_member],
                    },
                )

            return DecoderResult(
                decoder_name="zipfile/ZIP",
                attempted=True,
                success=True,
                error_message=None,
                partial_recovery_possible=True,
                details={"total_members": len(file_list), "members": file_list, "all_crc_valid": True},
            )
    except Exception as e:
        # Check if local headers exist for partial recovery
        has_pk = b"PK\x03\x04" in data
        return DecoderResult(
            decoder_name="zipfile/ZIP",
            attempted=True,
            success=False,
            error_message=str(e),
            partial_recovery_possible=has_pk,
            details={"has_local_headers": has_pk, "diagnostic": "Broken central directory or truncated archive"},
        )


def _decode_pdf(data: bytes) -> DecoderResult:
    """Validates PDF structural parseability (objects, streams, trailer)."""
    has_header = data[:5] == b"%PDF-"
    has_eof = b"%%EOF" in data[-1024:] if len(data) >= 8 else False

    obj_count = len(data.split(b"obj")) - 1
    endobj_count = len(data.split(b"endobj")) - 1
    stream_count = len(data.split(b"stream")) - 1
    endstream_count = len(data.split(b"endstream")) - 1

    objects_balanced = (obj_count > 0) and (abs(obj_count - endobj_count) <= 1)
    streams_balanced = abs(stream_count - endstream_count) <= 1

    if has_header and has_eof and objects_balanced and streams_balanced:
        return DecoderResult(
            decoder_name="NativeParser/PDF",
            attempted=True,
            success=True,
            error_message=None,
            partial_recovery_possible=True,
            details={
                "objects_count": obj_count,
                "streams_count": stream_count,
                "has_eof": True,
            },
        )
    else:
        reasons = []
        if not has_header:
            reasons.append("Missing %PDF- header")
        if not has_eof:
            reasons.append("Missing terminal %%EOF marker")
        if not objects_balanced:
            reasons.append(f"Unbalanced objects ({obj_count} obj vs {endobj_count} endobj)")
        if not streams_balanced:
            reasons.append(f"Unbalanced streams ({stream_count} stream vs {endstream_count} endstream)")

        partial_ok = bool(has_header and obj_count > 0)
        return DecoderResult(
            decoder_name="NativeParser/PDF",
            attempted=True,
            success=False,
            error_message="; ".join(reasons) or "PDF parser failed",
            partial_recovery_possible=partial_ok,
            details={
                "objects_count": obj_count,
                "streams_count": stream_count,
                "has_eof": has_eof,
                "diagnostic": "PDF trailer or stream boundaries corrupted",
            },
        )
