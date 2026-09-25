"""
backend/security_scan.py
========================
SAMDHAN AI — Active Security & Malicious Disguise Detection Scanner.

Specification:
- Extension vs Magic-byte mismatch check (e.g. .jpg with MZ header)
- High-entropy packed payload flag (entropy > 7.5)
- Embedded malicious stream detection:
  - PDF: /JavaScript, /JS, /Launch, /EmbeddedFile
  - Office/ZIP: VBA macros (vbaProject.bin)
  - Shell / execution triggers (cmd.exe, powershell -enc, rundll32)
"""

import math
import re
from typing import Dict, List, Optional, Any

from backend.anomaly import compute_entropy_for_window

# Named Thresholds
ENTROPY_PACKED_THRESHOLD = 7.5


def check_extension_magic_mismatch(data: bytes, filename: str) -> Optional[Dict[str, str]]:
    """
    Checks if an innocuous file extension disguises an executable or dangerous binary.
    """
    if not filename or len(data) < 2:
        return None

    fn_lower = filename.lower()
    innocuous_exts = (".jpg", ".jpeg", ".png", ".gif", ".pdf", ".txt", ".docx", ".xlsx", ".csv")

    is_innocuous = any(fn_lower.endswith(ext) for ext in innocuous_exts)
    if not is_innocuous:
        return None

    # Check for executable headers
    if data.startswith(b"MZ"):
        return {
            "threat": "Disguised Windows Portable Executable (PE/MZ)",
            "severity": "CRITICAL",
            "reason": f"File named '{filename}' contains MZ header (Win32/PE executable disguised as document/image)"
        }
    if data.startswith(b"\x7fELF"):
        return {
            "threat": "Disguised Linux ELF Executable",
            "severity": "CRITICAL",
            "reason": f"File named '{filename}' contains ELF executable header"
        }
    if data.startswith(b"#!/bin/") or data.startswith(b"#!/usr/bin/"):
        return {
            "threat": "Disguised Shell Script",
            "severity": "HIGH",
            "reason": f"File named '{filename}' contains shell shebang interpreter header"
        }

    return None


def scan_embedded_malicious_streams(data: bytes) -> List[Dict[str, str]]:
    """
    Scans for active content, macros, and embedded code execution vectors.
    """
    findings = []
    text_latin = data.decode("latin-1", errors="ignore")

    # 1. PDF Malicious Action streams
    pdf_triggers = [
        ("/JavaScript", "PDF Embedded JavaScript execution stream"),
        ("/JS", "PDF JS action trigger"),
        ("/Launch", "PDF /Launch arbitrary program execution object"),
        ("/EmbeddedFiles", "PDF hidden embedded file payload")
    ]
    for token, desc in pdf_triggers:
        if token in text_latin:
            findings.append({
                "vector": "PDF Active Content",
                "severity": "HIGH",
                "reason": desc
            })

    # 2. Office VBA Macros
    if b"vbaProject.bin" in data or b"word/vbaData.xml" in data or b"macroEnabled" in data:
        findings.append({
            "vector": "Office Macro",
            "severity": "HIGH",
            "reason": "Embedded VBA Project binary detected (potential macro malware)"
        })

    # 3. Encoded PowerShell or shell triggers
    patterns = [
        (r"powershell(?:\.exe)?\s+-[eE](?:nc(?:odedcommand)?)?\s+[A-Za-z0-9+/=]{20,}", "Encoded PowerShell payload invocation"),
        (r"(?:cmd\.exe|powershell\.exe)\s+/[cCkK]", "Suspicious command shell invocation sequence"),
        (r"rundll32(?:\.exe)?\s+.*,\s*(?:DllRegisterServer|EntryPoint)", "Rundll32 DLL execution injection")
    ]
    for pat, desc in patterns:
        if re.search(pat, text_latin, re.IGNORECASE):
            findings.append({
                "vector": "Execution Script",
                "severity": "CRITICAL",
                "reason": desc
            })

    return findings


def scan_file_security(data: bytes, filename: str = "") -> Dict[str, Any]:
    """
    Runs complete forensic security scan across the data bitstream:
    1. Extension vs magic header mismatch
    2. High-entropy packed payload analysis
    3. Active code / macro / PDF script stream detection
    """
    reasons = []
    is_blocked = False
    threat_level = "CLEAN"

    # 1. Mismatch check
    mismatch = check_extension_magic_mismatch(data, filename)
    if mismatch:
        reasons.append(mismatch["reason"])
        is_blocked = True
        threat_level = "CRITICAL"

    # 2. Entropy check
    ent = compute_entropy_for_window(data)
    is_packed = False
    if ent > ENTROPY_PACKED_THRESHOLD:
        # If it's disguised or has MZ header or non-standard format
        if mismatch or data.startswith(b"MZ") or filename.lower().endswith((".jpg", ".png", ".txt", ".pdf")):
            if mismatch or data.startswith(b"MZ"):
                reasons.append(f"High-entropy packed executable payload (Shannon Entropy H={ent:.2f} > {ENTROPY_PACKED_THRESHOLD})")
                is_blocked = True
                threat_level = "CRITICAL"
            is_packed = True

    # 3. Active execution streams (scanned only on active document / executable types, not passive databases or audit logs)
    fn_lower = filename.lower()
    is_passive_data = fn_lower.endswith((".db", ".sqlite", ".sqlite3", ".log", ".txt", ".csv"))
    if not is_passive_data:
        streams = scan_embedded_malicious_streams(data)
        for st in streams:
            reasons.append(f"{st['vector']}: {st['reason']}")
            if st["severity"] in ("CRITICAL", "HIGH"):
                is_blocked = True
                threat_level = "CRITICAL" if threat_level == "CRITICAL" else "HIGH"
    else:
        streams = []

    return {
        "filename": filename,
        "is_blocked": is_blocked,
        "has_threat": len(reasons) > 0,
        "threat_level": threat_level,
        "reasons": reasons,
        "entropy": round(ent, 3),
        "is_packed": is_packed,
        "mismatch_detected": mismatch is not None,
        "active_stream_count": len(streams),
    }
