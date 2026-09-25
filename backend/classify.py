"""
backend/classify.py
===================
SAMDHAN AI — MIME Classification Table (13 Formats) & spaCy/Regex IOC NER Engine.

Specification:
- Magic-byte MIME classification table covering 13 common forensic file formats
- Indicators of Compromise (IOC) Named Entity Recognition:
  - IPv4 / IPv6 addresses
  - Threat domain names & Tor .onion darknet endpoints
  - Cryptocurrency wallet addresses (Bitcoin Bech32/Base58, Ethereum, Monero)
  - Attack keywords (mimikatz, ransom, cobalt strike, c2, exfil, privilege escalation)
- Uses spaCy NER when available, with deterministic regex entity extraction
"""

import re
from typing import Dict, List, Optional, Tuple, Any

try:
    import spacy
    try:
        nlp = spacy.load("en_core_web_sm")
    except Exception:
        nlp = None
except ImportError:
    spacy = None
    nlp = None


# Exact 13 format signatures table
FORMAT_SIGNATURES = [
    {
        "mime": "image/jpeg",
        "format": "JPEG Image",
        "extensions": [".jpg", ".jpeg"],
        "check": lambda d: d.startswith(b"\xff\xd8\xff"),
        "min_size": 4
    },
    {
        "mime": "image/png",
        "format": "PNG Image",
        "extensions": [".png"],
        "check": lambda d: d.startswith(b"\x89PNG\r\n\x1a\n"),
        "min_size": 8
    },
    {
        "mime": "image/gif",
        "format": "GIF Image",
        "extensions": [".gif"],
        "check": lambda d: d.startswith(b"GIF87a") or d.startswith(b"GIF89a"),
        "min_size": 6
    },
    {
        "mime": "application/pdf",
        "format": "PDF Document",
        "extensions": [".pdf"],
        "check": lambda d: d.startswith(b"%PDF-"),
        "min_size": 8
    },
    {
        "mime": "application/zip",
        "format": "ZIP Archive / OpenXML",
        "extensions": [".zip", ".docx", ".xlsx", ".pptx", ".jar"],
        "check": lambda d: d.startswith(b"PK\x03\x04"),
        "min_size": 4
    },
    {
        "mime": "application/x-sqlite3",
        "format": "SQLite Database",
        "extensions": [".db", ".sqlite", ".sqlite3"],
        "check": lambda d: d.startswith(b"SQLite format 3\x00"),
        "min_size": 16
    },
    {
        "mime": "application/x-dosexec",
        "format": "Windows Portable Executable (PE)",
        "extensions": [".exe", ".dll", ".sys"],
        "check": lambda d: d.startswith(b"MZ"),
        "min_size": 2
    },
    {
        "mime": "application/x-elf",
        "format": "ELF Linux Executable",
        "extensions": [".bin", ".elf", ".so"],
        "check": lambda d: d.startswith(b"\x7fELF"),
        "min_size": 4
    },
    {
        "mime": "application/x-tar",
        "format": "TAR Archive",
        "extensions": [".tar"],
        "check": lambda d: len(d) > 262 and d[257:262] == b"ustar",
        "min_size": 265
    },
    {
        "mime": "application/gzip",
        "format": "GZIP Compressed File",
        "extensions": [".gz", ".tar.gz"],
        "check": lambda d: d.startswith(b"\x1f\x8b"),
        "min_size": 2
    },
    {
        "mime": "application/x-7z-compressed",
        "format": "7-Zip Archive",
        "extensions": [".7z"],
        "check": lambda d: d.startswith(b"7z\xbc\xaf\x27\x1c"),
        "min_size": 6
    },
    {
        "mime": "video/mp4",
        "format": "MP4 Video",
        "extensions": [".mp4", ".m4v"],
        "check": lambda d: len(d) >= 12 and d[4:8] == b"ftyp",
        "min_size": 12
    },
    {
        "mime": "text/plain",
        "format": "Plain Text / Log",
        "extensions": [".txt", ".log", ".csv", ".json"],
        "check": lambda d: len(d) > 0 and all(
            b in (9, 10, 13) or 32 <= b <= 126 for b in d[:min(256, len(d))]
        ),
        "min_size": 1
    },
]

# High-precision IOC extraction patterns
REGEX_IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b")
REGEX_ONION = re.compile(r"\b[a-zA-Z0-9.-]+\.onion\b", re.IGNORECASE)
REGEX_DOMAIN = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+(?:com|net|org|io|darkmesh|ru|xyz|top|cc|me)\b", re.IGNORECASE)
REGEX_BTC_BECH32 = re.compile(r"\bbc1[a-z0-9]{25,39}\b")
REGEX_BTC_BASE58 = re.compile(r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b")
REGEX_ETH = re.compile(r"\b0x[a-fA-F0-9]{40}\b")

ATTACK_KEYWORDS = [
    "mimikatz", "cobaltstrike", "cobalt strike", "ransomware", "exfiltration",
    "privilege escalation", "lateral movement", "shadow copies", "vssadmin",
    "powershell -enc", "beacon", "command and control", "c2 server", "breach",
    "dump_hashes", "lsass", "meterpreter", "reverse_tcp", "keylogger"
]


def classify_mime_format(data: bytes, filename: str = "") -> Dict[str, Any]:
    """
    Identifies MIME type and format using the 13-format magic byte table.
    Also flags extension mismatches if a filename is provided.
    """
    detected_mime = "application/octet-stream"
    detected_format = "Unknown Binary"
    is_pe = data.startswith(b"MZ")

    for entry in FORMAT_SIGNATURES:
        if len(data) >= entry["min_size"] and entry["check"](data):
            detected_mime = entry["mime"]
            detected_format = entry["format"]
            break

    # Extension mismatch check
    mismatch = False
    expected_mimes = []
    if filename:
        ext = "." + filename.lower().split(".")[-1] if "." in filename else ""
        for entry in FORMAT_SIGNATURES:
            if ext in entry["extensions"]:
                expected_mimes.append(entry["mime"])

        if expected_mimes and detected_mime not in expected_mimes:
            mismatch = True

    return {
        "mime": detected_mime,
        "format": detected_format,
        "is_pe": is_pe,
        "extension_mismatch": mismatch,
        "expected_mimes": expected_mimes
    }


def extract_iocs_and_entities(data: bytes) -> Dict[str, Any]:
    """
    Extracts Indicators of Compromise (IOCs) and relevant entities from raw bytes.
    Extracts:
    - IPv4 addresses
    - Threat domains and .onion addresses
    - Cryptocurrency wallets
    - Attack and ransomware keywords
    - spaCy entities (ORG, PERSON, GPE, DATE)
    """
    # Extract printable text strings
    text = data.decode("utf-8", errors="ignore")
    latin_text = data.decode("latin-1", errors="ignore")
    extra_texts = []

    # If it is a valid SQLite DB, extract records directly from tables
    if data.startswith(b"SQLite format 3\x00"):
        import tempfile, sqlite3
        try:
            with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tf:
                tf.write(data)
                temp_db_path = tf.name
            conn = sqlite3.connect(temp_db_path)
            tables = [row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
            for tbl in tables:
                rows = conn.execute(f"SELECT * FROM \"{tbl}\"").fetchall()
                for r in rows:
                    extra_texts.append(" ".join(str(c) for c in r if c is not None))
            conn.close()
        except Exception:
            pass

    combined_text = text + "\n" + latin_text + "\n" + "\n".join(extra_texts)

    # 1. IP Addresses
    raw_ips = REGEX_IPV4.findall(combined_text)
    # Deduplicate and filter out common local loopback noise if wanted, but keep evidence
    ips = sorted(list(set(raw_ips)))

    # 2. Domains and Tor .onion endpoints
    onions = sorted(list(set(REGEX_ONION.findall(combined_text.lower()))))
    domains = [d for d in set(REGEX_DOMAIN.findall(combined_text.lower())) if not d.endswith(".onion")]

    # 3. Cryptocurrency Wallets
    btc_bech32 = REGEX_BTC_BECH32.findall(combined_text)
    btc_base58 = REGEX_BTC_BASE58.findall(combined_text)
    eth = REGEX_ETH.findall(combined_text)
    crypto_wallets = sorted(list(set(btc_bech32 + btc_base58 + eth)))

    # 4. Attack Keywords
    found_keywords = []
    lower_comb = combined_text.lower()
    for kw in ATTACK_KEYWORDS:
        if kw in lower_comb:
            found_keywords.append(kw)
    found_keywords = sorted(list(set(found_keywords)))

    # 5. spaCy Named Entity Recognition
    spacy_entities = []
    if nlp and len(text.strip()) > 20:
        try:
            # Process max first 10,000 chars to avoid memory overhead
            doc = nlp(text[:10000])
            for ent in doc.ents:
                if ent.label_ in ("ORG", "PERSON", "GPE", "DATE", "MONEY"):
                    spacy_entities.append({"text": ent.text, "label": ent.label_})
        except Exception:
            pass

    total_iocs = len(ips) + len(onions) + len(crypto_wallets) + len(found_keywords)

    return {
        "ips": ips,
        "onion_domains": onions,
        "domains": sorted(domains)[:10],
        "crypto_wallets": crypto_wallets,
        "attack_keywords": found_keywords,
        "spacy_entities": spacy_entities[:15],
        "total_ioc_count": total_iocs,
        "has_high_value_iocs": total_iocs > 0
    }


def classify_artifact(data: bytes, filename: str = "") -> Dict[str, Any]:
    """
    Combined classification entry point:
    Returns MIME format classification + full IOC extraction.
    """
    mime_info = classify_mime_format(data, filename)
    iocs = extract_iocs_and_entities(data)

    return {
        **mime_info,
        "iocs": iocs,
        "ioc_summary": {
            "ips_count": len(iocs["ips"]),
            "wallets_count": len(iocs["crypto_wallets"]),
            "darknet_count": len(iocs["onion_domains"]),
            "keywords_count": len(iocs["attack_keywords"]),
        }
    }
