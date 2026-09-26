"""
backend/classify.py
===================
SAMDHAN AI — MIME Classification Table (13 Formats) & spaCy/Regex IOC NER Engine.

Features:
- Two-path forensic classification:
    PATH A: Deterministic Magic-Byte Signatures & Content Grammars across 7 Forensic Categories:
            1. Documents
            2. Database Logs
            3. Photos
            4. System Traces
            5. Network Captures
            6. Registry Hives
            7. Executables
    PATH B: Statistical/Semantic analysis for text, logs, scripts, and headerless fragments.
- Priority of Trust:
    ACTUAL BYTES > MIME / CONTAINER STRUCTURE > FILE EXTENSION (Lowest trust, trivially spoofed)
- Forensic Conflict Detection:
    Never silently trust filename extension (e.g. invoice.jpg with MZ header).
    Produces explicit extension_mismatch and EXTENSION_SIGNATURE_MISMATCH conflict flags.
- High-precision IOC & Semantic Entity Recognition:
    - IPv4 / IPv6 addresses
    - Threat domain names & Tor .onion darknet endpoints
    - Cryptocurrency wallet addresses (Bitcoin Bech32/Base58, Ethereum, Monero)
    - Attack keywords (mimikatz, ransom, cobalt strike, c2, exfil, privilege escalation, etc.)
- Low-confidence handling:
    Confidence < 0.60 sets review_required = True independently of priority.
"""

import re
from typing import Dict, List, Optional, Tuple, Any, Union

try:
    import spacy
    try:
        nlp = spacy.load("en_core_web_sm")
    except Exception:
        nlp = None
except ImportError:
    spacy = None
    nlp = None

# ---------------------------------------------------------------------------
# 7 Official Forensic Categories
# ---------------------------------------------------------------------------
CAT_DOCUMENTS = "Documents"
CAT_DATABASE_LOGS = "Database Logs"
CAT_PHOTOS = "Photos"
CAT_SYSTEM_TRACES = "System Traces"
CAT_NETWORK_CAPTURES = "Network Captures"
CAT_REGISTRY_HIVES = "Registry Hives"
CAT_EXECUTABLES = "Executables"

ALL_CATEGORIES = [
    CAT_DOCUMENTS,
    CAT_DATABASE_LOGS,
    CAT_PHOTOS,
    CAT_SYSTEM_TRACES,
    CAT_NETWORK_CAPTURES,
    CAT_REGISTRY_HIVES,
    CAT_EXECUTABLES,
]

# ---------------------------------------------------------------------------
# Exact 13 format signatures table (per SAMDHAN master specification)
# ---------------------------------------------------------------------------
FORMAT_SIGNATURES = [
    {
        "mime": "image/jpeg",
        "format": "JPEG Image",
        "category": CAT_PHOTOS,
        "extensions": [".jpg", ".jpeg"],
        "check": lambda d: d.startswith(b"\xff\xd8\xff"),
        "min_size": 4,
        "confidence": 0.99,
        "sig_hex": "ffd8ff"
    },
    {
        "mime": "image/png",
        "format": "PNG Image",
        "category": CAT_PHOTOS,
        "extensions": [".png"],
        "check": lambda d: d.startswith(b"\x89PNG\r\n\x1a\n"),
        "min_size": 8,
        "confidence": 0.995,
        "sig_hex": "89504e470d0a1a0a"
    },
    {
        "mime": "image/gif",
        "format": "GIF Image",
        "category": CAT_PHOTOS,
        "extensions": [".gif"],
        "check": lambda d: d.startswith(b"GIF87a") or d.startswith(b"GIF89a"),
        "min_size": 6,
        "confidence": 0.98,
        "sig_hex": "47494638"
    },
    {
        "mime": "application/pdf",
        "format": "PDF Document",
        "category": CAT_DOCUMENTS,
        "extensions": [".pdf"],
        "check": lambda d: d.startswith(b"%PDF-"),
        "min_size": 8,
        "confidence": 0.99,
        "sig_hex": "255044462d"
    },
    {
        "mime": "application/zip",
        "format": "ZIP Archive / OpenXML",
        "category": CAT_DOCUMENTS,
        "extensions": [".zip", ".docx", ".xlsx", ".pptx", ".jar"],
        "check": lambda d: d.startswith(b"PK\x03\x04"),
        "min_size": 4,
        "confidence": 0.95,
        "sig_hex": "504b0304"
    },
    {
        "mime": "application/x-sqlite3",
        "format": "SQLite Database",
        "category": CAT_DATABASE_LOGS,
        "extensions": [".db", ".sqlite", ".sqlite3"],
        "check": lambda d: d.startswith(b"SQLite format 3\x00"),
        "min_size": 16,
        "confidence": 0.995,
        "sig_hex": "53514c69746520666f726d6174203300"
    },
    {
        "mime": "application/x-dosexec",
        "format": "Windows Portable Executable (PE)",
        "category": CAT_EXECUTABLES,
        "extensions": [".exe", ".dll", ".sys"],
        "check": lambda d: d.startswith(b"MZ"),
        "min_size": 2,
        "confidence": 0.98,
        "sig_hex": "4d5a"
    },
    {
        "mime": "application/x-elf",
        "format": "ELF Linux Executable",
        "category": CAT_EXECUTABLES,
        "extensions": [".bin", ".elf", ".so"],
        "check": lambda d: d.startswith(b"\x7fELF"),
        "min_size": 4,
        "confidence": 0.99,
        "sig_hex": "7f454c46"
    },
    {
        "mime": "application/x-tar",
        "format": "TAR Archive",
        "category": CAT_DOCUMENTS,
        "extensions": [".tar"],
        "check": lambda d: len(d) > 262 and d[257:262] == b"ustar",
        "min_size": 265,
        "confidence": 0.95,
        "sig_hex": "ustar"
    },
    {
        "mime": "application/gzip",
        "format": "GZIP Compressed File",
        "category": CAT_DOCUMENTS,
        "extensions": [".gz", ".tar.gz"],
        "check": lambda d: d.startswith(b"\x1f\x8b"),
        "min_size": 2,
        "confidence": 0.95,
        "sig_hex": "1f8b"
    },
    {
        "mime": "application/x-7z-compressed",
        "format": "7-Zip Archive",
        "category": CAT_DOCUMENTS,
        "extensions": [".7z"],
        "check": lambda d: d.startswith(b"7z\xbc\xaf\x27\x1c"),
        "min_size": 6,
        "confidence": 0.98,
        "sig_hex": "7zbcaf271c"
    },
    {
        "mime": "video/mp4",
        "format": "MP4 Video",
        "category": CAT_PHOTOS,
        "extensions": [".mp4", ".m4v"],
        "check": lambda d: len(d) >= 12 and d[4:8] == b"ftyp",
        "min_size": 12,
        "confidence": 0.95,
        "sig_hex": "ftyp"
    },
    {
        "mime": "text/plain",
        "format": "Plain Text / Log",
        "category": CAT_DOCUMENTS,
        "extensions": [".txt", ".log", ".csv", ".json"],
        "check": lambda d: len(d) > 0 and all(
            b in (9, 10, 13) or 32 <= b <= 126 for b in d[:min(256, len(d))]
        ),
        "min_size": 1,
        "confidence": 0.88,
        "sig_hex": "text"
    },
]

# Supplementary signatures for comprehensive coverage of all 7 forensic categories
SUPPLEMENTARY_SIGNATURES = [
    {
        "mime": "application/x-ms-evtx",
        "format": "Windows XML Event Log (EVTX)",
        "detected_format": "EVTX",
        "category": CAT_SYSTEM_TRACES,
        "extensions": [".evtx"],
        "check": lambda d: d.startswith(b"ElfFile\x00"),
        "min_size": 8,
        "confidence": 0.99,
        "sig_hex": "456c6646696c6500"
    },
    {
        "mime": "application/vnd.tcpdump.pcap",
        "format": "PCAP Network Capture",
        "detected_format": "PCAP",
        "category": CAT_NETWORK_CAPTURES,
        "extensions": [".pcap", ".cap"],
        "check": lambda d: d.startswith(b"\xd4\xc3\xb2\xa1") or d.startswith(b"\xa1\xb2\xc3\xd4"),
        "min_size": 4,
        "confidence": 0.99,
        "sig_hex": "d4c3b2a1"
    },
    {
        "mime": "application/x-pcapng",
        "format": "PCAP-NG Network Capture",
        "detected_format": "PCAP",
        "category": CAT_NETWORK_CAPTURES,
        "extensions": [".pcapng"],
        "check": lambda d: d.startswith(b"\x0a\x0d\x0d\x0a"),
        "min_size": 4,
        "confidence": 0.98,
        "sig_hex": "0a0d0d0a"
    },
    {
        "mime": "application/x-regf",
        "format": "Windows NT Registry Hive (REGF)",
        "detected_format": "REGF",
        "category": CAT_REGISTRY_HIVES,
        "extensions": [".dat", ".hiv", ".regf"],
        "check": lambda d: d.startswith(b"regf"),
        "min_size": 4,
        "confidence": 0.98,
        "sig_hex": "72656766"
    },
    {
        "mime": "image/bmp",
        "format": "Windows BMP Image",
        "detected_format": "BMP",
        "category": CAT_PHOTOS,
        "extensions": [".bmp"],
        "check": lambda d: d.startswith(b"BM"),
        "min_size": 2,
        "confidence": 0.97,
        "sig_hex": "424d"
    },
    {
        "mime": "text/rtf",
        "format": "Rich Text Format (RTF)",
        "detected_format": "RTF",
        "category": CAT_DOCUMENTS,
        "extensions": [".rtf"],
        "check": lambda d: d.startswith(b"{\\rtf"),
        "min_size": 5,
        "confidence": 0.97,
        "sig_hex": "7b5c727466"
    },
]

ALL_SIGNATURES = FORMAT_SIGNATURES + SUPPLEMENTARY_SIGNATURES

# Text Grammar Heuristics
TEXT_GRAMMARS = [
    {
        "id": "EVTX_BATCH_SHADOW",
        "pattern": re.compile(r"(vssadmin|bcdedit|wmic\s+shadowcopy|Invoke-|invoke-mimikatz|sekurlsa|powershell\.exe)", re.IGNORECASE),
        "category": CAT_SYSTEM_TRACES,
        "mime": "text/x-shellscript",
        "format": "Anti-Forensics Batch Script / PS History",
        "confidence": 0.96,
        "method": "CONTENT_GRAMMAR"
    },
    {
        "id": "PSREADLINE_HISTORY",
        "pattern": re.compile(r"(New-Object\s+Net\.WebClient|DownloadString|IEX\(|Invoke-Expression|Set-ExecutionPolicy)", re.IGNORECASE),
        "category": CAT_SYSTEM_TRACES,
        "mime": "text/x-powershell",
        "format": "PowerShell PSReadLine Console History",
        "confidence": 0.95,
        "method": "CONTENT_GRAMMAR"
    },
    {
        "id": "RANSOM_NOTE",
        "pattern": re.compile(r"(bitcoin:|\.onion|decrypt|All your files|ransom|BTC|monero|README_TO_DECRYPT|recover_data)", re.IGNORECASE),
        "category": CAT_DOCUMENTS,
        "mime": "text/plain",
        "format": "Ransomware Extortion Note",
        "confidence": 0.98,
        "method": "CONTENT_GRAMMAR_IOC"
    },
    {
        "id": "SQL_LOG_PATTERN",
        "pattern": re.compile(r"(INSERT\s+INTO|SELECT\s+\*|UPDATE\s+\w+\s+SET|CREATE\s+TABLE|DROP\s+TABLE|COMMIT|ROLLBACK|BEGIN\s+TRANSACTION)", re.IGNORECASE),
        "category": CAT_DATABASE_LOGS,
        "mime": "text/x-sql",
        "format": "SQL Transaction / Query Log",
        "confidence": 0.94,
        "method": "CONTENT_GRAMMAR"
    },
    {
        "id": "RFC3164_SYSLOG",
        "pattern": re.compile(r"^(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d+\s+\d{2}:\d{2}:\d{2}", re.MULTILINE),
        "category": CAT_SYSTEM_TRACES,
        "mime": "text/x-syslog",
        "format": "Unix Syslog (RFC 3164)",
        "confidence": 0.94,
        "method": "CONTENT_GRAMMAR"
    }
]

# IOC extraction patterns
REGEX_IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b")
REGEX_ONION = re.compile(r"\b[a-zA-Z0-9.-]+\.onion\b", re.IGNORECASE)
REGEX_DOMAIN = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+(?:com|net|org|io|darkmesh|ru|xyz|top|cc|me|biz|info)\b", re.IGNORECASE)
REGEX_BTC_BECH32 = re.compile(r"\bbc1[a-z0-9]{25,39}\b")
REGEX_BTC_BASE58 = re.compile(r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b")
REGEX_ETH = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
REGEX_MONERO = re.compile(r"\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b")
REGEX_FILE_PATHS = re.compile(r"\b(?:[a-zA-Z]:\\[^\s\"'<>]+|/(?:etc|var|tmp|home|usr|opt|bin)/[^\s\"'<>]+)\b")

ATTACK_KEYWORD_PATTERNS = [
    ("mimikatz", 1.0, "Credential dumper signature"),
    ("cobaltstrike", 0.95, "Adversary emulation / C2 beacon"),
    ("cobalt strike", 0.95, "Adversary emulation / C2 beacon"),
    ("ransomware", 0.95, "Extortion / encryption malware"),
    ("ransom", 0.90, "Extortion indicator"),
    ("exfiltration", 0.90, "Unauthorized data egress"),
    ("privilege escalation", 0.90, "Privilege escalation indicator"),
    ("lateral movement", 0.85, "Network pivoting"),
    ("shadow copies", 0.95, "VSS deletion attempt"),
    ("shadowcopy delete", 1.0, "VSS shadow copy destruction"),
    ("vssadmin", 0.95, "VSS administration tool"),
    ("powershell -enc", 0.95, "Encoded PowerShell payload execution"),
    ("beacon", 0.80, "Command & control heartbeat"),
    ("command and control", 0.90, "C2 infrastructure"),
    ("c2 server", 0.90, "C2 infrastructure"),
    ("dump_hashes", 0.95, "NTLM hash extraction"),
    ("lsass", 0.90, "LSASS memory dumping target"),
    ("meterpreter", 0.95, "Metasploit payload"),
    ("reverse_tcp", 0.90, "Reverse TCP shell"),
    ("keylogger", 0.90, "Input surveillance payload"),
    ("drop table", 0.95, "Destructive database operation"),
    ("breach", 0.80, "Data security incident keyword"),
]

ATTACK_KEYWORDS = [kw for kw, _, _ in ATTACK_KEYWORD_PATTERNS]


def classify_mime_format(data: bytes, filename: str = "") -> Dict[str, Any]:
    """
    Identifies MIME type, format, and category using the signature registry.
    Detects and flags extension mismatches.
    """
    detected_mime = "application/octet-stream"
    detected_format = "Unknown Binary"
    short_format = "UNKNOWN_FRAGMENT"
    detected_category = CAT_DOCUMENTS
    confidence = 0.35
    method = "BINARY_HEURISTIC"
    is_pe = data.startswith(b"MZ")
    detected_sig = None

    # Check all signatures (13 core first, then supplementary)
    for entry in ALL_SIGNATURES:
        if len(data) >= entry["min_size"] and entry["check"](data):
            detected_mime = entry["mime"]
            detected_format = entry["format"]
            detected_category = entry.get("category", CAT_DOCUMENTS)
            confidence = entry.get("confidence", 0.95)
            method = "MAGIC_BYTES"
            detected_sig = entry.get("sig_hex", "")
            short_format = entry.get("detected_format")
            break

    # Format-specific short format normalization
    if is_pe:
        short_format = "PE"
        detected_category = CAT_EXECUTABLES
    elif detected_mime == "image/jpeg":
        short_format = "JPEG"
    elif detected_mime == "image/png":
        short_format = "PNG"
    elif detected_mime == "image/gif":
        short_format = "GIF"
    elif detected_mime == "application/pdf":
        short_format = "PDF"
    elif detected_mime == "application/x-sqlite3":
        short_format = "SQLITE"
    elif detected_mime == "application/x-ms-evtx":
        short_format = "EVTX"
        detected_category = CAT_SYSTEM_TRACES
    elif detected_mime in ("application/vnd.tcpdump.pcap", "application/x-pcapng"):
        short_format = "PCAP"
        detected_category = CAT_NETWORK_CAPTURES
    elif detected_mime == "application/zip":
        if filename.lower().endswith(".docx") or b"[Content_Types].xml" in data:
            short_format = "DOCX"
            detected_category = CAT_DOCUMENTS
        else:
            short_format = "ZIP"

    # Text grammar check
    if method == "BINARY_HEURISTIC" and len(data) > 0:
        try:
            text_sample = data[:8192].decode("utf-8", errors="ignore")
            for gram in TEXT_GRAMMARS:
                if gram["pattern"].search(text_sample):
                    detected_mime = gram["mime"]
                    detected_format = gram["format"]
                    detected_category = gram["category"]
                    confidence = gram.get("confidence", 0.90)
                    method = gram.get("method", "CONTENT_GRAMMAR")
                    short_format = "TEXT_GRAMMAR"
                    break
        except Exception:
            pass

    if short_format is None or method == "BINARY_HEURISTIC":
        short_format = "UNKNOWN_FRAGMENT"
        confidence = min(confidence, 0.45)

    # Extension mismatch check
    mismatch = False
    expected_mimes = []
    conflict_type = None
    forensic_message = None
    conflicts = []
    claimed_ext = ""

    if filename:
        claimed_ext = "." + filename.lower().split(".")[-1] if "." in filename else ""
        for entry in ALL_SIGNATURES:
            if claimed_ext in entry["extensions"]:
                expected_mimes.append(entry["mime"])

        if expected_mimes and detected_mime not in expected_mimes:
            mismatch = True
            conflict_type = "EXTENSION_SIGNATURE_MISMATCH"
            forensic_message = (
                f"File extension '{claimed_ext}' does not match detected binary signature "
                f"('{detected_format}' / {detected_mime}). Header takes precedence per forensic protocol."
            )
            conflict_item = {
                "conflict_type": conflict_type,
                "type": conflict_type,
                "description": forensic_message,
                "claimed_extension": claimed_ext,
                "detected_signature": "MZ / PE" if is_pe else detected_format,
                "detected_type": detected_format,
                "detected_category": detected_category
            }
            conflicts.append(conflict_item)

    review_required = confidence < 0.60 or mismatch

    return {
        "mime": detected_mime,
        "format": detected_format,
        "detected_format": short_format,
        "category": detected_category,
        "subtype": detected_format,
        "confidence": round(confidence, 3),
        "method": method,
        "detected_signature": "MZ / PE" if is_pe else (detected_sig or detected_format),
        "is_pe": is_pe,
        "extension_mismatch": mismatch,
        "expected_mimes": expected_mimes,
        "conflict": mismatch,
        "conflict_type": conflict_type,
        "forensic_message": forensic_message,
        "conflicts": conflicts,
        "forensic_conflicts": conflicts,
        "review_required": review_required,
        "review_reason": (
            "File extension does not match detected binary signature (tampering/disguise indicator)."
            if mismatch else
            ("Artifact relevance is high despite uncertain format classification." if confidence < 0.60 else None)
        )
    }


def extract_iocs_and_entities(data: bytes) -> Dict[str, Any]:
    """Extracts IOCs and relevant entities from raw bytes."""
    text = data.decode("utf-8", errors="ignore")
    latin_text = data.decode("latin-1", errors="ignore")
    extra_texts = []

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
    lines = combined_text.splitlines()

    semantic_indicators = []

    # 1. IP Addresses
    raw_ips = REGEX_IPV4.findall(combined_text)
    ips = sorted(list(set(raw_ips)))
    for ip in ips:
        for idx, line in enumerate(lines[:100]):
            if ip in line:
                semantic_indicators.append({
                    "term": ip,
                    "type": "IP_ADDRESS",
                    "location": f"line {idx + 1}",
                    "context": line.strip()[:100],
                    "strength": 0.85
                })
                break

    # 2. Domains and Tor .onion endpoints
    onions = sorted(list(set(REGEX_ONION.findall(combined_text.lower()))))
    for on in onions:
        for idx, line in enumerate(lines[:100]):
            if on in line.lower():
                semantic_indicators.append({
                    "term": on,
                    "type": "DARKNET_DOMAIN",
                    "location": f"line {idx + 1}",
                    "context": line.strip()[:100],
                    "strength": 0.98
                })
                break

    all_domains = set(REGEX_DOMAIN.findall(combined_text.lower()))
    domains = [d for d in all_domains if not d.endswith(".onion") and not d.endswith(".exe")]
    for dom in sorted(domains)[:10]:
        semantic_indicators.append({
            "term": dom,
            "type": "DOMAIN",
            "location": "content stream",
            "context": f"Network reference: {dom}",
            "strength": 0.75
        })

    # 3. Cryptocurrency Wallets
    btc_bech32 = REGEX_BTC_BECH32.findall(combined_text)
    btc_base58 = REGEX_BTC_BASE58.findall(combined_text)
    eth = REGEX_ETH.findall(combined_text)
    monero = REGEX_MONERO.findall(combined_text)
    crypto_wallets = sorted(list(set(btc_bech32 + btc_base58 + eth + monero)))
    for w in crypto_wallets:
        semantic_indicators.append({
            "term": w,
            "type": "CRYPTO_WALLET",
            "location": "content body",
            "context": f"Payment recipient: {w}",
            "strength": 0.95
        })

    # 4. Attack Keywords
    found_keywords = []
    lower_comb = combined_text.lower()
    for kw in ATTACK_KEYWORDS:
        if kw in lower_comb:
            found_keywords.append(kw)
            for idx, line in enumerate(lines[:150]):
                if kw in line.lower():
                    semantic_indicators.append({
                        "term": kw,
                        "type": "ATTACK_KEYWORD",
                        "location": f"line {idx + 1}",
                        "context": line.strip()[:120],
                        "strength": 0.90
                    })
                    break
    found_keywords = sorted(list(set(found_keywords)))

    # 5. File paths
    file_paths = sorted(list(set(REGEX_FILE_PATHS.findall(combined_text))))[:8]

    # 6. spaCy Named Entity Recognition
    spacy_entities = []
    if nlp and len(text.strip()) > 20:
        try:
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
        "file_paths": file_paths,
        "spacy_entities": spacy_entities[:15],
        "semantic_indicators": semantic_indicators,
        "semantic_analysis": {
            "entities": spacy_entities[:15],
            "ioc_matches": [ind for ind in semantic_indicators if ind["type"] in ("IP_ADDRESS", "DARKNET_DOMAIN", "CRYPTO_WALLET")],
            "keywords": found_keywords
        },
        "total_ioc_count": total_iocs,
        "has_high_value_iocs": total_iocs > 0
    }


def classify_artifact(data: bytes, filename: str = "") -> Dict[str, Any]:
    """Combined classification entry point."""
    mime_info = classify_mime_format(data, filename)
    iocs = extract_iocs_and_entities(data)

    return {
        **mime_info,
        "iocs": iocs,
        "semantic_analysis": iocs["semantic_analysis"],
        "semantic_indicators": iocs["semantic_indicators"],
        "ioc_summary": {
            "ips_count": len(iocs["ips"]),
            "wallets_count": len(iocs["crypto_wallets"]),
            "darknet_count": len(iocs["onion_domains"]),
            "keywords_count": len(iocs["attack_keywords"]),
        }
    }


def extract_semantic_indicators(text_or_data: Union[str, bytes]) -> List[Dict[str, Any]]:
    """
    Extracts semantic IOCs and attack keywords from text or binary data.
    Returns terms and normalized types (IP, CRYPTO_WALLET, DOMAIN, ATTACK_KEYWORD).
    """
    if isinstance(text_or_data, str):
        text = text_or_data
    else:
        text = text_or_data.decode("utf-8", errors="ignore")

    indicators = []

    # 1. IP Addresses
    raw_ips = REGEX_IPV4.findall(text)
    for ip in sorted(set(raw_ips)):
        indicators.append({
            "term": ip,
            "type": "IP",
            "context": f"IP Address: {ip}",
            "strength": 0.85
        })

    # 2. Tor .onion and standard domains
    for on in sorted(set(REGEX_ONION.findall(text.lower()))):
        indicators.append({
            "term": on,
            "type": "DARKNET_DOMAIN",
            "context": f"Darknet onion: {on}",
            "strength": 0.98
        })

    for dom in sorted(set(REGEX_DOMAIN.findall(text.lower()))):
        if not dom.endswith(".onion") and not dom.endswith(".exe"):
            indicators.append({
                "term": dom,
                "type": "DOMAIN",
                "context": f"Domain: {dom}",
                "strength": 0.75
            })

    # 3. Cryptocurrency Wallets
    crypto_matches = set(
        REGEX_BTC_BECH32.findall(text) +
        REGEX_BTC_BASE58.findall(text) +
        REGEX_ETH.findall(text) +
        REGEX_MONERO.findall(text)
    )
    for cw in sorted(crypto_matches):
        indicators.append({
            "term": cw,
            "type": "CRYPTO_WALLET",
            "context": f"Crypto wallet: {cw}",
            "strength": 0.95
        })

    # 4. Attack Keywords
    key_phrases = [
        "ransom", "mimikatz", "powershell", "DROP TABLE", "shadowcopy delete",
        "cobaltstrike", "cobalt strike", "ransomware", "exfiltration", "privilege escalation",
        "lateral movement", "shadow copies", "vssadmin", "powershell -enc", "beacon",
        "command and control", "c2 server", "dump_hashes", "lsass", "meterpreter",
        "reverse_tcp", "keylogger", "drop table", "breach"
    ]
    text_lower = text.lower()
    for kp in key_phrases:
        if kp.lower() in text_lower:
            indicators.append({
                "term": kp,
                "type": "ATTACK_KEYWORD",
                "context": f"Attack keyword: {kp}",
                "strength": 0.90
            })

    return indicators


def calculate_relevance(
    text_or_data: Union[str, bytes],
    incident_context: Optional[Dict[str, Any]] = None,
    artifact_type: str = "DOCUMENT"
) -> Dict[str, Any]:
    """
    Computes investigative relevance score in [0.0, 1.0] based on incident context.
    Matches incident IOCs, keywords, and target account entities.
    """
    if isinstance(text_or_data, str):
        text = text_or_data
    else:
        text = text_or_data.decode("utf-8", errors="ignore")

    ctx = incident_context or {}
    keywords = ctx.get("keywords", [])
    iocs = ctx.get("iocs", [])
    target_usernames = ctx.get("target_usernames", [])

    text_lower = text.lower()
    matched = []
    score = 0.10

    for kw in keywords:
        if kw.lower() in text_lower:
            matched.append(kw)
            score += 0.30

    for ioc in iocs:
        if ioc.lower() in text_lower:
            matched.append(ioc)
            score += 0.40

    for u in target_usernames:
        if u.lower() in text_lower:
            matched.append(u)
            score += 0.20

    final_score = min(1.0, round(score, 3))
    return {
        "score": final_score,
        "matched_indicators": list(dict.fromkeys(matched)),
        "artifact_type": artifact_type
    }

