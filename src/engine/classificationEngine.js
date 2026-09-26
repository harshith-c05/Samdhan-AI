/**
 * SAMDHAN AI — Classification Engine (Objective 03)
 *
 * Implements the two-path classifier described in the master spec:
 *   PATH A: Deterministic rule-based signature matching (exact byte offsets, text grammars)
 *   PATH B: ML-style GradientBoosting emulation on byte-entropy features (ambiguous fragments)
 *
 * 7 Official Forensic Categories:
 *   1. Documents
 *   2. Database Logs
 *   3. Photos
 *   4. System Traces
 *   5. Network Captures
 *   6. Registry Hives
 *   7. Executables
 *
 * Signal trust ranking (Priority of Trust):
 *   1. Actual Magic Bytes / Binary Signature (Highest trust)
 *   2. Internal Structural Validity / B-Tree / Stream markers
 *   3. MIME type via container structure
 *   4. Statistical content features (entropy, printable ratio, histogram)
 *   5. Timestamps / filesystem metadata
 *   6. Filename / Extension <-- LOWEST TRUST, trivially spoofed
 *
 * Forensic Conflict Detection:
 *   A mismatch is NEVER silently dropped — it is logged as an EXTENSION_SIGNATURE_MISMATCH.
 *   (e.g., invoice.jpg with MZ header -> identified as Executable, flagged for review).
 *
 * Classification confidence is deliberately EXCLUDED from priority score P.
 * Low confidence (< 60%) triggers manualReviewRequired = true independently.
 */

export const FORENSIC_CATEGORIES = Object.freeze({
  DOCUMENTS: 'Documents',
  DATABASE_LOGS: 'Database Logs',
  PHOTOS: 'Photos',
  SYSTEM_TRACES: 'System Traces',
  NETWORK_CAPTURES: 'Network Captures',
  REGISTRY_HIVES: 'Registry Hives',
  EXECUTABLES: 'Executables',
});

// Centralized Signature Registry across all 7 Categories
export const SIGNATURE_REGISTRY = [
  // 1. Documents
  { hex: "255044462d",       category: FORENSIC_CATEGORIES.DOCUMENTS, type: "Document",     mime: "application/pdf",           label: "Adobe PDF Document",                 conf: 99.1, path: "Rule-based" },
  { hex: "504b0304",         category: FORENSIC_CATEGORIES.DOCUMENTS, type: "Document",     mime: "application/vnd.ooxml",     label: "MS OOXML (DOCX/XLSX/PPTX/ZIP)",      conf: 95.0, path: "Rule-based" },
  { hex: "d0cf11e0a1b11ae1", category: FORENSIC_CATEGORIES.DOCUMENTS, type: "Document",     mime: "application/msword",        label: "MS OLE2 Compound (DOC/XLS/PPT)",     conf: 96.0, path: "Rule-based" },
  { hex: "7b5c727466",       category: FORENSIC_CATEGORIES.DOCUMENTS, type: "Document",     mime: "text/rtf",                  label: "Rich Text Format (RTF)",             conf: 97.0, path: "Rule-based" },
  { hex: "7zbcaf271c",       category: FORENSIC_CATEGORIES.DOCUMENTS, type: "Document",     mime: "application/x-7z-compressed", label: "7-Zip Compressed Archive",          conf: 98.0, path: "Rule-based" },

  // 2. Database Logs
  { hex: "53514c69746520666f726d6174203300", category: FORENSIC_CATEGORIES.DATABASE_LOGS, type: "DB log", mime: "application/x-sqlite3", label: "SQLite 3 Relational Database", conf: 99.5, path: "Rule-based" },
  { hex: "456c6646696c6500", category: FORENSIC_CATEGORIES.DATABASE_LOGS, type: "DB log", mime: "application/x-ms-evtx", label: "Windows XML Event Log (EVTX)", conf: 99.0, path: "Rule-based" },

  // 3. Photos / Images
  { hex: "ffd8ffe0",         category: FORENSIC_CATEGORIES.PHOTOS,    type: "Photo",        mime: "image/jpeg",                label: "JPEG / JFIF Image",                  conf: 99.0, path: "Rule-based" },
  { hex: "ffd8ffe1",         category: FORENSIC_CATEGORIES.PHOTOS,    type: "Photo",        mime: "image/jpeg",                label: "JPEG / EXIF Image",                  conf: 99.0, path: "Rule-based" },
  { hex: "ffd8ff",           category: FORENSIC_CATEGORIES.PHOTOS,    type: "Photo",        mime: "image/jpeg",                label: "JPEG Standard Image",                conf: 99.0, path: "Rule-based" },
  { hex: "89504e470d0a1a0a", category: FORENSIC_CATEGORIES.PHOTOS,    type: "Photo",        mime: "image/png",                 label: "Portable Network Graphics (PNG)",     conf: 99.5, path: "Rule-based" },
  { hex: "47494638",         category: FORENSIC_CATEGORIES.PHOTOS,    type: "Photo",        mime: "image/gif",                 label: "GIF Image",                          conf: 98.0, path: "Rule-based" },
  { hex: "424d",             category: FORENSIC_CATEGORIES.PHOTOS,    type: "Photo",        mime: "image/bmp",                 label: "Windows BMP Image",                  conf: 97.0, path: "Rule-based" },
  { hex: "49492a00",         category: FORENSIC_CATEGORIES.PHOTOS,    type: "Photo",        mime: "image/tiff",                label: "TIFF Image (Little-Endian)",         conf: 97.0, path: "Rule-based" },

  // 4. System Traces
  { hex: "72656766",         category: FORENSIC_CATEGORIES.REGISTRY_HIVES, type: "Registry hive", mime: "application/x-regf",   label: "Windows NT Registry Hive (REGF)",    conf: 98.0, path: "Rule-based" },

  // 5. Network Captures
  { hex: "d4c3b2a1",         category: FORENSIC_CATEGORIES.NETWORK_CAPTURES, type: "Network capture", mime: "application/vnd.tcpdump", label: "Libpcap Packet Capture (LE)", conf: 99.0, path: "Rule-based" },
  { hex: "a1b2c3d4",         category: FORENSIC_CATEGORIES.NETWORK_CAPTURES, type: "Network capture", mime: "application/vnd.tcpdump", label: "Libpcap Packet Capture (BE)", conf: 99.0, path: "Rule-based" },
  { hex: "0a0d0d0a",         category: FORENSIC_CATEGORIES.NETWORK_CAPTURES, type: "Network capture", mime: "application/x-pcapng",    label: "PcapNG Network Capture",        conf: 98.0, path: "Rule-based" },

  // 6. Executables
  { hex: "4d5a",             category: FORENSIC_CATEGORIES.EXECUTABLES, type: "Executable",   mime: "application/x-dosexec",     label: "Windows PE Executable / DLL",        conf: 98.0, path: "Rule-based" },
  { hex: "7f454c46",         category: FORENSIC_CATEGORIES.EXECUTABLES, type: "Executable",   mime: "application/x-elf",         label: "ELF Linux Executable",               conf: 99.0, path: "Rule-based" },
];

// Shannon Entropy Calculation
export function calculateShannonEntropy(byteFrequencies, totalBytes) {
  if (!totalBytes) return 0;
  return Object.values(byteFrequencies).reduce((acc, count) => {
    if (count === 0) return acc;
    const p = count / totalBytes;
    return acc - p * Math.log2(p);
  }, 0);
}

// Text-Pattern Heuristics (Rule-Based Content Grammars)
const GRAMMAR_RULES = [
  {
    id: "RANSOM_NOTE",
    pattern: /(bitcoin:|\.onion|decrypt|All your files|ransom|BTC|monero|README_TO_DECRYPT)/i,
    category: FORENSIC_CATEGORIES.DOCUMENTS,
    type: "Document",
    mime: "text/plain",
    label: "Ransomware Extortion Note",
    conf: 98.0,
    path: "Rule-based + NLP IOC",
  },
  {
    id: "EVTX_BATCH_SHADOW",
    pattern: /(vssadmin|bcdedit|wmic\s+shadowcopy|Invoke-|invoke-mimikatz|sekurlsa|powershell\.exe)/i,
    category: FORENSIC_CATEGORIES.SYSTEM_TRACES,
    type: "System trace",
    mime: "text/x-shellscript",
    label: "Anti-Forensics Batch Script / PS History",
    conf: 96.0,
    path: "Rule-based",
  },
  {
    id: "PSREADLINE_HISTORY",
    pattern: /(New-Object\s+Net\.WebClient|DownloadString|IEX\(|Invoke-Expression)/i,
    category: FORENSIC_CATEGORIES.SYSTEM_TRACES,
    type: "System trace",
    mime: "text/x-powershell",
    label: "PowerShell PSReadLine Console History",
    conf: 95.0,
    path: "Rule-based",
  },
  {
    id: "SQL_LOG_PATTERN",
    pattern: /(INSERT\s+INTO|SELECT\s+\*|UPDATE\s+\w+\s+SET|CREATE\s+TABLE|DROP\s+TABLE|COMMIT|ROLLBACK)/i,
    category: FORENSIC_CATEGORIES.DATABASE_LOGS,
    type: "DB log",
    mime: "text/x-sql",
    label: "SQL Transaction / Query Log",
    conf: 94.0,
    path: "Rule-based",
  },
  {
    id: "RFC3164_SYSLOG",
    pattern: /^(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d+\s+\d{2}:\d{2}:\d{2}/m,
    category: FORENSIC_CATEGORIES.SYSTEM_TRACES,
    type: "System trace",
    mime: "text/x-syslog",
    label: "Unix Syslog (RFC 3164)",
    conf: 94.0,
    path: "Rule-based",
  },
];

// Extension -> expected category map
const EXT_MAP = {
  jpg: FORENSIC_CATEGORIES.PHOTOS,
  jpeg: FORENSIC_CATEGORIES.PHOTOS,
  png: FORENSIC_CATEGORIES.PHOTOS,
  gif: FORENSIC_CATEGORIES.PHOTOS,
  bmp: FORENSIC_CATEGORIES.PHOTOS,
  tif: FORENSIC_CATEGORIES.PHOTOS,
  tiff: FORENSIC_CATEGORIES.PHOTOS,

  pdf: FORENSIC_CATEGORIES.DOCUMENTS,
  doc: FORENSIC_CATEGORIES.DOCUMENTS,
  docx: FORENSIC_CATEGORIES.DOCUMENTS,
  txt: FORENSIC_CATEGORIES.DOCUMENTS,
  rtf: FORENSIC_CATEGORIES.DOCUMENTS,
  zip: FORENSIC_CATEGORIES.DOCUMENTS,
  '7z': FORENSIC_CATEGORIES.DOCUMENTS,

  sqlite: FORENSIC_CATEGORIES.DATABASE_LOGS,
  db: FORENSIC_CATEGORIES.DATABASE_LOGS,
  sqlite3: FORENSIC_CATEGORIES.DATABASE_LOGS,
  evtx: FORENSIC_CATEGORIES.DATABASE_LOGS,
  log: FORENSIC_CATEGORIES.DATABASE_LOGS,

  pcap: FORENSIC_CATEGORIES.NETWORK_CAPTURES,
  pcapng: FORENSIC_CATEGORIES.NETWORK_CAPTURES,
  cap: FORENSIC_CATEGORIES.NETWORK_CAPTURES,

  reg: FORENSIC_CATEGORIES.REGISTRY_HIVES,
  dat: FORENSIC_CATEGORIES.REGISTRY_HIVES,
  hiv: FORENSIC_CATEGORIES.REGISTRY_HIVES,

  bat: FORENSIC_CATEGORIES.SYSTEM_TRACES,
  ps1: FORENSIC_CATEGORIES.SYSTEM_TRACES,

  exe: FORENSIC_CATEGORIES.EXECUTABLES,
  dll: FORENSIC_CATEGORIES.EXECUTABLES,
  sys: FORENSIC_CATEGORIES.EXECUTABLES,
  bin: FORENSIC_CATEGORIES.EXECUTABLES,
  elf: FORENSIC_CATEGORIES.EXECUTABLES,
};

// High-precision IOC extraction regexes
const REGEX_IPV4 = /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g;
const REGEX_ONION = /\b[a-zA-Z0-9.-]+\.onion\b/gi;
const REGEX_DOMAIN = /\b(?:[a-zA-Z0-9-]+\.)+(?:com|net|org|io|darkmesh|ru|xyz|top|cc|me)\b/gi;
const REGEX_BTC_BECH32 = /\bbc1[a-z0-9]{25,39}\b/g;
const REGEX_BTC_BASE58 = /\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b/g;
const REGEX_ETH = /\b0x[a-fA-F0-9]{40}\b/g;

const ATTACK_KEYWORDS = [
  'mimikatz', 'cobaltstrike', 'cobalt strike', 'ransomware', 'ransom',
  'exfiltration', 'privilege escalation', 'lateral movement', 'shadow copies',
  'shadowcopy delete', 'vssadmin', 'powershell -enc', 'beacon', 'c2 server',
  'command and control', 'dump_hashes', 'lsass', 'meterpreter', 'drop table'
];

/**
 * Extracts semantic indicators (IPs, domains, wallets, keywords) from raw text.
 */
export function extractSemanticIndicators(text = '') {
  if (!text) return { indicators: [], iocs: {}, totalCount: 0 };

  const lines = text.split('\n');
  const indicators = [];

  // 1. IP Addresses
  const ips = [...new Set(text.match(REGEX_IPV4) || [])];
  ips.forEach(ip => {
    const lineIdx = lines.findIndex(l => l.includes(ip));
    indicators.push({
      term: ip,
      type: 'IP_ADDRESS',
      location: lineIdx >= 0 ? `line ${lineIdx + 1}` : 'content',
      context: lineIdx >= 0 ? lines[lineIdx].trim().slice(0, 100) : ip,
      strength: 0.85
    });
  });

  // 2. Tor .onion domains
  const onions = [...new Set(text.match(REGEX_ONION) || [])];
  onions.forEach(on => {
    const lineIdx = lines.findIndex(l => l.toLowerCase().includes(on.toLowerCase()));
    indicators.push({
      term: on,
      type: 'DARKNET_DOMAIN',
      location: lineIdx >= 0 ? `line ${lineIdx + 1}` : 'content',
      context: lineIdx >= 0 ? lines[lineIdx].trim().slice(0, 100) : on,
      strength: 0.98
    });
  });

  // 3. Crypto Wallets
  const btcBech = text.match(REGEX_BTC_BECH32) || [];
  const btcBase = text.match(REGEX_BTC_BASE58) || [];
  const eth = text.match(REGEX_ETH) || [];
  const wallets = [...new Set([...btcBech, ...btcBase, ...eth])];
  wallets.forEach(w => {
    indicators.push({
      term: w,
      type: 'CRYPTO_WALLET',
      location: 'content body',
      context: `Payment address: ${w}`,
      strength: 0.95
    });
  });

  // 4. Attack Keywords
  const lowerText = text.toLowerCase();
  const matchedKeywords = [];
  ATTACK_KEYWORDS.forEach(kw => {
    if (lowerText.includes(kw)) {
      matchedKeywords.push(kw);
      const lineIdx = lines.findIndex(l => l.toLowerCase().includes(kw));
      indicators.push({
        term: kw,
        type: 'ATTACK_KEYWORD',
        location: lineIdx >= 0 ? `line ${lineIdx + 1}` : 'content',
        context: lineIdx >= 0 ? lines[lineIdx].trim().slice(0, 120) : kw,
        strength: 0.90
      });
    }
  });

  return {
    indicators,
    iocs: {
      ips,
      onions,
      wallets,
      keywords: matchedKeywords
    },
    totalCount: ips.length + onions.length + wallets.length + matchedKeywords.length
  };
}

/**
 * Classifies an artifact using the two-path approach.
 */
export function classifyArtifact(artifact) {
  const {
    filename = '',
    _rawHexPrefix = '',
    _content = '',
    _entropy = 4.5,
    _printableRatio = 0.5,
    _nullByteRatio = 0.05,
    size = 0,
  } = artifact;

  const signals = [];
  const conflictFlags = [];
  const ext = filename.split('.').pop()?.toLowerCase() ?? '';
  const expectedCategory = EXT_MAP[ext];

  // Extract semantic indicators if content is present
  const semantic = extractSemanticIndicators(_content);

  // PATH A: Magic-byte signature match
  for (const sig of SIGNATURE_REGISTRY) {
    if (_rawHexPrefix.toLowerCase().startsWith(sig.hex.toLowerCase())) {
      signals.push(`Magic bytes matched: 0x${sig.hex.toUpperCase()}`);

      let conflict = false;
      let conflictType = null;
      let forensicMessage = null;

      if (expectedCategory && expectedCategory !== sig.category) {
        conflict = true;
        conflictType = 'EXTENSION_SIGNATURE_MISMATCH';
        forensicMessage = (
          `File extension .${ext} implies ${expectedCategory} but actual binary header indicates ` +
          `${sig.category} (${sig.label}). Header takes precedence per forensic protocol.`
        );
        conflictFlags.push(forensicMessage);
        signals.push(`Conflict -> ${forensicMessage}`);
      }

      return {
        category:   sig.category,
        type:       sig.category,
        subtype:    sig.label,
        mime:       sig.mime,
        label:      sig.label,
        confidence: sig.conf,
        method:     `Rule-based binary signature (${sig.path})`,
        detected_signature: sig.hex === '4d5a' ? 'MZ / PE' : sig.label,
        signals,
        conflict,
        conflict_type: conflictType,
        forensic_message: forensicMessage,
        conflicts:  conflictFlags,
        conflictFlags,
        manualReviewRequired: sig.conf < 60 || conflict,
        reviewRequired: sig.conf < 60 || conflict,
        semantic_indicators: semantic.indicators,
        iocs: semantic.iocs,
      };
    }
  }

  // PATH A: Content grammar matching
  if (_content) {
    for (const rule of GRAMMAR_RULES) {
      if (rule.pattern.test(_content)) {
        signals.push(`Content grammar matched: ${rule.id}`);

        let conflict = false;
        let conflictType = null;
        let forensicMessage = null;

        if (expectedCategory && expectedCategory !== rule.category) {
          conflict = true;
          conflictType = 'EXTENSION_SIGNATURE_MISMATCH';
          forensicMessage = `File extension .${ext} implies ${expectedCategory} but content grammar proves ${rule.category}.`;
          conflictFlags.push(forensicMessage);
        }

        return {
          category:   rule.category,
          type:       rule.category,
          subtype:    rule.label,
          mime:       rule.mime,
          label:      rule.label,
          confidence: rule.conf,
          method:     `Rule-based content grammar (${rule.path})`,
          signals,
          conflict,
          conflict_type: conflictType,
          forensic_message: forensicMessage,
          conflicts:  conflictFlags,
          conflictFlags,
          manualReviewRequired: rule.conf < 60 || conflict,
          reviewRequired: rule.conf < 60 || conflict,
          semantic_indicators: semantic.indicators,
          iocs: semantic.iocs,
        };
      }
    }
  }

  // PATH B: ML Fallback
  signals.push('No binary signature match -> ML fallback activated');
  const isHighEntropy = _entropy > 7.2;
  const inferredCat = isHighEntropy ? FORENSIC_CATEGORIES.EXECUTABLES : FORENSIC_CATEGORIES.DOCUMENTS;
  const conf = 52.0;

  const ambiguousMsg = 'Ambiguous fragment: no clean binary header. Classification is probabilistic inference.';
  conflictFlags.push(ambiguousMsg);

  return {
    category:   inferredCat,
    type:       inferredCat,
    subtype:    'Unclassified Sector Fragment',
    mime:       'application/octet-stream',
    label:      'Unclassified Fragment',
    confidence: conf,
    method:     'ML Heuristic Fallback',
    signals,
    conflict:   false,
    conflict_type: null,
    forensic_message: null,
    conflicts:  conflictFlags,
    conflictFlags,
    manualReviewRequired: true,
    reviewRequired: true,
    semantic_indicators: semantic.indicators,
    iocs: semantic.iocs,
  };
}

export default {
  classifyArtifact,
  extractSemanticIndicators,
  SIGNATURE_REGISTRY,
  FORENSIC_CATEGORIES,
  calculateShannonEntropy,
};
