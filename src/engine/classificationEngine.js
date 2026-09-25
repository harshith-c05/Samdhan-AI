/**
 * SAMDHAN AI -- Classification Engine
 *
 * Implements the two-path classifier described in the master spec:
 *   PATH A: Deterministic rule-based signature matching (exact byte offsets, text grammars)
 *   PATH B: ML-style GradientBoosting emulation on byte-entropy features (ambiguous fragments)
 *
 * Signal trust ranking (most -> least reliable, per spec sec 3):
 *   1. Magic bytes / file signature
 *   2. Internal structural validity
 *   3. MIME type via libmagic
 *   4. Statistical content features (entropy, printable ratio, histogram)
 *   5. Timestamps / filesystem metadata
 *   6. Filename / extension  <-- LOWEST TRUST, trivially spoofed
 *
 * Conflict resolution: always trust the higher-ranked signal.
 *   A mismatch is NEVER silently dropped -- it is logged as a conflict flag,
 *   because a mismatch is itself potentially forensically interesting.
 *   (e.g. invoice.jpg with MZ header -> "executable disguised as image")
 *
 * Classification confidence is deliberately EXCLUDED from the priority score.
 * Low confidence (< 60%) triggers manualReviewRequired = true and routes to
 * the Manual Review Queue -- it never masquerades as a priority signal.
 */

// ─── File Signature Registry ────────────────────────────────────────────────
// Format: { hexPrefix: { type, mime, label, confidence, path } }
export const SIGNATURE_REGISTRY = [
  // Documents
  { hex: "255044462d",       type: "Document",     mime: "application/pdf",           label: "Adobe PDF",                          conf: 99.1, path: "Rule-based" },
  { hex: "504b0304",         type: "Document",     mime: "application/vnd.ooxml",     label: "MS OOXML (DOCX/XLSX/PPTX/ZIP)",      conf: 95.0, path: "Rule-based" },
  { hex: "d0cf11e0a1b11ae1", type: "Document",     mime: "application/msword",        label: "MS OLE2 Compound (DOC/XLS/PPT)",     conf: 96.0, path: "Rule-based" },
  { hex: "7b5c727466",       type: "Document",     mime: "text/rtf",                  label: "Rich Text Format",                   conf: 97.0, path: "Rule-based" },

  // Photos / Images
  { hex: "ffd8ffe0",         type: "Photo",        mime: "image/jpeg",                label: "JPEG / JFIF Image",                  conf: 99.0, path: "Rule-based" },
  { hex: "ffd8ffe1",         type: "Photo",        mime: "image/jpeg",                label: "JPEG / EXIF Image",                  conf: 99.0, path: "Rule-based" },
  { hex: "89504e470d0a1a0a", type: "Photo",        mime: "image/png",                 label: "Portable Network Graphics (PNG)",     conf: 99.5, path: "Rule-based" },
  { hex: "47494638",         type: "Photo",        mime: "image/gif",                 label: "GIF Image",                          conf: 98.0, path: "Rule-based" },
  { hex: "424d",             type: "Photo",        mime: "image/bmp",                 label: "Windows BMP Image",                  conf: 97.0, path: "Rule-based" },
  { hex: "49492a00",         type: "Photo",        mime: "image/tiff",                label: "TIFF Image (Little-Endian)",         conf: 97.0, path: "Rule-based" },

  // Database Logs
  { hex: "53514c69746520666f726d617420330000", type: "DB log", mime: "application/x-sqlite3", label: "SQLite 3 Relational Database", conf: 99.5, path: "Rule-based" },
  { hex: "456c6646696c6500", type: "DB log",      mime: "application/x-ms-evtx",     label: "Windows XML Event Log (EVTX 2.0)",   conf: 99.0, path: "Rule-based" },

  // System Traces
  { hex: "d4c3b2a1",         type: "System trace", mime: "application/vnd.tcpdump",  label: "Libpcap Packet Capture (LE)",        conf: 99.0, path: "Rule-based" },
  { hex: "a1b2c3d4",         type: "System trace", mime: "application/vnd.tcpdump",  label: "Libpcap Packet Capture (BE)",        conf: 99.0, path: "Rule-based" },
  { hex: "0a0d0d0a",         type: "System trace", mime: "application/x-pcapng",     label: "PcapNG Network Capture",             conf: 98.0, path: "Rule-based" },
  { hex: "72656766",         type: "System trace", mime: "application/x-regf",       label: "Windows NT Registry Hive (regf)",    conf: 95.0, path: "Rule-based" },
  { hex: "4d5a",             type: "System trace", mime: "application/x-msdownload", label: "Windows PE Executable / DLL",        conf: 91.0, path: "Rule-based" },
];

// ─── Shannon Entropy Calculation ────────────────────────────────────────────
export function calculateShannonEntropy(byteFrequencies, totalBytes) {
  if (!totalBytes) return 0;
  return Object.values(byteFrequencies).reduce((acc, count) => {
    if (count === 0) return acc;
    const p = count / totalBytes;
    return acc - p * Math.log2(p);
  }, 0);
}

// ─── Text-Pattern Heuristics (Rule-Based Grammar) ───────────────────────────
const GRAMMAR_RULES = [
  {
    id:      "RFC3164_SYSLOG",
    pattern: /^(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d+\s+\d{2}:\d{2}:\d{2}/m,
    type:    "System trace",
    mime:    "text/x-syslog",
    label:   "Unix Syslog (RFC 3164)",
    conf:    94.0,
    path:    "Rule-based",
  },
  {
    id:      "EVTX_BATCH_SHADOW",
    pattern: /(vssadmin|bcdedit|wmic shadowcopy|Invoke-|invoke-mimikatz|sekurlsa|powershell\.exe)/i,
    type:    "System trace",
    mime:    "text/x-shellscript",
    label:   "Anti-Forensics Batch Script / PS History",
    conf:    96.0,
    path:    "Rule-based",
  },
  {
    id:      "PSREADLINE_HISTORY",
    pattern: /(New-Object Net\.WebClient|DownloadString|IEX\(|Invoke-Expression)/i,
    type:    "System trace",
    mime:    "text/x-powershell",
    label:   "PowerShell PSReadLine Console History",
    conf:    95.0,
    path:    "Rule-based",
  },
  {
    id:      "RANSOM_NOTE",
    pattern: /(bitcoin:|\.onion|decrypt|All your files|ransom|BTC|monero)/i,
    type:    "Document",
    mime:    "text/plain",
    label:   "Ransomware Extortion Note",
    conf:    97.5,
    path:    "Rule-based + NLP IOC",
  },
  {
    id:      "SQL_LOG_PATTERN",
    pattern: /(INSERT INTO|SELECT \*|UPDATE \w+ SET|CREATE TABLE|COMMIT|ROLLBACK|BEGIN TRANSACTION)/i,
    type:    "DB log",
    mime:    "text/x-sql",
    label:   "SQL Transaction / Query Log",
    conf:    93.0,
    path:    "Rule-based",
  },
];

// ─── ML-Style GradientBoosting Emulation on Byte Entropy Features ───────────
// In the real backend this is scikit-learn GradientBoostingClassifier.
// Frontend emulates the decision boundary with the same feature thresholds.
function mlByteEntropyClassify(entropy, printableRatio, nullByteRatio, size) {
  // High-entropy (7.0+) → Encrypted/Packed/Compressed binary
  if (entropy > 7.5 && printableRatio < 0.15) {
    return { type: "System trace", mime: "application/octet-stream", label: "High-Entropy Unknown Binary / Packed Shellcode", conf: 72 + Math.min(8, (entropy - 7.5) * 40), path: "ML GradientBoosting" };
  }
  // Moderate entropy (5.0–7.5) + low printable → compressed archive or media
  if (entropy >= 5.0 && entropy < 7.5 && printableRatio < 0.4) {
    return { type: "Photo", mime: "image/unknown", label: "Compressed Image / Archive Segment", conf: 68.0, path: "ML GradientBoosting" };
  }
  // Low entropy + high printable → text document or log
  if (entropy < 5.0 && printableRatio > 0.80) {
    return { type: "Document", mime: "text/plain", label: "ASCII Text Fragment / Log Excerpt", conf: 82.0, path: "ML GradientBoosting" };
  }
  // Very low entropy → null-byte padding / slack space
  if (entropy < 1.5 && nullByteRatio > 0.85) {
    return { type: "Unknown/Fragment", mime: "application/octet-stream", label: "Null-Byte Slack Space / Unallocated Padding", conf: 55.0, path: "ML GradientBoosting" };
  }
  return { type: "Unknown/Fragment", mime: "application/octet-stream", label: "Unclassified Sector Fragment", conf: 48.0, path: "ML Heuristic Fallback" };
}

// Extension -> type map (LOWEST TRUST -- used only for conflict detection, never for classification)
const EXT_TYPE_MAP = {
  jpg: 'Photo', jpeg: 'Photo', png: 'Photo', gif: 'Photo', bmp: 'Photo', tiff: 'Photo',
  pdf: 'Document', doc: 'Document', docx: 'Document', txt: 'Document',
  xls: 'Document', xlsx: 'Document', ppt: 'Document', pptx: 'Document', rtf: 'Document',
  sqlite: 'DB log', db: 'DB log', log: 'DB log', evtx: 'DB log',
  pcap: 'System trace', pcapng: 'System trace',
  bat: 'System trace', ps1: 'System trace', reg: 'System trace',
  exe: 'System trace', dll: 'System trace',
};

// --- Primary Classifier Entry Point ------------------------------------------
/**
 * Classifies an artifact using the spec's two-path approach (sec 3 pseudocode).
 *
 * Conflict resolution (spec): always trust the higher-ranked signal.
 * A mismatch is NEVER silently dropped -- it is logged as a conflict flag.
 * conflict flags feed into evidence scoring (conflictRaisesRelevance).
 *
 * @param {Object} artifact - Raw artifact descriptor
 * @returns {Object} {
 *   type, mime, label, confidence, method, signals,
 *   conflictFlags,           // string[] -- each mismatch logged, never silently dropped
 *   manualReviewRequired,    // boolean  -- true when conf < 60; badge only, NOT in score
 *   conflictRaisesRelevance  // boolean  -- true for extension_mismatch (tampering signal)
 * }
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
  const extType = EXT_TYPE_MAP[ext];

  // ---- PATH A: Magic-byte signature match (strongest signal) ----------------
  for (const sig of SIGNATURE_REGISTRY) {
    if (_rawHexPrefix.toLowerCase().startsWith(sig.hex.toLowerCase())) {
      signals.push(`Magic bytes matched: 0x${sig.hex.toUpperCase().slice(0, 16)}`);

      let conflictRaisesRelevance = false;
      if (extType && extType !== sig.type) {
        const msg =
          `extension_mismatch: .${ext} implies ${extType} but binary header indicates ${sig.type}. ` +
          `Header takes precedence per forensic protocol. (Potential evidence tampering -- renamed file.)`;
        conflictFlags.push(msg);
        signals.push(`Conflict -> ${msg}`);
        // Spec worked example: MZ + .jpg = renamed executable -> feeds into relevance boost
        conflictRaisesRelevance = true;
      }

      return {
        type:       sig.type,
        mime:       sig.mime,
        label:      sig.label,
        confidence: sig.conf,
        method:     `Rule-based binary signature (${sig.path})`,
        signals,
        conflicts:  conflictFlags[0] || null,  // backward-compat single-string field
        conflictFlags,
        manualReviewRequired: sig.conf < 60,
        conflictRaisesRelevance,
      };
    }
  }

  // ---- PATH A: Text grammar pattern matching --------------------------------
  if (_content) {
    for (const rule of GRAMMAR_RULES) {
      if (rule.pattern.test(_content)) {
        signals.push(`Grammar rule matched: ${rule.id}`);

        let conflictRaisesRelevance = false;
        if (extType && extType !== rule.type) {
          const msg = `extension_mismatch: .${ext} implies ${extType} but content grammar indicates ${rule.type}.`;
          conflictFlags.push(msg);
          conflictRaisesRelevance = true;
        }

        return {
          type:       rule.type,
          mime:       rule.mime,
          label:      rule.label,
          confidence: rule.conf,
          method:     `Rule-based content grammar (${rule.path})`,
          signals,
          conflicts:  conflictFlags[0] || null,
          conflictFlags,
          manualReviewRequired: rule.conf < 60,
          conflictRaisesRelevance,
        };
      }
    }
  }

  // ---- PATH B: ML GradientBoosting fallback --------------------------------
  // No deterministic signature matched -- probabilistic inference only.
  signals.push('No signature match -> ML fallback activated');
  signals.push(`Shannon entropy: ${_entropy.toFixed(2)} bits/byte`);
  signals.push(`Printable ratio: ${(_printableRatio * 100).toFixed(1)}%`);

  const mlResult = mlByteEntropyClassify(_entropy, _printableRatio, _nullByteRatio, size);

  // Spec sec 3 pseudocode: if conf < 0.60 -> type = 'Unknown', route to Manual Review Queue
  const manualReviewRequired = mlResult.conf < 60;
  if (manualReviewRequired) {
    signals.push(
      `ML confidence ${mlResult.conf.toFixed(1)}% < 60% threshold -> ` +
      `type set to 'Unknown', artifact routed to Manual Review Queue`
    );
  }

  const ambiguousConflict =
    'Ambiguous fragment: no clean binary header. Classification is probabilistic inference, not verified fact.';
  conflictFlags.push(ambiguousConflict);

  return {
    type:       manualReviewRequired ? 'Unknown' : mlResult.type,
    mime:       mlResult.mime,
    label:      mlResult.label,
    confidence: mlResult.conf,
    method:     `ML GradientBoosting on byte-entropy features (${mlResult.path})`,
    signals,
    conflicts:  ambiguousConflict,
    conflictFlags,
    manualReviewRequired,
    conflictRaisesRelevance: false,
  };
}

export default { classifyArtifact, SIGNATURE_REGISTRY, calculateShannonEntropy };
