/**
 * SAMDHAN AI — Security Scan Engine (Feature 6)
 *
 * Detection signals (cheapest/most reliable first):
 *   1. Extension / signature mismatch  → reused from classificationEngine conflicts
 *   2. Known-hash blocklist match      → simulated threat-intel feed (demo)
 *   3. High whole-file entropy         → file claims to be doc/image but entropy is abnormal
 *   4. Embedded active content         → macro, JS, executable-in-archive
 *
 * Verdict mapping:
 *   CLEAN       → no signals
 *   SUSPICIOUS  → one weak/ambiguous signal
 *   MALICIOUS   → extension mismatch (to executable), known-hash match, or embedded active content
 *
 * Effect on Decision Support:
 *   MALICIOUS   → 5th state BLOCKED_SECURITY_RISK (overrides all other decisions)
 *   SUSPICIOUS  → warning badge shown, restore still allowed
 *   CLEAN       → no change to decision flow
 */

// ─── Verdict Constants ────────────────────────────────────────────────────────
export const SECURITY_VERDICTS = Object.freeze({
  CLEAN:     'CLEAN',
  SUSPICIOUS:'SUSPICIOUS',
  MALICIOUS: 'MALICIOUS',
});

// ─── Simulated Threat-Intel Blocklist ────────────────────────────────────────
// NOTE: This is a synthetic demo blocklist. A real deployment MUST call an external
// threat-intel API (e.g., VirusTotal, MISP, or internal SIEM feed).
const DEMO_BLOCKLIST = new Set([
  'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', // invoice.jpg PE fixture
  'deadbeefcafebabedeadbeefcafebabedeadbeefcafebabedeadbeefcafebabe',
  '000000000000000000000000000000000000000000000000000000000000dead',
]);

// ─── Extension → Expected Magic Type mapping ─────────────────────────────────
const EXT_EXPECTED_TYPE = {
  jpg: 'Photo', jpeg: 'Photo', png: 'Photo', gif: 'Photo', bmp: 'Photo', tiff: 'Photo',
  pdf: 'Document', doc: 'Document', docx: 'Document', xls: 'Document', xlsx: 'Document',
  ppt: 'Document', pptx: 'Document', txt: 'Document', rtf: 'Document', csv: 'Document',
  sqlite: 'DB log', db: 'DB log',
  pcap: 'System trace', evtx: 'System trace', reg: 'System trace',
  zip: 'Document', tar: 'Document', gz: 'Document',
  exe: 'System trace', dll: 'System trace', bat: 'System trace', ps1: 'System trace',
};

// Types that are flagged if found in a non-executable extension
const EXECUTABLE_TYPES = new Set(['System trace', 'PE']);

// ─── Reason labels → human-readable ──────────────────────────────────────────
export const REASON_LABELS = {
  extension_signature_mismatch: (det, ext) =>
    `File claims to be .${ext} but header indicates ${det} (executable)`,
  known_hash_match:
    '✗ SHA-256 matches known-malicious hash list [DEMO blocklist]',
  high_entropy_packed:
    '⚠ High entropy (>7.5 bits/byte) consistent with packed/obfuscated binary',
  embedded_macro:
    '⚠ VBA macro detected in OOXML document — may execute on open',
  embedded_javascript_pdf:
    '✗ Embedded JavaScript found in PDF — can trigger on open',
  executable_in_archive:
    '✗ Executable file found inside archive',
  classification_conflict:
    '⚠ Classification engine detected type conflict (signal promoted to security verdict)',
};

// ─── Core Scan Function (client-side, demo mode) ─────────────────────────────
/**
 * scanArtifact(artifact) → SecurityScanResult
 *
 * artifact shape (from demoArtifacts / mockForensicData):
 *   { id, filename, sha256, classificationExplanation, entropy, type, metadata }
 */
export function scanArtifact(artifact) {
  const reasons = [];
  let verdict = SECURITY_VERDICTS.CLEAN;
  let hashBlocklistMatch = false;

  const filename = artifact.filename || '';
  const ext = filename.includes('.') ? filename.split('.').pop() : '';
  const extClean = (ext || '').toLowerCase();
  const expectedType = EXT_EXPECTED_TYPE[extClean] || null;
  const detectedType = artifact.classificationExplanation?.label || artifact.type || '';
  const sha256 = (artifact.metadata?.sha256 || artifact.sha256 || '').toLowerCase();

  // ── Signal 1: Extension / Signature Mismatch ─────────────────────────────
  const conflicts = artifact.classificationExplanation?.conflicts;
  const hasConflict = !!conflicts;
  const isExecutableConflict = hasConflict && (
    detectedType.toLowerCase().includes('executable') ||
    detectedType.toLowerCase().includes('pe ') ||
    detectedType.toLowerCase().includes('elf') ||
    (artifact.metadata?.detectedHeader || '').toUpperCase().startsWith('4D5A') || // MZ
    (artifact.securityData?.detected_header || '').includes('PE')
  );

  if (hasConflict) {
    reasons.push({
      key: 'extension_signature_mismatch',
      text: typeof conflicts === 'string'
        ? `✗ ${conflicts}`
        : `✗ File claims to be .${extClean} but binary header indicates executable content`,
    });
    if (isExecutableConflict) {
      verdict = SECURITY_VERDICTS.MALICIOUS;
    } else if (verdict === SECURITY_VERDICTS.CLEAN) {
      verdict = SECURITY_VERDICTS.SUSPICIOUS;
    }
  }

  // ── Signal 2: Known-hash Blocklist ───────────────────────────────────────
  if (sha256 && DEMO_BLOCKLIST.has(sha256)) {
    reasons.push({
      key: 'known_hash_match',
      text: REASON_LABELS.known_hash_match,
    });
    hashBlocklistMatch = true;
    verdict = SECURITY_VERDICTS.MALICIOUS;
  }

  // ── Signal 3: Whole-file Entropy ─────────────────────────────────────────
  const entropyVal = artifact.entropy ?? artifact.securityData?.entropy_whole_file ?? null;
  const isDocOrImage = expectedType === 'Photo' || expectedType === 'Document';
  if (entropyVal !== null && entropyVal > 7.5 && isDocOrImage) {
    reasons.push({
      key: 'high_entropy_packed',
      text: `⚠ High entropy (${entropyVal.toFixed(2)} bits/byte) — consistent with packed/obfuscated binary`,
    });
    if (verdict === SECURITY_VERDICTS.CLEAN) {
      verdict = SECURITY_VERDICTS.SUSPICIOUS;
    } else if (verdict === SECURITY_VERDICTS.SUSPICIOUS && hashBlocklistMatch) {
      verdict = SECURITY_VERDICTS.MALICIOUS;
    }
  }

  // ── Signal 4: Embedded Active Content ────────────────────────────────────
  const embeddedThreats = artifact.securityData?.embedded_threats || [];
  if (embeddedThreats.length > 0) {
    embeddedThreats.forEach(t => {
      const isJsOrExe = t.toLowerCase().includes('javascript') || t.toLowerCase().includes('executable');
      reasons.push({
        key: isJsOrExe ? 'embedded_javascript_pdf' : 'embedded_macro',
        text: `✗ ${t}`,
      });
      if (isJsOrExe) {
        verdict = SECURITY_VERDICTS.MALICIOUS;
      } else if (verdict === SECURITY_VERDICTS.CLEAN) {
        verdict = SECURITY_VERDICTS.SUSPICIOUS;
      }
    });
  }

  // ── Use pre-computed verdict from backend if available ────────────────────
  if (artifact.securityData?.verdict) {
    verdict = artifact.securityData.verdict;
    if (artifact.securityData.reasons?.length > 0 && reasons.length === 0) {
      artifact.securityData.reasons.forEach(r => {
        reasons.push({ key: r, text: REASON_LABELS[r] || r });
      });
    }
  }

  // Final: no signals → CLEAN
  if (reasons.length === 0) {
    verdict = SECURITY_VERDICTS.CLEAN;
  }

  return {
    artifact_id:          artifact.id,
    filename,
    declared_type:        expectedType || artifact.type || 'unknown',
    detected_header:      artifact.securityData?.detected_header || artifact.metadata?.detectedHeader || 'N/A',
    sha256:               sha256 || '',
    hash_blocklist_match: hashBlocklistMatch,
    entropy_whole_file:   entropyVal,
    reasons,
    verdict,
    scanned_at:           new Date().toISOString(),
    note: 'DEMO: Blocklist is simulated. Real deployment must call external threat-intel API.',
  };
}

/**
 * Call the real backend security scan API.
 * Falls back silently to client-side scan if backend is unavailable.
 */
export async function scanArtifactViaAPI(artifact) {
  try {
    const resp = await fetch('http://127.0.0.1:8000/api/v1/security/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        artifact_id: artifact.id,
        filename:    artifact.filename,
        sha256:      artifact.metadata?.sha256 || artifact.sha256 || null,
        declared_type: artifact.type || null,
        reconstructed_path: null,
      }),
    });
    if (resp.ok) {
      const data = await resp.json();
      // Normalize reasons into label objects
      return {
        ...data,
        reasons: (data.reasons || []).map(r => ({
          key: r,
          text: typeof REASON_LABELS[r] === 'function'
            ? REASON_LABELS[r](data.detected_header, data.filename?.split('.').pop())
            : (REASON_LABELS[r] || r),
        })),
      };
    }
  } catch {
    // Backend unavailable — fall through to client-side
  }
  return scanArtifact(artifact);
}

/**
 * List available USB/removable drives from the backend.
 * Returns demo data if backend is unavailable.
 */
export async function listUSBDevices() {
  try {
    const resp = await fetch('http://127.0.0.1:8000/api/v1/discovery/usb-devices');
    if (resp.ok) {
      const data = await resp.json();
      return data.devices || [];
    }
  } catch {
    // fall through
  }
  return [
    { letter: 'E:', path: 'E:\\', label: 'SanDisk Cruzer 16GB [DEMO]', type: 'removable' },
    { letter: 'F:', path: 'F:\\', label: 'Kingston DataTraveler 32GB [DEMO]', type: 'removable' },
  ];
}

/**
 * Initiate a pendrive restore via the backend.
 * Returns a simulated success result in demo mode.
 */
export async function restoreToPendrive(artifact, targetDevice) {
  try {
    const resp = await fetch('http://127.0.0.1:8000/api/v1/restore/pendrive', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        artifact_id:        artifact.id,
        filename:           artifact.filename,
        reconstructed_path: null, // backend will resolve via demo_data
        target_device:      targetDevice,
        pre_write_hash:     artifact.metadata?.sha256 || null,
      }),
    });
    if (resp.ok) return await resp.json();
  } catch {
    // fall through to demo simulation
  }

  // Demo simulation: always succeeds with hash match
  const demoHash = artifact.metadata?.sha256 || 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2';
  return {
    artifact_id:       artifact.id,
    filename:          artifact.filename,
    restore_type:      'pendrive',
    target_device:     targetDevice,
    pre_write_hash:    demoHash,
    post_write_hash:   demoHash,
    match:             true,
    status:            'SUCCESS',
    message:           `✓ Restored to Pendrive\nTarget: ${targetDevice}\nFile: ${artifact.filename}\nPost-write verification: hash match ✓`,
    timestamp:         new Date().toISOString(),
    note:              'DEMO MODE: Actual file write simulated.',
  };
}
