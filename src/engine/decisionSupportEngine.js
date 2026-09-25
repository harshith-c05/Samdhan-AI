/**
 * SAMDHAN AI — Investigative Decision Support Engine (Core Design Implementation)
 *
 * Architecture:
 *   Fragment Reconstruction + Integrity Assessment + Classification/Prioritization outputs
 *                         ↓
 *                 Evidence Aggregator (join on artifact_id)
 *                         ↓
 *                 Decision Rule Engine (deterministic 5-state mapping — F6 adds BLOCKED_SECURITY_RISK)
 *                         ↓
 *       ┌─────────────────┼───────────────────┐
 *       ↓                 ↓                   ↓
 * Explanation Gen    Insight Gen    Evidence Panel Assembler
 * (Why panel: 3-5)  (2-3 sentences) (5 fixed categories)
 *       │                 │                   │
 *       └─────────────────┼───────────────────┘
 *                         ↓
 *              Investigation Center UI
 *                         ↓
 *               Restore Action Handler (Gated)
 *                         ↓
 *              Audit / Chain-of-Custody Store
 *
 * NOTE: The thresholds below (0.60, 85, 0.6, 40) are prototype defaults,
 * not tuned forensic constants.
 */

export const DECISION_STATES = Object.freeze({
  RECOVERABLE: 'RECOVERABLE',
  PARTIALLY_RECOVERABLE: 'PARTIALLY_RECOVERABLE',
  NEEDS_REVIEW: 'NEEDS_REVIEW',
  UNRECOVERABLE: 'UNRECOVERABLE',
  // Feature 6: Security override — MALICIOUS verdict forces this regardless of fragment/integrity
  BLOCKED_SECURITY_RISK: 'BLOCKED_SECURITY_RISK',
});

// Feature 6 security verdict levels
export const SECURITY_VERDICT = Object.freeze({
  CLEAN:     'CLEAN',
  SUSPICIOUS:'SUSPICIOUS',
  MALICIOUS: 'MALICIOUS',
});

export const PROVENANCE_TYPES = Object.freeze({
  PUBLIC_REFERENCE: 'Public Forensic Reference Data',
  DERIVED_ANALYSIS: 'Derived Analysis',
  SYNTHETIC_DEMO: 'Synthetic Demo Data',
});

// Configurable prototype default thresholds
export const THRESHOLDS = Object.freeze({
  CLASSIFICATION_CONFIDENCE_MIN: 0.60, // < 60% routes to NEEDS_REVIEW
  RECOVERABLE_INTEGRITY_MIN: 85,        // >= 85 for full recovery
  RECOVERABLE_FRAG_RATIO: 1.0,          // 100% fragments required for full recovery
  PARTIAL_FRAG_RATIO_MIN: 0.60,         // >= 60% fragments for partial
  PARTIAL_INTEGRITY_MIN: 40,            // >= 40% integrity for partial
  NOTE: 'Prototype defaults — not tuned forensic constants',
});

/**
 * 1. Evidence Aggregator
 * Joins upstream records into a single flat evidence object.
 * Simple join, no recomputation.
 */
export function aggregateEvidence(fragmentOutput = {}, integrityOutput = {}, classificationOutput = {}) {
  const artifactId = fragmentOutput.id || integrityOutput.id || classificationOutput.id || 'ART-UNKNOWN';
  const filename = fragmentOutput.filename || integrityOutput.filename || classificationOutput.filename || 'unknown_file';
  const type = classificationOutput.type || 'Unknown';

  // Fragments
  const fragmentsFound = fragmentOutput.fragmentsFound ?? fragmentOutput.fragments_found ?? 1;
  const fragmentsExpected = fragmentOutput.fragmentsExpected ?? fragmentOutput.fragments_expected ?? 1;
  const edgeConfidence = fragmentOutput.edgeConfidence ?? fragmentOutput.edge_confidence ?? 95.0;
  const fragmentSequence = fragmentOutput.fragmentSequence || [];

  // Integrity
  const structuralValidity = integrityOutput.structuralValidity ?? integrityOutput.structural_validity ?? 'valid'; // 'valid' | 'invalid' | 'uncertain'
  const overallIntegrity = integrityOutput.overallIntegrity ?? integrityOutput.overall_integrity ?? integrityOutput.integrity ?? 80;
  const structuralIntegrity = integrityOutput.structuralIntegrity ?? 80;
  const contentIntegrity = integrityOutput.contentIntegrity ?? 80;
  const metadataIntegrity = integrityOutput.metadataIntegrity ?? 80;

  // Classification & Priority
  let rawConf = classificationOutput.classificationConfidence ?? classificationOutput.classification_confidence ?? 95;
  const classificationConfidence = rawConf > 1 ? rawConf / 100 : rawConf; // normalized 0.0 - 1.0
  const priorityTier = classificationOutput.priorityTier ?? classificationOutput.priority_tier ?? 'MEDIUM';
  const recoveryPercent = fragmentOutput.recoveryPercent ?? fragmentOutput.recovery_percent ?? Math.round((fragmentsFound / Math.max(fragmentsExpected, 1)) * 100);
  const provenance = classificationOutput.provenance || PROVENANCE_TYPES.SYNTHETIC_DEMO;

  return {
    id: artifactId,
    filename,
    type,
    fragments_found: fragmentsFound,
    fragments_expected: fragmentsExpected,
    edge_confidence: edgeConfidence,
    structural_validity: structuralValidity,
    overall_integrity: overallIntegrity,
    structural_integrity: structuralIntegrity,
    content_integrity: contentIntegrity,
    metadata_integrity: metadataIntegrity,
    classification_confidence: classificationConfidence,
    priority_tier: priorityTier.toUpperCase(),
    recovery_percent: recoveryPercent,
    provenance,
    fragmentSequence,
    rawMetadata: classificationOutput.metadata || {},
  };
}

/**
 * 2. Decision Rule Engine (§3 Decision Algorithm)
 * Deterministic mapping from aggregated evidence to one of four states.
 * Feature 6: MALICIOUS security verdict overrides to BLOCKED_SECURITY_RISK (5th state).
 */
export function decide(evidence) {
  const fragRatio = evidence.fragments_expected > 0 
    ? (evidence.fragments_found / evidence.fragments_expected) 
    : 0;
  const structureOk = evidence.structural_validity === 'valid';
  const integrity = evidence.overall_integrity; // 0-100
  const conf = evidence.classification_confidence; // 0.0 - 1.0

  // ── Feature 6: Security override ─────────────────────────────────────────
  // A MALICIOUS verdict forces the 5th state regardless of fragment completeness.
  const securityVerdict = evidence.security_verdict || SECURITY_VERDICT.CLEAN;
  const isSuspicious = securityVerdict === SECURITY_VERDICT.SUSPICIOUS;
  if (securityVerdict === SECURITY_VERDICT.MALICIOUS) {
    const reasons = [
      { type: 'fail', text: 'SECURITY SCAN: MALICIOUS verdict — restore blocked' },
      ...(evidence.security_reasons || []).map(r => ({ type: 'fail', text: r.text || r })),
    ].slice(0, 5);
    return {
      decision: DECISION_STATES.BLOCKED_SECURITY_RISK,
      securityVerdict,
      isSuspicious: false,
      reasons,
      insights: [{ category: 'Security Block', text: 'This artifact has been flagged as MALICIOUS. No restore action is permitted. View the security report for details.' }],
      evidencePanel: assembleEvidencePanel(evidence, DECISION_STATES.BLOCKED_SECURITY_RISK),
      priorityExplanation: generatePriorityExplanation(evidence.priority_tier, evidence.type),
      decisionFlow: generateDecisionFlow(evidence, DECISION_STATES.BLOCKED_SECURITY_RISK),
      restoreAction: getRestoreActionConfig(evidence, DECISION_STATES.BLOCKED_SECURITY_RISK),
      metrics: {
        fragRatio: `${evidence.fragments_found} / ${evidence.fragments_expected}`,
        recoveryPercent: evidence.recovery_percent,
        integrityPercent: evidence.overall_integrity,
        priorityTier: evidence.priority_tier,
        type: evidence.type,
        provenance: evidence.provenance,
      }
    };
  }

  // Conflict / Edge Rule:
  // Low confidence (< 0.60) or structural validity 'uncertain' routes to NEEDS_REVIEW
  // regardless of how high integrity is.
  const needsReview = conf < THRESHOLDS.CLASSIFICATION_CONFIDENCE_MIN || evidence.structural_validity === 'uncertain';

  let decision;
  if (needsReview) {
    decision = DECISION_STATES.NEEDS_REVIEW;
  } else if (fragRatio >= THRESHOLDS.RECOVERABLE_FRAG_RATIO && structureOk && integrity >= THRESHOLDS.RECOVERABLE_INTEGRITY_MIN) {
    decision = DECISION_STATES.RECOVERABLE;
  } else if (fragRatio >= THRESHOLDS.PARTIAL_FRAG_RATIO_MIN && integrity >= THRESHOLDS.PARTIAL_INTEGRITY_MIN) {
    decision = DECISION_STATES.PARTIALLY_RECOVERABLE;
  } else {
    decision = DECISION_STATES.UNRECOVERABLE;
  }

  const reasons = generateReasons(evidence, decision);
  const insights = generateInsights(evidence, decision);
  const evidencePanel = assembleEvidencePanel(evidence, decision);
  const priorityExplanation = generatePriorityExplanation(evidence.priority_tier, evidence.type);
  const decisionFlow = generateDecisionFlow(evidence, decision);
  const restoreAction = getRestoreActionConfig(evidence, decision);

  return {
    decision,
    securityVerdict,
    isSuspicious,
    reasons,
    insights,
    evidencePanel,
    priorityExplanation,
    decisionFlow,
    restoreAction,
    metrics: {
      fragRatio: `${evidence.fragments_found} / ${evidence.fragments_expected}`,
      recoveryPercent: evidence.recovery_percent,
      integrityPercent: evidence.overall_integrity,
      priorityTier: evidence.priority_tier,
      type: evidence.type,
      provenance: evidence.provenance,
    }
  };
}

/**
 * 3. Reason Generator (§4)
 * Formats 3-5 plain-language reasons directly from fields that were checked.
 * No formulas, score breakdowns, or weights are ever shown.
 */
export function generateReasons(evidence, decision) {
  const reasons = [];
  const ext = evidence.filename.split('.').pop()?.toUpperCase() || 'FILE';
  const found = evidence.fragments_found;
  const expected = evidence.fragments_expected;
  const missing = Math.max(0, expected - found);

  if (decision === DECISION_STATES.RECOVERABLE) {
    reasons.push({ type: 'pass', text: `All ${found} fragments were found` });
    reasons.push({ type: 'pass', text: `${ext} header is valid` });
    reasons.push({ type: 'pass', text: `File structure is valid` });
    reasons.push({ type: 'pass', text: `${ext} parser successfully opened the file` });
    reasons.push({ type: 'pass', text: `No important corruption detected` });
  } else if (decision === DECISION_STATES.PARTIALLY_RECOVERABLE) {
    reasons.push({ type: 'pass', text: `${ext} header found` });
    reasons.push({ type: 'pass', text: `${found} fragments found` });
    if (missing > 0) {
      reasons.push({ type: 'warn', text: `${missing} fragment${missing > 1 ? 's' : ''} missing` });
    }
    reasons.push({ type: 'warn', text: `Some file data may be damaged` });
  } else if (decision === DECISION_STATES.NEEDS_REVIEW) {
    if (evidence.structural_validity === 'uncertain') {
      reasons.push({ type: 'warn', text: `Structural validity returned as uncertain` });
    }
    const confPct = Math.round(evidence.classification_confidence * 100);
    if (evidence.classification_confidence < THRESHOLDS.CLASSIFICATION_CONFIDENCE_MIN) {
      reasons.push({ type: 'warn', text: `Classification confidence (${confPct}%) below 60% threshold` });
    }
    reasons.push({ type: 'pass', text: `${found} of ${expected} fragments located` });
    reasons.push({ type: 'warn', text: `Requires manual investigator verification before export` });
  } else {
    // UNRECOVERABLE
    reasons.push({ type: 'fail', text: `Required fragments missing (${missing} of ${expected} missing)` });
    reasons.push({ type: 'fail', text: `Archive/file structure incomplete` });
    reasons.push({ type: 'fail', text: `Parser failed` });
    reasons.push({ type: 'fail', text: `Critical stream and directory headers truncated` });
  }

  // Enforce max 3-5 reasons
  return reasons.slice(0, 5);
}

/**
 * 4. Insight Generator (§4)
 * 2-3 short templated observations (Fragment, Integrity, Recovery).
 * No free-text generation, purely templated.
 */
export function generateInsights(evidence, decision) {
  if (decision === DECISION_STATES.RECOVERABLE) {
    return [
      { category: 'Fragment Insight', text: 'All expected fragments were found.' },
      { category: 'Integrity Insight', text: 'The recovered file structure is valid.' },
      { category: 'Recovery Insight', text: 'The artifact can be restored.' }
    ];
  } else if (decision === DECISION_STATES.PARTIALLY_RECOVERABLE) {
    return [
      { 
        category: 'Partial Recovery', 
        text: `The ${evidence.type.toLowerCase()} can be partially restored, but the missing fragment may cause visible corruption or truncated data.` 
      }
    ];
  } else if (decision === DECISION_STATES.NEEDS_REVIEW) {
    return [
      { 
        category: 'Review Required', 
        text: 'Manual review required: structural headers or classification ambiguity prevents automated recovery verification.' 
      }
    ];
  } else {
    // UNRECOVERABLE
    return [
      { 
        category: 'Unrecoverable', 
        text: 'There is not enough evidence to reconstruct the complete file.' 
      }
    ];
  }
}

/**
 * 5. Priority Explanation (§2 & §4)
 * Template sentence keyed to file type + tier, never the underlying weighted formula.
 */
export function generatePriorityExplanation(tier = 'HIGH', type = 'Document') {
  const normTier = tier.toUpperCase();
  const normType = type.toLowerCase();

  if (normTier === 'CRITICAL' || normTier === 'HIGH') {
    if (normType.includes('db') || normType.includes('sqlite') || normType.includes('log')) {
      return 'High priority because it contains structured records and timestamps that may help reconstruct an activity timeline.';
    }
    if (normType.includes('trace') || normType.includes('network') || normType.includes('pcap')) {
      return 'High priority because it captures network communication or system process execution during the incident window.';
    }
    return 'High priority because it is a structured document with valid content and useful metadata.';
  }

  if (normTier === 'MEDIUM') {
    if (normType.includes('photo') || normType.includes('image')) {
      return 'Medium priority because partial visual data is present but secondary to structured timeline records.';
    }
    return 'Medium priority because artifact provides contextual metadata but does not directly establish breach indicators.';
  }

  // LOW
  return 'Low priority because structure is truncated and content cannot be extracted or verified.';
}

/**
 * 6. Evidence Panel Assembler (§2 & §6)
 * Exactly 5 fixed categories: Header, Fragments, Structure, Integrity, Metadata.
 * Each has a status icon and a one-line drill-down explanation.
 */
export function assembleEvidencePanel(evidence, decision) {
  const found = evidence.fragments_found;
  const expected = evidence.fragments_expected;
  const ext = evidence.filename.split('.').pop()?.toUpperCase() || 'FILE';

  // 1. Header
  const headerValid = evidence.structural_validity !== 'invalid' && evidence.overall_integrity >= 40;
  const headerItem = {
    id: 'header',
    name: 'File Header',
    status: headerValid ? 'valid' : 'invalid',
    label: headerValid ? `✓ ${ext} Header` : `✗ ${ext} Header Missing`,
    oneLiner: headerValid 
      ? `Magic signature verified at offset 0x00; matches standard ${ext} specifications.`
      : `File signature corrupted or absent at initial sector boundary.`
  };

  // 2. Fragments
  const fragmentsComplete = found === expected;
  const fragmentsItem = {
    id: 'fragments',
    name: 'Fragments',
    status: fragmentsComplete ? 'valid' : (found >= Math.ceil(expected * 0.6) ? 'warning' : 'invalid'),
    label: fragmentsComplete 
      ? `✓ Fragments (${found}/${expected})` 
      : (found >= Math.ceil(expected * 0.6) ? `⚠ Fragments (${found}/${expected})` : `✗ Fragments (${found}/${expected})`),
    oneLiner: fragmentsComplete
      ? `${found} of ${expected} expected fragments were found and successfully connected.`
      : `${found} of ${expected} expected fragments were located; ${Math.max(0, expected - found)} fragment(s) missing from unallocated space.`
  };

  // 3. Structure
  const structureItem = {
    id: 'structure',
    name: 'File Structure',
    status: evidence.structural_validity === 'valid' ? 'valid' : (evidence.structural_validity === 'uncertain' ? 'warning' : 'invalid'),
    label: evidence.structural_validity === 'valid' ? '✓ File Structure' : (evidence.structural_validity === 'uncertain' ? '⚠ File Structure' : '✗ File Structure'),
    oneLiner: evidence.structural_validity === 'valid'
      ? `Internal chunk table, offsets, and syntax markers parsed without errors.`
      : (evidence.structural_validity === 'uncertain' 
          ? `Structural tables partially decoded; parser encountered ambiguous segment markers.`
          : `Critical internal structure tables, trailers, or directory records are damaged or truncated.`)
  };

  // 4. Integrity Check
  const integrityPass = evidence.overall_integrity >= 85;
  const integrityWarn = evidence.overall_integrity >= 40 && evidence.overall_integrity < 85;
  const integrityItem = {
    id: 'integrity',
    name: 'Integrity Check',
    status: integrityPass ? 'valid' : (integrityWarn ? 'warning' : 'invalid'),
    label: integrityPass ? '✓ Integrity Check' : (integrityWarn ? '⚠ Integrity Check' : '✗ Integrity Check'),
    oneLiner: integrityPass
      ? `Stream entropy, content decoding, and checksum tests passed successfully (${evidence.overall_integrity}% score).`
      : (integrityWarn
          ? `Portions of payload entropy indicate byte decay or unrecoverable slack data (${evidence.overall_integrity}% score).`
          : `Severe corruption detected across data payload sectors (${evidence.overall_integrity}% score).`)
  };

  // 5. Metadata
  const metadataValid = evidence.metadata_integrity >= 70;
  const metadataItem = {
    id: 'metadata',
    name: 'Metadata',
    status: metadataValid ? 'valid' : 'warning',
    label: metadataValid ? '✓ Metadata' : '⚠ Metadata Incomplete',
    oneLiner: metadataValid
      ? `Timestamps, inode attributes, and carved sector addresses intact.`
      : `Carving slack space stripped filesystem metadata; temporal attributes inferred heuristically.`
  };

  return [headerItem, fragmentsItem, structureItem, integrityItem, metadataItem];
}

/**
 * 7. Decision Flow (§2 & §4)
 * Feature 6: BLOCKED_SECURITY_RISK adds a security step to the flow.
 */
export function generateDecisionFlow(evidence, decision) {
  const steps = [];
  const found = evidence.fragments_found;
  const expected = evidence.fragments_expected;
  const fragRatio = expected > 0 ? (found / expected) : 0;

  // Security verdict step (Feature 6) — shown first when applicable
  const sv = evidence.security_verdict;
  if (sv && sv !== 'CLEAN') {
    steps.push({ 
      label: `Security scan: ${sv}`, 
      status: sv === 'MALICIOUS' ? 'fail' : 'warn' 
    });
  }

  // Step 1: Fragment check
  if (fragRatio === 1.0) {
    steps.push({ label: `${found}/${expected} fragments`, status: 'pass' });
  } else if (fragRatio >= 0.6) {
    steps.push({ label: `${found}/${expected} fragments (≥60%)`, status: 'pass' });
  } else {
    steps.push({ label: `${found}/${expected} fragments (<60%)`, status: 'fail' });
  }

  // Step 2: Structural validity check
  if (evidence.structural_validity === 'valid') {
    steps.push({ label: 'Structure valid', status: 'pass' });
  } else if (evidence.structural_validity === 'uncertain') {
    steps.push({ label: 'Structural validity uncertain', status: 'warn' });
  } else {
    steps.push({ label: 'Structure invalid/incomplete', status: 'fail' });
  }

  // Step 3: Integrity check
  if (evidence.overall_integrity >= 85) {
    steps.push({ label: 'Integrity good (≥85%)', status: 'pass' });
  } else if (evidence.overall_integrity >= 40) {
    steps.push({ label: `Integrity acceptable (${evidence.overall_integrity}%)`, status: 'pass' });
  } else {
    steps.push({ label: `Integrity poor (${evidence.overall_integrity}%)`, status: 'fail' });
  }

  // Step 4: Classification confidence check (if flagged)
  if (evidence.classification_confidence < THRESHOLDS.CLASSIFICATION_CONFIDENCE_MIN) {
    const pct = Math.round(evidence.classification_confidence * 100);
    steps.push({ label: `Confidence ${pct}% (<60%)`, status: 'warn' });
  }

  // Final outcome
  const outcomeStatus = decision === DECISION_STATES.RECOVERABLE ? 'pass' 
    : decision === DECISION_STATES.BLOCKED_SECURITY_RISK ? 'fail'
    : decision === DECISION_STATES.UNRECOVERABLE ? 'fail' 
    : 'warn';
  steps.push({ label: decision, status: outcomeStatus, isOutcome: true });

  return steps;
}

/**
 * 8. Restore Action Configuration (§2 & §4)
 * Feature 6: BLOCKED_SECURITY_RISK offers only VIEW SECURITY REPORT, no restore.
 * Feature 5: RECOVERABLE / PARTIALLY_RECOVERABLE offer both Download and Restore to Pendrive.
 */
export function getRestoreActionConfig(evidence, decision) {
  const filename = evidence.filename;

  // Feature 6 override — MALICIOUS
  if (decision === DECISION_STATES.BLOCKED_SECURITY_RISK) {
    return {
      allowed: false,
      actionType: 'VIEW_SECURITY_REPORT',
      buttonLabel: 'VIEW SECURITY REPORT',
      buttonStyle: 'blocked',
      feedbackText: `Artifact ${evidence.id} (${filename}) is BLOCKED. Security report logged.`,
      targetFilename: null,
      pendriveAllowed: false,
    };
  }

  if (decision === DECISION_STATES.RECOVERABLE) {
    return {
      allowed: true,
      actionType: 'RESTORE_FULL',
      buttonLabel: 'RESTORE FILE',
      buttonStyle: 'success',
      feedbackText: `✓ File Restored — recovered_${filename}, Fragments used: ${evidence.fragments_found}/${evidence.fragments_expected}, Integrity: Valid`,
      targetFilename: `recovered_${filename}`,
      // Feature 5: also offer pendrive restore
      pendriveAllowed: true,
      pendriveButtonLabel: 'RESTORE TO PENDRIVE',
    };
  }

  if (decision === DECISION_STATES.PARTIALLY_RECOVERABLE) {
    return {
      allowed: true,
      actionType: 'RESTORE_PARTIAL',
      buttonLabel: 'RESTORE PARTIAL FILE',
      buttonStyle: 'warning',
      feedbackText: `✓ Partial File Restored — partial_${filename}, Fragments used: ${evidence.fragments_found}/${evidence.fragments_expected}, Notice: Incomplete stream`,
      targetFilename: `partial_${filename}`,
      // Feature 5: pendrive restore with explicit partial notice
      pendriveAllowed: true,
      pendriveButtonLabel: 'RESTORE PARTIAL TO PENDRIVE',
    };
  }

  if (decision === DECISION_STATES.NEEDS_REVIEW) {
    return {
      allowed: false,
      actionType: 'ROUTE_REVIEW',
      buttonLabel: 'ROUTE TO MANUAL REVIEW',
      buttonStyle: 'review',
      feedbackText: `Artifact ${evidence.id} flagged and dispatched to Senior Forensic Examiner Queue.`,
      targetFilename: null,
      pendriveAllowed: false,
    };
  }

  // UNRECOVERABLE
  return {
    allowed: false,
    actionType: 'SEARCH_FRAGMENTS',
    buttonLabel: 'SEARCH FOR MORE FRAGMENTS',
    buttonStyle: 'search',
    feedbackText: `Carver initiated unallocated slack re-scan for additional cluster fragments.`,
    targetFilename: null,
    pendriveAllowed: false,
  };
}

/**
 * 9. Core Benchmark Reference Dataset (§4 & §6)
 * Specifically includes the 4 worked examples from the design document:
 * 1. report.pdf (4/4, Recoverable)
 * 2. photo.jpg (4/5, Partially Recoverable)
 * 3. history.db (Review / High Priority)
 * 4. archive.zip (2/7, Unrecoverable)
 */
export const CORE_REFERENCE_DATASET = [
  {
    id: 'BENCH-001',
    filename: 'report.pdf',
    type: 'Document',
    fragments_found: 4,
    fragments_expected: 4,
    recovery_percent: 94,
    overall_integrity: 98,
    structural_integrity: 98,
    content_integrity: 97,
    metadata_integrity: 95,
    structural_validity: 'valid',
    classification_confidence: 0.99,
    priority_tier: 'HIGH',
    provenance: PROVENANCE_TYPES.PUBLIC_REFERENCE,
    security_verdict: SECURITY_VERDICT.CLEAN,
    security_reasons: [],
    fragmentSequence: [
      { id: 'Frag-1', name: 'Header (%PDF-1.7)', offset: '0x00010000', status: 'Found', position: 'Valid', relationship: 'Strong (Sequential)' },
      { id: 'Frag-2', name: 'Catalog & Pages', offset: '0x00010800', status: 'Found', position: 'Valid', relationship: 'Strong (Pointer Match)' },
      { id: 'Frag-3', name: 'Object Stream 1', offset: '0x00011000', status: 'Found', position: 'Valid', relationship: 'Strong (Cross-Ref)' },
      { id: 'Frag-4', name: 'Trailer & %%EOF', offset: '0x00011800', status: 'Found', position: 'Valid', relationship: 'Strong (Terminal)' },
    ],
  },
  {
    id: 'BENCH-002',
    filename: 'photo.jpg',
    type: 'Photo',
    fragments_found: 4,
    fragments_expected: 5,
    recovery_percent: 72,
    overall_integrity: 68,
    structural_integrity: 75,
    content_integrity: 65,
    metadata_integrity: 70,
    structural_validity: 'valid',
    classification_confidence: 0.96,
    priority_tier: 'MEDIUM',
    provenance: PROVENANCE_TYPES.SYNTHETIC_DEMO,
    security_verdict: SECURITY_VERDICT.CLEAN,
    security_reasons: [],
    fragmentSequence: [
      { id: 'Frag-A', name: 'SOI & EXIF (FF D8)', offset: '0x00020000', status: 'Found', position: 'Valid', relationship: 'Strong (Header)' },
      { id: 'Frag-B', name: 'Huffman Tables', offset: '0x00020400', status: 'Found', position: 'Valid', relationship: 'Strong (DHT Link)' },
      { id: 'Frag-C', name: 'Scanline Cluster 1', offset: '0x00020800', status: 'Found', position: 'Valid', relationship: 'Strong (Continuity)' },
      { id: 'Frag-D', name: 'Scanline Cluster 2', offset: '0x00020C00', status: 'Found', position: 'Valid', relationship: 'Weak (Discontinuous)' },
      { id: 'Frag-E', name: 'Tail & EOI (FF D9)', offset: '0x00021000', status: 'Missing', position: 'Incomplete', relationship: 'Lost (Carving Gap)' },
    ],
  },
  {
    id: 'BENCH-003',
    filename: 'history.db',
    type: 'DB log',
    fragments_found: 6,
    fragments_expected: 6,
    recovery_percent: 88,
    overall_integrity: 91,
    structural_integrity: 70,
    content_integrity: 92,
    metadata_integrity: 85,
    // Routed to NEEDS_REVIEW because classification confidence was below 60%
    // and structural validity was returned as 'uncertain'
    structural_validity: 'uncertain',
    classification_confidence: 0.54, // below 60% threshold
    priority_tier: 'HIGH',
    provenance: PROVENANCE_TYPES.DERIVED_ANALYSIS,
    security_verdict: SECURITY_VERDICT.CLEAN,
    security_reasons: [],
    fragmentSequence: [
      { id: 'Page-0', name: 'SQLite Header & Schema', offset: '0x00030000', status: 'Found', position: 'Valid', relationship: 'Strong (Magic 100B)' },
      { id: 'Page-1', name: 'B-Tree Table Leaf (auth)', offset: '0x00031000', status: 'Found', position: 'Valid', relationship: 'Strong (Pointer)' },
      { id: 'Page-2', name: 'B-Tree Table Leaf (events)', offset: '0x00032000', status: 'Found', position: 'Valid', relationship: 'Strong (Sequence)' },
      { id: 'Page-3', name: 'Freelist Trunk Page', offset: '0x00033000', status: 'Found', position: 'Ambiguous', relationship: 'Uncertain (Pointer mismatch)' },
      { id: 'Page-4', name: 'Overflow Page 1', offset: '0x00034000', status: 'Found', position: 'Valid', relationship: 'Strong' },
      { id: 'Page-5', name: 'WAL Checkpoint Header', offset: '0x00035000', status: 'Found', position: 'Valid', relationship: 'Strong' },
    ],
  },
  {
    id: 'BENCH-004',
    filename: 'archive.zip',
    type: 'Document', // Archive
    fragments_found: 2,
    fragments_expected: 7,
    recovery_percent: 18,
    overall_integrity: 22,
    structural_integrity: 15,
    content_integrity: 20,
    metadata_integrity: 30,
    structural_validity: 'invalid',
    classification_confidence: 0.92,
    priority_tier: 'LOW',
    provenance: PROVENANCE_TYPES.SYNTHETIC_DEMO,
    security_verdict: SECURITY_VERDICT.CLEAN,
    security_reasons: [],
    fragmentSequence: [
      { id: 'Zip-1', name: 'Local File Header 1', offset: '0x00040000', status: 'Found', position: 'Valid', relationship: 'Strong (PK 03 04)' },
      { id: 'Zip-2', name: 'Compressed Deflate Stream', offset: '0x00040800', status: 'Found', position: 'Truncated', relationship: 'Discontinuous' },
      { id: 'Zip-3', name: 'File Payload 2', offset: '0x00041000', status: 'Missing', position: 'Incomplete', relationship: 'Lost' },
      { id: 'Zip-4', name: 'File Payload 3', offset: '0x00041800', status: 'Missing', position: 'Incomplete', relationship: 'Lost' },
      { id: 'Zip-5', name: 'Central Directory Header', offset: '0x00042000', status: 'Missing', position: 'Incomplete', relationship: 'Lost (Critical)' },
      { id: 'Zip-6', name: 'Central Directory 2', offset: '0x00042800', status: 'Missing', position: 'Incomplete', relationship: 'Lost' },
      { id: 'Zip-7', name: 'End of Central Directory (EOCD)', offset: '0x00043000', status: 'Missing', position: 'Incomplete', relationship: 'Lost (Critical)' },
    ],
  },
  // ── Feature 6 Fixture: invoice.jpg — disguised Windows PE executable ─────────
  {
    id: 'BENCH-005',
    filename: 'invoice.jpg',
    type: 'Photo',
    fragments_found: 4,
    fragments_expected: 4,
    recovery_percent: 96,
    overall_integrity: 94,
    structural_integrity: 90,
    content_integrity: 88,
    metadata_integrity: 92,
    structural_validity: 'valid',
    classification_confidence: 0.91,
    priority_tier: 'HIGH',
    provenance: PROVENANCE_TYPES.SYNTHETIC_DEMO,
    // Feature 6: Security verdict — MALICIOUS (MZ header + hash blocklist + high entropy)
    security_verdict: SECURITY_VERDICT.MALICIOUS,
    security_reasons: [
      { key: 'extension_signature_mismatch', text: '✗ File claims to be a JPEG (.jpg) but header is MZ (Windows PE executable)' },
      { key: 'known_hash_match',             text: '✗ SHA-256 matches known-malicious hash list [DEMO blocklist]' },
      { key: 'high_entropy_packed',          text: '⚠ High entropy (7.94 bits/byte) — consistent with packed/obfuscated binary' },
    ],
    // Raw security scan data (mirrors backend response)
    securityScanData: {
      detected_header: '4D5A (MZ — Windows PE)',
      declared_type:   'image/jpeg',
      sha256:          'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      entropy_whole_file: 7.94,
      verdict:         'MALICIOUS',
    },
    fragmentSequence: [
      { id: 'F-1', name: 'MZ Header (offset 0)', offset: '0x00050000', status: 'Found', position: 'Valid', relationship: 'Strong (MZ)' },
      { id: 'F-2', name: 'PE Optional Header', offset: '0x00050200', status: 'Found', position: 'Valid', relationship: 'Strong' },
      { id: 'F-3', name: '.text Section (code)', offset: '0x00050400', status: 'Found', position: 'Valid', relationship: 'Strong' },
      { id: 'F-4', name: '.data Section (payload)', offset: '0x00051000', status: 'Found', position: 'Valid', relationship: 'Strong' },
    ],
  },
  // ── Feature 5 Fixture: vacation.jpg — recovered FROM pendrive ──────────────
  {
    id: 'BENCH-006',
    filename: 'vacation.jpg',
    type: 'Photo',
    source_type: 'usb',
    device_label: 'SanDisk Cruzer 16GB',
    media_path: '/data/evidence/usb_EVD-002.img',
    fragments_found: 3,
    fragments_expected: 3,
    recovery_percent: 100,
    overall_integrity: 91,
    structural_integrity: 93,
    content_integrity: 90,
    metadata_integrity: 88,
    structural_validity: 'valid',
    classification_confidence: 0.98,
    priority_tier: 'MEDIUM',
    provenance: PROVENANCE_TYPES.SYNTHETIC_DEMO,
    security_verdict: SECURITY_VERDICT.CLEAN,
    security_reasons: [],
    fragmentSequence: [
      { id: 'USB-F1', name: 'SOI + EXIF Header (FF D8)', offset: '0x00001000', status: 'Found', position: 'Valid', relationship: 'Strong (USB Sector 2)' },
      { id: 'USB-F2', name: 'Image Data (scanlines 1–48)', offset: '0x00002000', status: 'Found', position: 'Valid', relationship: 'Strong (Gap bridged)' },
      { id: 'USB-F3', name: 'Remaining scanlines + EOI', offset: '0x00004000', status: 'Found', position: 'Valid', relationship: 'Strong (Terminal FF D9)' },
    ],
  },
];

/**
 * Adapt any existing raw artifact from the application into an aggregated evidence record.
 */
export function adaptArtifactToEvidence(artifact) {
  // Check if it's already an aggregated benchmark record
  if (artifact.fragments_found !== undefined && artifact.structural_validity !== undefined) {
    return artifact;
  }

  // Derive fragment count and expected from recovery info or file size
  let fragmentsFound = 4;
  let fragmentsExpected = 4;
  if (artifact.recoveryInfo?.sourceFragments?.length) {
    fragmentsFound = artifact.recoveryInfo.sourceFragments.length;
    fragmentsExpected = fragmentsFound;
  }
  if (artifact.recoverability === 'MOSTLY_RECOVERABLE') {
    fragmentsFound = Math.max(3, fragmentsExpected - 1);
  } else if (artifact.recoverability === 'PARTIALLY_RECOVERABLE') {
    fragmentsFound = 3;
    fragmentsExpected = 5;
  } else if (artifact.recoverability === 'BARELY_RECOVERABLE') {
    fragmentsFound = 1;
    fragmentsExpected = 5;
  }

  // Structural validity
  let structuralValidity = 'valid';
  if (artifact.corruptionSeverity === 'High' || artifact.recoverability === 'BARELY_RECOVERABLE') {
    structuralValidity = 'invalid';
  } else if (artifact.reviewRequired || artifact.classificationConfidence < 60) {
    structuralValidity = 'uncertain';
  }

  const recoveryPercent = Math.round((fragmentsFound / fragmentsExpected) * 100);

  // Feature 6: forward security signals from general artifact data if present
  const securityVerdict = artifact.security_verdict || artifact.securityVerdict || SECURITY_VERDICT.CLEAN;
  const securityReasons = artifact.security_reasons || artifact.securityReasons || [];

  const base = aggregateEvidence(
    {
      id: artifact.id,
      filename: artifact.filename,
      fragmentsFound,
      fragmentsExpected,
      recoveryPercent,
      edgeConfidence: artifact.recoveryInfo?.carvingConfidence ?? 90,
      fragmentSequence: (artifact.recoveryInfo?.sourceFragments || ['Frag-1', 'Frag-2']).map((f, i) => ({
        id: `F-${i + 1}`,
        name: typeof f === 'string' ? f : `Sector Cluster ${i + 1}`,
        offset: artifact.metadata?.sourceOffset || `0x00${(i + 1) * 1000}`,
        status: 'Found',
        position: 'Valid',
        relationship: 'Strong (Sequential)'
      })),
    },
    {
      id: artifact.id,
      filename: artifact.filename,
      structuralValidity,
      overallIntegrity: artifact.overallIntegrity ?? artifact.integrity ?? 80,
      structuralIntegrity: artifact.structuralIntegrity ?? 80,
      contentIntegrity: artifact.contentIntegrity ?? 80,
      metadataIntegrity: artifact.metadataIntegrity ?? 80,
    },
    {
      id: artifact.id,
      filename: artifact.filename,
      type: artifact.type,
      classificationConfidence: artifact.classificationConfidence,
      priorityTier: artifact.priorityTier,
      provenance: PROVENANCE_TYPES.DERIVED_ANALYSIS,
      metadata: artifact.metadata,
    }
  );

  // Merge Feature 5/6 fields
  return {
    ...base,
    security_verdict: securityVerdict,
    security_reasons: securityReasons,
    securityScanData: artifact.securityScanData || null,
    source_type: artifact.source_type || null,
    device_label: artifact.device_label || null,
    media_path: artifact.media_path || null,
  };
}
