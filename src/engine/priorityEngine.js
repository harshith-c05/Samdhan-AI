/**
 * SAMDHAN AI — Priority Scoring Engine (Objective 03)
 *
 * Formula (Master Spec Section 4):
 *   P = w1*I + w2*R + w3*T + w4*U - w5*N
 *
 *   w1 = 0.30  (Integrity)    -- completeness/validity score from Objective 02 deep parser
 *   w2 = 0.35  (Relevance)    -- keyword/entity/IOC match strength from case context
 *   w3 = 0.20  (Temporal)     -- proximity to incident window (T = 1.0 inside window)
 *   w4 = 0.15  (Uniqueness)   -- 1 - duplication_ratio; exact duplicates -> 0
 *   w5 = 0.10  (NoisePenalty) -- likelihood file is system junk/cache/temp (subtracted)
 *
 * Output range: 0.0 to 1.0 (clamped).
 *
 * CRITICAL INVARIANT:
 * Classification confidence is DELIBERATELY EXCLUDED from the priority formula.
 * An artifact can be perfectly classified (99% JPEG) and be forensically useless.
 * An uncertain format (<60%) can still be critical.
 * Low confidence triggers reviewRequired = true independently.
 *
 * Tiers:
 *   P >= 0.75       -> Critical
 *   0.50 <= P < 0.75 -> High
 *   0.25 <= P < 0.50 -> Medium
 *   P < 0.25        -> Low
 */

export const WEIGHTS = Object.freeze({
  integrity:    0.30,
  relevance:    0.35,
  recency:      0.20,
  temporal:     0.20,
  uniqueness:   0.15,
  noisePenalty: 0.10,
});

export const PRIORITY_PRESETS = Object.freeze({
  standard: {
    id: 'standard',
    name: 'Standard Forensic Triage',
    description: 'Balanced baseline across all 5 dimensions',
    weights: { relevance: 0.35, integrity: 0.30, recency: 0.20, uniqueness: 0.15, noisePenalty: 0.10 }
  },
  ransomware: {
    id: 'ransomware',
    name: 'Active Ransomware Incident',
    description: 'Heavily weights IOC matches and breach window recency',
    weights: { relevance: 0.45, integrity: 0.20, recency: 0.25, uniqueness: 0.10, noisePenalty: 0.10 }
  },
  time_critical: {
    id: 'time_critical',
    name: 'Time-Critical Breach',
    description: 'Focuses on events clustered directly around the breach window',
    weights: { relevance: 0.30, integrity: 0.20, recency: 0.40, uniqueness: 0.10, noisePenalty: 0.10 }
  },
  dedup_heavy: {
    id: 'dedup_heavy',
    name: 'Deduplication Heavy',
    description: 'Prioritizes intact, unique confidential files and penalizes noise/duplicates',
    weights: { relevance: 0.25, integrity: 0.35, recency: 0.10, uniqueness: 0.25, noisePenalty: 0.15 }
  }
});

// Noise-path heuristics
const NOISE_PATH_PATTERNS = [
  /\/tmp\//i,
  /\\temp\\/i,
  /\\cache\\/i,
  /\/cache\//i,
  /thumbs\.db$/i,
  /desktop\.ini$/i,
  /pagefile\.sys$/i,
  /hiberfil\.sys$/i,
  /\.ds_store$/i,
  /appdata\\local\\temp/i,
  /browserhistory\\cache/i,
  /\.(tmp|bak|old)$/i,
];

export function computeNoisePenalty(filename = '', path = '', type = '') {
  const combined = `${path} ${filename}`.toLowerCase();
  for (const pattern of NOISE_PATH_PATTERNS) {
    if (pattern.test(combined)) return 0.85;
  }
  if (type === 'Unknown/Fragment') return 0.25;
  return 0.0;
}

export function computeRecencyScore(inferredMtime, incidentStart, incidentEnd) {
  if (!inferredMtime) return 0.75;

  const t = new Date(inferredMtime).getTime();
  const tStart = new Date(incidentStart || '2026-09-24T10:00:00Z').getTime();
  const tEnd   = new Date(incidentEnd   || '2026-09-24T18:00:00Z').getTime();
  const windowMs = tEnd - tStart || 1;

  if (t >= tStart && t <= tEnd) return 1.0;

  const distMs = t < tStart ? (tStart - t) : (t - tEnd);
  return Math.max(0.1, 1 - distMs / (windowMs * 2));
}

export function computeUniquenessScore(isDuplicate, ssdeepSimilarity = 0) {
  if (isDuplicate)             return 0.0;
  if (ssdeepSimilarity > 0.90) return 0.10;
  if (ssdeepSimilarity > 0.70) return 0.20;
  if (ssdeepSimilarity > 0.40) return 0.55;
  return 1.0;
}

export function computePriorityScore({
  relevance             = 0.5,
  integrity             = 0.5,
  inferredMtime         = null,
  incidentStart         = null,
  incidentEnd           = null,
  isDuplicate           = false,
  ssdeepSimilarity      = 0,
  noisePenalty          = 0,
  classificationConfidence = 85,
  customWeights         = null,
  filename              = '',
  matchedIocs           = [],
}) {
  const w = customWeights || WEIGHTS;
  const wRel   = w.relevance ?? WEIGHTS.relevance;
  const wInteg = w.integrity ?? WEIGHTS.integrity;
  const wTemp  = w.recency ?? w.temporal ?? WEIGHTS.recency;
  const wUniq  = w.uniqueness ?? WEIGHTS.uniqueness;
  const wNoise = w.noisePenalty ?? WEIGHTS.noisePenalty;

  // Normalize all inputs to 0-1
  const R  = Math.max(0, Math.min(1, relevance > 1 ? relevance / 100 : relevance));
  const I  = Math.max(0, Math.min(1, integrity > 1 ? integrity / 100 : integrity));
  const T  = computeRecencyScore(inferredMtime, incidentStart, incidentEnd);
  const U  = computeUniquenessScore(isDuplicate, ssdeepSimilarity);
  const NP = Math.max(0, Math.min(1, noisePenalty > 1 ? noisePenalty / 100 : noisePenalty));

  // P = w1*I + w2*R + w3*T + w4*U - w5*NP
  const rawScore = (wInteg * I) + (wRel * R) + (wTemp * T) + (wUniq * U) - (wNoise * NP);
  const score = Math.max(0, Math.min(1, rawScore));

  const tier = score >= 0.75 || R >= 0.90 ? 'Critical'
             : score >= 0.50 ? 'High'
             : score >= 0.25 ? 'Medium'
             :                 'Low';

  const confNorm = classificationConfidence > 1 ? classificationConfidence : classificationConfidence * 100;
  const reviewRequired = confNorm < 60;

  // Generate explainable decision reasons
  const explanations = [];
  if (R >= 0.85) {
    explanations.push('High investigative relevance with identified attack/extortion indicators');
  } else if (R >= 0.60) {
    explanations.push('Moderate investigative relevance matching case context');
  }

  if (T >= 0.95) {
    explanations.push('Falls directly inside confirmed incident breach window (T = 1.00)');
  } else if (T >= 0.70) {
    explanations.push('Close temporal proximity to incident breach window');
  }

  if (U >= 0.90) {
    explanations.push('Unique artifact across evidence set (no duplicate sectors)');
  } else if (U <= 0.20) {
    explanations.push('Near-duplicate copy; uniqueness factor reduced');
  }

  if (I >= 0.90) {
    explanations.push(`High data integrity verified by Objective 02 (${Math.round(I * 100)}%)`);
  } else if (I < 0.40) {
    explanations.push(`Low integrity (${Math.round(I * 100)}%); partial carving required`);
  }

  if (NP >= 0.50) {
    explanations.push(`Known system noise pattern deducted ${Math.round(wNoise * NP * 100)}% from score`);
  }

  if (reviewRequired) {
    explanations.push(`Classification confidence (${Math.round(confNorm)}%) is below 60% threshold; requires manual review`);
  }

  if (explanations.length === 0) {
    explanations.push(`Balanced scoring across standard forensic dimensions placed artifact in ${tier} tier`);
  }

  return {
    score:          Math.round(score * 1000) / 1000,
    tier,
    reviewRequired,
    explanations,
    breakdown: {
      I:  Math.round(I  * 1000) / 1000,
      R:  Math.round(R  * 1000) / 1000,
      T:  Math.round(T  * 1000) / 1000,
      U:  Math.round(U  * 1000) / 1000,
      NP: Math.round(NP * 1000) / 1000,

      integrityContrib:      Math.round(wInteg * I  * 1000) / 1000,
      relevanceContrib:      Math.round(wRel   * R  * 1000) / 1000,
      recencyContrib:        Math.round(wTemp  * T  * 1000) / 1000,
      uniquenessContrib:     Math.round(wUniq  * U  * 1000) / 1000,
      noisePenaltyDeduction: Math.round(wNoise * NP * 1000) / 1000,

      total: Math.round(score * 1000) / 10,
      classificationConfidence: confNorm,
      reviewRequired,
    }
  };
}

export function getEdgeCaseExplanation(artifact) {
  const messages = [];
  const c  = artifact.classificationConfidence ?? 85;
  const i  = (artifact.integrity ?? 0) > 1 ? artifact.integrity / 100 : (artifact.integrity ?? 0);
  const r  = (artifact.evidenceRelevance ?? 0) > 1 ? artifact.evidenceRelevance / 100 : (artifact.evidenceRelevance ?? 0);
  const np = artifact.noisePenalty ?? 0;
  const dup = artifact.duplicate ?? false;

  if (c < 60) {
    messages.push(
      `Low classification confidence (${c.toFixed(1)}%) -> "Needs Review" flag active. ` +
      `Confidence is NOT mixed into priority score P (Objective 03 invariant).`
    );
  }

  if (i < 0.40 && r > 0.90) {
    messages.push(
      `Low integrity (${(i * 100).toFixed(0)}%) but very high relevance (${(r * 100).toFixed(1)}%) -> ` +
      `Promoted to High/Critical -- corrupted ransom notes remain vital investigative leads.`
    );
  }

  if (dup) {
    messages.push(
      `Exact duplicate detected -> Uniqueness score = 0. ` +
      `Duplicate copy receives lower priority to reduce investigator clutter.`
    );
  }

  if (np > 0) {
    messages.push(`Noise penalty applied (${(np * 100).toFixed(0)}%) -> System cache/temp junk.`);
  }

  return messages;
}

export default {
  computePriorityScore,
  computeRecencyScore,
  computeUniquenessScore,
  computeNoisePenalty,
  getEdgeCaseExplanation,
  WEIGHTS,
  PRIORITY_PRESETS
};
