/**
 * SAMDHAN AI — Priority Scoring Engine (sec 4 of Classification & Prioritization spec)
 *
 * Formula (spec sec 4, verbatim):
 *   Priority = w1*Integrity + w2*Relevance + w3*Recency + w4*Uniqueness - w5*NoisePenalty
 *
 *   w1 = 0.30  (Integrity)    -- completeness/validity score from integrity step
 *   w2 = 0.35  (Relevance)    -- keyword/entity/anomaly match strength (highest: investigator's core question)
 *   w3 = 0.20  (Recency)      -- temporal proximity to incident window
 *   w4 = 0.15  (Uniqueness)   -- 1 - duplication_ratio; exact duplicates -> 0
 *   w5 = 0.10  (NoisePenalty) -- likelihood the file is system junk/cache/temp; subtracted
 *
 * Output range: 0-1 (not 0-100).
 *
 * CRITICAL DESIGN INVARIANT (spec sec 4):
 * Classification confidence is DELIBERATELY EXCLUDED from the priority formula.
 * An artifact can be perfectly classified (99% JPEG) and still be forensically
 * worthless; an artifact with uncertain type (60% log) can still be highly
 * relevant. Mixing them would let "the system is sure what this is" masquerade
 * as "this matters" -- a real forensic-validity error.
 *
 * Low classification confidence triggers a separate REVIEW FLAG shown alongside
 * the score -- it is NEVER folded into the score itself.
 *
 * Tiers (spec sec 4):
 *   >= 0.75 -> Critical
 *   0.50 - 0.74 -> High
 *   0.25 - 0.49 -> Medium
 *   < 0.25 -> Low
 */

// Configurable Weight Constants (one place -- justifiable per case)
export const WEIGHTS = Object.freeze({
  integrity:    0.30,
  relevance:    0.35,
  recency:      0.20,
  uniqueness:   0.15,
  noisePenalty: 0.10,  // subtracted
});

// Noise-path heuristics -- known system junk locations
// Matches known noise patterns: temp dirs, browser cache, OS cache, thumbnails
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
];

/**
 * Compute noise penalty (0-1) for a given artifact.
 * Returns 1.0 for definite known-junk paths, 0.0 for paths with no noise signal.
 * @param {string} filename
 * @param {string} [path]
 * @param {string} [type]
 * @returns {number}
 */
export function computeNoisePenalty(filename = '', path = '', type = '') {
  const combined = `${path} ${filename}`.toLowerCase();

  for (const pattern of NOISE_PATH_PATTERNS) {
    if (pattern.test(combined)) return 1.0;
  }

  // Medium noise: unclassified fragments with low forensic value
  if (type === 'Unknown/Fragment') return 0.3;

  return 0.0;
}

/**
 * Compute temporal recency score (0-1).
 * Spec: Recency = 1 - min(1, |timestamp - incident_time| / window)
 * Returns 1.0 inside the window; decays linearly to 0 as distance increases.
 *
 * @param {string|null} inferredMtime  - ISO timestamp of artifact
 * @param {string|null} incidentStart  - ISO timestamp of breach window start
 * @param {string|null} incidentEnd    - ISO timestamp of breach window end
 * @returns {number} 0-1
 */
export function computeRecencyScore(inferredMtime, incidentStart, incidentEnd) {
  if (!inferredMtime) return 0.5; // Unknown -- neutral

  const t      = new Date(inferredMtime).getTime();
  const tStart = new Date(incidentStart || '2026-09-24T14:00:00Z').getTime();
  const tEnd   = new Date(incidentEnd   || '2026-09-24T22:30:00Z').getTime();
  const windowMs = tEnd - tStart;

  if (t >= tStart && t <= tEnd) return 1.0;

  const distMs = t < tStart ? (tStart - t) : (t - tEnd);
  return Math.max(0, 1 - distMs / windowMs);
}

/**
 * Compute uniqueness score (0-1).
 * Spec: Uniqueness = 1 - duplication_ratio
 * - Exact duplicate (SHA-256 match) -> 0
 * - Near-duplicate (ssdeep > 90%)   -> 0.10
 * - Near-duplicate (ssdeep > 70%)   -> 0.20
 * - Near-duplicate (ssdeep > 40%)   -> 0.55
 * - Unique                          -> 1.00
 *
 * @param {boolean} isDuplicate
 * @param {number}  ssdeepSimilarity  0-1
 * @returns {number} 0-1
 */
export function computeUniquenessScore(isDuplicate, ssdeepSimilarity = 0) {
  if (isDuplicate)             return 0;
  if (ssdeepSimilarity > 0.90) return 0.10;
  if (ssdeepSimilarity > 0.70) return 0.20;
  if (ssdeepSimilarity > 0.40) return 0.55;
  return 1.0;
}

/**
 * Full priority score computation.
 * All inputs are normalised 0-1; score output is also 0-1.
 *
 * @param {Object} params
 * @param {number}  params.relevance              - Evidence Relevance (0-1 or 0-100, auto-normalised)
 * @param {number}  params.integrity              - Data Integrity (0-1 or 0-100, auto-normalised)
 * @param {string}  params.inferredMtime          - ISO timestamp for temporal scoring
 * @param {string}  params.incidentStart          - ISO timestamp for incident window start
 * @param {string}  params.incidentEnd            - ISO timestamp for incident window end
 * @param {boolean} params.isDuplicate            - Exact SHA-256 duplicate
 * @param {number}  params.ssdeepSimilarity       - SSDEEP similarity (0-1)
 * @param {number}  params.noisePenalty           - Noise signal (0-1)
 * @param {number}  params.classificationConfidence - Used ONLY for reviewRequired flag, NOT the score
 * @returns {{ score: number, breakdown: Object, tier: string, reviewRequired: boolean }}
 */
export function computePriorityScore({
  relevance             = 0.5,
  integrity             = 0.5,
  inferredMtime         = null,
  incidentStart         = null,
  incidentEnd           = null,
  isDuplicate           = false,
  ssdeepSimilarity      = 0,
  noisePenalty          = 0,
  classificationConfidence = 80,
}) {
  // Normalise all inputs to 0-1 (accept either 0-100 or 0-1 scale gracefully)
  const R  = Math.max(0, Math.min(1, relevance  > 1 ? relevance  / 100 : relevance));
  const I  = Math.max(0, Math.min(1, integrity  > 1 ? integrity  / 100 : integrity));
  const T  = computeRecencyScore(inferredMtime, incidentStart, incidentEnd);
  const U  = computeUniquenessScore(isDuplicate, ssdeepSimilarity);
  const NP = Math.max(0, Math.min(1, noisePenalty));

  // Spec formula: P = w1*I + w2*R + w3*T + w4*U - w5*NP
  const rawScore =
    WEIGHTS.integrity    * I +
    WEIGHTS.relevance    * R +
    WEIGHTS.recency      * T +
    WEIGHTS.uniqueness   * U -
    WEIGHTS.noisePenalty * NP;

  const score = Math.max(0, Math.min(1, rawScore));

  // Tier thresholds (spec sec 4)
  const tier = score >= 0.75 ? 'Critical'
             : score >= 0.50 ? 'High'
             : score >= 0.25 ? 'Medium'
             :                 'Low';

  // Review flag: separate from score -- low classification confidence (<60%) triggers badge
  // NEVER mixed into the priority formula (spec sec 4 invariant)
  const reviewRequired = classificationConfidence < 60;

  return {
    score:          Math.round(score * 1000) / 1000,
    tier,
    reviewRequired,
    breakdown: {
      // Raw dimension values (0-1)
      I:  Math.round(I  * 1000) / 1000,
      R:  Math.round(R  * 1000) / 1000,
      T:  Math.round(T  * 1000) / 1000,
      U:  Math.round(U  * 1000) / 1000,
      NP: Math.round(NP * 1000) / 1000,

      // Weighted contributions to final score
      integrityContrib:      Math.round(WEIGHTS.integrity    * I  * 1000) / 1000,
      relevanceContrib:      Math.round(WEIGHTS.relevance    * R  * 1000) / 1000,
      recencyContrib:        Math.round(WEIGHTS.recency      * T  * 1000) / 1000,
      uniquenessContrib:     Math.round(WEIGHTS.uniqueness   * U  * 1000) / 1000,
      noisePenaltyDeduction: Math.round(WEIGHTS.noisePenalty * NP * 1000) / 1000,

      // Max possible from each dimension (for UI bar chart display)
      maxIntegrity:    WEIGHTS.integrity,
      maxRelevance:    WEIGHTS.relevance,
      maxRecency:      WEIGHTS.recency,
      maxUniqueness:   WEIGHTS.uniqueness,
      maxNoisePenalty: WEIGHTS.noisePenalty,

      // Metadata (not in formula)
      classificationConfidence,
      reviewRequired,
    }
  };
}

/**
 * Human-readable edge-case explanations (spec sec 5 Edge Cases table).
 * Shown in UI alongside the score -- NOT fed back into it.
 * @param {Object} artifact
 * @returns {string[]}
 */
export function getEdgeCaseExplanation(artifact) {
  const messages = [];
  const c  = artifact.classificationConfidence ?? 0;
  const i  = (artifact.integrity ?? 0) > 1 ? artifact.integrity / 100 : (artifact.integrity ?? 0);
  const r  = (artifact.evidenceRelevance ?? 0) > 1 ? artifact.evidenceRelevance / 100 : (artifact.evidenceRelevance ?? 0);
  const np = artifact.noisePenalty ?? 0;
  const dup = artifact.duplicate ?? false;

  if (c < 60) {
    messages.push(
      `Low classification confidence (${c.toFixed(1)}%) -> "Unverified Type -- Needs Review" badge shown. ` +
      `Confidence is NOT mixed into the priority score (spec sec 4 invariant).`
    );
  }

  if (i < 0.40 && r > 0.90) {
    messages.push(
      `Low integrity (${(i * 100).toFixed(0)}%) but very high relevance (${(r * 100).toFixed(1)}%) -> ` +
      `Promoted to High/Critical -- corrupted ransom notes and bash histories remain vital investigative leads.`
    );
  }

  if (i >= 0.95 && r < 0.15) {
    messages.push(
      `High integrity (${(i * 100).toFixed(0)}%) but near-zero relevance (${(r * 100).toFixed(1)}%) -> ` +
      `Stays in Low tier -- pristine default OS files should not crowd the triage queue.`
    );
  }

  if (dup) {
    messages.push(
      `Exact SHA-256 duplicate detected -> Uniqueness score = 0. ` +
      `Priority heavily reduced. Master artifact retains original score; this copy is linked as "duplicate of X".`
    );
  }

  if (np > 0) {
    messages.push(
      `Noise penalty applied (${(np * 100).toFixed(0)}%) -> Artifact path/type matches known system junk ` +
      `(temp dirs, cache, OS files). Deducted ${(WEIGHTS.noisePenalty * np * 100).toFixed(1)} points from score.`
    );
  }

  return messages;
}

export default { computePriorityScore, computeRecencyScore, computeUniquenessScore, computeNoisePenalty, WEIGHTS };
