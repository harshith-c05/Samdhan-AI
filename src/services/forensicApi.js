/**
 * SAMDHAN AI — Forensic API Service
 * Centralized client for all backend forensic endpoints:
 * - /api/triage (Consolidated Objective 03 Engine)
 * - /api/classify (Objective 03 Two-path classifier)
 * - /api/prioritize (Objective 03 Priority scoring)
 * - /api/artifacts (Ranked evidence collection)
 * - /api/priority-summary & /api/priority-distribution
 * - /api/classification-summary
 * - /api/priority/recalculate
 */

const API_BASE_URL = 'http://127.0.0.1:8000';

/**
 * Fetch with timeout helper.
 */
async function fetchWithTimeout(resource, options = {}) {
  const { timeout = 8000 } = options;
  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), timeout);
  try {
    const response = await fetch(resource, {
      ...options,
      signal: controller.signal,
    });
    clearTimeout(id);
    return response;
  } catch (error) {
    clearTimeout(id);
    throw error;
  }
}

/**
 * Runs end-to-end evidence triage on the backend.
 * Returns classified and prioritized artifacts with summaries and statistics.
 */
export async function triageEvidence(caseContext = {}, customWeights = null) {
  try {
    const res = await fetchWithTimeout(`${API_BASE_URL}/api/triage`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        case_id: caseContext.caseId || 'CASE-2026-NIGHTFALL',
        incident_start: caseContext.incidentStart || '2026-09-24T10:00:00Z',
        incident_end: caseContext.incidentEnd || '2026-09-24T18:00:00Z',
        case_keywords: caseContext.iocs ? caseContext.iocs.split(',').map(s => s.trim()) : null,
        custom_weights: customWeights,
      }),
      timeout: 10000,
    });

    if (!res.ok) throw new Error(`HTTP error ${res.status}`);
    return await res.json();
  } catch (err) {
    console.warn('[forensicApi] Backend /api/triage unavailable, using client fallback:', err.message);
    return null;
  }
}

/**
 * Classifies an individual artifact payload (hex or content) via backend.
 */
export async function classifyArtifactApi(payload) {
  try {
    const res = await fetchWithTimeout(`${API_BASE_URL}/api/classify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (!res.ok) throw new Error(`HTTP error ${res.status}`);
    return await res.json();
  } catch (err) {
    console.warn('[forensicApi] /api/classify failed:', err.message);
    return null;
  }
}

/**
 * Calculates priority score and tier via backend.
 */
export async function prioritizeArtifactsApi(payload) {
  try {
    const res = await fetchWithTimeout(`${API_BASE_URL}/api/prioritize`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (!res.ok) throw new Error(`HTTP error ${res.status}`);
    return await res.json();
  } catch (err) {
    console.warn('[forensicApi] /api/prioritize failed:', err.message);
    return null;
  }
}

/**
 * Retrieves all triaged artifacts from backend.
 */
export async function getArtifactsApi() {
  try {
    const res = await fetchWithTimeout(`${API_BASE_URL}/api/artifacts`);
    if (!res.ok) throw new Error(`HTTP error ${res.status}`);
    return await res.json();
  } catch (err) {
    console.warn('[forensicApi] /api/artifacts failed:', err.message);
    return null;
  }
}

/**
 * Retrieves single artifact details by ID.
 */
export async function getArtifactApi(id) {
  try {
    const res = await fetchWithTimeout(`${API_BASE_URL}/api/artifacts/${encodeURIComponent(id)}`);
    if (!res.ok) throw new Error(`HTTP error ${res.status}`);
    return await res.json();
  } catch (err) {
    console.warn(`[forensicApi] /api/artifacts/${id} failed:`, err.message);
    return null;
  }
}

/**
 * Retrieves priority summary counts.
 */
export async function getPrioritySummaryApi() {
  try {
    const res = await fetchWithTimeout(`${API_BASE_URL}/api/priority-summary`);
    if (!res.ok) throw new Error(`HTTP error ${res.status}`);
    return await res.json();
  } catch (err) {
    console.warn('[forensicApi] /api/priority-summary failed:', err.message);
    return null;
  }
}

/**
 * Retrieves priority distribution chart data.
 */
export async function getPriorityDistributionApi() {
  try {
    const res = await fetchWithTimeout(`${API_BASE_URL}/api/priority-distribution`);
    if (!res.ok) throw new Error(`HTTP error ${res.status}`);
    return await res.json();
  } catch (err) {
    console.warn('[forensicApi] /api/priority-distribution failed:', err.message);
    return null;
  }
}

/**
 * Retrieves classification summary breakdown.
 */
export async function getClassificationSummaryApi() {
  try {
    const res = await fetchWithTimeout(`${API_BASE_URL}/api/classification-summary`);
    if (!res.ok) throw new Error(`HTTP error ${res.status}`);
    return await res.json();
  } catch (err) {
    console.warn('[forensicApi] /api/classification-summary failed:', err.message);
    return null;
  }
}

/**
 * Recalculates priorities for a set of artifacts on the backend.
 */
export async function recalculatePriorityApi(artifacts, weights) {
  try {
    const res = await fetchWithTimeout(`${API_BASE_URL}/api/priority/recalculate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ artifacts, weights }),
    });
    if (!res.ok) throw new Error(`HTTP error ${res.status}`);
    return await res.json();
  } catch (err) {
    console.warn('[forensicApi] /api/priority/recalculate failed:', err.message);
    return null;
  }
}

export default {
  triageEvidence,
  classifyArtifactApi,
  prioritizeArtifactsApi,
  getArtifactsApi,
  getArtifactApi,
  getPrioritySummaryApi,
  getPriorityDistributionApi,
  getClassificationSummaryApi,
  recalculatePriorityApi,
};
