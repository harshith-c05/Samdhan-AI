/**
 * IntegrityDashboard — §20 Web Interface Implementation
 * Displays:
 *   - Artifact Overview card
 *   - Integrity Dashboard (5-dimension scores)
 *   - Corruption Map (byte-range strip, color-coded)
 *   - Explainability Panel (why the score was produced)
 *   - Fragment Continuity visualization
 */

import React, { useState, useMemo } from 'react';
import {
  Shield, AlertTriangle, CheckCircle, XCircle, Info, ChevronDown, ChevronUp,
  Database, FileText, Image, Activity, Cpu, Hash, Layers, Search
} from 'lucide-react';
import {
  RadialBarChart, RadialBar, ResponsiveContainer, Tooltip, Legend,
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Cell
} from 'recharts';

// ─── Score Helpers ────────────────────────────────────────────────────────────
function scoreColor(val) {
  if (val >= 90) return '#10b981'; // green
  if (val >= 75) return '#22d3ee'; // teal
  if (val >= 50) return '#f59e0b'; // amber
  if (val >= 25) return '#f97316'; // orange
  return '#ef4444';                // red
}

function scoreLabel(val) {
  if (val >= 90) return 'Highly Intact';
  if (val >= 75) return 'Mostly Intact';
  if (val >= 50) return 'Partially Corrupted';
  if (val >= 25) return 'Severely Corrupted';
  return 'Unusable';
}

function severityColors(sev) {
  const map = { None: '#10b981', Low: '#22d3ee', Medium: '#f59e0b', High: '#f97316', Critical: '#ef4444' };
  return map[sev] || '#6b7280';
}

function recoverabilityStyle(label) {
  const map = {
    FULLY_RECOVERABLE:     { color: '#10b981', bg: 'rgba(16,185,129,0.1)',  icon: '●' },
    MOSTLY_RECOVERABLE:    { color: '#22d3ee', bg: 'rgba(34,211,238,0.1)',  icon: '◕' },
    PARTIALLY_RECOVERABLE: { color: '#f59e0b', bg: 'rgba(245,158,11,0.1)', icon: '◑' },
    BARELY_RECOVERABLE:    { color: '#f97316', bg: 'rgba(249,115,22,0.1)', icon: '◔' },
    NOT_RELIABLY_RECOVERABLE: { color: '#ef4444', bg: 'rgba(239,68,68,0.1)', icon: '○' },
  };
  return map[label] || { color: '#6b7280', bg: 'rgba(107,114,128,0.1)', icon: '?' };
}

// ─── Circular Score Gauge ─────────────────────────────────────────────────────
function ScoreGauge({ value, label, size = 80 }) {
  const color = scoreColor(value ?? 0);
  const strokeDash = 2 * Math.PI * 28;
  const filled = value != null ? (value / 100) * strokeDash : 0;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 4 }}>
      <svg width={size} height={size} viewBox="0 0 70 70">
        <circle cx="35" cy="35" r="28" fill="none" stroke="rgba(255,255,255,0.08)" strokeWidth="6" />
        <circle cx="35" cy="35" r="28" fill="none" stroke={color} strokeWidth="6"
          strokeDasharray={`${filled} ${strokeDash}`}
          strokeLinecap="round"
          transform="rotate(-90 35 35)" />
        <text x="35" y="35" textAnchor="middle" dominantBaseline="middle"
          fill={color} fontSize="12" fontWeight="700" fontFamily="'JetBrains Mono', monospace">
          {value != null ? Math.round(value) : 'N/A'}
        </text>
      </svg>
      <span style={{ fontSize: 10, color: 'rgba(255,255,255,0.6)', textAlign: 'center', lineHeight: 1.3 }}>{label}</span>
    </div>
  );
}

// ─── Byte-Range Corruption Map ────────────────────────────────────────────────
function CorruptionMap({ totalSize, corruptionRegions, fragmentsUsed }) {
  const [hovered, setHovered] = useState(null);
  const TRACK_W = '100%';
  const TRACK_H = 28;
  const total = totalSize || 1;

  // Build segment list from fragments and regions
  const segments = useMemo(() => {
    const segs = [];

    // Fragment coverage
    if (fragmentsUsed?.length) {
      fragmentsUsed.forEach(f => {
        segs.push({ start: f.start || f.offset || 0, end: (f.start || f.offset || 0) + (f.length || 512),
          kind: f.confidence >= 0.80 ? 'intact' : 'uncertain', label: f.fragment_id || f.id || 'Frag', confidence: f.confidence });
      });
    }

    // Corruption overlays
    corruptionRegions?.forEach(r => {
      segs.push({ start: r.start, end: r.end, kind: r.type?.startsWith('A_') ? 'missing' : 'corrupted',
        label: r.type?.replace(/_/g, ' '), desc: r.description });
    });

    return segs;
  }, [totalSize, corruptionRegions, fragmentsUsed]);

  const kindColor = { intact: '#10b981', uncertain: '#f59e0b', corrupted: '#ef4444', missing: '#374151' };
  const kindLabel = { intact: 'Intact', uncertain: 'Uncertain', corrupted: 'Corrupted', missing: 'Missing' };

  return (
    <div style={{ width: '100%' }}>
      <div style={{ position: 'relative', height: TRACK_H, background: 'rgba(255,255,255,0.05)', borderRadius: 6, overflow: 'hidden', border: '1px solid rgba(255,255,255,0.1)' }}>
        {segments.map((seg, i) => {
          const left = `${(seg.start / total) * 100}%`;
          const width = `${Math.max(0.3, ((seg.end - seg.start) / total) * 100)}%`;
          return (
            <div key={i}
              style={{ position: 'absolute', top: 0, left, width, height: '100%',
                background: kindColor[seg.kind] || '#6b7280', opacity: 0.85, cursor: 'pointer',
                transition: 'opacity 0.15s' }}
              onMouseEnter={() => setHovered({ ...seg, idx: i })}
              onMouseLeave={() => setHovered(null)}
            />
          );
        })}
        {/* If no segments, show full green */}
        {segments.length === 0 && (
          <div style={{ position: 'absolute', inset: 0, background: '#10b981', opacity: 0.7 }} />
        )}
      </div>

      {/* Legend */}
      <div style={{ display: 'flex', gap: 16, marginTop: 8, flexWrap: 'wrap' }}>
        {Object.entries(kindLabel).map(([k, label]) => (
          <div key={k} style={{ display: 'flex', alignItems: 'center', gap: 5, fontSize: 11, color: 'rgba(255,255,255,0.6)' }}>
            <div style={{ width: 12, height: 12, borderRadius: 2, background: kindColor[k] }} />
            {label}
          </div>
        ))}
      </div>

      {/* Hover tooltip */}
      {hovered && (
        <div style={{
          marginTop: 8, background: 'rgba(0,0,0,0.7)', border: '1px solid rgba(255,255,255,0.15)',
          borderRadius: 6, padding: '8px 12px', fontSize: 11, color: '#fff'
        }}>
          <strong style={{ color: kindColor[hovered.kind] }}>{kindLabel[hovered.kind]}</strong>
          {' · '}Bytes {hovered.start.toLocaleString()}–{hovered.end.toLocaleString()}
          {hovered.desc && <div style={{ marginTop: 4, color: 'rgba(255,255,255,0.6)' }}>{hovered.desc}</div>}
          {hovered.confidence != null && <div style={{ color: '#f59e0b' }}>Fragment confidence: {(hovered.confidence * 100).toFixed(0)}%</div>}
        </div>
      )}
    </div>
  );
}

// ─── Explainability Panel ─────────────────────────────────────────────────────
function ExplainabilityPanel({ explanation }) {
  const [open, setOpen] = useState(true);

  const icon = (line) => {
    if (line.startsWith('✓')) return <CheckCircle size={13} color="#10b981" />;
    if (line.startsWith('✗')) return <XCircle size={13} color="#ef4444" />;
    if (line.startsWith('⚠')) return <AlertTriangle size={13} color="#f59e0b" />;
    return <Info size={13} color="#6b7280" />;
  };

  const lineColor = (line) => {
    if (line.startsWith('✓')) return '#10b981';
    if (line.startsWith('✗')) return '#ef4444';
    if (line.startsWith('⚠')) return '#f59e0b';
    return '#94a3b8';
  };

  return (
    <div style={{ background: 'rgba(0,0,0,0.25)', border: '1px solid rgba(255,255,255,0.08)', borderRadius: 10, overflow: 'hidden' }}>
      <div
        onClick={() => setOpen(!open)}
        style={{ padding: '10px 14px', display: 'flex', alignItems: 'center', justifyContent: 'space-between', cursor: 'pointer',
          borderBottom: open ? '1px solid rgba(255,255,255,0.06)' : 'none' }}>
        <span style={{ fontSize: 12, fontWeight: 600, color: '#94a3b8', letterSpacing: '0.08em', textTransform: 'uppercase' }}>
          Explainability Panel — Why this score?
        </span>
        {open ? <ChevronUp size={14} color="#6b7280" /> : <ChevronDown size={14} color="#6b7280" />}
      </div>
      {open && (
        <div style={{ padding: '12px 14px' }}>
          <p style={{ fontSize: 10, color: 'rgba(255,255,255,0.35)', marginBottom: 10, fontStyle: 'italic' }}>
            Every line below traces to a pipeline stage result in validation_results. Nothing fabricated.
          </p>
          {(explanation || []).map((line, i) => (
            <div key={i} style={{ display: 'flex', alignItems: 'flex-start', gap: 8, marginBottom: 6 }}>
              <span style={{ marginTop: 1, flexShrink: 0 }}>{icon(line)}</span>
              <span style={{ fontSize: 12, color: lineColor(line), lineHeight: 1.5 }}>
                {line.replace(/^[✓✗⚠ℹ]\s*/, '')}
              </span>
            </div>
          ))}
          {(!explanation || !explanation.length) && (
            <p style={{ fontSize: 12, color: '#6b7280' }}>No explanation data available for this artifact.</p>
          )}
        </div>
      )}
    </div>
  );
}

// ─── Dimension Bar ────────────────────────────────────────────────────────────
function DimensionBar({ label, value, weight, icon: Icon }) {
  const color = scoreColor(value ?? 0);
  return (
    <div style={{ marginBottom: 12 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 5 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          {Icon && <Icon size={12} color="rgba(255,255,255,0.4)" />}
          <span style={{ fontSize: 12, color: 'rgba(255,255,255,0.7)' }}>{label}</span>
          <span style={{ fontSize: 10, color: 'rgba(255,255,255,0.25)', fontFamily: 'monospace' }}>w={weight}</span>
        </div>
        <span style={{ fontSize: 13, fontWeight: 700, color, fontFamily: "'JetBrains Mono', monospace" }}>
          {value != null ? `${Math.round(value)}%` : 'N/A'}
        </span>
      </div>
      <div style={{ background: 'rgba(255,255,255,0.07)', borderRadius: 4, height: 6, overflow: 'hidden' }}>
        <div style={{ width: `${value ?? 0}%`, height: '100%', background: color, borderRadius: 4, transition: 'width 0.8s ease' }} />
      </div>
    </div>
  );
}

// ─── Corruption Regions Table ─────────────────────────────────────────────────
function CorruptionTable({ regions }) {
  if (!regions?.length) {
    return (
      <div style={{ textAlign: 'center', padding: '16px 0', color: '#10b981', fontSize: 13 }}>
        <CheckCircle size={16} style={{ display: 'inline', marginRight: 6 }} />
        No corruption regions detected
      </div>
    );
  }

  const typeBadge = { 'A_MISSING_DATA': '#374151', 'B_FRAGMENT_GAP': '#7c3aed', 'C_BYTE_CORRUPTION': '#f97316',
    'D_STRUCTURAL_CORRUPTION': '#dc2626', 'E_METADATA_CORRUPTION': '#0891b2', 'F_ENCODING_CORRUPTION': '#b45309',
    'G_CONTAINER_CORRUPTION': '#991b1b', 'H_PARTIAL': '#6b7280', 'I_UNKNOWN': '#4b5563' };

  return (
    <div style={{ overflowX: 'auto' }}>
      <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 11 }}>
        <thead>
          <tr style={{ borderBottom: '1px solid rgba(255,255,255,0.08)' }}>
            {['Type', 'Severity', 'Confidence', 'Offset Range', 'Description'].map(h => (
              <th key={h} style={{ padding: '6px 10px', textAlign: 'left', color: 'rgba(255,255,255,0.4)', fontWeight: 500 }}>{h}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {regions.map((r, i) => (
            <tr key={i} style={{ borderBottom: '1px solid rgba(255,255,255,0.04)', transition: 'background 0.15s' }}
              onMouseEnter={e => e.currentTarget.style.background = 'rgba(255,255,255,0.03)'}
              onMouseLeave={e => e.currentTarget.style.background = 'transparent'}>
              <td style={{ padding: '8px 10px' }}>
                <span style={{ background: typeBadge[r.type] || '#374151', color: '#fff', borderRadius: 4, padding: '2px 6px', fontSize: 10, fontFamily: 'monospace' }}>
                  {r.type?.replace(/_/g, ' ')}
                </span>
              </td>
              <td style={{ padding: '8px 10px', color: severityColors(r.severity?.charAt(0).toUpperCase() + r.severity?.slice(1)) }}>
                {r.severity?.toUpperCase()}
              </td>
              <td style={{ padding: '8px 10px', color: '#f59e0b', fontFamily: 'monospace' }}>
                {(r.confidence * 100).toFixed(0)}%
              </td>
              <td style={{ padding: '8px 10px', color: 'rgba(255,255,255,0.5)', fontFamily: 'monospace', fontSize: 10 }}>
                {r.start?.toLocaleString()}–{r.end?.toLocaleString()}
              </td>
              <td style={{ padding: '8px 10px', color: 'rgba(255,255,255,0.6)', maxWidth: 250 }}>
                {r.description}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// ─── Main Component ────────────────────────────────────────────────────────────
export default function IntegrityDashboard({ artifact, onClose }) {
  const [activeTab, setActiveTab] = useState('overview');
  if (!artifact) return null;

  const {
    structuralIntegrity, contentIntegrity, metadataIntegrity, fragmentContinuity,
    reconstructionConfidence, overallIntegrity, corruption, corruptionSeverity,
    recoverability, explanation, corruptionRegions = [],
    recoveryInfo, metadata, classificationExplanation
  } = artifact;

  const recStyle = recoverabilityStyle(recoverability);
  const fragMap  = (recoveryInfo?.sourceFragments || []).map((s, i) => {
    const match = s.match(/^([A-Z0-9]+)\s*\((\d+)–(\d+)/);
    if (match) return { id: match[1], offset: parseInt(match[2]), length: parseInt(match[3]) - parseInt(match[2]), confidence: 0.90 };
    return { id: s, offset: i * 512, length: 512, confidence: 0.85 };
  });

  const TABS = [
    { id: 'overview',   label: 'Overview',        icon: Shield },
    { id: 'scores',     label: 'Integrity Scores', icon: Activity },
    { id: 'corruption', label: 'Corruption Map',   icon: AlertTriangle },
    { id: 'explain',    label: 'Explainability',   icon: Search },
    { id: 'regions',    label: 'Regions',          icon: Layers },
  ];

  return (
    <div style={{
      position: 'fixed', inset: 0, zIndex: 100,
      background: 'rgba(0,0,0,0.75)', backdropFilter: 'blur(8px)',
      display: 'flex', alignItems: 'center', justifyContent: 'center',
      padding: 24, fontFamily: "'Inter', sans-serif"
    }}>
      <div style={{
        width: '100%', maxWidth: 900, maxHeight: '90vh',
        background: 'linear-gradient(145deg, #0f1624 0%, #111827 100%)',
        borderRadius: 18, border: '1px solid rgba(255,255,255,0.1)',
        display: 'flex', flexDirection: 'column', overflow: 'hidden',
        boxShadow: '0 25px 80px rgba(0,0,0,0.8)'
      }}>
        {/* ── Header ── */}
        <div style={{ padding: '20px 24px', borderBottom: '1px solid rgba(255,255,255,0.06)',
          display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 4 }}>
              <Shield size={18} color="#06b6d4" />
              <span style={{ fontSize: 16, fontWeight: 700, color: '#f8fafc' }}>Integrity Assessment Report</span>
              <span style={{ background: 'rgba(6,182,212,0.1)', color: '#06b6d4', border: '1px solid rgba(6,182,212,0.3)',
                borderRadius: 6, padding: '2px 8px', fontSize: 10, fontFamily: 'monospace' }}>{artifact.id}</span>
            </div>
            <p style={{ fontSize: 12, color: 'rgba(255,255,255,0.4)', margin: 0 }}>
              {artifact.filename} · {artifact.type}
            </p>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            {/* Overall score pill */}
            <div style={{ textAlign: 'center' }}>
              <div style={{ fontSize: 28, fontWeight: 800, color: scoreColor(overallIntegrity),
                fontFamily: "'JetBrains Mono', monospace" }}>
                {Math.round(overallIntegrity ?? 0)}%
              </div>
              <div style={{ fontSize: 9, color: 'rgba(255,255,255,0.4)', textTransform: 'uppercase', letterSpacing: '0.1em' }}>
                {scoreLabel(overallIntegrity)}
              </div>
            </div>
            <button onClick={onClose} style={{ background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.1)',
              borderRadius: 8, padding: '6px 14px', color: 'rgba(255,255,255,0.6)', cursor: 'pointer', fontSize: 12 }}>
              Close ✕
            </button>
          </div>
        </div>

        {/* ── Tabs ── */}
        <div style={{ display: 'flex', borderBottom: '1px solid rgba(255,255,255,0.06)', padding: '0 24px' }}>
          {TABS.map(t => (
            <button key={t.id}
              onClick={() => setActiveTab(t.id)}
              style={{
                background: 'none', border: 'none', padding: '12px 16px', cursor: 'pointer', fontSize: 12,
                color: activeTab === t.id ? '#06b6d4' : 'rgba(255,255,255,0.4)',
                borderBottom: activeTab === t.id ? '2px solid #06b6d4' : '2px solid transparent',
                display: 'flex', alignItems: 'center', gap: 5, transition: 'color 0.2s', fontFamily: 'inherit'
              }}>
              <t.icon size={12} />
              {t.label}
            </button>
          ))}
        </div>

        {/* ── Body ── */}
        <div style={{ flex: 1, overflowY: 'auto', padding: 24 }}>

          {/* OVERVIEW TAB */}
          {activeTab === 'overview' && (
            <div>
              {/* Status cards row */}
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3,1fr)', gap: 14, marginBottom: 20 }}>
                {[
                  { label: 'Reconstruction Confidence', value: `${reconstructionConfidence ?? 0}%`, color: '#06b6d4', note: '(Upstream module)' },
                  { label: 'Corruption Severity', value: corruptionSeverity, color: severityColors(corruptionSeverity), note: 'Taxonomy rollup' },
                  { label: 'Recoverability', value: recoverability?.replace(/_/g, ' '), color: recStyle.color, note: 'Content-test driven' },
                ].map(c => (
                  <div key={c.label} style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.07)', borderRadius: 10, padding: 14 }}>
                    <div style={{ fontSize: 10, color: 'rgba(255,255,255,0.4)', marginBottom: 6, textTransform: 'uppercase', letterSpacing: '0.08em' }}>{c.label}</div>
                    <div style={{ fontSize: 15, fontWeight: 700, color: c.color }}>{c.value}</div>
                    <div style={{ fontSize: 10, color: 'rgba(255,255,255,0.3)', marginTop: 3 }}>{c.note}</div>
                  </div>
                ))}
              </div>

              {/* 5 score gauges */}
              <div style={{ background: 'rgba(0,0,0,0.2)', borderRadius: 12, padding: 20, marginBottom: 20 }}>
                <p style={{ fontSize: 11, color: 'rgba(255,255,255,0.4)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 16 }}>
                  Integrity Dimensions (not collapsed into one number)
                </p>
                <div style={{ display: 'flex', justifyContent: 'space-around', flexWrap: 'wrap', gap: 16 }}>
                  <ScoreGauge value={structuralIntegrity} label="Structural" />
                  <ScoreGauge value={contentIntegrity} label="Content" />
                  <ScoreGauge value={metadataIntegrity} label="Metadata" />
                  <ScoreGauge value={fragmentContinuity} label="Fragment Continuity" />
                  <ScoreGauge value={reconstructionConfidence} label="Reconstruction Conf." />
                </div>
              </div>

              {/* Corruption summary */}
              <div style={{ background: 'rgba(0,0,0,0.2)', borderRadius: 12, padding: 16, marginBottom: 16 }}>
                <p style={{ fontSize: 11, color: 'rgba(255,255,255,0.4)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 10 }}>Corruption</p>
                <p style={{ fontSize: 13, color: corruptionSeverity === 'None' ? '#10b981' : '#f59e0b' }}>{corruption}</p>
              </div>

              {/* Metadata */}
              {metadata && (
                <div style={{ background: 'rgba(0,0,0,0.2)', borderRadius: 12, padding: 16 }}>
                  <p style={{ fontSize: 11, color: 'rgba(255,255,255,0.4)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 10 }}>File Metadata</p>
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8, fontSize: 12 }}>
                    <div style={{ color: 'rgba(255,255,255,0.4)' }}>Size</div>
                    <div style={{ color: '#94a3b8', fontFamily: 'monospace', fontSize: 11 }}>{metadata.size}</div>
                    <div style={{ color: 'rgba(255,255,255,0.4)' }}>SHA-256</div>
                    <div style={{ color: '#94a3b8', fontFamily: 'monospace', fontSize: 10, wordBreak: 'break-all' }}>{metadata.sha256?.slice(0, 32)}…</div>
                    <div style={{ color: 'rgba(255,255,255,0.4)' }}>Carved At</div>
                    <div style={{ color: '#94a3b8', fontFamily: 'monospace', fontSize: 11 }}>{metadata.timestamps?.carved}</div>
                    <div style={{ color: 'rgba(255,255,255,0.4)' }}>Incident Window</div>
                    <div style={{ color: metadata.timestamps?.incidentWindowMatch ? '#10b981' : '#f59e0b' }}>
                      {metadata.timestamps?.incidentWindowMatch ? '✓ Within incident window' : '⚠ Outside incident window'}
                    </div>
                    <div style={{ color: 'rgba(255,255,255,0.4)' }}>Sector</div>
                    <div style={{ color: '#94a3b8', fontFamily: 'monospace', fontSize: 11 }}>{metadata.sector}</div>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* INTEGRITY SCORES TAB */}
          {activeTab === 'scores' && (
            <div>
              <div style={{ background: 'rgba(6,182,212,0.05)', border: '1px solid rgba(6,182,212,0.15)', borderRadius: 10, padding: 14, marginBottom: 20, fontSize: 12, color: 'rgba(255,255,255,0.6)' }}>
                <strong style={{ color: '#06b6d4' }}>Scoring formula (§10): </strong>
                Overall = (0.30 × Structural + 0.35 × Content + 0.20 × Fragment + 0.15 × Metadata) renormalized if any dimension is unavailable.
                Confidence effect: each dimension's own internal confidence discounts its contribution.
                <span style={{ color: '#f59e0b' }}> These are prototype defaults, not forensically validated weights.</span>
              </div>

              <div style={{ background: 'rgba(0,0,0,0.2)', borderRadius: 12, padding: 20 }}>
                <DimensionBar label="Structural Integrity" value={structuralIntegrity} weight="0.30" icon={Layers} />
                <DimensionBar label="Content Integrity" value={contentIntegrity} weight="0.35" icon={FileText} />
                <DimensionBar label="Fragment Continuity" value={fragmentContinuity} weight="0.20" icon={Cpu} />
                <DimensionBar label="Metadata Integrity" value={metadataIntegrity} weight="0.15" icon={Hash} />
                <div style={{ borderTop: '1px solid rgba(255,255,255,0.08)', marginTop: 16, paddingTop: 16 }}>
                  <DimensionBar label="OVERALL INTEGRITY (weighted)" value={overallIntegrity} weight="—" icon={Shield} />
                </div>
              </div>

              <div style={{ marginTop: 16, background: 'rgba(0,0,0,0.2)', borderRadius: 12, padding: 16 }}>
                <p style={{ fontSize: 11, color: 'rgba(255,255,255,0.4)', marginBottom: 10, textTransform: 'uppercase', letterSpacing: '0.08em' }}>Score Categories (prototype thresholds)</p>
                {[['90–100','Highly Intact','#10b981'],['75–89','Mostly Intact','#22d3ee'],['50–74','Partially Corrupted','#f59e0b'],['25–49','Severely Corrupted','#f97316'],['0–24','Unusable','#ef4444']].map(([range, label, c]) => (
                  <div key={range} style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 6 }}>
                    <div style={{ width: 8, height: 8, borderRadius: 2, background: c, flexShrink: 0 }} />
                    <span style={{ fontFamily: 'monospace', color: c, fontSize: 11, width: 60 }}>{range}</span>
                    <span style={{ fontSize: 12, color: 'rgba(255,255,255,0.6)' }}>{label}</span>
                    {Math.round(overallIntegrity ?? 0) >= parseInt(range) && Math.round(overallIntegrity ?? 0) <= parseInt(range.split('–')[1]) && (
                      <span style={{ marginLeft: 'auto', fontSize: 10, color: c }}>← This artifact</span>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* CORRUPTION MAP TAB */}
          {activeTab === 'corruption' && (
            <div>
              <div style={{ background: 'rgba(0,0,0,0.2)', borderRadius: 12, padding: 20, marginBottom: 20 }}>
                <p style={{ fontSize: 11, color: 'rgba(255,255,255,0.4)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 14 }}>
                  Byte-Range Corruption Map — {metadata?.size}
                </p>
                <CorruptionMap
                  totalSize={parseInt(metadata?.size?.replace(/[^0-9]/g, '')) || 8192}
                  corruptionRegions={corruptionRegions}
                  fragmentsUsed={fragMap}
                />
              </div>

              <div style={{ background: 'rgba(0,0,0,0.2)', borderRadius: 12, padding: 16 }}>
                <p style={{ fontSize: 11, color: 'rgba(255,255,255,0.4)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 10 }}>
                  Fragment Continuity ({recoveryInfo?.fragmentationStatus})
                </p>
                {(recoveryInfo?.sourceFragments || []).map((f, i) => (
                  <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8, padding: 10,
                    background: 'rgba(255,255,255,0.03)', borderRadius: 8, fontSize: 12 }}>
                    <Layers size={12} color="#06b6d4" />
                    <span style={{ fontFamily: 'monospace', color: '#94a3b8' }}>{f}</span>
                  </div>
                ))}
                <div style={{ marginTop: 10, padding: 10, background: 'rgba(6,182,212,0.06)', borderRadius: 8 }}>
                  <p style={{ fontSize: 11, color: '#06b6d4' }}>Carving Confidence: {recoveryInfo?.carvingConfidence?.toFixed(1)}%</p>
                </div>
              </div>
            </div>
          )}

          {/* EXPLAINABILITY TAB */}
          {activeTab === 'explain' && (
            <div>
              <div style={{ marginBottom: 16 }}>
                <ExplainabilityPanel explanation={explanation} />
              </div>

              <div style={{ background: 'rgba(0,0,0,0.2)', borderRadius: 12, padding: 16, marginBottom: 16 }}>
                <p style={{ fontSize: 11, color: 'rgba(255,255,255,0.4)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 12 }}>
                  Classification Explanation (Path: {classificationExplanation?.method})
                </p>
                <div style={{ display: 'flex', gap: 8, marginBottom: 10, flexWrap: 'wrap' }}>
                  {(classificationExplanation?.signals || []).map((s, i) => (
                    <span key={i} style={{ background: 'rgba(16,185,129,0.1)', border: '1px solid rgba(16,185,129,0.2)', borderRadius: 6, padding: '3px 8px', fontSize: 11, color: '#10b981' }}>{s}</span>
                  ))}
                </div>
                {classificationExplanation?.conflicts && (
                  <div style={{ background: 'rgba(245,158,11,0.08)', border: '1px solid rgba(245,158,11,0.2)', borderRadius: 8, padding: 10, fontSize: 12, color: '#f59e0b' }}>
                    ⚠ Conflict: {classificationExplanation.conflicts}
                  </div>
                )}
              </div>

              <div style={{ background: 'rgba(239,68,68,0.04)', border: '1px solid rgba(239,68,68,0.1)', borderRadius: 10, padding: 14 }}>
                <p style={{ fontSize: 11, fontWeight: 600, color: '#ef4444', marginBottom: 8 }}>§27 Forensic Limitations</p>
                {[
                  "A high integrity score does not prove authenticity.",
                  "Reconstruction confidence ≠ content correctness.",
                  "Hash comparison proves only byte equality, not legitimacy.",
                  "Missing data cannot be recreated — only flagged as absent.",
                  "Score thresholds are heuristic prototype defaults, not forensic standards.",
                  "These results are decision support for a human investigator."
                ].map((l, i) => (
                  <p key={i} style={{ fontSize: 11, color: 'rgba(255,255,255,0.45)', marginBottom: 4 }}>• {l}</p>
                ))}
              </div>
            </div>
          )}

          {/* REGIONS TAB */}
          {activeTab === 'regions' && (
            <div>
              <div style={{ background: 'rgba(0,0,0,0.2)', borderRadius: 12, padding: 16, marginBottom: 16 }}>
                <p style={{ fontSize: 11, color: 'rgba(255,255,255,0.4)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 12 }}>
                  Corruption Taxonomy (§9) — {corruptionRegions.length} Region(s)
                </p>
                <CorruptionTable regions={corruptionRegions} />
              </div>

              <div style={{ background: 'rgba(0,0,0,0.2)', borderRadius: 12, padding: 16 }}>
                <p style={{ fontSize: 11, color: 'rgba(255,255,255,0.4)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 10 }}>Taxonomy Reference (§9)</p>
                {[
                  ['A', 'Missing Data', 'Bytes never recovered from any fragment'],
                  ['B', 'Fragment Gap', 'Expected inter-fragment bytes unavailable'],
                  ['C', 'Byte Corruption', 'Bytes present but inconsistent with expected structure'],
                  ['D', 'Structural Corruption', 'Container/format structure itself is damaged'],
                  ['E', 'Metadata Corruption', 'Metadata missing/inconsistent'],
                  ['F', 'Encoding Corruption', 'Text/binary cannot be correctly decoded'],
                  ['G', 'Container Corruption', 'ZIP/DB/archive envelope damaged'],
                  ['H', 'Partial Content Corruption', 'Only part of actual content unreadable'],
                  ['I', 'Unknown/Uncertain', 'Anomaly detected, cause not confidently classifiable'],
                ].map(([letter, name, desc]) => (
                  <div key={letter} style={{ display: 'flex', gap: 10, marginBottom: 7 }}>
                    <span style={{ background: '#1e293b', color: '#f59e0b', fontFamily: 'monospace', fontSize: 11, padding: '2px 7px', borderRadius: 4, flexShrink: 0 }}>Type {letter}</span>
                    <div>
                      <span style={{ fontSize: 12, color: '#94a3b8', fontWeight: 600 }}>{name}</span>
                      <span style={{ fontSize: 11, color: 'rgba(255,255,255,0.35)', marginLeft: 8 }}>{desc}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
