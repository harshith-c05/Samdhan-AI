/**
 * SecurityScanModal.jsx
 * Feature 6 — Malicious File Detection Security Report Viewer
 *
 * Shows the full security scan verdict with signal breakdown.
 * Called when investigator clicks "VIEW SECURITY REPORT" on a BLOCKED artifact.
 * Also shown as a warning panel on SUSPICIOUS artifacts (non-blocking).
 */

import React from 'react';
import { ShieldAlert, ShieldCheck, AlertTriangle, X, Zap, Hash, Activity, FileCode, Lock } from 'lucide-react';
import { SECURITY_VERDICTS } from '../engine/securityScanEngine';

// ─── Verdict Config ────────────────────────────────────────────────────────────
const VERDICT_CONFIG = {
  [SECURITY_VERDICTS.MALICIOUS]: {
    icon: ShieldAlert,
    label: 'MALICIOUS',
    bg:    'bg-red-950/60',
    border:'border-red-500',
    text:  'text-red-400',
    glow:  'shadow-[0_0_30px_rgba(239,68,68,0.35)]',
    badge: 'bg-red-900/80 text-red-300 border border-red-500/60',
    description: 'This artifact has been flagged as MALICIOUS. No restore action is permitted.',
  },
  [SECURITY_VERDICTS.SUSPICIOUS]: {
    icon: AlertTriangle,
    label: 'SUSPICIOUS',
    bg:    'bg-amber-950/50',
    border:'border-amber-500',
    text:  'text-amber-400',
    glow:  'shadow-[0_0_20px_rgba(245,158,11,0.25)]',
    badge: 'bg-amber-900/80 text-amber-300 border border-amber-500/60',
    description: 'One or more weak indicators were detected. Restore is allowed but proceed with caution.',
  },
  [SECURITY_VERDICTS.CLEAN]: {
    icon: ShieldCheck,
    label: 'CLEAN',
    bg:    'bg-emerald-950/40',
    border:'border-emerald-500',
    text:  'text-emerald-400',
    glow:  'shadow-[0_0_20px_rgba(52,211,153,0.2)]',
    badge: 'bg-emerald-900/80 text-emerald-300 border border-emerald-500/60',
    description: 'No security signals detected. File cleared for restore.',
  },
};

const REASON_ICONS = {
  extension_signature_mismatch: FileCode,
  known_hash_match:             Hash,
  high_entropy_packed:          Activity,
  embedded_macro:               Zap,
  embedded_javascript_pdf:      Zap,
  executable_in_archive:        Lock,
  classification_conflict:      AlertTriangle,
};

const SIGNAL_SEVERITY = {
  extension_signature_mismatch: 'STRONG',
  known_hash_match:             'STRONG',
  high_entropy_packed:          'MEDIUM',
  embedded_macro:               'MEDIUM',
  embedded_javascript_pdf:      'STRONG',
  executable_in_archive:        'STRONG',
  classification_conflict:      'MEDIUM',
};

function SignalRow({ reason }) {
  const key = reason.key || '';
  const IconComp = REASON_ICONS[key] || AlertTriangle;
  const severity = SIGNAL_SEVERITY[key] || 'MEDIUM';
  const isStrong = severity === 'STRONG';

  return (
    <div className={`flex items-start gap-3 p-3 rounded-lg border ${
      isStrong
        ? 'bg-red-950/40 border-red-800/60'
        : 'bg-amber-950/30 border-amber-800/40'
    }`}>
      <IconComp className={`w-4 h-4 mt-0.5 flex-shrink-0 ${isStrong ? 'text-red-400' : 'text-amber-400'}`} />
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2">
          <span className={`text-[10px] font-mono font-bold uppercase tracking-wider px-1.5 py-0.5 rounded ${
            isStrong ? 'bg-red-900/60 text-red-300' : 'bg-amber-900/60 text-amber-300'
          }`}>
            {severity}
          </span>
          <span className="text-xs font-mono text-zinc-400">{key}</span>
        </div>
        <p className="text-sm text-zinc-200 mt-1 font-mono">{reason.text}</p>
      </div>
    </div>
  );
}

export default function SecurityScanModal({ artifact, scanResult, onClose }) {
  if (!artifact || !scanResult) return null;

  const verdict = scanResult.verdict || SECURITY_VERDICTS.CLEAN;
  const cfg = VERDICT_CONFIG[verdict] || VERDICT_CONFIG[SECURITY_VERDICTS.CLEAN];
  const VerdictIcon = cfg.icon;
  const reasons = scanResult.reasons || [];
  const isMalicious = verdict === SECURITY_VERDICTS.MALICIOUS;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-fadeIn">
      <div className={`relative w-full max-w-2xl rounded-2xl border ${cfg.border} ${cfg.bg} ${cfg.glow} overflow-hidden`}>

        {/* Header */}
        <div className={`flex items-center justify-between p-5 border-b ${cfg.border}/40`}>
          <div className="flex items-center gap-3">
            <div className={`p-2 rounded-xl ${cfg.bg} border ${cfg.border}/60`}>
              <VerdictIcon className={`w-6 h-6 ${cfg.text}`} />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-lg font-bold font-mono text-white">Security Report</h2>
                <span className={`text-[11px] font-mono font-bold uppercase tracking-widest px-2 py-0.5 rounded ${cfg.badge}`}>
                  {cfg.label}
                </span>
              </div>
              <p className="text-xs text-zinc-400 font-mono mt-0.5">{artifact.filename}</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg hover:bg-zinc-800 text-zinc-400 hover:text-white transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Body */}
        <div className="p-5 space-y-5 max-h-[70vh] overflow-y-auto custom-scroll">

          {/* Artifact Summary */}
          <div className="grid grid-cols-2 gap-3">
            {[
              ['Filename',       artifact.filename],
              ['Declared Type',  scanResult.declared_type || artifact.type || '—'],
              ['Detected Header',scanResult.detected_header || '—'],
              ['SHA-256',        (scanResult.sha256 || '—').slice(0, 24) + '…'],
              ['Entropy',        scanResult.entropy_whole_file != null
                                   ? `${Number(scanResult.entropy_whole_file).toFixed(2)} bits/byte`
                                   : '—'],
              ['Hash Blocklist', scanResult.hash_blocklist_match ? '✗ Match Found' : '✓ No Match'],
            ].map(([label, val]) => (
              <div key={label} className="p-3 rounded-lg bg-zinc-900/70 border border-zinc-800">
                <div className="text-[10px] font-mono text-zinc-500 uppercase tracking-wider">{label}</div>
                <div className={`text-sm font-mono mt-0.5 ${
                  val?.toString().startsWith('✗') ? 'text-red-400' :
                  val?.toString().startsWith('✓') ? 'text-emerald-400' :
                  'text-zinc-200'
                }`}>{val}</div>
              </div>
            ))}
          </div>

          {/* Verdict Banner */}
          <div className={`p-4 rounded-xl border ${cfg.border} ${cfg.bg} flex items-start gap-3`}>
            <VerdictIcon className={`w-5 h-5 mt-0.5 ${cfg.text} flex-shrink-0`} />
            <div>
              <div className={`text-sm font-bold font-mono ${cfg.text}`}>
                Security Scan: {verdict}
              </div>
              <p className="text-xs text-zinc-300 mt-1">{cfg.description}</p>
            </div>
          </div>

          {/* Signal Breakdown */}
          {reasons.length > 0 && (
            <div>
              <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-zinc-400 mb-2">
                Detection Signals ({reasons.length})
              </h3>
              <div className="space-y-2">
                {reasons.map((r, i) => (
                  <SignalRow key={i} reason={r} />
                ))}
              </div>
            </div>
          )}

          {/* Decision override notice */}
          {isMalicious && (
            <div className="p-4 rounded-xl bg-red-950/50 border border-red-700 flex items-start gap-3">
              <Lock className="w-4 h-4 text-red-400 mt-0.5 flex-shrink-0" />
              <div className="text-xs font-mono text-red-300 leading-relaxed">
                <strong className="text-red-200 block mb-1">DECISION: BLOCKED — SECURITY RISK</strong>
                No restore action is offered. The only available action is this security report.
                A MALICIOUS verdict overrides fragment completeness and integrity scores.
              </div>
            </div>
          )}

          {/* Disclaimer */}
          <div className="p-3 rounded-lg bg-zinc-900/50 border border-zinc-800 text-[11px] font-mono text-zinc-500 leading-relaxed">
            <strong className="text-zinc-400">DEMO NOTE:</strong> The hash blocklist is simulated for demonstration purposes.
            A production deployment must integrate a real threat-intel API (e.g., VirusTotal, MISP, or an internal SIEM feed).
            Verdicts shown here are NOT admissible as legal evidence without external verification.
          </div>
        </div>

        {/* Footer */}
        <div className={`flex items-center justify-between p-4 border-t ${cfg.border}/30 bg-zinc-950/50`}>
          <span className="text-[11px] font-mono text-zinc-500">
            Scanned: {scanResult.scanned_at ? new Date(scanResult.scanned_at).toLocaleString() : new Date().toLocaleString()}
          </span>
          <button
            onClick={onClose}
            className="px-4 py-2 rounded-lg bg-zinc-800 hover:bg-zinc-700 text-sm font-mono text-white transition-colors"
          >
            Close Report
          </button>
        </div>
      </div>
    </div>
  );
}
