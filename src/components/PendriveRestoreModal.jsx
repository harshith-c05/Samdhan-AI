/**
 * PendriveRestoreModal.jsx
 * Feature 5 — Pendrive / USB Restore
 *
 * Lets the investigator:
 *   1. Select a target USB/removable drive from the detected list
 *   2. Confirm the restore action
 *   3. View real-time write progress simulation
 *   4. See the post-write hash verification result
 *   5. View the audit log entry that was created
 *
 * On hash mismatch: hard failure — file is never left in a silently-corrupted state.
 */

import React, { useState, useEffect } from 'react';
import {
  Usb, X, CheckCircle2, XCircle, Loader2, HardDrive,
  ShieldCheck, Hash, AlertTriangle, RefreshCw, Download
} from 'lucide-react';
import { listUSBDevices, restoreToPendrive } from '../engine/securityScanEngine';

// ─── Stage constants ───────────────────────────────────────────────────────────
const STAGES = {
  SELECT:    'SELECT',     // Choose target drive
  CONFIRM:   'CONFIRM',   // Show pre-write hash, confirm
  WRITING:   'WRITING',   // In-progress animation
  VERIFYING: 'VERIFYING', // Post-write hash check animation
  SUCCESS:   'SUCCESS',   // Hash match ✓
  FAIL:      'FAIL',      // Hash mismatch ✗
};

// ─── Helper: short hash display ───────────────────────────────────────────────
function shortHash(h) {
  if (!h) return '—';
  return `${h.slice(0, 8)}…${h.slice(-8)}`;
}

export default function PendriveRestoreModal({ artifact, onClose, onAddAuditLog }) {
  const [stage, setStage]           = useState(STAGES.SELECT);
  const [devices, setDevices]       = useState([]);
  const [loadingDevices, setLoadingDevices] = useState(true);
  const [selectedDevice, setSelectedDevice] = useState(null);
  const [result, setResult]         = useState(null);
  const [progress, setProgress]     = useState(0);

  // ── Load USB devices on mount ────────────────────────────────────────────────
  useEffect(() => {
    let cancelled = false;
    setLoadingDevices(true);
    listUSBDevices().then(devs => {
      if (!cancelled) {
        setDevices(devs);
        setLoadingDevices(false);
      }
    });
    return () => { cancelled = true; };
  }, []);

  // ── Write + Verify simulation ────────────────────────────────────────────────
  const handleConfirm = async () => {
    if (!selectedDevice) return;
    setStage(STAGES.WRITING);
    setProgress(0);

    // Simulate write progress
    const interval = setInterval(() => {
      setProgress(p => {
        if (p >= 95) {
          clearInterval(interval);
          return 95;
        }
        return p + Math.round(5 + Math.random() * 10);
      });
    }, 160);

    // Call backend/demo restore
    const res = await restoreToPendrive(artifact, selectedDevice.letter);

    clearInterval(interval);
    setProgress(100);
    setStage(STAGES.VERIFYING);

    // Brief verification pause
    await new Promise(r => setTimeout(r, 1200));

    setResult(res);
    setStage(res.match ? STAGES.SUCCESS : STAGES.FAIL);

    // Emit audit log entry
    if (onAddAuditLog) {
      onAddAuditLog({
        id:        `AUDIT-USB-${Date.now().toString().slice(-4)}`,
        timestamp: res.timestamp || new Date().toISOString(),
        stage:     'Pendrive Restore (Feature 5)',
        artifact:  `${artifact.filename} (${artifact.id})`,
        inputHash: res.pre_write_hash || '—',
        output:    res.match
          ? `RESTORED to ${selectedDevice.label} — post-write hash match ✓`
          : `HASH MISMATCH on ${selectedDevice.label} — file deleted ✗`,
        actor:     'Investigator',
        modelOrRule: 'SHA-256 Pre/Post-Write Verification',
        status:    res.match ? 'VERIFIED' : 'FAILED',
      });
    }
  };

  // ── Render helpers ────────────────────────────────────────────────────────────
  function renderSelect() {
    return (
      <div className="space-y-4">
        <p className="text-sm text-zinc-400 font-mono">
          Select the target USB/removable drive. The file will be written to a
          <code className="text-cyber-neon mx-1">SAMDHAN_RECOVERED\</code> folder on the drive.
          A post-write SHA-256 verification will run automatically.
        </p>

        {loadingDevices ? (
          <div className="flex items-center gap-2 text-zinc-400 text-sm font-mono py-6 justify-center">
            <Loader2 className="w-4 h-4 animate-spin" />
            <span>Detecting removable drives…</span>
          </div>
        ) : devices.length === 0 ? (
          <div className="p-4 rounded-xl bg-zinc-900 border border-zinc-700 text-center text-zinc-400 text-sm font-mono">
            No removable drives detected. Insert a USB drive and try again.
          </div>
        ) : (
          <div className="space-y-2">
            {devices.map(dev => (
              <button
                key={dev.letter}
                onClick={() => setSelectedDevice(dev)}
                className={`w-full flex items-center gap-3 p-4 rounded-xl border text-left transition-all ${
                  selectedDevice?.letter === dev.letter
                    ? 'bg-cyber-500/15 border-cyber-500 shadow-[0_0_12px_rgba(0,255,102,0.2)]'
                    : 'bg-zinc-900/70 border-zinc-700 hover:border-cyber-500/50 hover:bg-zinc-800/60'
                }`}
              >
                <div className={`p-2 rounded-lg ${
                  selectedDevice?.letter === dev.letter ? 'bg-cyber-500/20' : 'bg-zinc-800'
                }`}>
                  <Usb className={`w-5 h-5 ${
                    selectedDevice?.letter === dev.letter ? 'text-cyber-neon' : 'text-zinc-400'
                  }`} />
                </div>
                <div className="flex-1">
                  <div className="text-sm font-mono font-semibold text-white">{dev.label}</div>
                  <div className="text-xs font-mono text-zinc-500">{dev.letter} · {dev.type}</div>
                </div>
                {selectedDevice?.letter === dev.letter && (
                  <CheckCircle2 className="w-5 h-5 text-cyber-neon" />
                )}
              </button>
            ))}
          </div>
        )}

        {/* Pendrive as Input Source note */}
        {artifact.source_type === 'usb' && (
          <div className="p-3 rounded-lg bg-blue-950/40 border border-blue-700/50 flex items-start gap-2">
            <HardDrive className="w-4 h-4 text-blue-400 mt-0.5 flex-shrink-0" />
            <div className="text-xs font-mono text-blue-300">
              <strong className="text-blue-200">USB Source:</strong> This artifact was originally recovered
              from <span className="text-white">{artifact.device_label || 'a USB drive'}</span>.
              You are now writing it back to a pendrive.
            </div>
          </div>
        )}

        <div className="flex justify-end gap-3 pt-2">
          <button onClick={onClose} className="px-4 py-2 rounded-lg bg-zinc-800 hover:bg-zinc-700 text-sm font-mono text-zinc-300 transition-colors">
            Cancel
          </button>
          <button
            onClick={() => setStage(STAGES.CONFIRM)}
            disabled={!selectedDevice}
            className="px-5 py-2 rounded-lg bg-cyber-500/20 hover:bg-cyber-500/30 border border-cyber-500/60 text-cyber-neon text-sm font-mono font-bold transition-all disabled:opacity-40 disabled:cursor-not-allowed"
          >
            Continue →
          </button>
        </div>
      </div>
    );
  }

  function renderConfirm() {
    return (
      <div className="space-y-4">
        <div className="p-4 rounded-xl bg-zinc-900 border border-zinc-700 space-y-3">
          {[
            ['File',          artifact.filename],
            ['Target Drive',  `${selectedDevice?.label} (${selectedDevice?.letter})`],
            ['Destination',   `${selectedDevice?.letter}\\SAMDHAN_RECOVERED\\${artifact.filename}`],
            ['Pre-Write Hash', shortHash(artifact.metadata?.sha256 || 'a1b2c3d4…')],
            ['Verification',  'SHA-256 post-write re-hash (automatic)'],
          ].map(([label, val]) => (
            <div key={label} className="flex justify-between items-center">
              <span className="text-xs font-mono text-zinc-500">{label}</span>
              <span className="text-xs font-mono text-zinc-200 text-right">{val}</span>
            </div>
          ))}
        </div>

        <div className="p-3 rounded-lg bg-amber-950/40 border border-amber-700/50 text-xs font-mono text-amber-300">
          <AlertTriangle className="w-3.5 h-3.5 inline mr-1.5 -mt-0.5" />
          If the post-write hash does not match, the file will be <strong>automatically deleted</strong> from the drive to prevent silent corruption.
        </div>

        <div className="flex justify-end gap-3 pt-1">
          <button onClick={() => setStage(STAGES.SELECT)} className="px-4 py-2 rounded-lg bg-zinc-800 hover:bg-zinc-700 text-sm font-mono text-zinc-300 transition-colors">
            ← Back
          </button>
          <button
            onClick={handleConfirm}
            className="px-5 py-2 rounded-lg bg-emerald-600/30 hover:bg-emerald-600/50 border border-emerald-500/70 text-emerald-300 text-sm font-mono font-bold transition-all"
          >
            Confirm Restore
          </button>
        </div>
      </div>
    );
  }

  function renderWriting() {
    return (
      <div className="space-y-5 py-4 text-center">
        <Loader2 className="w-10 h-10 text-cyber-neon mx-auto animate-spin" />
        <div>
          <div className="text-sm font-mono text-white font-bold">Writing to Pendrive…</div>
          <div className="text-xs font-mono text-zinc-400 mt-1">
            {artifact.filename} → {selectedDevice?.letter}\SAMDHAN_RECOVERED\
          </div>
        </div>
        <div className="mx-4">
          <div className="h-2 rounded-full bg-zinc-800 overflow-hidden">
            <div
              className="h-full bg-cyber-neon rounded-full transition-all duration-150"
              style={{ width: `${progress}%` }}
            />
          </div>
          <div className="text-right text-xs font-mono text-zinc-400 mt-1">{progress}%</div>
        </div>
      </div>
    );
  }

  function renderVerifying() {
    return (
      <div className="space-y-4 py-4 text-center">
        <Hash className="w-10 h-10 text-sky-400 mx-auto animate-pulse" />
        <div>
          <div className="text-sm font-mono text-white font-bold">Verifying Write Integrity…</div>
          <div className="text-xs font-mono text-zinc-400 mt-1">SHA-256 post-write re-hash</div>
        </div>
      </div>
    );
  }

  function renderSuccess() {
    return (
      <div className="space-y-4">
        <div className="p-5 rounded-xl bg-emerald-950/50 border border-emerald-500 shadow-[0_0_20px_rgba(52,211,153,0.2)] text-center space-y-3">
          <CheckCircle2 className="w-12 h-12 text-emerald-400 mx-auto" />
          <div className="text-base font-bold font-mono text-white">Restored to Pendrive</div>
          <div className="text-xs font-mono text-emerald-400 font-semibold">Post-write hash verification: MATCH ✓</div>
        </div>

        <div className="p-4 rounded-xl bg-zinc-900 border border-zinc-700 space-y-3">
          {[
            ['Target',          `${selectedDevice?.label} (${selectedDevice?.letter})`],
            ['File',            result?.filename],
            ['Pre-write Hash',  shortHash(result?.pre_write_hash)],
            ['Post-write Hash', shortHash(result?.post_write_hash)],
            ['Match',           '✓ Identical'],
            ['Timestamp',       result?.timestamp ? new Date(result.timestamp).toLocaleString() : '—'],
          ].map(([label, val]) => (
            <div key={label} className="flex justify-between items-center">
              <span className="text-xs font-mono text-zinc-500">{label}</span>
              <span className={`text-xs font-mono ${val === '✓ Identical' ? 'text-emerald-400' : 'text-zinc-200'}`}>{val}</span>
            </div>
          ))}
        </div>

        {result?.note && (
          <div className="text-[11px] font-mono text-zinc-500 px-1">{result.note}</div>
        )}

        <div className="flex justify-end">
          <button onClick={onClose} className="px-5 py-2 rounded-lg bg-emerald-600/30 border border-emerald-500/70 text-emerald-300 text-sm font-mono font-bold hover:bg-emerald-600/50 transition-all">
            Done
          </button>
        </div>
      </div>
    );
  }

  function renderFail() {
    return (
      <div className="space-y-4">
        <div className="p-5 rounded-xl bg-red-950/50 border border-red-500 shadow-[0_0_20px_rgba(239,68,68,0.2)] text-center space-y-3">
          <XCircle className="w-12 h-12 text-red-400 mx-auto" />
          <div className="text-base font-bold font-mono text-white">Post-write Hash Mismatch</div>
          <div className="text-xs font-mono text-red-400 font-semibold">File automatically deleted from target drive ✗</div>
        </div>

        <div className="p-4 rounded-xl bg-zinc-900 border border-zinc-700 space-y-3">
          {[
            ['Expected Hash', shortHash(result?.pre_write_hash)],
            ['Actual Hash',   shortHash(result?.post_write_hash)],
            ['File Deleted',  '✗ Yes (automatic)'],
          ].map(([label, val]) => (
            <div key={label} className="flex justify-between items-center">
              <span className="text-xs font-mono text-zinc-500">{label}</span>
              <span className={`text-xs font-mono ${val.startsWith('✗') ? 'text-red-400' : 'text-zinc-200'}`}>{val}</span>
            </div>
          ))}
        </div>

        <div className="flex justify-end gap-3">
          <button
            onClick={() => { setStage(STAGES.SELECT); setResult(null); setProgress(0); }}
            className="px-4 py-2 rounded-lg bg-zinc-800 hover:bg-zinc-700 text-sm font-mono text-zinc-300 transition-colors flex items-center gap-1.5"
          >
            <RefreshCw className="w-3.5 h-3.5" /> Try Again
          </button>
          <button onClick={onClose} className="px-4 py-2 rounded-lg bg-red-900/40 border border-red-700/60 text-red-300 text-sm font-mono hover:bg-red-900/60 transition-colors">
            Close
          </button>
        </div>
      </div>
    );
  }

  const STAGE_CONTENT = {
    [STAGES.SELECT]:    renderSelect,
    [STAGES.CONFIRM]:   renderConfirm,
    [STAGES.WRITING]:   renderWriting,
    [STAGES.VERIFYING]: renderVerifying,
    [STAGES.SUCCESS]:   renderSuccess,
    [STAGES.FAIL]:      renderFail,
  };

  const stageLabel = {
    [STAGES.SELECT]:    'Select Target Drive',
    [STAGES.CONFIRM]:   'Confirm Restore',
    [STAGES.WRITING]:   'Writing…',
    [STAGES.VERIFYING]: 'Verifying…',
    [STAGES.SUCCESS]:   'Restore Successful',
    [STAGES.FAIL]:      'Restore Failed',
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-fadeIn">
      <div className="relative w-full max-w-lg rounded-2xl border border-zinc-700 bg-dark-950/95 shadow-2xl overflow-hidden">

        {/* Header */}
        <div className="flex items-center justify-between p-5 border-b border-zinc-800">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-xl bg-blue-500/15 border border-blue-500/40">
              <Usb className="w-5 h-5 text-blue-400" />
            </div>
            <div>
              <h2 className="text-base font-bold font-mono text-white">Restore to Pendrive</h2>
              <p className="text-xs text-zinc-500 font-mono mt-0.5">{stageLabel[stage]} · {artifact.filename}</p>
            </div>
          </div>
          {![STAGES.WRITING, STAGES.VERIFYING].includes(stage) && (
            <button onClick={onClose} className="p-1.5 rounded-lg hover:bg-zinc-800 text-zinc-400 hover:text-white transition-colors">
              <X className="w-5 h-5" />
            </button>
          )}
        </div>

        {/* Stage progress indicator */}
        <div className="flex h-1">
          {[STAGES.SELECT, STAGES.CONFIRM, STAGES.WRITING, STAGES.VERIFYING].map((s, i) => {
            const stageOrder = [STAGES.SELECT, STAGES.CONFIRM, STAGES.WRITING, STAGES.VERIFYING, STAGES.SUCCESS, STAGES.FAIL];
            const current = stageOrder.indexOf(stage);
            const filled = i <= current - 1 || (stage === STAGES.SUCCESS && true) || (stage === STAGES.FAIL && i <= 3);
            return (
              <div key={s} className={`flex-1 ${i > 0 ? 'ml-0.5' : ''} ${
                filled ? 'bg-cyber-neon/80' : 'bg-zinc-800'
              } transition-all duration-500`} />
            );
          })}
        </div>

        {/* Body */}
        <div className="p-5">
          {STAGE_CONTENT[stage]?.()}
        </div>
      </div>
    </div>
  );
}
