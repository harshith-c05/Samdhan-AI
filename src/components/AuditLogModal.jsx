import React from 'react';
import { X, Terminal, ShieldCheck, Download, Clock, Database, Lock } from 'lucide-react';
import { INITIAL_AUDIT_LOG } from '../data/mockForensicData';
import { truncateHash } from '../utils/forensicUtils';

export default function AuditLogModal({ onClose, caseContext, auditLogs = INITIAL_AUDIT_LOG }) {
  const exportLog = () => {
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(auditLogs, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute("href", dataStr);
    downloadAnchor.setAttribute("download", `AUDIT_LOG_${caseContext.caseId || 'CASE_EVIDENCE'}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  return (
    <div className="fixed inset-0 z-50 overflow-y-auto bg-black/80 backdrop-blur-sm flex items-center justify-center p-3 sm:p-6 animate-fadeIn">
      <div 
        className="relative bg-dark-900 border border-cyber-500/30 w-full max-w-5xl rounded-2xl shadow-2xl overflow-hidden flex flex-col max-h-[90vh]"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="px-6 py-4 bg-dark-950 border-b border-zinc-800 flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <div className="p-2 rounded-lg bg-cyber-500/10 border border-cyber-500/30 text-cyber-neon">
              <Terminal className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <h2 className="text-base font-bold text-white font-mono">
                  IMMUTABLE APPEND-ONLY FORENSIC AUDIT TRAIL
                </h2>
                <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-emerald-500/20 text-emerald-400 border border-emerald-500/40">
                  TAMPER-SEALED
                </span>
              </div>
              <p className="text-xs text-zinc-400 font-mono">
                Complies with Section 9: Security &amp; Forensic Integrity Standards
              </p>
            </div>
          </div>

          <button
            onClick={onClose}
            className="p-1.5 rounded-lg bg-dark-850 hover:bg-dark-800 text-zinc-400 hover:text-white border border-zinc-700 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Security Info */}
        <div className="p-4 bg-dark-950/80 border-b border-zinc-800 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs font-mono">
          <div className="flex items-center space-x-2 text-zinc-300">
            <Lock className="w-4 h-4 text-cyber-neon" />
            <span>Case ID: <strong className="text-white">{caseContext.caseId || 'CASE-2026-NIGHTFALL'}</strong></span>
            <span>•</span>
            <span>Investigator: <strong className="text-white">{caseContext.investigator || 'Det. H. Chen'}</strong></span>
          </div>

          <button
            onClick={exportLog}
            className="px-3 py-1.5 rounded-lg bg-dark-800 hover:bg-dark-750 text-cyber-neon border border-cyber-500/30 text-xs flex items-center space-x-1.5 transition-colors self-start sm:self-auto"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Export Audit Trail (JSON)</span>
          </button>
        </div>

        {/* Audit Log Table */}
        <div className="p-6 overflow-y-auto space-y-4 scrollbar-thin">
          <div className="rounded-xl border border-zinc-800 overflow-hidden bg-dark-950">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-dark-900 border-b border-zinc-800 text-[11px] text-zinc-400 uppercase">
                <tr>
                  <th className="py-3 px-3 font-semibold">Log ID</th>
                  <th className="py-3 px-3 font-semibold">Timestamp (UTC)</th>
                  <th className="py-3 px-3 font-semibold">Stage</th>
                  <th className="py-3 px-3 font-semibold">Artifact Target</th>
                  <th className="py-3 px-3 font-semibold">Input Hash</th>
                  <th className="py-3 px-4 font-semibold">Output Summary</th>
                  <th className="py-3 px-3 font-semibold">Engine / Rule Version</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-zinc-800/60">
                {auditLogs.map((entry) => (
                  <tr key={entry.id} className="hover:bg-dark-900/50 transition-colors">
                    <td className="py-2.5 px-3 font-bold text-cyber-neon whitespace-nowrap">
                      {entry.id}
                    </td>

                    <td className="py-2.5 px-3 text-zinc-400 whitespace-nowrap text-[11px]">
                      {entry.timestamp?.slice(11, 23)}
                    </td>

                    <td className="py-2.5 px-3 font-semibold text-white whitespace-nowrap">
                      {entry.stage}
                    </td>

                    <td className="py-2.5 px-3 text-zinc-300 whitespace-nowrap">
                      {entry.artifact}
                    </td>

                    <td className="py-2.5 px-3 font-mono text-[10px] text-zinc-400 select-all whitespace-nowrap">
                      {truncateHash(entry.inputHash, 6)}
                    </td>

                    <td className="py-2.5 px-4 text-zinc-300 text-xs font-sans">
                      {entry.output}
                    </td>

                    <td className="py-2.5 px-3 text-zinc-400 text-[11px] whitespace-nowrap">
                      {entry.modelOrRule}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Footer */}
        <div className="px-6 py-3.5 bg-dark-950 border-t border-zinc-800 flex items-center justify-between text-xs font-mono text-zinc-500">
          <span>Cryptographic Hash Tree: No modifications detected</span>
          <button
            onClick={onClose}
            className="px-4 py-1.5 rounded-lg bg-zinc-800 hover:bg-zinc-700 text-white transition-colors"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
}
