import React from 'react';
import { 
  FileText, Database, Image as ImageIcon, Terminal, Binary, AlertCircle, 
  CheckCircle, Copy, ArrowUpDown, ChevronRight, AlertTriangle, Shield
} from 'lucide-react';
import { getTierBadgeClass, getConfidenceBadgeClass } from '../utils/forensicUtils';

export default function ArtifactTable({ 
  artifacts, 
  onSelectArtifact,
  onOpenIntegrity,
  sortField, 
  sortOrder, 
  onSort 
}) {
  const getTypeIcon = (type) => {
    switch (type?.toLowerCase()) {
      case 'document':
        return <FileText className="w-3.5 h-3.5 text-blue-400" />;
      case 'db log':
        return <Database className="w-3.5 h-3.5 text-emerald-400" />;
      case 'photo':
      case 'photos':
        return <ImageIcon className="w-3.5 h-3.5 text-amber-400" />;
      case 'system trace':
        return <Terminal className="w-3.5 h-3.5 text-purple-400" />;
      default:
        return <Binary className="w-3.5 h-3.5 text-zinc-400" />;
    }
  };

  return (
    <div className="bg-dark-900 border border-zinc-800 rounded-xl overflow-hidden shadow-cyber-card">
      <div className="overflow-x-auto scrollbar-thin">
        <table className="w-full text-left border-collapse font-sans text-xs">
          {/* Header Row */}
          <thead>
            <tr className="bg-dark-950/80 border-b border-zinc-800 text-[11px] font-mono text-zinc-400 uppercase tracking-wider select-none">
              <th 
                className="py-3.5 px-4 font-semibold hover:text-white cursor-pointer"
                onClick={() => onSort('id')}
              >
                <div className="flex items-center space-x-1">
                  <span>Artifact ID</span>
                  <ArrowUpDown className="w-3 h-3 text-zinc-600" />
                </div>
              </th>

              <th 
                className="py-3.5 px-4 font-semibold hover:text-white cursor-pointer"
                onClick={() => onSort('filename')}
              >
                <div className="flex items-center space-x-1">
                  <span>Filename</span>
                  <ArrowUpDown className="w-3 h-3 text-zinc-600" />
                </div>
              </th>

              <th 
                className="py-3.5 px-3 font-semibold hover:text-white cursor-pointer"
                onClick={() => onSort('type')}
              >
                <div className="flex items-center space-x-1">
                  <span>Type</span>
                  <ArrowUpDown className="w-3 h-3 text-zinc-600" />
                </div>
              </th>

              {/* Confidence gets separate icon/badge column */}
              <th 
                className="py-3.5 px-3 font-semibold hover:text-white cursor-pointer"
                onClick={() => onSort('classificationConfidence')}
              >
                <div className="flex items-center space-x-1">
                  <span>Confidence</span>
                  <ArrowUpDown className="w-3 h-3 text-zinc-600" />
                </div>
              </th>

              <th 
                className="py-3.5 px-3 font-semibold hover:text-white cursor-pointer"
                onClick={() => onSort('integrity')}
              >
                <div className="flex items-center space-x-1">
                  <span>Integrity</span>
                  <ArrowUpDown className="w-3 h-3 text-zinc-600" />
                </div>
              </th>

              <th className="py-3.5 px-3 font-semibold">
                Corruption
              </th>

              <th 
                className="py-3.5 px-3 font-semibold hover:text-white cursor-pointer"
                onClick={() => onSort('evidenceRelevance')}
              >
                <div className="flex items-center space-x-1">
                  <span>Relevance</span>
                  <ArrowUpDown className="w-3 h-3 text-zinc-600" />
                </div>
              </th>

              <th className="py-3.5 px-3 font-semibold text-center">
                Duplicate
              </th>

              <th 
                className="py-3.5 px-3 font-semibold hover:text-white cursor-pointer"
                onClick={() => onSort('priorityScore')}
              >
                <div className="flex items-center space-x-1">
                  <span>Score</span>
                  <ArrowUpDown className="w-3 h-3 text-zinc-600" />
                </div>
              </th>

              {/* Color coded Tier (Red, Orange, Yellow, Gray) */}
              <th 
                className="py-3.5 px-3 font-semibold hover:text-white cursor-pointer"
                onClick={() => onSort('priorityTier')}
              >
                <div className="flex items-center space-x-1">
                  <span>Priority Tier</span>
                  <ArrowUpDown className="w-3 h-3 text-zinc-600" />
                </div>
              </th>

              <th className="py-3.5 px-4 font-semibold min-w-[200px]">
                Reason (Short)
              </th>

              <th className="py-3.5 px-3 font-semibold"
                onClick={() => onSort('recoverability')}
              >
                <div className="flex items-center space-x-1">
                  <span>Recoverability</span>
                  <ArrowUpDown className="w-3 h-3 text-zinc-600" />
                </div>
              </th>

              <th className="py-3.5 px-2 text-center">
                <span className="text-[11px]">Integrity</span>
              </th>

              <th className="py-3.5 px-2 text-right"></th>
            </tr>
          </thead>

          {/* Table Body */}
          <tbody className="divide-y divide-zinc-800/60 font-mono">
            {artifacts.length === 0 ? (
              <tr>
                <td colSpan={12} className="py-12 text-center text-zinc-500 font-mono">
                  No artifacts match current filter criteria.
                </td>
              </tr>
            ) : (
              artifacts.map((artifact) => {
                const isCorrupted = artifact.integrity < 90 || artifact.corruption !== "None";
                const tierClass = getTierBadgeClass(artifact.priorityTier);
                const confClass = getConfidenceBadgeClass(artifact.classificationConfidence);

                return (
                  <tr
                    key={artifact.id}
                    onClick={() => onSelectArtifact(artifact)}
                    className="hover:bg-dark-800/80 transition-colors cursor-pointer group"
                  >
                    {/* Artifact ID */}
                    <td className="py-3 px-4 font-bold text-cyber-neon tracking-tight shrink-0 whitespace-nowrap">
                      {artifact.id}
                    </td>

                    {/* Filename */}
                    <td className="py-3 px-4 text-white font-medium truncate max-w-[190px]" title={artifact.filename}>
                      {artifact.filename}
                    </td>

                    {/* Type with icon */}
                    <td className="py-3 px-3 whitespace-nowrap">
                      <span className="inline-flex items-center space-x-1.5 px-2 py-0.5 rounded bg-dark-950 text-zinc-300 border border-zinc-800 text-[11px]">
                        {getTypeIcon(artifact.type)}
                        <span>{artifact.type}</span>
                      </span>
                    </td>

                    {/* Classification Confidence (Distinct badge/meter so not conflated with tier) */}
                    <td className="py-3 px-3 whitespace-nowrap">
                      <span className={`inline-flex items-center space-x-1 px-2 py-0.5 rounded font-bold text-[11px] ${confClass}`}>
                        <span>{artifact.classificationConfidence.toFixed(1)}%</span>
                      </span>
                    </td>

                    {/* Integrity % */}
                    <td className="py-3 px-3 whitespace-nowrap">
                      <div className="flex items-center space-x-2">
                        <div className="w-12 h-1.5 bg-dark-950 rounded-full overflow-hidden border border-zinc-800">
                          <div 
                            className={`h-full rounded-full ${
                              artifact.integrity >= 90 ? 'bg-emerald-400' : artifact.integrity >= 60 ? 'bg-amber-400' : 'bg-red-400'
                            }`}
                            style={{ width: `${artifact.integrity}%` }}
                          />
                        </div>
                        <span className="text-zinc-300 text-[11px]">{artifact.integrity.toFixed(0)}%</span>
                      </div>
                    </td>

                    {/* Corruption State */}
                    <td className="py-3 px-3 text-[11px] text-zinc-400 truncate max-w-[170px]" title={artifact.corruption}>
                      {artifact.corruption === "None" ? (
                        <span className="text-emerald-400/90 font-sans">Clean</span>
                      ) : (
                        <span className="text-amber-400/90 font-sans flex items-center space-x-1">
                          <AlertTriangle className="w-3 h-3 text-amber-400 shrink-0" />
                          <span className="truncate">{artifact.corruption}</span>
                        </span>
                      )}
                    </td>

                    {/* Evidence Relevance */}
                    <td className="py-3 px-3 whitespace-nowrap">
                      <span className={`text-[11px] font-semibold ${
                        artifact.evidenceRelevance >= 90 ? 'text-red-400' : artifact.evidenceRelevance >= 70 ? 'text-orange-300' : 'text-zinc-400'
                      }`}>
                        {artifact.evidenceRelevance.toFixed(1)}%
                      </span>
                    </td>

                    {/* Duplicate Indicator */}
                    <td className="py-3 px-3 text-center whitespace-nowrap">
                      {artifact.duplicate ? (
                        <span className="px-1.5 py-0.5 rounded bg-zinc-800 text-zinc-400 border border-zinc-700 text-[10px] inline-flex items-center space-x-1">
                          <Copy className="w-2.5 h-2.5" />
                          <span>DUP</span>
                        </span>
                      ) : (
                        <span className="text-zinc-600 text-[11px]">-</span>
                      )}
                    </td>

                    {/* Priority Score */}
                    <td className="py-3 px-3 whitespace-nowrap font-bold text-white text-xs">
                      {artifact.priorityScore.toFixed(1)}
                    </td>

                    {/* Priority Tier (Red, Orange, Yellow, Gray) */}
                    <td className="py-3 px-3 whitespace-nowrap">
                      <span className={`px-2.5 py-1 rounded text-[11px] font-bold uppercase tracking-wider ${tierClass}`}>
                        {artifact.priorityTier}
                      </span>
                    </td>

                    {/* Reason (Short) */}
                    <td className="py-3 px-4 text-zinc-300 text-xs font-sans line-clamp-2 max-w-[240px]" title={artifact.reason}>
                      {artifact.reason}
                    </td>

                    {/* Recoverability */}
                    <td className="py-3 px-3 whitespace-nowrap">
                      {(() => {
                        const r = artifact.recoverability || '';
                        const c = r === 'FULLY_RECOVERABLE' ? 'text-emerald-400'
                               : r === 'MOSTLY_RECOVERABLE' ? 'text-cyan-400'
                               : r === 'PARTIALLY_RECOVERABLE' ? 'text-amber-400'
                               : r === 'BARELY_RECOVERABLE' ? 'text-orange-400'
                               : 'text-red-400';
                        return <span className={`text-[10px] font-bold ${c}`}>{r?.replace(/_/g,' ') || '—'}</span>;
                      })()}
                    </td>

                    {/* Integrity Detail Button */}
                    <td className="py-3 px-2 text-center" onClick={e => e.stopPropagation()}>
                      {artifact.overallIntegrity != null && (
                        <button
                          onClick={() => onOpenIntegrity?.(artifact)}
                          title="Open Integrity Assessment"
                          className="inline-flex items-center gap-1 px-2 py-1 rounded text-[10px] font-bold bg-cyan-950/50 text-cyan-400 border border-cyan-700/30 hover:bg-cyan-900/60 transition-colors"
                        >
                          <Shield className="w-3 h-3" />
                          {Math.round(artifact.overallIntegrity)}%
                        </button>
                      )}
                    </td>

                    {/* Action Arrow */}
                    <td className="py-3 px-2 text-right">
                      <ChevronRight className="w-4 h-4 text-zinc-500 group-hover:text-cyber-neon group-hover:translate-x-0.5 transition-all" />
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>
      
      {/* Table Footer */}
      <div className="px-4 py-2.5 bg-dark-950/90 border-t border-zinc-800 flex items-center justify-between text-xs font-mono text-zinc-500">
        <span>Showing {artifacts.length} carved evidence records</span>
        <span className="text-[11px] text-zinc-400">Click any row for comprehensive forensic analysis &amp; preview</span>
      </div>
    </div>
  );
}
