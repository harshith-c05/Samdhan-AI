import React from 'react';
import { 
  FileText, Database, Image as ImageIcon, Terminal, Binary, AlertCircle, 
  CheckCircle, Copy, ArrowUpDown, ChevronRight, AlertTriangle, Shield,
  Radio, HardDrive, Cpu, ShieldAlert
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
  const getCategoryIcon = (category) => {
    const c = (category || '').toLowerCase();
    if (c.includes('doc')) return <FileText className="w-3.5 h-3.5 text-blue-400" />;
    if (c.includes('db') || c.includes('data')) return <Database className="w-3.5 h-3.5 text-emerald-400" />;
    if (c.includes('photo') || c.includes('image')) return <ImageIcon className="w-3.5 h-3.5 text-amber-400" />;
    if (c.includes('system') || c.includes('trace')) return <Terminal className="w-3.5 h-3.5 text-purple-400" />;
    if (c.includes('network') || c.includes('pcap')) return <Radio className="w-3.5 h-3.5 text-cyan-400" />;
    if (c.includes('registry') || c.includes('hive')) return <HardDrive className="w-3.5 h-3.5 text-rose-400" />;
    if (c.includes('exec') || c.includes('pe') || c.includes('elf')) return <Cpu className="w-3.5 h-3.5 text-red-500" />;
    return <Binary className="w-3.5 h-3.5 text-zinc-400" />;
  };

  const getCategoryColor = (category) => {
    const c = (category || '').toLowerCase();
    if (c.includes('doc')) return 'border-blue-500/30 text-blue-300 bg-blue-500/10';
    if (c.includes('db') || c.includes('data')) return 'border-emerald-500/30 text-emerald-300 bg-emerald-500/10';
    if (c.includes('photo') || c.includes('image')) return 'border-amber-500/30 text-amber-300 bg-amber-500/10';
    if (c.includes('system') || c.includes('trace')) return 'border-purple-500/30 text-purple-300 bg-purple-500/10';
    if (c.includes('network') || c.includes('pcap')) return 'border-cyan-500/30 text-cyan-300 bg-cyan-500/10';
    if (c.includes('registry') || c.includes('hive')) return 'border-rose-500/30 text-rose-300 bg-rose-500/10';
    if (c.includes('exec') || c.includes('pe')) return 'border-red-500/40 text-red-300 bg-red-500/15 font-bold';
    return 'border-zinc-700 text-zinc-300 bg-zinc-800/40';
  };

  return (
    <div className="bg-dark-900 border border-zinc-800 rounded-xl overflow-hidden shadow-cyber-card">
      <div className="overflow-x-auto scrollbar-thin">
        <table className="w-full text-left border-collapse font-sans text-xs">
          {/* Header Row */}
          <thead>
            <tr className="bg-dark-950/90 border-b border-zinc-800 text-[11px] font-mono text-zinc-400 uppercase tracking-wider select-none">
              
              {/* Rank */}
              <th 
                className="py-3 px-3 font-semibold hover:text-white cursor-pointer w-12 text-center"
                onClick={() => onSort('rank')}
              >
                <span>Rank</span>
              </th>

              {/* Artifact */}
              <th 
                className="py-3 px-3 font-semibold hover:text-white cursor-pointer min-w-[180px]"
                onClick={() => onSort('filename')}
              >
                <div className="flex items-center space-x-1">
                  <span>Artifact</span>
                  <ArrowUpDown className="w-3 h-3 text-zinc-600" />
                </div>
              </th>

              {/* Type / Category */}
              <th 
                className="py-3 px-3 font-semibold hover:text-white cursor-pointer"
                onClick={() => onSort('type')}
              >
                <div className="flex items-center space-x-1">
                  <span>Type</span>
                  <ArrowUpDown className="w-3 h-3 text-zinc-600" />
                </div>
              </th>

              {/* Classification */}
              <th 
                className="py-3 px-3 font-semibold hover:text-white cursor-pointer min-w-[150px]"
                onClick={() => onSort('subtype')}
              >
                <div className="flex items-center space-x-1">
                  <span>Classification</span>
                  <ArrowUpDown className="w-3 h-3 text-zinc-600" />
                </div>
              </th>

              {/* Priority Tier */}
              <th 
                className="py-3 px-3 font-semibold hover:text-white cursor-pointer"
                onClick={() => onSort('priorityTier')}
              >
                <div className="flex items-center space-x-1">
                  <span>Priority</span>
                  <ArrowUpDown className="w-3 h-3 text-zinc-600" />
                </div>
              </th>

              {/* Priority Score (P) */}
              <th 
                className="py-3 px-3 font-semibold hover:text-white cursor-pointer text-right"
                onClick={() => onSort('priorityScore')}
              >
                <div className="flex items-center justify-end space-x-1">
                  <span>Score</span>
                  <ArrowUpDown className="w-3 h-3 text-zinc-600" />
                </div>
              </th>

              {/* Integrity (I) */}
              <th 
                className="py-3 px-3 font-semibold hover:text-white cursor-pointer text-center"
                onClick={() => onSort('integrity')}
              >
                <div className="flex items-center justify-center space-x-1">
                  <span>Integrity</span>
                  <ArrowUpDown className="w-3 h-3 text-zinc-600" />
                </div>
              </th>

              {/* Relevance (R) */}
              <th 
                className="py-3 px-3 font-semibold hover:text-white cursor-pointer text-center"
                onClick={() => onSort('evidenceRelevance')}
              >
                <div className="flex items-center justify-center space-x-1">
                  <span>Relevance</span>
                  <ArrowUpDown className="w-3 h-3 text-zinc-600" />
                </div>
              </th>

              {/* Temporal (T) */}
              <th 
                className="py-3 px-3 font-semibold hover:text-white cursor-pointer text-center"
                onClick={() => onSort('temporal')}
              >
                <div className="flex items-center justify-center space-x-1">
                  <span>Temporal</span>
                  <ArrowUpDown className="w-3 h-3 text-zinc-600" />
                </div>
              </th>

              {/* Uniqueness (U) */}
              <th 
                className="py-3 px-3 font-semibold hover:text-white cursor-pointer text-center"
                onClick={() => onSort('uniqueness')}
              >
                <div className="flex items-center justify-center space-x-1">
                  <span>Uniqueness</span>
                  <ArrowUpDown className="w-3 h-3 text-zinc-600" />
                </div>
              </th>

              {/* Noise (N) */}
              <th 
                className="py-3 px-3 font-semibold hover:text-white cursor-pointer text-center"
                onClick={() => onSort('noisePenalty')}
              >
                <div className="flex items-center justify-center space-x-1">
                  <span>Noise</span>
                  <ArrowUpDown className="w-3 h-3 text-zinc-600" />
                </div>
              </th>

              {/* Review Required */}
              <th 
                className="py-3 px-3 font-semibold hover:text-white cursor-pointer text-center"
                onClick={() => onSort('reviewRequired')}
              >
                <div className="flex items-center justify-center space-x-1">
                  <span>Review</span>
                  <ArrowUpDown className="w-3 h-3 text-zinc-600" />
                </div>
              </th>

              <th className="py-3 px-2 text-right"></th>
            </tr>
          </thead>

          {/* Table Body */}
          <tbody className="divide-y divide-zinc-800/60 font-mono">
            {artifacts.length === 0 ? (
              <tr>
                <td colSpan={13} className="py-12 text-center text-zinc-500 font-mono">
                  No artifacts match current filter criteria.
                </td>
              </tr>
            ) : (
              artifacts.map((artifact, index) => {
                const rankNum = artifact.rank ?? (index + 1);
                const tierClass = getTierBadgeClass(artifact.priorityTier);
                const category = artifact.category || artifact.type || 'Document';
                const hasConflict = artifact.conflict || artifact.antiForensicAlert;
                const scoreDisplay = typeof artifact.priorityScore === 'number'
                  ? (artifact.priorityScore > 1 ? (artifact.priorityScore / 100).toFixed(3) : artifact.priorityScore.toFixed(3))
                  : '0.000';

                // Normalized dimension percentages (0 - 100%)
                const integPct = Math.round((artifact.integrity > 1 ? artifact.integrity : artifact.integrity * 100) || artifact.overallIntegrity || 0);
                const relPct = Math.round((artifact.evidenceRelevance > 1 ? artifact.evidenceRelevance : artifact.evidenceRelevance * 100) || (artifact.relevance ? artifact.relevance * 100 : 0));
                const tempPct = Math.round((artifact.temporal > 1 ? artifact.temporal : (artifact.temporal != null ? artifact.temporal * 100 : 75)));
                const uniqPct = Math.round((artifact.uniqueness > 1 ? artifact.uniqueness : (artifact.uniqueness != null ? artifact.uniqueness * 100 : (artifact.duplicate ? 0 : 100))));
                const noisePct = Math.round((artifact.noisePenalty > 1 ? artifact.noisePenalty : (artifact.noisePenalty != null ? artifact.noisePenalty * 100 : (artifact.noise ? artifact.noise * 100 : 0))));

                const isReviewRequired = artifact.reviewRequired || artifact.review_required || (artifact.classificationConfidence < 60) || hasConflict;

                return (
                  <tr
                    key={artifact.id || artifact.artifact_id || artifact.filename}
                    onClick={() => onSelectArtifact(artifact)}
                    className="hover:bg-dark-800/80 transition-colors cursor-pointer group"
                  >
                    {/* Rank */}
                    <td className="py-3 px-3 text-center font-bold text-zinc-500 group-hover:text-cyber-neon">
                      #{rankNum}
                    </td>

                    {/* Artifact */}
                    <td className="py-3 px-3 text-white font-medium max-w-[220px]" title={artifact.filename}>
                      <div className="flex items-center space-x-1.5">
                        <span className="shrink-0">{getCategoryIcon(category)}</span>
                        <span className="truncate font-mono text-xs">{artifact.filename}</span>
                        {hasConflict && (
                          <span 
                            className="px-1.5 py-0.5 rounded text-[9px] font-mono font-bold bg-rose-500/25 text-rose-300 border border-rose-500/50 shrink-0 flex items-center space-x-1 animate-pulse"
                            title={artifact.forensic_message || "EXTENSION_SIGNATURE_MISMATCH: Extension spoof detected. Binary header does not match."}
                          >
                            <AlertTriangle className="w-2.5 h-2.5 text-rose-400" />
                            <span>CONFLICT</span>
                          </span>
                        )}
                      </div>
                      <div className="text-[10px] text-zinc-500 font-mono mt-0.5">
                        {artifact.metadata?.size || `${artifact.size || 0} bytes`}
                      </div>
                    </td>

                    {/* Type / Category */}
                    <td className="py-3 px-3 whitespace-nowrap">
                      <span className={`inline-flex items-center space-x-1 px-2 py-0.5 rounded border text-[11px] ${getCategoryColor(category)}`}>
                        <span>{category}</span>
                      </span>
                    </td>

                    {/* Classification */}
                    <td className="py-3 px-3 text-xs text-zinc-300 truncate max-w-[170px]" title={artifact.subtype || artifact.label || artifact.classification?.subtype}>
                      <div className="truncate font-sans font-medium text-zinc-200">
                        {artifact.subtype || artifact.label || artifact.classification?.subtype || artifact.classification?.format || 'Detected binary'}
                      </div>
                      <div className="text-[10px] text-zinc-500 font-mono truncate">
                        {artifact.classification?.method || artifact.classificationExplanation?.method || 'Rule-based magic bytes'}
                      </div>
                    </td>

                    {/* Priority Tier */}
                    <td className="py-3 px-3 whitespace-nowrap">
                      <span className={`px-2.5 py-1 rounded text-[11px] font-bold uppercase tracking-wider ${tierClass}`}>
                        {artifact.priorityTier}
                      </span>
                    </td>

                    {/* Score (P) */}
                    <td className="py-3 px-3 whitespace-nowrap font-bold text-white text-xs text-right font-mono">
                      <span className="text-cyber-neon font-semibold text-[13px]">{scoreDisplay}</span>
                    </td>

                    {/* Integrity % */}
                    <td className="py-3 px-3 whitespace-nowrap text-center">
                      <span className={`text-[11px] font-bold ${integPct >= 90 ? 'text-emerald-400' : integPct >= 60 ? 'text-amber-400' : 'text-red-400'}`}>
                        {integPct}%
                      </span>
                    </td>

                    {/* Relevance % */}
                    <td className="py-3 px-3 whitespace-nowrap text-center">
                      <span className={`text-[11px] font-bold ${relPct >= 85 ? 'text-red-400' : relPct >= 60 ? 'text-orange-400' : 'text-zinc-400'}`}>
                        {relPct}%
                      </span>
                    </td>

                    {/* Temporal % */}
                    <td className="py-3 px-3 whitespace-nowrap text-center">
                      <span className={`text-[11px] font-mono ${tempPct >= 95 ? 'text-cyan-400 font-bold' : 'text-zinc-400'}`}>
                        {tempPct}%
                      </span>
                    </td>

                    {/* Uniqueness % */}
                    <td className="py-3 px-3 whitespace-nowrap text-center">
                      {artifact.duplicate ? (
                        <span className="px-1.5 py-0.5 rounded bg-zinc-800 text-zinc-400 border border-zinc-700 text-[10px] inline-flex items-center space-x-1">
                          <Copy className="w-2.5 h-2.5" />
                          <span>0%</span>
                        </span>
                      ) : (
                        <span className="text-[11px] text-zinc-300 font-mono">{uniqPct}%</span>
                      )}
                    </td>

                    {/* Noise % */}
                    <td className="py-3 px-3 whitespace-nowrap text-center">
                      <span className={`text-[11px] font-mono ${noisePct > 50 ? 'text-rose-400 font-bold' : 'text-zinc-500'}`}>
                        {noisePct}%
                      </span>
                    </td>

                    {/* Review Required */}
                    <td className="py-3 px-3 whitespace-nowrap text-center">
                      {isReviewRequired ? (
                        <span 
                          className="px-2 py-0.5 rounded text-[10px] font-bold bg-amber-500/20 text-amber-300 border border-amber-500/40 inline-flex items-center space-x-1"
                          title="Requires manual analyst inspection due to conflict, low confidence, or high anomaly."
                        >
                          <AlertCircle className="w-2.5 h-2.5" />
                          <span>REQUIRED</span>
                        </span>
                      ) : (
                        <span className="text-emerald-400/80 text-[10px] font-mono inline-flex items-center space-x-1">
                          <CheckCircle className="w-2.5 h-2.5" />
                          <span>CLEAN</span>
                        </span>
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
        <span>Displaying {artifacts.length} ranked evidence artifacts (Formula: P = 0.30·I + 0.35·R + 0.20·T + 0.15·U − 0.10·N)</span>
        <span className="text-[11px] text-zinc-400">Click any row for explainable forensic triage drawer</span>
      </div>
    </div>
  );
}
