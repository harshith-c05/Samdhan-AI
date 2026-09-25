import React, { useState } from 'react';
import { 
  X, ShieldCheck, FileText, Database, Image as ImageIcon, Terminal, 
  Binary, Clock, Hash, Layers, CheckCircle2, AlertTriangle, AlertCircle, 
  ExternalLink, BarChart2, ShieldAlert, Cpu, Lock, Download, Copy 
} from 'lucide-react';
import { getTierBadgeClass, getConfidenceBadgeClass, truncateHash } from '../utils/forensicUtils';
import { ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip, Cell } from 'recharts';

export default function ArtifactDetailModal({ 
  artifact, 
  onClose, 
  onSelectRelated,
  caseContext 
}) {
  const [activeTab, setActiveTab] = useState('overview'); // overview, preview, integrity, chain
  const [copiedField, setCopiedField] = useState(null);

  if (!artifact) return null;

  const copyToClipboard = (text, fieldName) => {
    navigator.clipboard.writeText(text);
    setCopiedField(fieldName);
    setTimeout(() => setCopiedField(null), 1800);
  };

  const tierClass = getTierBadgeClass(artifact.priorityTier);
  const confClass = getConfidenceBadgeClass(artifact.classificationConfidence);

  // Score contribution bar chart data
  const scoreData = [
    { name: 'Relevance', value: artifact.priorityExplanation?.relevanceContrib || 30, max: 40, fill: '#ef4444' },
    { name: 'Integrity', value: artifact.priorityExplanation?.integrityContrib || 25, max: 30, fill: '#10b981' },
    { name: 'Recency/Window', value: artifact.priorityExplanation?.recencyContrib || 18, max: 20, fill: '#3b82f6' },
    { name: 'Uniqueness', value: artifact.priorityExplanation?.uniquenessContrib || 8, max: 10, fill: '#eab308' },
  ];

  return (
    <div className="fixed inset-0 z-50 overflow-y-auto bg-black/80 backdrop-blur-sm flex items-center justify-center p-3 sm:p-6 animate-fadeIn">
      <div 
        className="relative bg-dark-900 border border-cyber-500/30 w-full max-w-5xl rounded-2xl shadow-2xl overflow-hidden flex flex-col max-h-[92vh]"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Top Header Bar */}
        <div className="px-6 py-4 bg-dark-950 border-b border-zinc-800 flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <div className="p-2 rounded-lg bg-cyber-500/10 border border-cyber-500/30 text-cyber-neon font-mono font-bold text-sm">
              {artifact.id}
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <h2 className="text-base font-bold text-white font-mono truncate max-w-md">
                  {artifact.filename}
                </h2>
                <span className={`px-2 py-0.5 rounded text-[11px] font-bold uppercase tracking-wider ${tierClass}`}>
                  {artifact.priorityTier} Priority
                </span>
                <span className={`px-2 py-0.5 rounded text-[11px] font-bold ${confClass}`}>
                  {artifact.classificationConfidence.toFixed(1)}% Confidence
                </span>
              </div>
              <p className="text-xs text-zinc-400 mt-0.5 font-mono">
                Source Sector: <span className="text-cyber-neon">{artifact.metadata?.sourceOffset}</span> ({artifact.metadata?.sector}) • Type: {artifact.type}
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

        {/* Tab Navigation */}
        <div className="px-6 bg-dark-950/60 border-b border-zinc-800 flex space-x-4 text-xs font-mono">
          <button
            onClick={() => setActiveTab('overview')}
            className={`py-3 border-b-2 font-medium transition-colors ${
              activeTab === 'overview'
                ? 'border-cyber-neon text-cyber-neon'
                : 'border-transparent text-zinc-400 hover:text-zinc-200'
            }`}
          >
            Overview &amp; Triaging
          </button>

          <button
            onClick={() => setActiveTab('preview')}
            className={`py-3 border-b-2 font-medium transition-colors ${
              activeTab === 'preview'
                ? 'border-cyber-neon text-cyber-neon'
                : 'border-transparent text-zinc-400 hover:text-zinc-200'
            }`}
          >
            Safe Preview &amp; Hex Dump
          </button>

          <button
            onClick={() => setActiveTab('integrity')}
            className={`py-3 border-b-2 font-medium transition-colors ${
              activeTab === 'integrity'
                ? 'border-cyber-neon text-cyber-neon'
                : 'border-transparent text-zinc-400 hover:text-zinc-200'
            }`}
          >
            Integrity &amp; Recovery Details
          </button>

          <button
            onClick={() => setActiveTab('chain')}
            className={`py-3 border-b-2 font-medium transition-colors flex items-center space-x-1.5 ${
              activeTab === 'chain'
                ? 'border-cyber-neon text-cyber-neon'
                : 'border-transparent text-zinc-400 hover:text-zinc-200'
            }`}
          >
            <Lock className="w-3.5 h-3.5 text-cyber-neon" />
            <span>Chain of Custody</span>
          </button>
        </div>

        {/* Modal Scrollable Body */}
        <div className="p-6 overflow-y-auto space-y-6 scrollbar-thin">
          {activeTab === 'overview' && (
            <div className="space-y-6">
              {/* Reason & Priority Score Banner */}
              <div className="p-4 rounded-xl bg-dark-950 border border-cyber-500/20 flex flex-col md:flex-row md:items-center justify-between gap-4">
                <div className="space-y-1">
                  <div className="text-[11px] font-mono text-zinc-400 uppercase tracking-wider">
                    Forensic Triaging Rationale
                  </div>
                  <p className="text-sm font-semibold text-white leading-relaxed">
                    {artifact.reason}
                  </p>
                </div>
                <div className="text-right shrink-0 px-4 py-2 bg-dark-900 border border-zinc-800 rounded-lg">
                  <div className="text-[10px] font-mono text-zinc-400 uppercase">Composite Score</div>
                  <div className="text-2xl font-mono font-extrabold text-cyber-neon">
                    {artifact.priorityScore.toFixed(1)} <span className="text-xs text-zinc-500">/ 100</span>
                  </div>
                </div>
              </div>

              {/* Grid: Classification Explanation + Score Breakdown */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                {/* Classification Explanation */}
                <div className="p-4 rounded-xl bg-dark-950 border border-zinc-800 space-y-3">
                  <div className="flex items-center space-x-2 text-xs font-mono font-semibold text-cyber-neon">
                    <Cpu className="w-4 h-4" />
                    <span>CLASSIFICATION EXPLANATION</span>
                  </div>

                  <div className="space-y-2 text-xs">
                    <div>
                      <span className="text-zinc-400">Class Label:</span>
                      <span className="ml-2 font-bold text-white">{artifact.classificationExplanation?.label}</span>
                    </div>
                    <div>
                      <span className="text-zinc-400">Detection Method:</span>
                      <span className="ml-2 font-mono text-zinc-200">{artifact.classificationExplanation?.method}</span>
                    </div>

                    <div className="pt-2">
                      <span className="text-zinc-400 block mb-1.5 font-semibold">Signals Evaluated:</span>
                      <ul className="space-y-1 list-disc list-inside font-mono text-[11px] text-zinc-300">
                        {artifact.classificationExplanation?.signals?.map((sig, i) => (
                          <li key={i}>{sig}</li>
                        ))}
                      </ul>
                    </div>

                    {artifact.classificationExplanation?.conflicts && (
                      <div className="p-2.5 rounded bg-amber-500/10 border border-amber-500/30 text-amber-300 text-[11px] font-mono">
                        <strong>Anomaly / Conflict:</strong> {artifact.classificationExplanation.conflicts}
                      </div>
                    )}
                  </div>
                </div>

                {/* Score Breakdown Bar Chart */}
                <div className="p-4 rounded-xl bg-dark-950 border border-zinc-800 space-y-3">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-2 text-xs font-mono font-semibold text-cyber-neon">
                      <BarChart2 className="w-4 h-4" />
                      <span>SCORE CONTRIBUTION FACTORS</span>
                    </div>
                    <span className="text-[10px] font-mono text-zinc-500">Algorithm v2.4</span>
                  </div>

                  <div className="space-y-2 pt-1 font-mono text-xs">
                    {scoreData.map((s, idx) => (
                      <div key={idx} className="space-y-1">
                        <div className="flex justify-between text-[11px]">
                          <span className="text-zinc-400">{s.name}</span>
                          <span className="text-white font-bold">{s.value.toFixed(1)} / {s.max}</span>
                        </div>
                        <div className="w-full h-2 bg-dark-900 rounded-full overflow-hidden border border-zinc-800">
                          <div 
                            className="h-full rounded-full transition-all"
                            style={{ 
                              width: `${(s.value / s.max) * 100}%`,
                              backgroundColor: s.fill 
                            }}
                          />
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>

              {/* Visual Timeline: Relevant Timestamps vs Incident Window */}
              <div className="p-4 rounded-xl bg-dark-950 border border-zinc-800 space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-2 text-xs font-mono font-semibold text-cyber-neon">
                    <Clock className="w-4 h-4" />
                    <span>TEMPORAL RELEVANCE VS. INCIDENT WINDOW</span>
                  </div>
                  {artifact.metadata?.timestamps?.incidentWindowMatch ? (
                    <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-red-500/20 text-red-400 border border-red-500/40">
                      FLAGGED: INSIDE ACTIVE BREACH WINDOW
                    </span>
                  ) : (
                    <span className="px-2 py-0.5 rounded text-[10px] font-mono text-zinc-400 bg-zinc-800 border border-zinc-700">
                      Outside Active Breach Window
                    </span>
                  )}
                </div>

                <div className="p-3 bg-dark-900 rounded-lg border border-zinc-800 space-y-2">
                  <div className="flex flex-col sm:flex-row justify-between text-[11px] font-mono text-zinc-400">
                    <div>
                      <span>Incident Window: </span>
                      <span className="text-white font-semibold">
                        {caseContext.incidentStart || '2026-09-24 14:00'} → {caseContext.incidentEnd || '2026-09-24 22:30'}
                      </span>
                    </div>
                    <div>
                      <span>Artifact Carved Mtime: </span>
                      <span className="text-cyber-neon font-bold">
                        {artifact.metadata?.timestamps?.inferredMtime || '2026-09-24 18:42:10 UTC'}
                      </span>
                    </div>
                  </div>

                  {/* Timeline Graphic Bar */}
                  <div className="relative pt-4 pb-2">
                    <div className="w-full h-3 bg-zinc-800 rounded-full relative overflow-hidden">
                      {/* Active Incident Window highlighted zone */}
                      <div className="absolute left-[30%] right-[25%] h-full bg-red-500/30 border-x-2 border-red-500" />
                    </div>

                    {/* Marker for Artifact's Inferred Timestamp */}
                    <div 
                      className="absolute top-1 transform -translate-x-1/2 flex flex-col items-center"
                      style={{ left: artifact.metadata?.timestamps?.incidentWindowMatch ? '52%' : '15%' }}
                    >
                      <div className="w-3 h-3 rounded-full bg-cyber-neon shadow-[0_0_8px_#00ff66] border-2 border-black" />
                      <span className="text-[10px] font-mono text-cyber-bright font-bold mt-1">
                        Artifact Timestamp
                      </span>
                    </div>
                  </div>
                </div>
              </div>

              {/* Related Artifacts and Cluster Members */}
              {artifact.relatedArtifacts && artifact.relatedArtifacts.length > 0 && (
                <div className="p-4 rounded-xl bg-dark-950 border border-zinc-800 space-y-3">
                  <div className="flex items-center space-x-2 text-xs font-mono font-semibold text-cyber-neon">
                    <Layers className="w-4 h-4" />
                    <span>CORRELATED ARTIFACTS &amp; CLUSTER MEMBERS</span>
                  </div>

                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                    {artifact.relatedArtifacts.map((rel, i) => (
                      <div
                        key={i}
                        onClick={() => onSelectRelated && onSelectRelated(rel.id)}
                        className="p-3 rounded-lg bg-dark-900 border border-zinc-800 hover:border-cyber-500/40 cursor-pointer transition-colors flex items-center justify-between"
                      >
                        <div>
                          <div className="text-xs font-mono font-bold text-cyber-neon">{rel.id}</div>
                          <div className="text-xs text-white truncate max-w-[200px]">{rel.name}</div>
                          <div className="text-[10px] text-zinc-400 font-mono mt-0.5">{rel.relation}</div>
                        </div>
                        <ExternalLink className="w-4 h-4 text-zinc-500 hover:text-cyber-neon" />
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Tab 2: Safe Preview & Hex Viewer */}
          {activeTab === 'preview' && (
            <div className="space-y-6">
              {/* Render based on artifact preview kind */}
              {artifact.preview?.kind === 'text' && (
                <div className="space-y-3">
                  <div className="flex items-center justify-between text-xs font-mono">
                    <span className="text-zinc-400 font-semibold uppercase">Decoded Text &amp; Log Excerpt</span>
                    <span className="text-emerald-400">Safely Sanitized / Non-Executable</span>
                  </div>
                  <div className="p-4 rounded-xl bg-black border border-zinc-800 font-mono text-xs text-zinc-200 whitespace-pre-wrap leading-relaxed max-h-72 overflow-y-auto">
                    {artifact.preview.content}
                  </div>
                </div>
              )}

              {artifact.preview?.kind === 'db' && (
                <div className="space-y-3">
                  <div className="flex items-center justify-between text-xs font-mono">
                    <span className="text-zinc-400 font-semibold uppercase">
                      Extracted SQLite Table: <strong className="text-cyber-neon">{artifact.preview.tableName}</strong>
                    </span>
                    <span className="text-zinc-500">Read-Only Carved Records</span>
                  </div>
                  <div className="overflow-x-auto rounded-xl border border-zinc-800 bg-dark-950">
                    <table className="w-full text-left font-mono text-xs">
                      <thead className="bg-dark-900 border-b border-zinc-800 text-[11px] text-zinc-400">
                        <tr>
                          {artifact.preview.columns?.map((col, idx) => (
                            <th key={idx} className="py-2.5 px-3 uppercase font-semibold">{col}</th>
                          ))}
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-zinc-800/60">
                        {artifact.preview.rows?.map((row, rIdx) => (
                          <tr key={rIdx} className="hover:bg-dark-900/50">
                            {row.map((cell, cIdx) => (
                              <td key={cIdx} className="py-2 px-3 text-zinc-200">
                                {cell === 'FLAGGED' || cell === 'CRITICAL' ? (
                                  <span className="px-1.5 py-0.5 rounded bg-red-500/20 text-red-400 border border-red-500/40 text-[10px]">
                                    {cell}
                                  </span>
                                ) : (
                                  cell
                                )}
                              </td>
                            ))}
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}

              {artifact.preview?.kind === 'image' && (
                <div className="space-y-3">
                  <div className="flex items-center justify-between text-xs font-mono">
                    <span className="text-zinc-400 font-semibold uppercase">Reconstructed Photo Raster</span>
                    <span className="text-amber-400">Scanline Glitch / Incomplete Sector</span>
                  </div>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4 p-4 rounded-xl bg-black border border-zinc-800">
                    <div className="relative rounded-lg overflow-hidden border border-zinc-800 max-h-64 flex items-center justify-center bg-dark-950">
                      <img 
                        src={artifact.preview.imageUrl} 
                        alt="Recovered evidence" 
                        className="max-h-60 object-contain"
                      />
                      <div className="absolute bottom-0 inset-x-0 bg-black/75 p-2 text-[10px] font-mono text-amber-300 text-center">
                        {artifact.preview.caption}
                      </div>
                    </div>
                    <div className="space-y-3 font-mono text-xs">
                      <div className="text-zinc-400 font-semibold uppercase text-[11px] border-b border-zinc-800 pb-1">
                        EXIF Metadata Dump:
                      </div>
                      {artifact.preview.exif && Object.entries(artifact.preview.exif).map(([key, val]) => (
                        <div key={key} className="flex justify-between py-1 border-b border-zinc-900 text-xs">
                          <span className="text-zinc-500 capitalize">{key}:</span>
                          <span className="text-white font-medium">{val}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              )}

              {/* Raw Hex & ASCII Dump View */}
              <div className="space-y-2">
                <div className="flex items-center justify-between text-xs font-mono">
                  <span className="text-zinc-400 font-semibold uppercase flex items-center space-x-1">
                    <Binary className="w-3.5 h-3.5 text-cyber-neon" />
                    <span>Raw Hex &amp; ASCII Inspection (Offset {artifact.metadata?.sourceOffset})</span>
                  </span>
                  <button
                    onClick={() => copyToClipboard(artifact.hexDump || '', 'hex')}
                    className="text-[11px] text-cyber-neon hover:underline flex items-center space-x-1"
                  >
                    <Copy className="w-3 h-3" />
                    <span>{copiedField === 'hex' ? 'Copied!' : 'Copy Hex'}</span>
                  </button>
                </div>
                <div className="p-4 rounded-xl bg-black border border-zinc-800 font-mono text-[11px] text-emerald-400/90 whitespace-pre overflow-x-auto leading-relaxed max-h-56">
                  {artifact.hexDump || '00000000  00 00 00 00 00 00 00 00  |........|'}
                </div>
              </div>
            </div>
          )}

          {/* Tab 3: Integrity Analysis & Recovery Details */}
          {activeTab === 'integrity' && (
            <div className="space-y-6">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                {/* Integrity Analysis */}
                <div className="p-5 rounded-xl bg-dark-950 border border-zinc-800 space-y-4">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-mono font-bold text-white uppercase tracking-wider">
                      Structural Integrity
                    </span>
                    <span className="font-mono text-sm font-extrabold text-cyber-neon">
                      {artifact.integrity.toFixed(0)}% Complete
                    </span>
                  </div>

                  <div className="w-full h-2.5 bg-dark-900 rounded-full overflow-hidden border border-zinc-800">
                    <div 
                      className={`h-full rounded-full ${
                        artifact.integrity >= 90 ? 'bg-emerald-400' : artifact.integrity >= 60 ? 'bg-amber-400' : 'bg-red-400'
                      }`}
                      style={{ width: `${artifact.integrity}%` }}
                    />
                  </div>

                  <div className="space-y-2 text-xs font-mono pt-2">
                    <div>
                      <span className="text-zinc-500 uppercase text-[10px] block">Corruption Classification:</span>
                      <span className="text-amber-300 font-semibold">{artifact.integrityAnalysis?.corruptionType}</span>
                    </div>
                    <div>
                      <span className="text-zinc-500 uppercase text-[10px] block">Missing Sector Info:</span>
                      <span className="text-zinc-300">{artifact.integrityAnalysis?.missingData}</span>
                    </div>
                  </div>
                </div>

                {/* Recovery & Carving Engine Info */}
                <div className="p-5 rounded-xl bg-dark-950 border border-zinc-800 space-y-4">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-mono font-bold text-white uppercase tracking-wider">
                      Carving Assembly Metrics
                    </span>
                    <span className="font-mono text-xs text-cyber-bright">
                      Confidence: {artifact.recoveryInfo?.carvingConfidence}%
                    </span>
                  </div>

                  <div className="space-y-2 text-xs font-mono">
                    <div>
                      <span className="text-zinc-500 uppercase text-[10px] block">Fragmentation Status:</span>
                      <span className="text-white font-semibold">{artifact.recoveryInfo?.fragmentationStatus}</span>
                    </div>
                    <div>
                      <span className="text-zinc-500 uppercase text-[10px] block">Source Reassembled Fragments:</span>
                      <ul className="mt-1 space-y-1 list-disc list-inside text-zinc-300 text-[11px]">
                        {artifact.recoveryInfo?.sourceFragments?.map((frag, idx) => (
                          <li key={idx}>{frag}</li>
                        ))}
                      </ul>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Tab 4: Chain of Custody & Judicial Proof */}
          {activeTab === 'chain' && (
            <div className="space-y-6">
              {/* Cryptographic Seal Banner */}
              <div className="p-4 rounded-xl bg-emerald-950/30 border border-emerald-500/40 flex items-center space-x-3 text-emerald-400">
                <ShieldCheck className="w-8 h-8 shrink-0 text-emerald-400" />
                <div className="text-xs font-mono">
                  <div className="font-bold text-sm text-white">ISO/IEC 27037 ADMISSIBLE CHAIN OF CUSTODY VERIFIED</div>
                  <div className="text-emerald-300 mt-0.5">
                    Derived from read-only image copy. Original source bitstream remains 100% unaltered.
                  </div>
                </div>
              </div>

              {/* Cryptographic Hashes Table */}
              <div className="p-4 rounded-xl bg-dark-950 border border-zinc-800 space-y-3 font-mono text-xs">
                <div className="text-zinc-400 font-semibold uppercase text-[11px]">
                  Artifact Cryptographic Signatures
                </div>

                <div className="space-y-2">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1 p-2 rounded bg-dark-900 border border-zinc-800/80">
                    <span className="text-zinc-500 uppercase text-[10px]">SHA-256:</span>
                    <div className="flex items-center space-x-2">
                      <span className="text-cyber-neon font-mono select-all text-[11px] truncate max-w-sm sm:max-w-md">
                        {artifact.metadata?.sha256}
                      </span>
                      <button
                        onClick={() => copyToClipboard(artifact.metadata?.sha256, 'sha256')}
                        className="text-zinc-400 hover:text-white"
                      >
                        <Copy className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  </div>

                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1 p-2 rounded bg-dark-900 border border-zinc-800/80">
                    <span className="text-zinc-500 uppercase text-[10px]">SSDEEP Fuzzy Hash:</span>
                    <span className="text-zinc-300 font-mono text-[11px] truncate max-w-sm sm:max-w-md">
                      {artifact.metadata?.ssdeep}
                    </span>
                  </div>

                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1 p-2 rounded bg-dark-900 border border-zinc-800/80">
                    <span className="text-zinc-500 uppercase text-[10px]">Source Disk Hash (Ingest):</span>
                    <span className="text-zinc-400 font-mono text-[11px]">
                      {caseContext.rawImageHash || 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'}
                    </span>
                  </div>
                </div>
              </div>

              {/* Pipeline Versions & Custody Meta */}
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 font-mono text-xs">
                <div className="p-3 rounded-lg bg-dark-950 border border-zinc-800">
                  <span className="text-[10px] text-zinc-500 uppercase block">Investigator / Actor</span>
                  <span className="text-white font-semibold">{caseContext.investigator || 'Det. H. Chen'}</span>
                </div>

                <div className="p-3 rounded-lg bg-dark-950 border border-zinc-800">
                  <span className="text-[10px] text-zinc-500 uppercase block">Pipeline Engines</span>
                  <span className="text-white font-semibold">GB-v2.1 • LibMagic-5.41</span>
                </div>

                <div className="p-3 rounded-lg bg-dark-950 border border-zinc-800">
                  <span className="text-[10px] text-zinc-500 uppercase block">Tamper Verification</span>
                  <span className="text-emerald-400 font-semibold">PASS (Zero Delta)</span>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Modal Footer Bar */}
        <div className="px-6 py-3.5 bg-dark-950 border-t border-zinc-800 flex items-center justify-between text-xs font-mono">
          <span className="text-zinc-500">
            Case: {caseContext.caseId || 'CASE-2026-NIGHTFALL'} • Sector Offset: {artifact.metadata?.sourceOffset}
          </span>
          <button
            onClick={onClose}
            className="px-4 py-2 rounded-lg bg-zinc-800 hover:bg-zinc-700 text-white font-medium transition-colors"
          >
            Close Inspector
          </button>
        </div>
      </div>
    </div>
  );
}
