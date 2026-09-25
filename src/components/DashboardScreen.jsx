import React, { useState, useMemo } from 'react';
import { 
  FileText, Database, Image as ImageIcon, Terminal, Binary, AlertOctagon, 
  Copy, CheckCircle, Percent, Filter, Search, RotateCcw, SlidersHorizontal, 
  Layers, BarChart2, ShieldAlert, Sliders, ChevronDown, ChevronUp, AlertTriangle,
  ArrowRight, ExternalLink, Zap, ShieldCheck, Download
} from 'lucide-react';
import ArtifactTable from './ArtifactTable';
import { ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip, Cell, RadarChart, Radar, PolarGrid, PolarAngleAxis } from 'recharts';
import { computePriorityScore, WEIGHTS, PRIORITY_PRESETS } from '../engine/priorityEngine';
import { getTierBadgeClass, getConfidenceBadgeClass } from '../utils/forensicUtils';

export default function DashboardScreen({ 
  artifacts, 
  onSelectArtifact, 
  onOpenIntegrity,
  onNavigateToInvestigation,
  caseContext 
}) {
  const [searchTerm, setSearchTerm] = useState('');
  const [typeFilter, setTypeFilter] = useState('All');
  const [tierFilter, setTierFilter] = useState('All');
  const [confFilter, setConfFilter] = useState('All');
  const [hideDuplicates, setHideDuplicates] = useState(false);
  const [incidentWindowOnly, setIncidentWindowOnly] = useState(false);
  const [sortField, setSortField] = useState('priorityScore');
  const [sortOrder, setSortOrder] = useState('desc');
  const [showCharts, setShowCharts] = useState(false);
  
  // ── View Mode: Ranked Table vs 4 High-Value Groups (Lanes) ─────────────
  const [viewMode, setViewMode] = useState('table'); // 'table' | 'lanes'

  // ── Interactive Priority Weight Simulator State ──────────────────────────
  const [showWeightSimulator, setShowWeightSimulator] = useState(false);
  const [activeWeights, setActiveWeights] = useState({ ...WEIGHTS });
  const [activePreset, setActivePreset] = useState('standard');

  // Dynamic re-scoring of artifacts with active custom weights
  const rescoredArtifacts = useMemo(() => {
    return artifacts.map(a => {
      const scored = computePriorityScore({
        relevance: a.evidenceRelevance,
        integrity: a.integrity,
        inferredMtime: a.metadata?.timestamps?.inferredMtime,
        incidentStart: caseContext?.incidentStart,
        incidentEnd: caseContext?.incidentEnd,
        isDuplicate: a.duplicate,
        ssdeepSimilarity: a.ssdeepSimilarity ?? 0,
        noisePenalty: a.noisePenalty ?? 0,
        classificationConfidence: a.classificationConfidence,
        customWeights: activeWeights,
      });

      return {
        ...a,
        priorityScore: scored.score,
        priorityTier: scored.tier,
        reviewRequired: scored.reviewRequired,
        priorityExplanation: {
          ...a.priorityExplanation,
          ...scored.breakdown,
          total: Math.round(scored.score * 1000) / 10
        }
      };
    });
  }, [artifacts, activeWeights, caseContext]);

  // Compute summary stats dynamically from rescored artifacts
  const stats = useMemo(() => {
    const total = rescoredArtifacts.length;
    let docs = 0;
    let dbs = 0;
    let photos = 0;
    let traces = 0;
    let critical = 0;
    let high = 0;
    let medium = 0;
    let low = 0;
    let corrupted = 0;
    let duplicates = 0;
    let totalConf = 0;

    rescoredArtifacts.forEach(a => {
      const t = a.type?.toLowerCase() || '';
      if (t === 'document') docs++;
      else if (t === 'db log') dbs++;
      else if (t.includes('photo')) photos++;
      else if (t === 'system trace') traces++;

      const tier = a.priorityTier?.toLowerCase();
      if (tier === 'critical') critical++;
      else if (tier === 'high') high++;
      else if (tier === 'medium') medium++;
      else if (tier === 'low') low++;

      if (a.integrity < 95 || a.corruption !== 'None') corrupted++;
      if (a.duplicate) duplicates++;
      totalConf += a.classificationConfidence;
    });

    const avgConf = total > 0 ? (totalConf / total).toFixed(1) : '0';

    return {
      total,
      docs,
      dbs,
      photos,
      traces,
      critical,
      high,
      medium,
      low,
      corrupted,
      duplicates,
      avgConf
    };
  }, [rescoredArtifacts]);

  // Apply a weight preset
  const handleApplyPreset = (presetKey) => {
    const preset = PRIORITY_PRESETS[presetKey];
    if (preset) {
      setActivePreset(presetKey);
      setActiveWeights({ ...preset.weights });
    }
  };

  // Adjust a single weight slider
  const handleWeightChange = (key, val) => {
    setActivePreset('custom');
    setActiveWeights(prev => ({ ...prev, [key]: parseFloat(val) }));
  };

  // Export current filtered artifacts as CSV
  const handleExportCSV = () => {
    const cols = ['id','filename','type','priorityTier','priorityScore','classificationConfidence','integrity','corruption','evidenceRelevance','recoverability','duplicate'];
    const header = cols.join(',');
    const rows = filteredArtifacts.map(a =>
      cols.map(c => {
        const v = a[c];
        if (typeof v === 'string' && v.includes(',')) return `"${v}"`;
        return v ?? '';
      }).join(',')
    );
    const csv = [header, ...rows].join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `CLASSIFICATION_EXPORT_${caseContext?.caseId || 'CASE'}.csv`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  // Tier distribution chart data
  const tierChartData = [
    { name: 'Critical', count: stats.critical, fill: '#ef4444' },
    { name: 'High', count: stats.high, fill: '#f97316' },
    { name: 'Medium', count: stats.medium, fill: '#eab308' },
    { name: 'Low', count: stats.low, fill: '#71717a' },
  ];

  // Handle sorting
  const handleSort = (field) => {
    if (sortField === field) {
      setSortOrder(sortOrder === 'asc' ? 'desc' : 'asc');
    } else {
      setSortField(field);
      setSortOrder('desc');
    }
  };

  // Filtered and sorted artifacts
  const filteredArtifacts = useMemo(() => {
    return rescoredArtifacts
      .filter((a) => {
        // Search
        if (searchTerm) {
          const q = searchTerm.toLowerCase();
          const matchId = a.id.toLowerCase().includes(q);
          const matchName = a.filename.toLowerCase().includes(q);
          const matchReason = a.reason.toLowerCase().includes(q);
          const matchOffset = a.metadata?.sourceOffset?.toLowerCase().includes(q);
          if (!matchId && !matchName && !matchReason && !matchOffset) return false;
        }

        // Type
        if (typeFilter !== 'All') {
          if (typeFilter === 'Photos' && !a.type?.toLowerCase().includes('photo')) return false;
          if (typeFilter !== 'Photos' && a.type !== typeFilter) return false;
        }

        // Tier
        if (tierFilter !== 'All' && a.priorityTier !== tierFilter) {
          return false;
        }

        // Confidence
        if (confFilter === '>95%' && a.classificationConfidence < 95) return false;
        if (confFilter === '>85%' && a.classificationConfidence < 85) return false;
        if (confFilter === '<85%' && a.classificationConfidence >= 85) return false;

        // Duplicates
        if (hideDuplicates && a.duplicate) return false;

        // Incident window
        if (incidentWindowOnly && !a.metadata?.timestamps?.incidentWindowMatch) return false;

        return true;
      })
      .sort((a, b) => {
        let valA = a[sortField];
        let valB = b[sortField];

        if (typeof valA === 'string') {
          valA = valA.toLowerCase();
          valB = valB.toLowerCase();
        }

        if (valA < valB) return sortOrder === 'asc' ? -1 : 1;
        if (valA > valB) return sortOrder === 'asc' ? 1 : -1;
        return 0;
      });
  }, [rescoredArtifacts, searchTerm, typeFilter, tierFilter, confFilter, hideDuplicates, incidentWindowOnly, sortField, sortOrder]);

  // Grouped artifacts into the 4 high-value categories (for 4-Lane Grouped View)
  const laneGroups = useMemo(() => {
    const filterAndSort = (items) => {
      return items.sort((a, b) => b.priorityScore - a.priorityScore);
    };

    return {
      documents: filterAndSort(rescoredArtifacts.filter(a => a.type === 'Document')),
      dbLogs: filterAndSort(rescoredArtifacts.filter(a => a.type === 'DB log')),
      photos: filterAndSort(rescoredArtifacts.filter(a => a.type?.toLowerCase().includes('photo'))),
      systemTraces: filterAndSort(rescoredArtifacts.filter(a => a.type === 'System trace')),
    };
  }, [rescoredArtifacts]);

  return (
    <div className="space-y-6 animate-fadeIn font-sans">
      
      {/* ── Top Banner with Case Info & Navigation Actions ───────────── */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-4 rounded-xl bg-dark-900 border border-zinc-800">
        <div>
          <div className="flex items-center space-x-2">
            <span className="px-2 py-0.5 text-[10px] font-mono font-semibold bg-cyber-500/20 text-cyber-neon border border-cyber-500/40 rounded">
              EVIDENCE MATRIX ACTIVE
            </span>
            <span className="text-xs font-mono text-zinc-400">
              Case ID: <span className="text-white font-semibold">{caseContext?.caseId || 'CASE-2026-NIGHTFALL'}</span>
            </span>
          </div>
          <h2 className="text-lg font-bold text-white mt-1 font-mono">
            {caseContext?.caseTitle || 'Carved Fragments Triaging & Relevance Assessment'}
          </h2>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          {/* Priority Simulator Toggle */}
          <button
            onClick={() => setShowWeightSimulator(!showWeightSimulator)}
            className={`px-3 py-1.5 rounded-lg text-xs font-mono border transition-all flex items-center space-x-1.5 ${
              showWeightSimulator 
                ? 'bg-amber-500/20 text-amber-300 border-amber-500/40 shadow-sm' 
                : 'bg-dark-950 text-zinc-400 border-zinc-700 hover:text-white'
            }`}
          >
            <Sliders className="w-3.5 h-3.5 text-amber-400" />
            <span>{showWeightSimulator ? 'Hide Weights Simulator' : '⚡ Priority Simulator'}</span>
          </button>

          {/* Visual Analytics Toggle */}
          <button
            onClick={() => setShowCharts(!showCharts)}
            className={`px-3 py-1.5 rounded-lg text-xs font-mono border transition-all flex items-center space-x-1.5 ${
              showCharts 
                ? 'bg-cyber-500/20 text-cyber-neon border-cyber-500/40' 
                : 'bg-dark-950 text-zinc-400 border-zinc-700 hover:text-white'
            }`}
          >
            <BarChart2 className="w-3.5 h-3.5" />
            <span>{showCharts ? 'Hide Visual Analytics' : 'Visual Analytics'}</span>
          </button>

          {/* CSV Export */}
          <button
            onClick={handleExportCSV}
            className="px-3 py-1.5 rounded-lg text-xs font-mono border transition-all flex items-center space-x-1.5 bg-dark-950 text-zinc-400 border-zinc-700 hover:text-emerald-400 hover:border-emerald-500/40"
            title="Export classified artifacts to CSV"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Export CSV</span>
          </button>

          {/* Quick Decision Support Navigation */}
          {onNavigateToInvestigation && (
            <button
              onClick={onNavigateToInvestigation}
              className="px-3 py-1.5 rounded-lg text-xs font-mono font-bold bg-cyber-500/20 text-cyber-neon border border-cyber-500/50 hover:bg-cyber-500/30 transition-all flex items-center space-x-1.5 shadow-neon"
              title="Launch 5-Second Case Triage & Decision Engine"
            >
              <ShieldAlert className="w-3.5 h-3.5 text-cyber-neon" />
              <span>Decision Support Center →</span>
            </button>
          )}
        </div>
      </div>

      {/* ── INTERACTIVE CATEGORY SUMMARY CARDS (Click to filter) ───────── */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
        {/* Total Artifacts */}
        <div 
          onClick={() => setTypeFilter('All')}
          className={`cursor-pointer p-3.5 rounded-xl transition-all border ${
            typeFilter === 'All'
              ? 'bg-dark-850 border-cyber-500/80 shadow-neon ring-1 ring-cyber-neon'
              : 'bg-dark-900 border-zinc-800 hover:border-zinc-700'
          }`}
        >
          <div className="text-[11px] font-mono text-zinc-400 uppercase tracking-wider">Total Artifacts</div>
          <div className="text-2xl font-mono font-extrabold text-white mt-1">{stats.total}</div>
          <div className="text-[10px] text-zinc-500 mt-1 font-mono">Click to show all</div>
        </div>

        {/* Documents */}
        <div 
          onClick={() => setTypeFilter(typeFilter === 'Document' ? 'All' : 'Document')}
          className={`cursor-pointer p-3.5 rounded-xl transition-all border ${
            typeFilter === 'Document'
              ? 'bg-blue-950/40 border-blue-400 shadow-[0_0_15px_rgba(96,165,250,0.3)] ring-1 ring-blue-400'
              : 'bg-dark-900 border-zinc-800 hover:border-blue-500/40'
          }`}
        >
          <div className="text-[11px] font-mono text-blue-400 uppercase tracking-wider flex items-center space-x-1">
            <FileText className="w-3 h-3" />
            <span>Documents</span>
          </div>
          <div className="text-2xl font-mono font-extrabold text-white mt-1">{stats.docs}</div>
          <div className="text-[10px] text-zinc-400 mt-1 font-mono">PDF, DOCX, TXT</div>
        </div>

        {/* DB Logs */}
        <div 
          onClick={() => setTypeFilter(typeFilter === 'DB log' ? 'All' : 'DB log')}
          className={`cursor-pointer p-3.5 rounded-xl transition-all border ${
            typeFilter === 'DB log'
              ? 'bg-emerald-950/40 border-emerald-400 shadow-[0_0_15px_rgba(52,211,153,0.3)] ring-1 ring-emerald-400'
              : 'bg-dark-900 border-zinc-800 hover:border-emerald-500/40'
          }`}
        >
          <div className="text-[11px] font-mono text-emerald-400 uppercase tracking-wider flex items-center space-x-1">
            <Database className="w-3 h-3" />
            <span>DB Logs</span>
          </div>
          <div className="text-2xl font-mono font-extrabold text-white mt-1">{stats.dbs}</div>
          <div className="text-[10px] text-zinc-400 mt-1 font-mono">SQLite, EVTX, Wal</div>
        </div>

        {/* Photos */}
        <div 
          onClick={() => setTypeFilter(typeFilter === 'Photos' ? 'All' : 'Photos')}
          className={`cursor-pointer p-3.5 rounded-xl transition-all border ${
            typeFilter === 'Photos'
              ? 'bg-amber-950/40 border-amber-400 shadow-[0_0_15px_rgba(251,191,36,0.3)] ring-1 ring-amber-400'
              : 'bg-dark-900 border-zinc-800 hover:border-amber-500/40'
          }`}
        >
          <div className="text-[11px] font-mono text-amber-400 uppercase tracking-wider flex items-center space-x-1">
            <ImageIcon className="w-3 h-3" />
            <span>Photos</span>
          </div>
          <div className="text-2xl font-mono font-extrabold text-white mt-1">{stats.photos}</div>
          <div className="text-[10px] text-zinc-400 mt-1 font-mono">JPEG, PNG, EXIF</div>
        </div>

        {/* System Traces */}
        <div 
          onClick={() => setTypeFilter(typeFilter === 'System trace' ? 'All' : 'System trace')}
          className={`cursor-pointer p-3.5 rounded-xl transition-all border ${
            typeFilter === 'System trace'
              ? 'bg-purple-950/40 border-purple-400 shadow-[0_0_15px_rgba(192,132,252,0.3)] ring-1 ring-purple-400'
              : 'bg-dark-900 border-zinc-800 hover:border-purple-500/40'
          }`}
        >
          <div className="text-[11px] font-mono text-purple-400 uppercase tracking-wider flex items-center space-x-1">
            <Terminal className="w-3 h-3" />
            <span>System Traces</span>
          </div>
          <div className="text-2xl font-mono font-extrabold text-white mt-1">{stats.traces}</div>
          <div className="text-[10px] text-zinc-400 mt-1 font-mono">PCAP, PE, Regf</div>
        </div>

        {/* Avg Confidence */}
        <div className="p-3.5 rounded-xl bg-dark-900 border border-cyber-500/30 shadow-neon">
          <div className="text-[11px] font-mono text-cyber-neon uppercase tracking-wider flex items-center space-x-1">
            <Percent className="w-3 h-3" />
            <span>Avg. Confidence</span>
          </div>
          <div className="text-2xl font-mono font-extrabold text-cyber-bright mt-1">{stats.avgConf}%</div>
          <div className="text-[10px] text-zinc-500 mt-1 font-mono">ML + Rule Accuracy</div>
        </div>
      </div>

      {/* ── PRIORITY WEIGHT SIMULATOR PANEL (Interactive §4 Math Config) ── */}
      {showWeightSimulator && (
        <div className="p-5 rounded-xl bg-dark-950 border border-amber-500/40 shadow-2xl space-y-4 animate-fadeIn font-mono">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-zinc-800 pb-3">
            <div>
              <div className="flex items-center space-x-2">
                <Sliders className="w-4 h-4 text-amber-400" />
                <h3 className="text-sm font-bold text-white uppercase tracking-wider">
                  Interactive Priority Formula Simulator (§4 Spec)
                </h3>
              </div>
              <p className="text-xs text-zinc-400 mt-0.5">
                Formula: <strong className="text-amber-300">P = w1·Integrity + w2·Relevance + w3·Recency + w4·Uniqueness - w5·Noise</strong>
              </p>
            </div>

            {/* Presets */}
            <div className="flex items-center space-x-1 text-xs">
              <span className="text-zinc-500 text-[11px] mr-1">Case Presets:</span>
              <button
                onClick={() => handleApplyPreset('standard')}
                className={`px-2.5 py-1 rounded transition-colors ${
                  activePreset === 'standard' 
                    ? 'bg-amber-500/20 text-amber-300 border border-amber-500/50 font-bold' 
                    : 'bg-dark-900 text-zinc-400 hover:text-white border border-zinc-800'
                }`}
              >
                Standard Triage
              </button>
              <button
                onClick={() => handleApplyPreset('ransomware')}
                className={`px-2.5 py-1 rounded transition-colors ${
                  activePreset === 'ransomware' 
                    ? 'bg-red-500/20 text-red-300 border border-red-500/50 font-bold' 
                    : 'bg-dark-900 text-zinc-400 hover:text-white border border-zinc-800'
                }`}
              >
                Ransomware Breach
              </button>
              <button
                onClick={() => handleApplyPreset('exfiltration')}
                className={`px-2.5 py-1 rounded transition-colors ${
                  activePreset === 'exfiltration' 
                    ? 'bg-blue-500/20 text-blue-300 border border-blue-500/50 font-bold' 
                    : 'bg-dark-900 text-zinc-400 hover:text-white border border-zinc-800'
                }`}
              >
                IP Exfiltration
              </button>
            </div>
          </div>

          {/* Sliders */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4 pt-1">
            {/* w2 Relevance */}
            <div className="p-3 rounded-lg bg-dark-900 border border-zinc-800 space-y-1.5">
              <div className="flex justify-between text-xs">
                <span className="text-red-400 font-bold">w2 Relevance:</span>
                <span className="text-white font-mono font-bold">{(activeWeights.relevance * 100).toFixed(0)}%</span>
              </div>
              <input
                type="range"
                min="0.05"
                max="0.60"
                step="0.05"
                value={activeWeights.relevance}
                onChange={(e) => handleWeightChange('relevance', e.target.value)}
                className="w-full accent-red-500 cursor-pointer"
              />
              <div className="text-[10px] text-zinc-500">IOC / keyword match weight</div>
            </div>

            {/* w1 Integrity */}
            <div className="p-3 rounded-lg bg-dark-900 border border-zinc-800 space-y-1.5">
              <div className="flex justify-between text-xs">
                <span className="text-emerald-400 font-bold">w1 Integrity:</span>
                <span className="text-white font-mono font-bold">{(activeWeights.integrity * 100).toFixed(0)}%</span>
              </div>
              <input
                type="range"
                min="0.05"
                max="0.60"
                step="0.05"
                value={activeWeights.integrity}
                onChange={(e) => handleWeightChange('integrity', e.target.value)}
                className="w-full accent-emerald-500 cursor-pointer"
              />
              <div className="text-[10px] text-zinc-500">Completeness &amp; validity</div>
            </div>

            {/* w3 Recency */}
            <div className="p-3 rounded-lg bg-dark-900 border border-zinc-800 space-y-1.5">
              <div className="flex justify-between text-xs">
                <span className="text-blue-400 font-bold">w3 Recency:</span>
                <span className="text-white font-mono font-bold">{(activeWeights.recency * 100).toFixed(0)}%</span>
              </div>
              <input
                type="range"
                min="0.05"
                max="0.50"
                step="0.05"
                value={activeWeights.recency}
                onChange={(e) => handleWeightChange('recency', e.target.value)}
                className="w-full accent-blue-500 cursor-pointer"
              />
              <div className="text-[10px] text-zinc-500">Incident window proximity</div>
            </div>

            {/* w4 Uniqueness */}
            <div className="p-3 rounded-lg bg-dark-900 border border-zinc-800 space-y-1.5">
              <div className="flex justify-between text-xs">
                <span className="text-amber-400 font-bold">w4 Uniqueness:</span>
                <span className="text-white font-mono font-bold">{(activeWeights.uniqueness * 100).toFixed(0)}%</span>
              </div>
              <input
                type="range"
                min="0.05"
                max="0.40"
                step="0.05"
                value={activeWeights.uniqueness}
                onChange={(e) => handleWeightChange('uniqueness', e.target.value)}
                className="w-full accent-amber-500 cursor-pointer"
              />
              <div className="text-[10px] text-zinc-500">Penalizes duplicate hashes</div>
            </div>

            {/* w5 Noise Penalty */}
            <div className="p-3 rounded-lg bg-dark-900 border border-zinc-800 space-y-1.5">
              <div className="flex justify-between text-xs">
                <span className="text-zinc-400 font-bold">w5 Noise Penalty:</span>
                <span className="text-white font-mono font-bold">-{(activeWeights.noisePenalty * 100).toFixed(0)}%</span>
              </div>
              <input
                type="range"
                min="0.00"
                max="0.30"
                step="0.05"
                value={activeWeights.noisePenalty}
                onChange={(e) => handleWeightChange('noisePenalty', e.target.value)}
                className="w-full accent-zinc-400 cursor-pointer"
              />
              <div className="text-[10px] text-zinc-500">Demotes temp/cache noise</div>
            </div>
          </div>
        </div>
      )}

      {/* ── RICH VISUAL ANALYTICS PANEL ──────────────────────────────── */}
      {showCharts && (
        <div className="p-5 rounded-xl bg-dark-950 border border-cyber-500/30 shadow-2xl space-y-5 animate-fadeIn">
          <div className="flex items-center justify-between border-b border-zinc-800 pb-3">
            <div className="flex items-center space-x-2">
              <BarChart2 className="w-4 h-4 text-cyber-neon" />
              <h3 className="text-sm font-bold text-white font-mono uppercase tracking-wider">Visual Analytics — Evidence Classification Matrix</h3>
            </div>
            <span className="text-[10px] text-zinc-500 font-mono">{rescoredArtifacts.length} artifacts · Live rescored</span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4">
            {/* Chart 1: Priority Tier Distribution */}
            <div className="p-3 rounded-xl bg-dark-900 border border-zinc-800 space-y-2">
              <div className="text-[11px] font-mono text-zinc-400 uppercase tracking-wider font-semibold">Priority Tier Distribution</div>
              <ResponsiveContainer width="100%" height={140}>
                <BarChart data={tierChartData} margin={{ top: 4, right: 4, left: -20, bottom: 4 }}>
                  <XAxis dataKey="name" tick={{ fill: '#71717a', fontSize: 10 }} axisLine={false} tickLine={false} />
                  <YAxis tick={{ fill: '#71717a', fontSize: 10 }} axisLine={false} tickLine={false} />
                  <Tooltip contentStyle={{ background: '#0f172a', border: '1px solid #334155', borderRadius: 8, fontSize: 11 }} />
                  <Bar dataKey="count" radius={[4,4,0,0]}>
                    {tierChartData.map((entry, i) => <Cell key={i} fill={entry.fill} />)}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>

            {/* Chart 2: Artifact Type Breakdown */}
            <div className="p-3 rounded-xl bg-dark-900 border border-zinc-800 space-y-2">
              <div className="text-[11px] font-mono text-zinc-400 uppercase tracking-wider font-semibold">Artifact Type Breakdown</div>
              <ResponsiveContainer width="100%" height={140}>
                <BarChart
                  data={[
                    { name: 'Documents', count: stats.docs, fill: '#60a5fa' },
                    { name: 'DB Logs', count: stats.dbs, fill: '#34d399' },
                    { name: 'Photos', count: stats.photos, fill: '#fbbf24' },
                    { name: 'Sys Traces', count: stats.traces, fill: '#c084fc' },
                  ]}
                  margin={{ top: 4, right: 4, left: -20, bottom: 4 }}
                >
                  <XAxis dataKey="name" tick={{ fill: '#71717a', fontSize: 9 }} axisLine={false} tickLine={false} />
                  <YAxis tick={{ fill: '#71717a', fontSize: 10 }} axisLine={false} tickLine={false} />
                  <Tooltip contentStyle={{ background: '#0f172a', border: '1px solid #334155', borderRadius: 8, fontSize: 11 }} />
                  <Bar dataKey="count" radius={[4,4,0,0]}>
                    {[{ fill: '#60a5fa' }, { fill: '#34d399' }, { fill: '#fbbf24' }, { fill: '#c084fc' }].map((e, i) => <Cell key={i} fill={e.fill} />)}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>

            {/* Chart 3: Integrity Spread (histogram buckets) */}
            <div className="p-3 rounded-xl bg-dark-900 border border-zinc-800 space-y-2">
              <div className="text-[11px] font-mono text-zinc-400 uppercase tracking-wider font-semibold">Integrity Score Spread</div>
              <ResponsiveContainer width="100%" height={140}>
                <BarChart
                  data={(() => {
                    const buckets = [
                      { range: '0-25', count: 0, fill: '#ef4444' },
                      { range: '25-50', count: 0, fill: '#f97316' },
                      { range: '50-75', count: 0, fill: '#eab308' },
                      { range: '75-90', count: 0, fill: '#22d3ee' },
                      { range: '90+', count: 0, fill: '#10b981' },
                    ];
                    rescoredArtifacts.forEach(a => {
                      const v = a.overallIntegrity ?? a.integrity ?? 0;
                      if (v < 25) buckets[0].count++;
                      else if (v < 50) buckets[1].count++;
                      else if (v < 75) buckets[2].count++;
                      else if (v < 90) buckets[3].count++;
                      else buckets[4].count++;
                    });
                    return buckets;
                  })()}
                  margin={{ top: 4, right: 4, left: -20, bottom: 4 }}
                >
                  <XAxis dataKey="range" tick={{ fill: '#71717a', fontSize: 9 }} axisLine={false} tickLine={false} />
                  <YAxis tick={{ fill: '#71717a', fontSize: 10 }} axisLine={false} tickLine={false} />
                  <Tooltip contentStyle={{ background: '#0f172a', border: '1px solid #334155', borderRadius: 8, fontSize: 11 }} />
                  <Bar dataKey="count" radius={[4,4,0,0]}>
                    {[{ fill: '#ef4444' }, { fill: '#f97316' }, { fill: '#eab308' }, { fill: '#22d3ee' }, { fill: '#10b981' }].map((e, i) => <Cell key={i} fill={e.fill} />)}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>

            {/* Chart 4: Classification Confidence Histogram */}
            <div className="p-3 rounded-xl bg-dark-900 border border-zinc-800 space-y-2">
              <div className="text-[11px] font-mono text-zinc-400 uppercase tracking-wider font-semibold">Confidence Histogram</div>
              <ResponsiveContainer width="100%" height={140}>
                <BarChart
                  data={(() => {
                    const buckets = [
                      { range: '<70%', count: 0, fill: '#ef4444' },
                      { range: '70-80%', count: 0, fill: '#f97316' },
                      { range: '80-90%', count: 0, fill: '#eab308' },
                      { range: '90-95%', count: 0, fill: '#22d3ee' },
                      { range: '95%+', count: 0, fill: '#10b981' },
                    ];
                    rescoredArtifacts.forEach(a => {
                      const c = a.classificationConfidence ?? 0;
                      if (c < 70) buckets[0].count++;
                      else if (c < 80) buckets[1].count++;
                      else if (c < 90) buckets[2].count++;
                      else if (c < 95) buckets[3].count++;
                      else buckets[4].count++;
                    });
                    return buckets;
                  })()}
                  margin={{ top: 4, right: 4, left: -20, bottom: 4 }}
                >
                  <XAxis dataKey="range" tick={{ fill: '#71717a', fontSize: 9 }} axisLine={false} tickLine={false} />
                  <YAxis tick={{ fill: '#71717a', fontSize: 10 }} axisLine={false} tickLine={false} />
                  <Tooltip contentStyle={{ background: '#0f172a', border: '1px solid #334155', borderRadius: 8, fontSize: 11 }} />
                  <Bar dataKey="count" radius={[4,4,0,0]}>
                    {[{ fill: '#ef4444' }, { fill: '#f97316' }, { fill: '#eab308' }, { fill: '#22d3ee' }, { fill: '#10b981' }].map((e, i) => <Cell key={i} fill={e.fill} />)}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* Stats Summary Row */}
          <div className="grid grid-cols-3 sm:grid-cols-6 gap-2 pt-2 border-t border-zinc-800 font-mono text-xs">
            {[
              { label: 'Corrupted', val: stats.corrupted, color: 'text-rose-400' },
              { label: 'Duplicates', val: stats.duplicates, color: 'text-zinc-400' },
              { label: 'Critical', val: stats.critical, color: 'text-red-400' },
              { label: 'High', val: stats.high, color: 'text-orange-400' },
              { label: 'Medium', val: stats.medium, color: 'text-amber-400' },
              { label: 'Avg Conf', val: stats.avgConf + '%', color: 'text-cyber-neon' },
            ].map(({ label, val, color }) => (
              <div key={label} className="p-2 rounded bg-dark-900 border border-zinc-800 text-center">
                <div className={`font-bold text-sm ${color}`}>{val}</div>
                <div className="text-zinc-500 text-[10px] uppercase">{label}</div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ── VIEW SWITCHER BAR & FILTER CONTROLS ─────────────────────── */}
      <div className="p-4 rounded-xl bg-dark-900 border border-zinc-800 space-y-3">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
          
          {/* Search Input */}
          <div className="relative flex-1 max-w-md">
            <Search className="w-4 h-4 text-zinc-500 absolute left-3 top-2.5" />
            <input
              type="text"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder="Search filename, sector offset (0x...), hash, or IOC..."
              className="w-full pl-9 pr-4 py-2 bg-dark-950 border border-zinc-700/80 rounded-lg text-xs font-mono text-white placeholder-zinc-500 focus:outline-none focus:border-cyber-neon"
            />
          </div>

          {/* View Mode Switcher (Ranked Table vs 4 High-Value Groups) */}
          <div className="flex items-center space-x-2">
            <div className="bg-dark-950 p-1 rounded-lg border border-zinc-800 flex items-center text-xs font-mono">
              <button
                onClick={() => setViewMode('table')}
                className={`px-3 py-1.5 rounded transition-all flex items-center space-x-1.5 ${
                  viewMode === 'table'
                    ? 'bg-cyber-500/20 text-cyber-neon border border-cyber-500/40 font-bold shadow-sm'
                    : 'text-zinc-400 hover:text-white'
                }`}
              >
                <span>📋 Ranked Table View</span>
              </button>
              <button
                onClick={() => setViewMode('lanes')}
                className={`px-3 py-1.5 rounded transition-all flex items-center space-x-1.5 ${
                  viewMode === 'lanes'
                    ? 'bg-cyber-500/20 text-cyber-neon border border-cyber-500/40 font-bold shadow-sm'
                    : 'text-zinc-400 hover:text-white'
                }`}
              >
                <Layers className="w-3.5 h-3.5 text-cyber-neon" />
                <span>🗂️ 4 High-Value Groups</span>
              </button>
            </div>
          </div>
        </div>

        {/* Filter Pills: Type and Tier */}
        <div className="flex flex-wrap items-center justify-between gap-3 pt-2 border-t border-zinc-800/80 text-xs font-mono">
          {/* Type Filter Pills */}
          <div className="flex flex-wrap items-center gap-1.5">
            <span className="text-zinc-500 mr-1 text-[11px] uppercase">Group:</span>
            {['All', 'Document', 'DB log', 'Photos', 'System trace'].map((t) => (
              <button
                key={t}
                onClick={() => setTypeFilter(t)}
                className={`px-2.5 py-1 rounded text-[11px] transition-colors ${
                  typeFilter === t
                    ? 'bg-cyber-500/20 text-cyber-neon border border-cyber-500/40 font-semibold'
                    : 'bg-dark-950 text-zinc-400 hover:text-white border border-zinc-800'
                }`}
              >
                {t === 'All' ? 'All Groups' : t}
              </button>
            ))}
          </div>

          {/* Tier Filter Pills */}
          <div className="flex flex-wrap items-center gap-1.5">
            <span className="text-zinc-500 mr-1 text-[11px] uppercase">Priority:</span>
            {['All', 'Critical', 'High', 'Medium', 'Low'].map((tier) => (
              <button
                key={tier}
                onClick={() => setTierFilter(tier)}
                className={`px-2.5 py-1 rounded text-[11px] transition-colors ${
                  tierFilter === tier
                    ? 'bg-zinc-200 text-black font-bold'
                    : 'bg-dark-950 text-zinc-400 hover:text-white border border-zinc-800'
                }`}
              >
                {tier}
              </button>
            ))}

            {(searchTerm || typeFilter !== 'All' || tierFilter !== 'All' || hideDuplicates || incidentWindowOnly) && (
              <button
                onClick={() => {
                  setSearchTerm('');
                  setTypeFilter('All');
                  setTierFilter('All');
                  setHideDuplicates(false);
                  setIncidentWindowOnly(false);
                }}
                className="ml-2 px-2 py-1 rounded bg-zinc-800 hover:bg-zinc-750 text-zinc-300 text-[10px] flex items-center space-x-1"
                title="Reset All Filters"
              >
                <RotateCcw className="w-3 h-3" />
                <span>Reset</span>
              </button>
            )}
          </div>
        </div>
      </div>

      {/* ── RENDER VIEW: 4 HIGH-VALUE GROUPS (LANES) VS RANKED TABLE ─── */}
      {viewMode === 'lanes' ? (
        /* ── 4 HIGH-VALUE GROUPS (LANES VIEW) ────────────────────────── */
        <div className="space-y-3 animate-fadeIn">
          <div className="flex items-center justify-between text-xs font-mono px-1">
            <span className="text-zinc-400 font-bold uppercase">
              Categorized &amp; Prioritized Evidence Matrix (4 Target Forensic Groups)
            </span>
            <span className="text-zinc-500 text-[11px]">
              Sorted by Priority Score within each lane
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4">
            
            {/* 1. DOCUMENTS LANE */}
            <div className="rounded-xl border border-blue-500/30 bg-dark-900 overflow-hidden flex flex-col">
              <div className="p-3 bg-dark-950 border-b border-zinc-800 flex items-center justify-between">
                <div className="flex items-center space-x-2">
                  <FileText className="w-4 h-4 text-blue-400" />
                  <span className="font-mono font-bold text-white text-xs">1. Documents</span>
                </div>
                <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-blue-500/20 text-blue-400 border border-blue-500/40">
                  {laneGroups.documents.length} Files
                </span>
              </div>

              <div className="p-3 space-y-2.5 overflow-y-auto max-h-[650px] scrollbar-thin flex-1">
                {laneGroups.documents.map((art) => (
                  <ArtifactLaneCard 
                    key={art.id} 
                    artifact={art} 
                    onSelect={() => onSelectArtifact(art)}
                    onOpenIntegrity={() => onOpenIntegrity(art)}
                  />
                ))}
              </div>
            </div>

            {/* 2. DATABASE LOGS LANE */}
            <div className="rounded-xl border border-emerald-500/30 bg-dark-900 overflow-hidden flex flex-col">
              <div className="p-3 bg-dark-950 border-b border-zinc-800 flex items-center justify-between">
                <div className="flex items-center space-x-2">
                  <Database className="w-4 h-4 text-emerald-400" />
                  <span className="font-mono font-bold text-white text-xs">2. Database Logs</span>
                </div>
                <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-emerald-500/20 text-emerald-400 border border-emerald-500/40">
                  {laneGroups.dbLogs.length} Files
                </span>
              </div>

              <div className="p-3 space-y-2.5 overflow-y-auto max-h-[650px] scrollbar-thin flex-1">
                {laneGroups.dbLogs.map((art) => (
                  <ArtifactLaneCard 
                    key={art.id} 
                    artifact={art} 
                    onSelect={() => onSelectArtifact(art)}
                    onOpenIntegrity={() => onOpenIntegrity(art)}
                  />
                ))}
              </div>
            </div>

            {/* 3. PHOTOS LANE */}
            <div className="rounded-xl border border-amber-500/30 bg-dark-900 overflow-hidden flex flex-col">
              <div className="p-3 bg-dark-950 border-b border-zinc-800 flex items-center justify-between">
                <div className="flex items-center space-x-2">
                  <ImageIcon className="w-4 h-4 text-amber-400" />
                  <span className="font-mono font-bold text-white text-xs">3. Photos / Images</span>
                </div>
                <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-amber-500/20 text-amber-400 border border-amber-500/40">
                  {laneGroups.photos.length} Files
                </span>
              </div>

              <div className="p-3 space-y-2.5 overflow-y-auto max-h-[650px] scrollbar-thin flex-1">
                {laneGroups.photos.map((art) => (
                  <ArtifactLaneCard 
                    key={art.id} 
                    artifact={art} 
                    onSelect={() => onSelectArtifact(art)}
                    onOpenIntegrity={() => onOpenIntegrity(art)}
                  />
                ))}
              </div>
            </div>

            {/* 4. SYSTEM TRACES LANE */}
            <div className="rounded-xl border border-purple-500/30 bg-dark-900 overflow-hidden flex flex-col">
              <div className="p-3 bg-dark-950 border-b border-zinc-800 flex items-center justify-between">
                <div className="flex items-center space-x-2">
                  <Terminal className="w-4 h-4 text-purple-400" />
                  <span className="font-mono font-bold text-white text-xs">4. System Traces</span>
                </div>
                <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-purple-500/20 text-purple-400 border border-purple-500/40">
                  {laneGroups.systemTraces.length} Files
                </span>
              </div>

              <div className="p-3 space-y-2.5 overflow-y-auto max-h-[650px] scrollbar-thin flex-1">
                {laneGroups.systemTraces.map((art) => (
                  <ArtifactLaneCard 
                    key={art.id} 
                    artifact={art} 
                    onSelect={() => onSelectArtifact(art)}
                    onOpenIntegrity={() => onOpenIntegrity(art)}
                  />
                ))}
              </div>
            </div>

          </div>
        </div>
      ) : (
        /* ── RANKED TABLE VIEW ────────────────────────────────────────── */
        <ArtifactTable
          artifacts={filteredArtifacts}
          onSelectArtifact={onSelectArtifact}
          onOpenIntegrity={onOpenIntegrity}
          sortField={sortField}
          sortOrder={sortOrder}
          onSort={handleSort}
        />
      )}

    </div>
  );
}

// ── SUB-COMPONENT: Artifact Card in 4-Lane Grouped View ──────────────────
function ArtifactLaneCard({ artifact, onSelect, onOpenIntegrity }) {
  const tierClass = getTierBadgeClass(artifact.priorityTier);
  const confClass = getConfidenceBadgeClass(artifact.classificationConfidence);
  const isSpoofed = artifact.antiForensicAlert || artifact.conflictDetected;

  return (
    <div 
      onClick={onSelect}
      className={`p-3 rounded-xl border transition-all cursor-pointer bg-dark-950/80 hover:bg-dark-850 ${
        isSpoofed 
          ? 'border-rose-500/50 hover:border-rose-400 shadow-[0_0_12px_rgba(244,63,94,0.2)]' 
          : 'border-zinc-800/80 hover:border-zinc-700'
      }`}
    >
      {/* Top row: ID and Priority Tier Badge */}
      <div className="flex items-center justify-between gap-1 mb-1.5 font-mono">
        <span className="text-[11px] text-cyber-neon font-bold">
          {artifact.id}
        </span>
        <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${tierClass}`}>
          {artifact.priorityTier} ({artifact.priorityScore.toFixed(3)})
        </span>
      </div>

      {/* Filename & Spoof Alert */}
      <div className="font-semibold text-white text-xs truncate" title={artifact.filename}>
        {artifact.filename}
      </div>

      {/* Anti-forensic spoof banner if detected */}
      {isSpoofed && (
        <div className="mt-1 px-1.5 py-0.5 rounded bg-rose-500/20 border border-rose-500/40 text-rose-300 text-[10px] font-mono flex items-center space-x-1 animate-pulse">
          <AlertTriangle className="w-3 h-3 text-rose-400 shrink-0" />
          <span className="truncate">Spoofed Ext: Disguised Executable</span>
        </div>
      )}

      {/* Reason text */}
      <p className="text-[11px] text-zinc-400 line-clamp-2 mt-1 leading-snug">
        {artifact.reason}
      </p>

      {/* Badges: Integrity meter & Classification Method */}
      <div className="mt-2.5 pt-2 border-t border-zinc-900 flex items-center justify-between text-[10px] font-mono text-zinc-400">
        <div className="flex items-center space-x-1.5">
          <span>Integ:</span>
          <span className="font-bold text-white">{artifact.integrity}%</span>
        </div>
        <div className="text-[9px] px-1.5 py-0.5 rounded bg-dark-900 border border-zinc-800 text-zinc-300">
          {artifact.classificationExplanation?.method?.includes('Rule') ? 'Rule: Magic' : 'ML: Entropy'}
        </div>
      </div>
    </div>
  );
}
