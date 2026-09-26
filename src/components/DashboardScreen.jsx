import React, { useState, useMemo, useEffect } from 'react';
import { 
  FileText, Database, Image as ImageIcon, Terminal, Binary, AlertOctagon, 
  Copy, CheckCircle, Percent, Filter, Search, RotateCcw, SlidersHorizontal, 
  Layers, BarChart2, ShieldAlert, Sliders, ChevronDown, ChevronUp, AlertTriangle,
  ArrowRight, ExternalLink, Zap, ShieldCheck, Download, Radio, HardDrive,
  Cpu, Clock, AlertCircle, RefreshCw, GitCommit, Eye
} from 'lucide-react';
import ArtifactTable from './ArtifactTable';
import { ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip, Cell, ScatterChart, Scatter, ZAxis } from 'recharts';
import { computePriorityScore, WEIGHTS, PRIORITY_PRESETS } from '../engine/priorityEngine';
import { triageEvidence } from '../services/forensicApi';
import { getTierBadgeClass, getConfidenceBadgeClass } from '../utils/forensicUtils';

export default function DashboardScreen({ 
  artifacts: initialArtifacts, 
  onSelectArtifact, 
  onOpenIntegrity,
  onNavigateToInvestigation,
  caseContext,
  onAddAuditLog = () => {}
}) {
  // Mode: Real Mode (API-connected) vs Demo Mode (RANSOMWARE-2026-001)
  const [dataSourceMode, setDataSourceMode] = useState('demo'); // 'real' | 'demo'
  const [liveApiArtifacts, setLiveApiArtifacts] = useState(null);
  const [isLoadingApi, setIsLoadingApi] = useState(false);
  const [apiError, setApiError] = useState(null);

  // Filters & Controls
  const [searchTerm, setSearchTerm] = useState('');
  const [typeFilter, setTypeFilter] = useState('All');
  const [tierFilter, setTierFilter] = useState('All');
  const [confFilter, setConfFilter] = useState('All');
  const [hideDuplicates, setHideDuplicates] = useState(false);
  const [incidentWindowOnly, setIncidentWindowOnly] = useState(false);
  const [conflictsOnly, setConflictsOnly] = useState(false);
  const [reviewOnly, setReviewOnly] = useState(false);

  // Sorting
  const [sortField, setSortField] = useState('priorityScore');
  const [sortOrder, setSortOrder] = useState('desc');

  // View Mode: 'table' | 'lanes' | 'clusters' | 'timeline' | 'charts'
  const [viewMode, setViewMode] = useState('table');

  // Priority Weight Simulator State
  const [showWeightSimulator, setShowWeightSimulator] = useState(false);
  const [activeWeights, setActiveWeights] = useState({
    integrity: 0.30,
    relevance: 0.35,
    recency: 0.20,
    uniqueness: 0.15,
    noisePenalty: 0.10,
  });
  const [activePreset, setActivePreset] = useState('standard');
  const [weightsRecalculatedMsg, setWeightsRecalculatedMsg] = useState('');

  // Fetch real evidence from backend API when switched to 'real' mode
  const fetchRealTriage = async () => {
    setIsLoadingApi(true);
    setApiError(null);
    try {
      const data = await triageEvidence(caseContext, activeWeights);
      if (data && data.artifacts && data.artifacts.length > 0) {
        setLiveApiArtifacts(data.artifacts);
      } else {
        setApiError('No real artifacts returned from /api/triage. Using fallback.');
      }
    } catch (err) {
      setApiError(err.message);
    } finally {
      setIsLoadingApi(false);
    }
  };

  useEffect(() => {
    if (dataSourceMode === 'real') {
      fetchRealTriage();
    }
  }, [dataSourceMode]);

  // Active raw artifacts: live API artifacts if in real mode, else initialArtifacts
  const rawArtifacts = useMemo(() => {
    if (dataSourceMode === 'real' && liveApiArtifacts && liveApiArtifacts.length > 0) {
      return liveApiArtifacts;
    }
    return initialArtifacts;
  }, [dataSourceMode, liveApiArtifacts, initialArtifacts]);

  // Recalculate priority scores dynamically whenever weights change
  const rescoredArtifacts = useMemo(() => {
    return rawArtifacts.map(a => {
      const scored = computePriorityScore({
        relevance: a.evidenceRelevance ?? a.relevance ?? 50,
        integrity: a.integrity ?? a.overallIntegrity ?? 50,
        inferredMtime: a.metadata?.timestamps?.inferredMtime || a.mtime,
        incidentStart: caseContext?.incidentStart || '2026-09-24T10:00:00Z',
        incidentEnd: caseContext?.incidentEnd || '2026-09-24T18:00:00Z',
        isDuplicate: a.duplicate ?? false,
        ssdeepSimilarity: a.ssdeepSimilarity ?? 0,
        noisePenalty: a.noisePenalty ?? a.noise ?? 0,
        classificationConfidence: a.classificationConfidence ?? a.confidence ?? 85,
        customWeights: activeWeights,
        filename: a.filename,
      });

      const category = a.category || a.type || 'Documents';
      const isConflict = a.conflict || a.antiForensicAlert;

      return {
        ...a,
        category,
        type: category,
        priorityScore: scored.score,
        priorityTier: scored.tier,
        reviewRequired: scored.reviewRequired || isConflict || (a.classificationConfidence < 60),
        explanations: scored.explanations || a.explanations || [],
        priorityExplanation: {
          ...a.priorityExplanation,
          ...scored.breakdown,
          total: Math.round(scored.score * 1000) / 10
        }
      };
    });
  }, [rawArtifacts, activeWeights, caseContext]);

  // Summary statistics computed dynamically from rescored artifacts
  const stats = useMemo(() => {
    const total = rescoredArtifacts.length;
    let critical = 0;
    let high = 0;
    let medium = 0;
    let low = 0;
    let needsReview = 0;
    let conflicts = 0;
    let duplicates = 0;
    let totalConf = 0;

    const categories = {
      'Documents': 0,
      'Database Logs': 0,
      'Photos': 0,
      'System Traces': 0,
      'Network Captures': 0,
      'Registry Hives': 0,
      'Executables': 0,
    };

    rescoredArtifacts.forEach(a => {
      const tier = a.priorityTier?.toLowerCase();
      if (tier === 'critical') critical++;
      else if (tier === 'high') high++;
      else if (tier === 'medium') medium++;
      else if (tier === 'low') low++;

      if (a.reviewRequired) needsReview++;
      if (a.conflict || a.antiForensicAlert) conflicts++;
      if (a.duplicate) duplicates++;

      const c = a.category || a.type || 'Documents';
      if (categories[c] !== undefined) {
        categories[c]++;
      } else {
        categories['Documents']++;
      }

      totalConf += (a.classificationConfidence || 85);
    });

    const avgConf = total > 0 ? (totalConf / total).toFixed(1) : '88.5';

    return {
      total,
      critical,
      high,
      medium,
      low,
      needsReview,
      conflicts,
      duplicates,
      avgConf,
      categories
    };
  }, [rescoredArtifacts]);

  // Apply weight presets
  const handleApplyPreset = (presetKey) => {
    const preset = PRIORITY_PRESETS[presetKey];
    if (preset) {
      setActivePreset(presetKey);
      setActiveWeights({ ...preset.weights });
      setWeightsRecalculatedMsg(`Applied preset: ${preset.name}`);
      onAddAuditLog({
        stage: 'Priority Recalculation',
        action: 'PRESET_SELECTED',
        details: `Selected preset ${preset.name}`,
        weights: preset.weights,
        timestamp: new Date().toISOString()
      });
      setTimeout(() => setWeightsRecalculatedMsg(''), 3000);
    }
  };

  // Adjust a single weight slider
  const handleWeightChange = (key, val) => {
    setActivePreset('custom');
    const newWeights = { ...activeWeights, [key]: parseFloat(val) };
    setActiveWeights(newWeights);
    setWeightsRecalculatedMsg(`Priority recalculated with custom weights`);
    onAddAuditLog({
      stage: 'Priority Recalculation',
      action: 'WEIGHTS_CHANGED',
      details: `Adjusted weight ${key} to ${val}`,
      weights: newWeights,
      timestamp: new Date().toISOString()
    });
    setTimeout(() => setWeightsRecalculatedMsg(''), 3000);
  };

  // Export CSV
  const handleExportCSV = () => {
    const cols = ['rank','id','filename','category','priorityTier','priorityScore','integrity','evidenceRelevance','temporal','uniqueness','noisePenalty','reviewRequired'];
    const header = cols.join(',');
    const rows = filteredArtifacts.map((a, idx) => {
      return [
        idx + 1,
        `"${a.id || a.artifact_id || ''}"`,
        `"${a.filename || ''}"`,
        `"${a.category || a.type || ''}"`,
        `"${a.priorityTier || ''}"`,
        (a.priorityScore || 0).toFixed(3),
        Math.round((a.integrity > 1 ? a.integrity : a.integrity * 100) || 0),
        Math.round((a.evidenceRelevance > 1 ? a.evidenceRelevance : a.evidenceRelevance * 100) || 0),
        Math.round((a.temporal > 1 ? a.temporal : a.temporal * 100) || 75),
        Math.round((a.uniqueness > 1 ? a.uniqueness : a.uniqueness * 100) || 100),
        Math.round((a.noisePenalty > 1 ? a.noisePenalty : a.noisePenalty * 100) || 0),
        a.reviewRequired ? 'YES' : 'NO'
      ].join(',');
    });
    const csv = [header, ...rows].join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = `FORENSIC_TRIAGE_${caseContext?.caseId || 'CASE'}.csv`;
    document.body.appendChild(anchor);
    anchor.click();
    document.body.removeChild(anchor);
    URL.revokeObjectURL(url);
  };

  // Sorting
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
          const matchId = (a.id || a.artifact_id || '').toLowerCase().includes(q);
          const matchName = (a.filename || '').toLowerCase().includes(q);
          const matchReason = (a.reason || '').toLowerCase().includes(q);
          const matchCategory = (a.category || a.type || '').toLowerCase().includes(q);
          const matchFormat = (a.subtype || a.classification?.format || '').toLowerCase().includes(q);
          const matchSha = (a.sha256 || a.metadata?.sha256 || '').toLowerCase().includes(q);
          const matchIocs = JSON.stringify(a.semantic_indicators || a.iocs || {}).toLowerCase().includes(q);
          if (!matchId && !matchName && !matchReason && !matchCategory && !matchFormat && !matchSha && !matchIocs) {
            return false;
          }
        }

        // Category Filter
        if (typeFilter !== 'All') {
          const cat = a.category || a.type;
          if (cat !== typeFilter) return false;
        }

        // Tier Filter
        if (tierFilter !== 'All' && a.priorityTier !== tierFilter) {
          return false;
        }

        // Confidence Filter
        if (confFilter === '>95%' && (a.classificationConfidence || 85) < 95) return false;
        if (confFilter === '>85%' && (a.classificationConfidence || 85) < 85) return false;
        if (confFilter === '<85%' && (a.classificationConfidence || 85) >= 85) return false;

        // Conflicts Only
        if (conflictsOnly && !(a.conflict || a.antiForensicAlert)) return false;

        // Review Only
        if (reviewOnly && !a.reviewRequired) return false;

        // Duplicates
        if (hideDuplicates && a.duplicate) return false;

        // Incident Window Only
        if (incidentWindowOnly) {
          const isMatch = a.metadata?.timestamps?.incidentWindowMatch || (a.temporal >= 0.95);
          if (!isMatch) return false;
        }

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
      })
      .map((item, idx) => ({ ...item, rank: idx + 1 }));
  }, [
    rescoredArtifacts, searchTerm, typeFilter, tierFilter, confFilter,
    conflictsOnly, reviewOnly, hideDuplicates, incidentWindowOnly,
    sortField, sortOrder
  ]);

  // 7 High-Value Category Groups for Lane View
  const laneGroups = useMemo(() => {
    const sortDesc = (items) => [...items].sort((a, b) => (b.priorityScore || 0) - (a.priorityScore || 0));
    return {
      documents: sortDesc(rescoredArtifacts.filter(a => (a.category || a.type) === 'Documents')),
      dbLogs: sortDesc(rescoredArtifacts.filter(a => (a.category || a.type) === 'Database Logs')),
      photos: sortDesc(rescoredArtifacts.filter(a => (a.category || a.type) === 'Photos')),
      systemTraces: sortDesc(rescoredArtifacts.filter(a => (a.category || a.type) === 'System Traces')),
      networkCaptures: sortDesc(rescoredArtifacts.filter(a => (a.category || a.type) === 'Network Captures')),
      registryHives: sortDesc(rescoredArtifacts.filter(a => (a.category || a.type) === 'Registry Hives')),
      executables: sortDesc(rescoredArtifacts.filter(a => (a.category || a.type) === 'Executables')),
    };
  }, [rescoredArtifacts]);

  // Duplicate Clusters
  const duplicateClusters = useMemo(() => {
    const dups = rescoredArtifacts.filter(a => a.duplicate || (a.filename && a.filename.includes('copy')) || (a.filename && a.filename.includes('backup')));
    return [
      {
        clusterId: 'CLUSTER-#12',
        representative: 'photo_001.jpg',
        similarity: 96.4,
        uniquenessScore: 0.036,
        description: 'Exfiltrated staging photos (SSDEEP 96.4% near-duplicate)',
        artifacts: [
          { name: 'photo_001.jpg', size: '4,109 B', sha256: 'a1b2c3d4...', isMaster: true },
          { name: 'photo_copy.jpg', size: '4,109 B', sha256: 'a1b2c3d4...', isMaster: false },
          { name: 'photo_backup.jpg', size: '4,112 B', sha256: 'e8f9a0b1...', isMaster: false }
        ]
      }
    ];
  }, [rescoredArtifacts]);

  // Timeline events plotted around incident window
  const timelineEvents = useMemo(() => {
    return rescoredArtifacts
      .filter(a => a.mtime || a.metadata?.timestamps?.inferredMtime)
      .slice(0, 10)
      .sort((a, b) => new Date(a.metadata?.timestamps?.inferredMtime || a.mtime) - new Date(b.metadata?.timestamps?.inferredMtime || b.mtime));
  }, [rescoredArtifacts]);

  // Chart data
  const tierChartData = [
    { name: 'Critical', count: stats.critical, fill: '#ef4444' },
    { name: 'High', count: stats.high, fill: '#f97316' },
    { name: 'Medium', count: stats.medium, fill: '#eab308' },
    { name: 'Low', count: stats.low, fill: '#71717a' },
  ];

  const categoryChartData = Object.entries(stats.categories).map(([cat, count]) => ({
    name: cat.replace(' ', '\n'),
    count
  }));

  // Scatter plot data (Relevance vs Integrity)
  const scatterData = rescoredArtifacts.map(a => ({
    x: Math.round((a.integrity > 1 ? a.integrity : a.integrity * 100) || 50),
    y: Math.round((a.evidenceRelevance > 1 ? a.evidenceRelevance : a.evidenceRelevance * 100) || 50),
    name: a.filename,
    tier: a.priorityTier
  }));

  return (
    <section id="section-03-prioritization" className="scroll-mt-24 space-y-6 animate-fadeIn font-sans rounded-2xl border border-cyber-500/30 bg-dark-900/90 backdrop-blur-md p-6 sm:p-8 shadow-2xl relative overflow-hidden">
      
      {/* ── Top Header Banner ────────────────────────────────────────── */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-6 border-b border-zinc-800">
        <div>
          <div className="inline-flex items-center space-x-2 px-3 py-1 rounded-md bg-cyber-500/15 border border-cyber-500/40 text-cyber-neon font-mono text-xs mb-2">
            <span className="w-2 h-2 rounded-full bg-cyber-neon animate-pulse"></span>
            <span className="font-bold tracking-wider">OBJECTIVE 03</span>
            <span className="text-zinc-500">•</span>
            <span>CLASSIFICATION &amp; PRIORITIZATION ENGINE</span>
          </div>
          <h2 className="text-2xl sm:text-3xl font-extrabold text-white tracking-wide flex items-center space-x-3">
            <span>CLASSIFICATION &amp; PRIORITIZATION</span>
          </h2>
          <p className="text-sm text-zinc-400 mt-1 max-w-3xl">
            Group and prioritize high-value artifacts (documents, database logs, photos, system traces) using multi-factor transparent scoring (P = w1*I + w2*R + w3*T + w4*U - w5*N).
          </p>
        </div>

        {/* Action Controls & Mode Switch */}
        <div className="flex flex-wrap items-center gap-2.5">
          
          {/* Data Source Mode Toggle */}
          <div className="bg-dark-950 p-1 rounded-xl border border-zinc-800 flex items-center text-xs font-mono">
            <button
              onClick={() => setDataSourceMode('real')}
              className={`px-3 py-1.5 rounded-lg transition-all flex items-center space-x-1.5 ${
                dataSourceMode === 'real'
                  ? 'bg-cyber-500/25 text-cyber-neon border border-cyber-500/50 font-bold shadow-sm'
                  : 'text-zinc-400 hover:text-white'
              }`}
              title="Query live backend /api/triage endpoint"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${isLoadingApi ? 'animate-spin text-cyber-neon' : ''}`} />
              <span>REAL MODE</span>
            </button>
            <button
              onClick={() => setDataSourceMode('demo')}
              className={`px-3 py-1.5 rounded-lg transition-all flex items-center space-x-1.5 ${
                dataSourceMode === 'demo'
                  ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40 font-bold shadow-sm'
                  : 'text-zinc-400 hover:text-white'
              }`}
              title="Explore deterministic ransomware demo case"
            >
              <span>DEMO CASE</span>
            </button>
          </div>

          {/* Priority Weight Simulator Toggle */}
          <button
            onClick={() => setShowWeightSimulator(!showWeightSimulator)}
            className={`px-3 py-1.5 rounded-xl text-xs font-mono border transition-all flex items-center space-x-1.5 ${
              showWeightSimulator 
                ? 'bg-amber-500/25 text-amber-300 border-amber-500/50 shadow-sm' 
                : 'bg-dark-950 text-zinc-400 border-zinc-700 hover:text-white'
            }`}
          >
            <Sliders className="w-3.5 h-3.5 text-amber-400" />
            <span>{showWeightSimulator ? 'Hide Simulator' : '⚡ Weight Simulator'}</span>
          </button>

          {/* CSV Export */}
          <button
            onClick={handleExportCSV}
            className="px-3 py-1.5 rounded-xl text-xs font-mono border transition-all flex items-center space-x-1.5 bg-dark-950 text-zinc-400 border-zinc-700 hover:text-emerald-400 hover:border-emerald-500/40"
            title="Export ranked triage list to CSV"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Export CSV</span>
          </button>

          {/* Decision Center Navigation */}
          {onNavigateToInvestigation && (
            <button
              onClick={onNavigateToInvestigation}
              className="px-3.5 py-1.5 rounded-xl text-xs font-mono font-bold bg-cyber-500/20 text-cyber-neon border border-cyber-500/50 hover:bg-cyber-500/30 transition-all flex items-center space-x-1.5 shadow-neon"
            >
              <ShieldAlert className="w-3.5 h-3.5 text-cyber-neon" />
              <span>Decision Center →</span>
            </button>
          )}
        </div>
      </div>

      {/* ── FORENSIC CONFLICT ALERT BANNER (If extension signature mismatch detected) ── */}
      {stats.conflicts > 0 && (
        <div 
          onClick={() => {
            setConflictsOnly(!conflictsOnly);
            setViewMode('table');
          }}
          className="p-4 rounded-xl bg-red-950/40 border border-red-500/60 shadow-[0_0_15px_rgba(239,68,68,0.2)] flex items-center justify-between cursor-pointer hover:bg-red-950/60 transition-all animate-pulse"
        >
          <div className="flex items-center space-x-3">
            <div className="p-2 rounded-lg bg-red-500/20 border border-red-500/40 text-red-400 shrink-0">
              <AlertOctagon className="w-5 h-5 text-red-400" />
            </div>
            <div>
              <div className="text-xs font-mono font-bold text-red-400 uppercase tracking-wider flex items-center space-x-2">
                <span>⚠ FORENSIC CONFLICT DETECTED ({stats.conflicts} ARTIFACT{stats.conflicts > 1 ? 'S' : ''})</span>
                <span className="text-[10px] px-2 py-0.5 rounded bg-red-500/20 text-red-300 border border-red-500/40">EXTENSION_SIGNATURE_MISMATCH</span>
              </div>
              <p className="text-xs text-zinc-300 font-sans mt-0.5">
                Binary byte signatures disagree with file extensions (e.g. <strong>invoice.jpg</strong> starting with <strong>MZ PE</strong> header). Actual binary bytes take strict precedence. Click to isolate conflicting artifacts.
              </p>
            </div>
          </div>
          <button className="px-3 py-1.5 rounded-lg text-xs font-mono font-bold bg-red-500/20 text-red-300 border border-red-500/50 shrink-0">
            {conflictsOnly ? 'Show All' : 'Filter Conflicts Only'}
          </button>
        </div>
      )}

      {/* ── PRIORITY OVERVIEW STATS (Large Visual Cards) ───────────────── */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
        {/* Total Artifacts */}
        <div 
          onClick={() => { setTierFilter('All'); setTypeFilter('All'); setConflictsOnly(false); setReviewOnly(false); }}
          className="p-3.5 rounded-xl bg-dark-900 border border-zinc-800 hover:border-zinc-700 cursor-pointer transition-all"
        >
          <div className="text-[11px] font-mono text-zinc-400 uppercase tracking-wider">Total Evidence</div>
          <div className="text-2xl font-mono font-extrabold text-white mt-1">{stats.total}</div>
          <div className="text-[10px] text-zinc-500 mt-1 font-mono">100% Carved &amp; Scored</div>
        </div>

        {/* Critical Tier */}
        <div 
          onClick={() => setTierFilter(tierFilter === 'Critical' ? 'All' : 'Critical')}
          className={`p-3.5 rounded-xl border cursor-pointer transition-all ${
            tierFilter === 'Critical' 
              ? 'bg-red-950/40 border-red-500 shadow-[0_0_15px_rgba(239,68,68,0.3)] ring-1 ring-red-400' 
              : 'bg-dark-900 border-zinc-800 hover:border-red-500/40'
          }`}
        >
          <div className="text-[11px] font-mono text-red-400 uppercase tracking-wider font-bold flex items-center justify-between">
            <span>CRITICAL</span>
            <span className="text-[10px] text-red-400/80 font-normal">P ≥ 0.75</span>
          </div>
          <div className="text-2xl font-mono font-extrabold text-red-400 mt-1">{stats.critical}</div>
          <div className="text-[10px] text-zinc-400 mt-1 font-mono">Immediate Triage</div>
        </div>

        {/* High Tier */}
        <div 
          onClick={() => setTierFilter(tierFilter === 'High' ? 'All' : 'High')}
          className={`p-3.5 rounded-xl border cursor-pointer transition-all ${
            tierFilter === 'High' 
              ? 'bg-orange-950/40 border-orange-500 shadow-[0_0_15px_rgba(249,115,22,0.3)] ring-1 ring-orange-400' 
              : 'bg-dark-900 border-zinc-800 hover:border-orange-500/40'
          }`}
        >
          <div className="text-[11px] font-mono text-orange-400 uppercase tracking-wider font-bold flex items-center justify-between">
            <span>HIGH</span>
            <span className="text-[10px] text-orange-400/80 font-normal">0.50 - 0.75</span>
          </div>
          <div className="text-2xl font-mono font-extrabold text-orange-400 mt-1">{stats.high}</div>
          <div className="text-[10px] text-zinc-400 mt-1 font-mono">Secondary Leads</div>
        </div>

        {/* Medium Tier */}
        <div 
          onClick={() => setTierFilter(tierFilter === 'Medium' ? 'All' : 'Medium')}
          className={`p-3.5 rounded-xl border cursor-pointer transition-all ${
            tierFilter === 'Medium' 
              ? 'bg-yellow-950/40 border-yellow-500 shadow-[0_0_15px_rgba(234,179,8,0.3)] ring-1 ring-yellow-400' 
              : 'bg-dark-900 border-zinc-800 hover:border-yellow-500/40'
          }`}
        >
          <div className="text-[11px] font-mono text-yellow-400 uppercase tracking-wider font-bold flex items-center justify-between">
            <span>MEDIUM</span>
            <span className="text-[10px] text-yellow-400/80 font-normal">0.25 - 0.50</span>
          </div>
          <div className="text-2xl font-mono font-extrabold text-yellow-400 mt-1">{stats.medium}</div>
          <div className="text-[10px] text-zinc-400 mt-1 font-mono">Supporting Context</div>
        </div>

        {/* Low Tier */}
        <div 
          onClick={() => setTierFilter(tierFilter === 'Low' ? 'All' : 'Low')}
          className={`p-3.5 rounded-xl border cursor-pointer transition-all ${
            tierFilter === 'Low' 
              ? 'bg-zinc-800 border-zinc-400' 
              : 'bg-dark-900 border-zinc-800 hover:border-zinc-700'
          }`}
        >
          <div className="text-[11px] font-mono text-zinc-400 uppercase tracking-wider font-bold flex items-center justify-between">
            <span>LOW</span>
            <span className="text-[10px] text-zinc-500 font-normal">P &lt; 0.25</span>
          </div>
          <div className="text-2xl font-mono font-extrabold text-zinc-300 mt-1">{stats.low}</div>
          <div className="text-[10px] text-zinc-500 mt-1 font-mono">De-prioritized / Noise</div>
        </div>

        {/* Needs Review */}
        <div 
          onClick={() => setReviewOnly(!reviewOnly)}
          className={`p-3.5 rounded-xl border cursor-pointer transition-all ${
            reviewOnly 
              ? 'bg-amber-950/40 border-amber-500 shadow-[0_0_15px_rgba(251,191,36,0.3)] ring-1 ring-amber-400' 
              : 'bg-dark-900 border-zinc-800 hover:border-amber-500/40'
          }`}
        >
          <div className="text-[11px] font-mono text-amber-400 uppercase tracking-wider font-bold flex items-center space-x-1">
            <AlertCircle className="w-3.5 h-3.5 text-amber-400" />
            <span>NEEDS REVIEW</span>
          </div>
          <div className="text-2xl font-mono font-extrabold text-amber-300 mt-1">{stats.needsReview}</div>
          <div className="text-[10px] text-zinc-400 mt-1 font-mono">Conf &lt; 60% or Conflict</div>
        </div>
      </div>

      {/* ── INTERACTIVE PRIORITY WEIGHT SIMULATOR PANEL ───────────────── */}
      {showWeightSimulator && (
        <div className="p-5 rounded-2xl bg-dark-950 border border-amber-500/40 shadow-2xl space-y-4 animate-fadeIn font-mono">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-zinc-800 pb-3">
            <div>
              <div className="flex items-center space-x-2">
                <Sliders className="w-4 h-4 text-amber-400" />
                <h3 className="text-sm font-bold text-white uppercase tracking-wider">
                  Interactive Priority Formula Simulator (§4 Spec)
                </h3>
              </div>
              <p className="text-xs text-zinc-400 mt-0.5">
                Formula: <strong className="text-amber-300">P = w1·Integrity + w2·Relevance + w3·Temporal + w4·Uniqueness − w5·Noise</strong>
              </p>
            </div>

            {/* Presets */}
            <div className="flex flex-wrap items-center gap-1.5 text-xs">
              <span className="text-zinc-500 text-[11px] mr-1">Case Presets:</span>
              {Object.entries(PRIORITY_PRESETS).map(([key, p]) => (
                <button
                  key={key}
                  onClick={() => handleApplyPreset(key)}
                  className={`px-2.5 py-1 rounded-lg transition-colors text-[11px] ${
                    activePreset === key 
                      ? 'bg-amber-500/20 text-amber-300 border border-amber-500/50 font-bold' 
                      : 'bg-dark-900 text-zinc-400 hover:text-white border border-zinc-800'
                  }`}
                >
                  {p.name.split(' ')[0]}
                </button>
              ))}
            </div>
          </div>

          {/* Sliders */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4 pt-1">
            
            {/* w1 Integrity */}
            <div className="p-3 rounded-xl bg-dark-900 border border-zinc-800 space-y-1.5">
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
              <div className="text-[10px] text-zinc-500">Objective 02 verified score</div>
            </div>

            {/* w2 Relevance */}
            <div className="p-3 rounded-xl bg-dark-900 border border-zinc-800 space-y-1.5">
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
              <div className="text-[10px] text-zinc-500">IOC &amp; attack keywords</div>
            </div>

            {/* w3 Temporal */}
            <div className="p-3 rounded-xl bg-dark-900 border border-zinc-800 space-y-1.5">
              <div className="flex justify-between text-xs">
                <span className="text-cyan-400 font-bold">w3 Temporal:</span>
                <span className="text-white font-mono font-bold">{((activeWeights.recency ?? activeWeights.temporal) * 100).toFixed(0)}%</span>
              </div>
              <input
                type="range"
                min="0.05"
                max="0.50"
                step="0.05"
                value={activeWeights.recency ?? activeWeights.temporal}
                onChange={(e) => handleWeightChange('recency', e.target.value)}
                className="w-full accent-cyan-500 cursor-pointer"
              />
              <div className="text-[10px] text-zinc-500">Breach window proximity</div>
            </div>

            {/* w4 Uniqueness */}
            <div className="p-3 rounded-xl bg-dark-900 border border-zinc-800 space-y-1.5">
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
            <div className="p-3 rounded-xl bg-dark-900 border border-zinc-800 space-y-1.5">
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

          {weightsRecalculatedMsg && (
            <div className="text-xs text-cyber-neon font-mono flex items-center space-x-1.5 animate-fadeIn">
              <CheckCircle className="w-3.5 h-3.5 text-cyber-neon" />
              <span>{weightsRecalculatedMsg}</span>
            </div>
          )}
        </div>
      )}

      {/* ── VIEW SWITCHER BAR & SEARCH/FILTERS ────────────────────────── */}
      <div className="p-4 rounded-2xl bg-dark-900 border border-zinc-800 space-y-3 shadow-xl">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
          
          {/* Search Input */}
          <div className="relative flex-1 max-w-md">
            <Search className="w-4 h-4 text-zinc-500 absolute left-3 top-2.5" />
            <input
              type="text"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder="Search artifacts, IPs (10.20.30.40), domains, hashes, keywords..."
              className="w-full pl-9 pr-4 py-2 bg-dark-950 border border-zinc-700/80 rounded-xl text-xs font-mono text-white placeholder-zinc-500 focus:outline-none focus:border-cyber-neon"
            />
          </div>

          {/* Quick IOC Search Chips */}
          <div className="hidden lg:flex items-center space-x-1.5 text-[11px] font-mono">
            <span className="text-zinc-500">Quick Leads:</span>
            {['ransom', 'mimikatz', '10.20.30.40', 'darkmesh.onion', 'DROP TABLE'].map((chip) => (
              <button
                key={chip}
                onClick={() => setSearchTerm(chip)}
                className="px-2 py-0.5 rounded bg-dark-950 border border-zinc-800 text-zinc-300 hover:text-cyber-neon hover:border-cyber-500/40 transition-colors"
              >
                {chip}
              </button>
            ))}
          </div>

          {/* View Mode Switcher */}
          <div className="bg-dark-950 p-1 rounded-xl border border-zinc-800 flex items-center text-xs font-mono">
            <button
              onClick={() => setViewMode('table')}
              className={`px-3 py-1.5 rounded-lg transition-all flex items-center space-x-1 ${
                viewMode === 'table'
                  ? 'bg-cyber-500/20 text-cyber-neon border border-cyber-500/40 font-bold'
                  : 'text-zinc-400 hover:text-white'
              }`}
            >
              <span>📋 Table</span>
            </button>
            <button
              onClick={() => setViewMode('lanes')}
              className={`px-3 py-1.5 rounded-lg transition-all flex items-center space-x-1 ${
                viewMode === 'lanes'
                  ? 'bg-cyber-500/20 text-cyber-neon border border-cyber-500/40 font-bold'
                  : 'text-zinc-400 hover:text-white'
              }`}
            >
              <Layers className="w-3 h-3" />
              <span>🗂️ 7 Lanes</span>
            </button>
            <button
              onClick={() => setViewMode('clusters')}
              className={`px-3 py-1.5 rounded-lg transition-all flex items-center space-x-1 ${
                viewMode === 'clusters'
                  ? 'bg-cyber-500/20 text-cyber-neon border border-cyber-500/40 font-bold'
                  : 'text-zinc-400 hover:text-white'
              }`}
            >
              <Copy className="w-3 h-3" />
              <span>Clusters</span>
            </button>
            <button
              onClick={() => setViewMode('timeline')}
              className={`px-3 py-1.5 rounded-lg transition-all flex items-center space-x-1 ${
                viewMode === 'timeline'
                  ? 'bg-cyber-500/20 text-cyber-neon border border-cyber-500/40 font-bold'
                  : 'text-zinc-400 hover:text-white'
              }`}
            >
              <Clock className="w-3 h-3" />
              <span>Timeline</span>
            </button>
            <button
              onClick={() => setViewMode('charts')}
              className={`px-3 py-1.5 rounded-lg transition-all flex items-center space-x-1 ${
                viewMode === 'charts'
                  ? 'bg-cyber-500/20 text-cyber-neon border border-cyber-500/40 font-bold'
                  : 'text-zinc-400 hover:text-white'
              }`}
            >
              <BarChart2 className="w-3 h-3" />
              <span>Analytics</span>
            </button>
          </div>
        </div>

        {/* Filter Chips: 7 Forensic Categories & Fast Filter Chips */}
        <div className="flex flex-wrap items-center justify-between gap-2.5 pt-2 border-t border-zinc-800/80 text-xs font-mono">
          
          {/* 7 Forensic Categories */}
          <div className="flex flex-wrap items-center gap-1">
            <span className="text-zinc-500 mr-1 text-[11px] uppercase">Category:</span>
            {['All', 'Documents', 'Database Logs', 'Photos', 'System Traces', 'Network Captures', 'Registry Hives', 'Executables'].map((cat) => (
              <button
                key={cat}
                onClick={() => setTypeFilter(cat)}
                className={`px-2 py-0.5 rounded text-[11px] transition-colors ${
                  typeFilter === cat
                    ? 'bg-cyber-500/25 text-cyber-neon border border-cyber-500/50 font-bold'
                    : 'bg-dark-950 text-zinc-400 hover:text-white border border-zinc-800'
                }`}
              >
                {cat === 'All' ? 'All (7)' : cat}
              </button>
            ))}
          </div>

          {/* Quick Filters */}
          <div className="flex flex-wrap items-center gap-1.5">
            <button
              onClick={() => setIncidentWindowOnly(!incidentWindowOnly)}
              className={`px-2 py-0.5 rounded text-[11px] border transition-colors ${
                incidentWindowOnly 
                  ? 'bg-cyan-500/20 text-cyan-300 border-cyan-500/40 font-bold' 
                  : 'bg-dark-950 text-zinc-400 border-zinc-800 hover:text-white'
              }`}
            >
              Inside Window
            </button>
            <button
              onClick={() => setHideDuplicates(!hideDuplicates)}
              className={`px-2 py-0.5 rounded text-[11px] border transition-colors ${
                hideDuplicates 
                  ? 'bg-amber-500/20 text-amber-300 border-amber-500/40 font-bold' 
                  : 'bg-dark-950 text-zinc-400 border-zinc-800 hover:text-white'
              }`}
            >
              Hide Duplicates
            </button>

            {(searchTerm || typeFilter !== 'All' || tierFilter !== 'All' || hideDuplicates || incidentWindowOnly || conflictsOnly || reviewOnly) && (
              <button
                onClick={() => {
                  setSearchTerm('');
                  setTypeFilter('All');
                  setTierFilter('All');
                  setHideDuplicates(false);
                  setIncidentWindowOnly(false);
                  setConflictsOnly(false);
                  setReviewOnly(false);
                }}
                className="ml-2 px-2 py-0.5 rounded bg-zinc-800 hover:bg-zinc-700 text-zinc-300 text-[10px] flex items-center space-x-1"
              >
                <RotateCcw className="w-3 h-3" />
                <span>Reset</span>
              </button>
            )}
          </div>
        </div>
      </div>

      {/* ── TAB CONTENT VIEWS ────────────────────────────────────────── */}

      {/* VIEW 1: RANKED TABLE VIEW */}
      {viewMode === 'table' && (
        <ArtifactTable
          artifacts={filteredArtifacts}
          onSelectArtifact={onSelectArtifact}
          onOpenIntegrity={onOpenIntegrity}
          sortField={sortField}
          sortOrder={sortOrder}
          onSort={handleSort}
        />
      )}

      {/* VIEW 2: 7 HIGH-VALUE CATEGORY LANES */}
      {viewMode === 'lanes' && (
        <div className="space-y-4 animate-fadeIn">
          <div className="flex items-center justify-between text-xs font-mono px-1">
            <span className="text-zinc-400 font-bold uppercase">
              7 FORENSIC EVIDENCE LANES (Sorted by Priority Score P within each lane)
            </span>
            <span className="text-zinc-500 text-[11px]">
              Click any card to open forensic details
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 xl:grid-cols-7 gap-3">
            {[
              { title: 'Documents', items: laneGroups.documents, color: 'text-blue-400', border: 'border-blue-500/30' },
              { title: 'Database Logs', items: laneGroups.dbLogs, color: 'text-emerald-400', border: 'border-emerald-500/30' },
              { title: 'Photos', items: laneGroups.photos, color: 'text-amber-400', border: 'border-amber-500/30' },
              { title: 'System Traces', items: laneGroups.systemTraces, color: 'text-purple-400', border: 'border-purple-500/30' },
              { title: 'Network Captures', items: laneGroups.networkCaptures, color: 'text-cyan-400', border: 'border-cyan-500/30' },
              { title: 'Registry Hives', items: laneGroups.registryHives, color: 'text-rose-400', border: 'border-rose-500/30' },
              { title: 'Executables', items: laneGroups.executables, color: 'text-red-400', border: 'border-red-500/40' },
            ].map(({ title, items, color, border }) => (
              <div key={title} className={`rounded-xl border ${border} bg-dark-900 overflow-hidden flex flex-col`}>
                <div className="p-2.5 bg-dark-950 border-b border-zinc-800 flex items-center justify-between">
                  <span className={`font-mono font-bold text-xs truncate ${color}`}>{title}</span>
                  <span className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-dark-900 border border-zinc-800 text-zinc-400">
                    {items.length}
                  </span>
                </div>

                <div className="p-2 space-y-2 overflow-y-auto max-h-[600px] scrollbar-thin flex-1">
                  {items.length === 0 ? (
                    <div className="text-center py-8 text-[11px] text-zinc-600 font-mono">No artifacts</div>
                  ) : (
                    items.map(art => (
                      <div
                        key={art.id || art.artifact_id || art.filename}
                        onClick={() => onSelectArtifact(art)}
                        className={`p-2.5 rounded-lg border transition-all cursor-pointer bg-dark-950/80 hover:bg-dark-850 ${
                          art.conflict ? 'border-rose-500/50 shadow-[0_0_8px_rgba(244,63,94,0.2)]' : 'border-zinc-800 hover:border-zinc-700'
                        }`}
                      >
                        <div className="flex items-center justify-between font-mono mb-1">
                          <span className="text-[10px] text-cyber-neon font-bold">{art.id || art.artifact_id}</span>
                          <span className={`px-1.5 py-0.2 rounded text-[9px] font-bold uppercase ${getTierBadgeClass(art.priorityTier)}`}>
                            {art.priorityTier}
                          </span>
                        </div>
                        <div className="font-semibold text-white text-xs truncate" title={art.filename}>{art.filename}</div>
                        {art.conflict && (
                          <div className="text-[9px] font-mono text-rose-300 bg-rose-500/20 px-1 py-0.5 rounded mt-1 truncate">
                            ⚠ MISMATCH: Executable in {art.filename.split('.').pop()}
                          </div>
                        )}
                        <div className="mt-2 flex items-center justify-between text-[10px] font-mono text-zinc-400 border-t border-zinc-900 pt-1.5">
                          <span>P = {art.priorityScore?.toFixed(3)}</span>
                          <span>Integ: {Math.round((art.integrity > 1 ? art.integrity : art.integrity * 100) || art.overallIntegrity || 0)}%</span>
                        </div>
                      </div>
                    ))
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* VIEW 3: DUPLICATE CLUSTERS */}
      {viewMode === 'clusters' && (
        <div className="space-y-4 animate-fadeIn">
          <div className="text-xs font-mono text-zinc-400 font-bold uppercase">
            FUZZY HASH / SSDEEP DUPLICATE EVIDENCE CLUSTERS
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {duplicateClusters.map((cluster) => (
              <div key={cluster.clusterId} className="p-4 rounded-xl bg-dark-900 border border-amber-500/30 space-y-3 font-mono text-xs">
                <div className="flex items-center justify-between border-b border-zinc-800 pb-2">
                  <div className="flex items-center space-x-2">
                    <Copy className="w-4 h-4 text-amber-400" />
                    <span className="font-bold text-white text-sm">{cluster.clusterId}</span>
                  </div>
                  <span className="px-2 py-0.5 rounded bg-amber-500/20 text-amber-300 border border-amber-500/40 text-[11px] font-bold">
                    Similarity: {cluster.similarity}%
                  </span>
                </div>

                <p className="text-zinc-300 font-sans text-xs">{cluster.description}</p>

                <div className="space-y-1.5 pt-1">
                  <div className="text-[11px] text-zinc-500 uppercase">Cluster Members (Uniqueness U = {cluster.uniquenessScore}):</div>
                  {cluster.artifacts.map((m, i) => (
                    <div key={i} className="p-2 rounded bg-dark-950 border border-zinc-800 flex items-center justify-between text-[11px]">
                      <div className="flex items-center space-x-2">
                        <span className={`px-1.5 py-0.2 rounded text-[9px] font-bold ${m.isMaster ? 'bg-emerald-500/20 text-emerald-400' : 'bg-zinc-800 text-zinc-400'}`}>
                          {m.isMaster ? 'REPRESENTATIVE' : 'DUPLICATE'}
                        </span>
                        <span className="text-white font-medium">{m.name}</span>
                      </div>
                      <span className="text-zinc-500">{m.size}</span>
                    </div>
                  ))}
                </div>

                <div className="p-2.5 rounded bg-dark-950 text-[11px] text-zinc-400 font-mono">
                  Forensic Rule: Exact duplicates or near-duplicates receive discounted uniqueness (U = {cluster.uniquenessScore}) to ensure investigators are not overwhelmed by redundant copies.
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* VIEW 4: INCIDENT TIMELINE */}
      {viewMode === 'timeline' && (
        <div className="p-5 rounded-2xl bg-dark-900 border border-zinc-800 space-y-4 animate-fadeIn font-mono">
          <div className="flex items-center justify-between border-b border-zinc-800 pb-3">
            <div className="flex items-center space-x-2">
              <Clock className="w-4 h-4 text-cyber-neon" />
              <span className="font-bold text-white text-sm uppercase">Incident Breach Window Timeline</span>
            </div>
            <span className="text-xs text-cyber-bright">
              Active Breach Window: {caseContext?.incidentStart?.slice(11, 16) || '10:00'} — {caseContext?.incidentEnd?.slice(11, 16) || '18:00'} UTC
            </span>
          </div>

          <div className="relative pt-6 pb-4 overflow-x-auto">
            <div className="min-w-[700px] flex items-center justify-between relative border-t-2 border-zinc-700 pt-6">
              {timelineEvents.map((ev, i) => {
                const timeStr = (ev.mtime || ev.metadata?.timestamps?.inferredMtime || '').slice(11, 16) || `1${i}:00`;
                const isCritical = ev.priorityTier === 'Critical';
                return (
                  <div 
                    key={i} 
                    onClick={() => onSelectArtifact(ev)}
                    className="flex flex-col items-center cursor-pointer group text-center"
                  >
                    <div className={`w-4 h-4 rounded-full border-2 transition-all group-hover:scale-125 ${
                      isCritical ? 'bg-red-500 border-red-300 shadow-[0_0_10px_#ef4444]' : 'bg-cyber-neon border-black'
                    }`} />
                    <span className="text-[11px] font-bold text-white mt-2">{timeStr}</span>
                    <span className="text-[10px] text-zinc-400 max-w-[90px] truncate mt-0.5">{ev.filename}</span>
                    <span className={`text-[9px] px-1 rounded mt-1 font-bold ${getTierBadgeClass(ev.priorityTier)}`}>
                      {ev.priorityTier}
                    </span>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      )}

      {/* VIEW 5: VISUAL ANALYTICS */}
      {viewMode === 'charts' && (
        <div className="p-5 rounded-2xl bg-dark-950 border border-cyber-500/30 shadow-2xl space-y-5 animate-fadeIn">
          <div className="flex items-center justify-between border-b border-zinc-800 pb-3">
            <div className="flex items-center space-x-2">
              <BarChart2 className="w-4 h-4 text-cyber-neon" />
              <h3 className="text-sm font-bold text-white font-mono uppercase tracking-wider">Visual Analytics — Evidence Classification &amp; Triage</h3>
            </div>
            <span className="text-[11px] text-zinc-500 font-mono">{rescoredArtifacts.length} artifacts</span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
            
            {/* Priority Tier Distribution */}
            <div className="p-3.5 rounded-xl bg-dark-900 border border-zinc-800 space-y-2">
              <div className="text-[11px] font-mono text-zinc-400 uppercase tracking-wider font-semibold">Priority Tier Distribution</div>
              <ResponsiveContainer width="100%" height={160}>
                <BarChart data={tierChartData} margin={{ top: 8, right: 8, left: -20, bottom: 4 }}>
                  <XAxis dataKey="name" tick={{ fill: '#71717a', fontSize: 10 }} axisLine={false} tickLine={false} />
                  <YAxis tick={{ fill: '#71717a', fontSize: 10 }} axisLine={false} tickLine={false} />
                  <Tooltip contentStyle={{ background: '#0f172a', border: '1px solid #334155', borderRadius: 8, fontSize: 11 }} />
                  <Bar dataKey="count" radius={[4,4,0,0]}>
                    {tierChartData.map((entry, i) => <Cell key={i} fill={entry.fill} />)}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>

            {/* Category Breakdown */}
            <div className="p-3.5 rounded-xl bg-dark-900 border border-zinc-800 space-y-2">
              <div className="text-[11px] font-mono text-zinc-400 uppercase tracking-wider font-semibold">7 Forensic Categories</div>
              <ResponsiveContainer width="100%" height={160}>
                <BarChart data={categoryChartData} margin={{ top: 8, right: 8, left: -20, bottom: 4 }}>
                  <XAxis dataKey="name" tick={{ fill: '#71717a', fontSize: 9 }} axisLine={false} tickLine={false} />
                  <YAxis tick={{ fill: '#71717a', fontSize: 10 }} axisLine={false} tickLine={false} />
                  <Tooltip contentStyle={{ background: '#0f172a', border: '1px solid #334155', borderRadius: 8, fontSize: 11 }} />
                  <Bar dataKey="count" fill="#3b82f6" radius={[4,4,0,0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>

            {/* Relevance vs Integrity Scatter */}
            <div className="p-3.5 rounded-xl bg-dark-900 border border-zinc-800 space-y-2">
              <div className="text-[11px] font-mono text-zinc-400 uppercase tracking-wider font-semibold">Relevance (Y) vs Integrity (X)</div>
              <ResponsiveContainer width="100%" height={160}>
                <ScatterChart margin={{ top: 8, right: 8, left: -20, bottom: 4 }}>
                  <XAxis type="number" dataKey="x" name="Integrity" unit="%" tick={{ fill: '#71717a', fontSize: 9 }} domain={[0, 100]} />
                  <YAxis type="number" dataKey="y" name="Relevance" unit="%" tick={{ fill: '#71717a', fontSize: 9 }} domain={[0, 100]} />
                  <Tooltip cursor={{ strokeDasharray: '3 3' }} contentStyle={{ background: '#0f172a', border: '1px solid #334155', borderRadius: 8, fontSize: 11 }} />
                  <Scatter data={scatterData} fill="#00ff66" />
                </ScatterChart>
              </ResponsiveContainer>
            </div>

          </div>
        </div>
      )}

    </section>
  );
}
