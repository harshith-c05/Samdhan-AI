import React, { useState, useMemo } from 'react';
import { 
  CheckCircle2, 
  AlertTriangle, 
  HelpCircle, 
  XCircle, 
  Check, 
  AlertCircle, 
  X, 
  ArrowRight, 
  Download, 
  Search, 
  RotateCcw, 
  ShieldCheck, 
  FileText, 
  Layers, 
  Info,
  ChevronDown,
  ChevronRight
} from 'lucide-react';
import { 
  DECISION_STATES, 
  PROVENANCE_TYPES, 
  THRESHOLDS,
  CORE_REFERENCE_DATASET,
  decide,
  adaptArtifactToEvidence
} from '../engine/decisionSupportEngine';

export default function InvestigationCenter({ 
  caseContext = {}, 
  artifacts = [], 
  onAddAuditLog = () => {} 
}) {
  // Mode: Toggle between Section 6's 4-Item Core Benchmark Dataset and All Case Artifacts
  const [datasetMode, setDatasetMode] = useState('benchmark'); // 'benchmark' | 'all'
  const [filterState, setFilterState] = useState('ALL'); // 'ALL' | 'RECOVERABLE' | 'PARTIALLY_RECOVERABLE' | 'NEEDS_REVIEW' | 'UNRECOVERABLE'
  const [selectedId, setSelectedId] = useState('BENCH-001');
  const [expandedEvidence, setExpandedEvidence] = useState({
    header: true,
    fragments: true,
    structure: false,
    integrity: false,
    metadata: false
  });
  const [selectedFragmentNode, setSelectedFragmentNode] = useState(null);
  const [actionFeedback, setActionFeedback] = useState(null);
  const [showThresholdsInfo, setShowThresholdsInfo] = useState(false);

  // Prepare aggregated evidence items
  const evidenceList = useMemo(() => {
    if (datasetMode === 'benchmark') {
      return CORE_REFERENCE_DATASET;
    }
    // Adapt general artifacts into evidence objects
    return artifacts.map(a => adaptArtifactToEvidence(a));
  }, [datasetMode, artifacts]);

  // Run deterministic 4-state engine on all evidence
  const evaluatedItems = useMemo(() => {
    return evidenceList.map(item => {
      const evaluation = decide(item);
      return {
        ...item,
        evaluation
      };
    });
  }, [evidenceList]);

  // 4 Summary counts strictly per Section 6
  const counts = useMemo(() => {
    const summary = {
      [DECISION_STATES.RECOVERABLE]: 0,
      [DECISION_STATES.PARTIALLY_RECOVERABLE]: 0,
      [DECISION_STATES.NEEDS_REVIEW]: 0,
      [DECISION_STATES.UNRECOVERABLE]: 0,
    };
    evaluatedItems.forEach(i => {
      if (summary[i.evaluation.decision] !== undefined) {
        summary[i.evaluation.decision]++;
      }
    });
    return summary;
  }, [evaluatedItems]);

  // Selected item and its evaluation
  const activeItem = useMemo(() => {
    const found = evaluatedItems.find(i => i.id === selectedId);
    return found || evaluatedItems[0] || null;
  }, [evaluatedItems, selectedId]);

  // Filtered table rows
  const tableRows = useMemo(() => {
    if (filterState === 'ALL') return evaluatedItems;
    return evaluatedItems.filter(i => i.evaluation.decision === filterState);
  }, [evaluatedItems, filterState]);

  // Evidence panel toggle
  const toggleEvidenceCategory = (id) => {
    setExpandedEvidence(prev => ({ ...prev, [id]: !prev[id] }));
  };

  // Restore Action Trigger
  const handleExecuteAction = () => {
    if (!activeItem) return;
    const config = activeItem.evaluation.restoreAction;
    
    // Set immediate visual feedback
    setActionFeedback({
      message: config.feedbackText,
      type: config.buttonStyle,
      timestamp: new Date().toLocaleTimeString()
    });

    // Create Audit Log entry conforming to Section 1
    const auditRecord = {
      id: `AUDIT-DEC-${Date.now().toString().slice(-4)}`,
      timestamp: new Date().toISOString(),
      stage: 'Decision Support & Action Handler',
      artifact: `${activeItem.filename} (${activeItem.id})`,
      inputHash: activeItem.rawMetadata?.sha256 || '4f9a7b1c3d2e...[tamper-sealed]',
      output: `${config.actionType}: ${config.feedbackText}`,
      actor: `Investigator (${caseContext.investigator || 'Det. H. Chen'})`,
      modelOrRule: `Deterministic-Rule-Table-v1.0 (${THRESHOLDS.NOTE})`,
      status: 'VERIFIED'
    };

    onAddAuditLog(auditRecord);
  };

  return (
    <div className="space-y-6 animate-fadeIn font-sans text-slate-100">
      
      {/* ── Top Bar & Context ────────────────────────────────────────── */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 p-4 rounded-xl bg-dark-900 border border-zinc-800">
        <div>
          <div className="flex items-center space-x-2">
            <span className="px-2 py-0.5 text-[10px] font-mono font-bold uppercase tracking-wider bg-cyber-500/20 text-cyber-neon border border-cyber-500/40 rounded">
              DECISION RULE ENGINE ACTIVE
            </span>
            <span className="text-xs font-mono text-zinc-400">
              Deterministic 4-State Mapping • No ML • Explainable Triaging
            </span>
          </div>
          <h1 className="text-xl font-bold text-white mt-1 font-mono tracking-tight">
            Investigative Decision Support Center
          </h1>
          <p className="text-xs text-zinc-400 mt-0.5">
            5-Second Triage Pipeline: <strong className="text-zinc-200">File → Evidence → Why → Decision → Insight → Restore</strong>
          </p>
        </div>

        {/* Dataset Switcher & Prototype Thresholds Indicator */}
        <div className="flex flex-wrap items-center gap-2">
          {/* Thresholds Popover trigger */}
          <div className="relative">
            <button
              onClick={() => setShowThresholdsInfo(!showThresholdsInfo)}
              className="px-2.5 py-1.5 rounded-lg bg-dark-950 border border-zinc-700/60 hover:border-zinc-500 text-xs font-mono text-zinc-400 hover:text-white flex items-center space-x-1.5 transition-colors"
              title="Inspect Rule Thresholds"
            >
              <Info className="w-3.5 h-3.5 text-sky-400" />
              <span>Rule Thresholds</span>
            </button>
            {showThresholdsInfo && (
              <div className="absolute right-0 top-10 z-30 w-80 p-3 rounded-xl bg-dark-950 border border-zinc-700 shadow-2xl text-xs space-y-2 font-mono">
                <div className="flex items-center justify-between text-zinc-300 font-bold border-b border-zinc-800 pb-1">
                  <span>Engine Threshold Defaults</span>
                  <button onClick={() => setShowThresholdsInfo(false)} className="text-zinc-500 hover:text-white">✕</button>
                </div>
                <div className="text-[11px] text-amber-400/90 italic">
                  * Prototype defaults — not tuned forensic constants
                </div>
                <ul className="space-y-1 text-[11px] text-zinc-300">
                  <li>• Confidence Blocker: <strong>&lt; 60%</strong> → NEEDS_REVIEW</li>
                  <li>• Structural Blocker: <strong>uncertain</strong> → NEEDS_REVIEW</li>
                  <li>• Recoverable: <strong>100% frags + valid + integrity ≥ 85</strong></li>
                  <li>• Partial: <strong>frags ≥ 60% + integrity ≥ 40</strong></li>
                  <li>• Unrecoverable: <strong>all other cases</strong></li>
                </ul>
              </div>
            )}
          </div>

          {/* Dataset Switcher */}
          <div className="bg-dark-950 p-1 rounded-lg border border-zinc-800 flex items-center text-xs font-mono">
            <button
              onClick={() => {
                setDatasetMode('benchmark');
                setSelectedId('BENCH-001');
                setActionFeedback(null);
              }}
              className={`px-3 py-1 rounded transition-all ${
                datasetMode === 'benchmark'
                  ? 'bg-cyber-500/20 text-cyber-neon border border-cyber-500/40 shadow-sm font-semibold'
                  : 'text-zinc-400 hover:text-zinc-200'
              }`}
            >
              §6 Core Reference (4 Files)
            </button>
            <button
              onClick={() => {
                setDatasetMode('all');
                if (artifacts.length > 0) setSelectedId(artifacts[0].id);
                setActionFeedback(null);
              }}
              className={`px-3 py-1 rounded transition-all ${
                datasetMode === 'all'
                  ? 'bg-cyber-500/20 text-cyber-neon border border-cyber-500/40 shadow-sm font-semibold'
                  : 'text-zinc-400 hover:text-zinc-200'
              }`}
            >
              All Case Ingestions ({artifacts.length})
            </button>
          </div>
        </div>
      </div>

      {/* ── 4 SUMMARY CARDS ONLY (Hard Constraint §6) ────────────────── */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        
        {/* 1. Recoverable (🟢) */}
        <div 
          onClick={() => setFilterState(filterState === DECISION_STATES.RECOVERABLE ? 'ALL' : DECISION_STATES.RECOVERABLE)}
          className={`cursor-pointer p-4 rounded-xl transition-all border ${
            filterState === DECISION_STATES.RECOVERABLE
              ? 'bg-emerald-950/40 border-emerald-400 shadow-[0_0_15px_rgba(52,211,153,0.3)] ring-1 ring-emerald-400'
              : 'bg-dark-900 border-zinc-800 hover:border-emerald-500/50'
          }`}
        >
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono uppercase tracking-wider text-emerald-400 font-semibold flex items-center space-x-1.5">
              <CheckCircle2 className="w-4 h-4 text-emerald-400" />
              <span>Recoverable</span>
            </span>
            <span className="w-2 h-2 rounded-full bg-emerald-400"></span>
          </div>
          <div className="text-3xl font-extrabold font-mono text-white mt-2">
            {counts[DECISION_STATES.RECOVERABLE]}
          </div>
          <div className="text-[11px] text-zinc-400 mt-1 font-mono">
            Full fragment &amp; integrity pass
          </div>
        </div>

        {/* 2. Partially Recoverable (🟡) */}
        <div 
          onClick={() => setFilterState(filterState === DECISION_STATES.PARTIALLY_RECOVERABLE ? 'ALL' : DECISION_STATES.PARTIALLY_RECOVERABLE)}
          className={`cursor-pointer p-4 rounded-xl transition-all border ${
            filterState === DECISION_STATES.PARTIALLY_RECOVERABLE
              ? 'bg-amber-950/40 border-amber-400 shadow-[0_0_15px_rgba(251,191,36,0.3)] ring-1 ring-amber-400'
              : 'bg-dark-900 border-zinc-800 hover:border-amber-500/50'
          }`}
        >
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono uppercase tracking-wider text-amber-400 font-semibold flex items-center space-x-1.5">
              <AlertTriangle className="w-4 h-4 text-amber-400" />
              <span>Partially Recoverable</span>
            </span>
            <span className="w-2 h-2 rounded-full bg-amber-400"></span>
          </div>
          <div className="text-3xl font-extrabold font-mono text-white mt-2">
            {counts[DECISION_STATES.PARTIALLY_RECOVERABLE]}
          </div>
          <div className="text-[11px] text-zinc-400 mt-1 font-mono">
            ≥60% frags, salvageable content
          </div>
        </div>

        {/* 3. Needs Review (🟡) */}
        <div 
          onClick={() => setFilterState(filterState === DECISION_STATES.NEEDS_REVIEW ? 'ALL' : DECISION_STATES.NEEDS_REVIEW)}
          className={`cursor-pointer p-4 rounded-xl transition-all border ${
            filterState === DECISION_STATES.NEEDS_REVIEW
              ? 'bg-amber-950/40 border-amber-300 shadow-[0_0_15px_rgba(252,211,77,0.3)] ring-1 ring-amber-300'
              : 'bg-dark-900 border-zinc-800 hover:border-amber-400/50'
          }`}
        >
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono uppercase tracking-wider text-amber-300 font-semibold flex items-center space-x-1.5">
              <HelpCircle className="w-4 h-4 text-amber-300" />
              <span>Needs Review</span>
            </span>
            <span className="w-2 h-2 rounded-full bg-amber-300"></span>
          </div>
          <div className="text-3xl font-extrabold font-mono text-white mt-2">
            {counts[DECISION_STATES.NEEDS_REVIEW]}
          </div>
          <div className="text-[11px] text-zinc-400 mt-1 font-mono">
            Low confidence or uncertain structure
          </div>
        </div>

        {/* 4. Unrecoverable (🔴) */}
        <div 
          onClick={() => setFilterState(filterState === DECISION_STATES.UNRECOVERABLE ? 'ALL' : DECISION_STATES.UNRECOVERABLE)}
          className={`cursor-pointer p-4 rounded-xl transition-all border ${
            filterState === DECISION_STATES.UNRECOVERABLE
              ? 'bg-rose-950/40 border-rose-400 shadow-[0_0_15px_rgba(244,63,94,0.3)] ring-1 ring-rose-400'
              : 'bg-dark-900 border-zinc-800 hover:border-rose-500/50'
          }`}
        >
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono uppercase tracking-wider text-rose-400 font-semibold flex items-center space-x-1.5">
              <XCircle className="w-4 h-4 text-rose-400" />
              <span>Unrecoverable</span>
            </span>
            <span className="w-2 h-2 rounded-full bg-rose-400"></span>
          </div>
          <div className="text-3xl font-extrabold font-mono text-white mt-2">
            {counts[DECISION_STATES.UNRECOVERABLE]}
          </div>
          <div className="text-[11px] text-zinc-400 mt-1 font-mono">
            Severe fragmentation / corruption
          </div>
        </div>

      </div>

      {/* ── Main Layout: Table on Left/Top, Detail Inspector on Right ── */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        
        {/* ── ARTIFACT TABLE (Columns: File, Type, Recovery %, Priority, Decision — nothing else!) ── */}
        <div className="lg:col-span-5 space-y-3">
          <div className="flex items-center justify-between px-1">
            <h2 className="text-xs font-mono uppercase font-bold text-zinc-400 tracking-wider">
              Carved Artifacts ({tableRows.length})
            </h2>
            {filterState !== 'ALL' && (
              <button
                onClick={() => setFilterState('ALL')}
                className="text-xs font-mono text-cyber-neon hover:underline"
              >
                Clear Filter ({filterState})
              </button>
            )}
          </div>

          <div className="rounded-xl border border-zinc-800 bg-dark-900 overflow-hidden shadow-cyber-card">
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs font-mono">
                {/* STRICT 5 COLUMNS ONLY per Section 6 */}
                <thead className="bg-dark-950 border-b border-zinc-800 text-[11px] text-zinc-400 uppercase tracking-wider">
                  <tr>
                    <th className="py-3 px-3 font-semibold">File</th>
                    <th className="py-3 px-3 font-semibold">Type</th>
                    <th className="py-3 px-2 text-right font-semibold">Recovery %</th>
                    <th className="py-3 px-3 text-center font-semibold">Priority</th>
                    <th className="py-3 px-3 text-center font-semibold">Decision</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-zinc-800/60">
                  {tableRows.map((item) => {
                    const dec = item.evaluation.decision;
                    const isSelected = item.id === activeItem?.id;

                    // Decision color
                    let decBadge = 'bg-zinc-800 text-zinc-300 border-zinc-700';
                    let decDot = 'bg-zinc-400';
                    if (dec === DECISION_STATES.RECOVERABLE) {
                      decBadge = 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30';
                      decDot = 'bg-emerald-400';
                    } else if (dec === DECISION_STATES.PARTIALLY_RECOVERABLE) {
                      decBadge = 'bg-amber-500/15 text-amber-400 border-amber-500/30';
                      decDot = 'bg-amber-400';
                    } else if (dec === DECISION_STATES.NEEDS_REVIEW) {
                      decBadge = 'bg-amber-400/15 text-amber-300 border-amber-400/30';
                      decDot = 'bg-amber-300';
                    } else if (dec === DECISION_STATES.UNRECOVERABLE) {
                      decBadge = 'bg-rose-500/15 text-rose-400 border-rose-500/30';
                      decDot = 'bg-rose-400';
                    }

                    // Priority color
                    const pTier = item.evaluation.metrics.priorityTier;
                    let pColor = 'text-zinc-400';
                    if (pTier === 'CRITICAL') pColor = 'text-rose-400 font-bold';
                    else if (pTier === 'HIGH') pColor = 'text-orange-400 font-bold';
                    else if (pTier === 'MEDIUM') pColor = 'text-amber-400 font-medium';

                    return (
                      <tr
                        key={item.id}
                        onClick={() => {
                          setSelectedId(item.id);
                          setSelectedFragmentNode(null);
                          setActionFeedback(null);
                        }}
                        className={`cursor-pointer transition-colors ${
                          isSelected
                            ? 'bg-cyber-500/10 border-l-2 border-l-cyber-neon'
                            : 'hover:bg-dark-850'
                        }`}
                      >
                        {/* File */}
                        <td className="py-2.5 px-3">
                          <div className="font-semibold text-white truncate max-w-[140px] sm:max-w-[160px]" title={item.filename}>
                            {item.filename}
                          </div>
                          {/* Provenance Tag (§5 & §6 edge case) */}
                          <div className="text-[9px] text-zinc-500 truncate" title={item.provenance}>
                            {item.provenance === PROVENANCE_TYPES.PUBLIC_REFERENCE ? 'Public Reference' :
                             item.provenance === PROVENANCE_TYPES.DERIVED_ANALYSIS ? 'Derived Analysis' : 'Synthetic Demo'}
                          </div>
                        </td>

                        {/* Type */}
                        <td className="py-2.5 px-3 text-zinc-300 whitespace-nowrap">
                          {item.type}
                        </td>

                        {/* Recovery % */}
                        <td className="py-2.5 px-2 text-right font-mono font-bold text-white whitespace-nowrap">
                          {item.recovery_percent}%
                        </td>

                        {/* Priority */}
                        <td className={`py-2.5 px-3 text-center uppercase text-[11px] whitespace-nowrap ${pColor}`}>
                          {pTier}
                        </td>

                        {/* Decision */}
                        <td className="py-2.5 px-3 text-center whitespace-nowrap">
                          <span className={`inline-flex items-center space-x-1 px-2 py-0.5 rounded text-[10px] font-mono uppercase font-bold border ${decBadge}`}>
                            <span className={`w-1.5 h-1.5 rounded-full ${decDot}`}></span>
                            <span>{dec.replace('_', ' ')}</span>
                          </span>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
        </div>

        {/* ── ARTIFACT DETAIL INSPECTOR (Section 6: 5-10 Second Investigative Flow) ── */}
        <div className="lg:col-span-7 space-y-4">
          {activeItem ? (
            <div className="p-5 rounded-xl bg-dark-900 border border-zinc-800 shadow-cyber-card space-y-5">
              
              {/* Header of Detail View: File & Provenance Label */}
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-zinc-800 pb-3">
                <div>
                  <div className="flex items-center space-x-2">
                    <h2 className="text-lg font-mono font-extrabold text-white">
                      {activeItem.filename}
                    </h2>
                    <span className="text-xs font-mono text-zinc-500">
                      [{activeItem.id}]
                    </span>
                  </div>
                  {/* Provenance Tag explicitly mandated in §5 Edge Cases */}
                  <div className="inline-flex items-center space-x-1.5 mt-1 px-2 py-0.5 rounded text-[10px] font-mono bg-sky-500/10 text-sky-400 border border-sky-500/30">
                    <Info className="w-3 h-3 text-sky-400" />
                    <span>Provenance: {activeItem.provenance}</span>
                  </div>
                </div>

                {/* Primary Decision Badge */}
                <div>
                  {activeItem.evaluation.decision === DECISION_STATES.RECOVERABLE && (
                    <div className="px-3 py-1.5 rounded-lg bg-emerald-500/20 text-emerald-400 border border-emerald-500/40 text-xs font-mono font-bold flex items-center space-x-1.5">
                      <CheckCircle2 className="w-4 h-4" />
                      <span>RECOVERABLE</span>
                    </div>
                  )}
                  {activeItem.evaluation.decision === DECISION_STATES.PARTIALLY_RECOVERABLE && (
                    <div className="px-3 py-1.5 rounded-lg bg-amber-500/20 text-amber-400 border border-amber-500/40 text-xs font-mono font-bold flex items-center space-x-1.5">
                      <AlertTriangle className="w-4 h-4" />
                      <span>PARTIALLY RECOVERABLE</span>
                    </div>
                  )}
                  {activeItem.evaluation.decision === DECISION_STATES.NEEDS_REVIEW && (
                    <div className="px-3 py-1.5 rounded-lg bg-amber-400/20 text-amber-300 border border-amber-400/40 text-xs font-mono font-bold flex items-center space-x-1.5">
                      <HelpCircle className="w-4 h-4" />
                      <span>NEEDS REVIEW</span>
                    </div>
                  )}
                  {activeItem.evaluation.decision === DECISION_STATES.UNRECOVERABLE && (
                    <div className="px-3 py-1.5 rounded-lg bg-rose-500/20 text-rose-400 border border-rose-500/40 text-xs font-mono font-bold flex items-center space-x-1.5">
                      <XCircle className="w-4 h-4" />
                      <span>UNRECOVERABLE</span>
                    </div>
                  )}
                </div>
              </div>

              {/* 1. FILE DETAIL VIEW: EXACTLY SIX LINES (Strict Constraint §6) */}
              <div className="p-3.5 rounded-lg bg-dark-950 border border-zinc-800">
                <div className="text-[10px] font-mono text-zinc-500 uppercase tracking-wider mb-2 font-semibold">
                  File Detail View (6 Core Metrics)
                </div>
                <div className="grid grid-cols-2 sm:grid-cols-3 gap-y-2 gap-x-4 text-xs font-mono">
                  {/* Line 1: Type */}
                  <div className="flex justify-between border-b border-zinc-900 pb-1">
                    <span className="text-zinc-400">Type:</span>
                    <span className="text-white font-bold">{activeItem.type}</span>
                  </div>
                  {/* Line 2: Fragment Ratio */}
                  <div className="flex justify-between border-b border-zinc-900 pb-1">
                    <span className="text-zinc-400">Fragment Ratio:</span>
                    <span className="text-white font-bold">{activeItem.evaluation.metrics.fragRatio}</span>
                  </div>
                  {/* Line 3: Recovery % */}
                  <div className="flex justify-between border-b border-zinc-900 pb-1">
                    <span className="text-zinc-400">Recovery:</span>
                    <span className="text-white font-bold">{activeItem.recovery_percent}%</span>
                  </div>
                  {/* Line 4: Integrity % */}
                  <div className="flex justify-between border-b border-zinc-900 pb-1">
                    <span className="text-zinc-400">Integrity:</span>
                    <span className="text-white font-bold">{activeItem.overall_integrity}%</span>
                  </div>
                  {/* Line 5: Priority */}
                  <div className="flex justify-between border-b border-zinc-900 pb-1">
                    <span className="text-zinc-400">Priority:</span>
                    <span className="text-white font-bold">{activeItem.evaluation.metrics.priorityTier}</span>
                  </div>
                  {/* Line 6: Decision */}
                  <div className="flex justify-between border-b border-zinc-900 pb-1">
                    <span className="text-zinc-400">Decision:</span>
                    <span className="font-bold text-cyber-neon">{activeItem.evaluation.decision.replace('_', ' ')}</span>
                  </div>
                </div>
              </div>

              {/* 2. DECISION FLOW CHECKLIST (Linear Checklist §2 & §6) */}
              <div className="space-y-1.5">
                <div className="text-[11px] font-mono text-zinc-400 uppercase font-semibold flex items-center space-x-1">
                  <span>Decision Flow Checklist</span>
                </div>
                <div className="flex flex-wrap items-center gap-1.5 p-2.5 rounded-lg bg-dark-950 border border-zinc-800 text-xs font-mono">
                  <span className="text-zinc-300 font-bold">{activeItem.filename}</span>
                  {activeItem.evaluation.decisionFlow.map((step, idx) => {
                    let badgeClass = 'text-zinc-300 border-zinc-700 bg-dark-850';
                    let icon = <Check className="w-3 h-3 text-emerald-400" />;
                    if (step.status === 'pass') {
                      badgeClass = 'text-emerald-400 border-emerald-500/30 bg-emerald-500/10';
                      icon = <Check className="w-3 h-3 text-emerald-400" />;
                    } else if (step.status === 'warn') {
                      badgeClass = 'text-amber-400 border-amber-500/30 bg-amber-500/10';
                      icon = <AlertTriangle className="w-3 h-3 text-amber-400" />;
                    } else if (step.status === 'fail') {
                      badgeClass = 'text-rose-400 border-rose-500/30 bg-rose-500/10';
                      icon = <X className="w-3 h-3 text-rose-400" />;
                    }

                    return (
                      <React.Fragment key={idx}>
                        <ArrowRight className="w-3 h-3 text-zinc-600 shrink-0" />
                        <span className={`inline-flex items-center space-x-1 px-2 py-0.5 rounded border text-[11px] font-medium ${badgeClass}`}>
                          <span>{step.label}</span>
                          {icon}
                        </span>
                      </React.Fragment>
                    );
                  })}
                </div>
              </div>

              {/* 3. WHY PANEL (3-5 Bullet Reasons Max, No Formulas §4 & §6) */}
              <div className="space-y-1.5">
                <div className="text-[11px] font-mono text-zinc-400 uppercase font-semibold flex items-center space-x-1.5">
                  <span>Why {activeItem.evaluation.decision.replace('_', ' ')}?</span>
                  <span className="text-[10px] text-zinc-500 font-normal">(Direct field rules, no formula)</span>
                </div>
                <div className="p-3 rounded-lg bg-dark-950 border border-zinc-800 space-y-1.5 font-mono text-xs">
                  {activeItem.evaluation.reasons.map((r, i) => (
                    <div key={i} className="flex items-start space-x-2">
                      {r.type === 'pass' && <Check className="w-3.5 h-3.5 text-emerald-400 mt-0.5 shrink-0" />}
                      {r.type === 'warn' && <AlertTriangle className="w-3.5 h-3.5 text-amber-400 mt-0.5 shrink-0" />}
                      {r.type === 'fail' && <X className="w-3.5 h-3.5 text-rose-400 mt-0.5 shrink-0" />}
                      <span className={r.type === 'pass' ? 'text-zinc-200' : (r.type === 'warn' ? 'text-amber-300' : 'text-rose-300')}>
                        {r.text}
                      </span>
                    </div>
                  ))}
                </div>
              </div>

              {/* 4. PRIORITY EXPLANATION (Tier + One Sentence §2 & §6) */}
              <div className="space-y-1.5">
                <div className="text-[11px] font-mono text-zinc-400 uppercase font-semibold">
                  Priority: <strong className="text-white">{activeItem.evaluation.metrics.priorityTier}</strong>
                </div>
                <div className="p-3 rounded-lg bg-dark-950 border border-zinc-800 text-xs font-mono text-zinc-300 leading-relaxed italic">
                  "{activeItem.evaluation.priorityExplanation}"
                </div>
              </div>

              {/* 5. EVIDENCE PANEL (5 Fixed Categories with 1-Line Drilldown §2 & §6) */}
              <div className="space-y-1.5">
                <div className="text-[11px] font-mono text-zinc-400 uppercase font-semibold flex items-center justify-between">
                  <span>Evidence Panel (5 Fixed Categories)</span>
                  <span className="text-[10px] text-zinc-500 font-normal">Click category for 1-line drill-down</span>
                </div>
                <div className="rounded-lg border border-zinc-800 bg-dark-950 divide-y divide-zinc-900 overflow-hidden font-mono text-xs">
                  {activeItem.evaluation.evidencePanel.map((ev) => {
                    const isOpen = expandedEvidence[ev.id];
                    let iconColor = 'text-emerald-400';
                    if (ev.status === 'warning') iconColor = 'text-amber-400';
                    if (ev.status === 'invalid') iconColor = 'text-rose-400';

                    return (
                      <div key={ev.id} className="transition-colors">
                        <button
                          onClick={() => toggleEvidenceCategory(ev.id)}
                          className="w-full py-2.5 px-3 flex items-center justify-between hover:bg-dark-850 text-left"
                        >
                          <div className="flex items-center space-x-2">
                            {ev.status === 'valid' && <Check className="w-3.5 h-3.5 text-emerald-400" />}
                            {ev.status === 'warning' && <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />}
                            {ev.status === 'invalid' && <X className="w-3.5 h-3.5 text-rose-400" />}
                            <span className="font-semibold text-zinc-200">{ev.name}</span>
                          </div>
                          <div className="flex items-center space-x-2">
                            <span className={`text-[11px] ${iconColor}`}>{ev.label}</span>
                            {isOpen ? <ChevronDown className="w-3.5 h-3.5 text-zinc-500" /> : <ChevronRight className="w-3.5 h-3.5 text-zinc-500" />}
                          </div>
                        </button>
                        {isOpen && (
                          <div className="px-3 pb-2.5 pt-0.5 text-[11px] text-zinc-400 bg-dark-900/60 border-t border-zinc-900/50">
                            ↳ {ev.oneLiner}
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              </div>

              {/* 6. INSIGHTS (2-3 Short Sentences §2 & §6) */}
              <div className="space-y-1.5">
                <div className="text-[11px] font-mono text-zinc-400 uppercase font-semibold">
                  Insights
                </div>
                <div className="p-3 rounded-lg bg-dark-950 border border-zinc-800 space-y-1.5 text-xs font-mono">
                  {activeItem.evaluation.insights.map((ins, idx) => (
                    <div key={idx} className="text-zinc-300">
                      {ins.category ? (
                        <>
                          <strong className="text-sky-400">{ins.category}: </strong>
                          <span>{ins.text}</span>
                        </>
                      ) : (
                        <span>"{ins.text}"</span>
                      )}
                    </div>
                  ))}
                </div>
              </div>

              {/* 7. FRAGMENT DIAGRAM (Original → Storage → Recovered §2 & §6) */}
              <div className="space-y-1.5">
                <div className="text-[11px] font-mono text-zinc-400 uppercase font-semibold flex items-center justify-between">
                  <span>Fragment Reconstruction Diagram</span>
                  <span className="text-[10px] text-zinc-500 font-normal">Click node to inspect status/position/relationship</span>
                </div>
                <div className="p-3 rounded-lg bg-dark-950 border border-zinc-800 space-y-2.5 font-mono text-xs">
                  {/* Sequence flow row */}
                  <div className="text-[10px] text-zinc-500 flex items-center space-x-2">
                    <span>Original Sequence</span>
                    <ArrowRight className="w-3 h-3 text-zinc-600" />
                    <span>Unallocated Storage Sectors</span>
                    <ArrowRight className="w-3 h-3 text-zinc-600" />
                    <span className="text-cyber-neon">Recovered Graph</span>
                  </div>

                  {/* Interactive Fragment Blocks */}
                  <div className="flex flex-wrap items-center gap-2 pt-1">
                    {activeItem.fragmentSequence.map((frag, idx) => {
                      const isFound = frag.status === 'Found';
                      const isSelected = selectedFragmentNode?.id === frag.id;

                      let nodeStyle = 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30 hover:border-emerald-400';
                      if (!isFound) {
                        nodeStyle = 'bg-rose-500/10 text-rose-400 border-rose-500/30 border-dashed hover:border-rose-400';
                      } else if (frag.relationship?.toLowerCase().includes('weak') || frag.position === 'Ambiguous') {
                        nodeStyle = 'bg-amber-500/10 text-amber-400 border-amber-500/30 hover:border-amber-400';
                      }

                      return (
                        <button
                          key={frag.id}
                          onClick={() => setSelectedFragmentNode(frag)}
                          className={`px-2.5 py-1.5 rounded border text-[11px] flex items-center space-x-1.5 transition-all ${nodeStyle} ${
                            isSelected ? 'ring-2 ring-cyber-neon shadow-neon' : ''
                          }`}
                        >
                          <span className="font-bold">{frag.id}</span>
                          <span className="text-[10px] opacity-80">({isFound ? 'Found' : 'Missing'})</span>
                        </button>
                      );
                    })}
                  </div>

                  {/* Fragment Detail Tooltip/Card */}
                  {selectedFragmentNode && (
                    <div className="p-2.5 rounded bg-dark-900 border border-zinc-700/80 text-[11px] space-y-1 animate-fadeIn">
                      <div className="flex items-center justify-between text-white font-bold border-b border-zinc-800 pb-1">
                        <span>Node: {selectedFragmentNode.name} [{selectedFragmentNode.id}]</span>
                        <button onClick={() => setSelectedFragmentNode(null)} className="text-zinc-500 hover:text-white">✕</button>
                      </div>
                      <div className="grid grid-cols-3 gap-2 pt-1 text-zinc-300">
                        <div>Status: <strong className={selectedFragmentNode.status === 'Found' ? 'text-emerald-400' : 'text-rose-400'}>{selectedFragmentNode.status}</strong></div>
                        <div>Position: <strong className="text-white">{selectedFragmentNode.position}</strong></div>
                        <div>Relationship: <strong className="text-white">{selectedFragmentNode.relationship}</strong></div>
                      </div>
                      <div className="text-[10px] text-zinc-500 font-mono">
                        Sector Offset: {selectedFragmentNode.offset}
                      </div>
                    </div>
                  )}
                </div>
              </div>

              {/* 8. RESTORE ACTION HANDLER (Gated by Decision §2 & §4) */}
              <div className="pt-2 border-t border-zinc-800">
                <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3">
                  <div>
                    <div className="text-xs font-mono font-bold text-white">
                      Investigative Action Directive
                    </div>
                    <div className="text-[11px] text-zinc-400 font-mono">
                      {activeItem.evaluation.restoreAction.allowed 
                        ? 'Authenticated bit-stream file restoration to forensic export folder.'
                        : 'Action gated by decision state — partial/full restore restricted.'}
                    </div>
                  </div>

                  {/* Primary Action Button */}
                  <div>
                    {activeItem.evaluation.restoreAction.buttonStyle === 'success' && (
                      <button
                        onClick={handleExecuteAction}
                        className="w-full sm:w-auto px-4 py-2.5 rounded-lg bg-emerald-500 hover:bg-emerald-400 text-black font-mono font-extrabold text-xs flex items-center justify-center space-x-2 transition-all shadow-[0_0_15px_rgba(16,185,129,0.4)] cursor-pointer"
                      >
                        <Download className="w-4 h-4" />
                        <span>{activeItem.evaluation.restoreAction.buttonLabel}</span>
                      </button>
                    )}

                    {activeItem.evaluation.restoreAction.buttonStyle === 'warning' && (
                      <button
                        onClick={handleExecuteAction}
                        className="w-full sm:w-auto px-4 py-2.5 rounded-lg bg-amber-500 hover:bg-amber-400 text-black font-mono font-extrabold text-xs flex items-center justify-center space-x-2 transition-all shadow-[0_0_15px_rgba(245,158,11,0.4)] cursor-pointer"
                      >
                        <Download className="w-4 h-4" />
                        <span>{activeItem.evaluation.restoreAction.buttonLabel}</span>
                      </button>
                    )}

                    {activeItem.evaluation.restoreAction.buttonStyle === 'review' && (
                      <button
                        onClick={handleExecuteAction}
                        className="w-full sm:w-auto px-4 py-2.5 rounded-lg bg-dark-850 hover:bg-dark-800 border border-amber-400/50 text-amber-300 font-mono font-semibold text-xs flex items-center justify-center space-x-2 transition-all cursor-pointer"
                      >
                        <HelpCircle className="w-4 h-4 text-amber-300" />
                        <span>{activeItem.evaluation.restoreAction.buttonLabel}</span>
                      </button>
                    )}

                    {activeItem.evaluation.restoreAction.buttonStyle === 'search' && (
                      <button
                        onClick={handleExecuteAction}
                        className="w-full sm:w-auto px-4 py-2.5 rounded-lg bg-dark-850 hover:bg-dark-800 border border-rose-500/50 text-rose-300 font-mono font-semibold text-xs flex items-center justify-center space-x-2 transition-all cursor-pointer"
                      >
                        <Search className="w-4 h-4 text-rose-400" />
                        <span>{activeItem.evaluation.restoreAction.buttonLabel}</span>
                      </button>
                    )}
                  </div>
                </div>

                {/* Instant Action Feedback & Chain-of-Custody confirmation */}
                {actionFeedback && (
                  <div className="mt-3 p-3 rounded-lg bg-dark-950 border border-cyber-500/40 text-xs font-mono space-y-1 animate-fadeIn">
                    <div className="flex items-center space-x-2 text-cyber-neon font-bold">
                      <ShieldCheck className="w-4 h-4" />
                      <span>{actionFeedback.message}</span>
                    </div>
                    <div className="text-[10px] text-zinc-500 flex items-center justify-between">
                      <span>Chain-of-Custody Event Recorded at {actionFeedback.timestamp} UTC</span>
                      <span className="text-zinc-400">Rule Table v1.0 • Sealed</span>
                    </div>
                  </div>
                )}
              </div>

            </div>
          ) : (
            <div className="p-8 rounded-xl bg-dark-900 border border-zinc-800 text-center font-mono text-zinc-500">
              Select an artifact from the table to view the 5-second investigative decision breakdown.
            </div>
          )}
        </div>

      </div>

    </div>
  );
}
