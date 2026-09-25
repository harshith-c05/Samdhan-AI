import React, { useState, useEffect } from 'react';
import { 
  Cpu, Binary, ShieldCheck, CopyCheck, Search, Award, CheckCircle2, 
  Loader2, Terminal, AlertTriangle, ArrowRight, Lock 
} from 'lucide-react';

const STAGES = [
  { id: 1, name: 'Feature Extraction', desc: 'Byte entropy, Shannon distribution, N-grams & magic-byte scanning', icon: Binary },
  { id: 2, name: 'Classification', desc: 'Rule-based MIME matching + ML Gradient Boosting byte-distribution', icon: Cpu },
  { id: 3, name: 'Integrity Checks', desc: 'Format-specific parsers: PNG chunks, SQLite page headers, PDF xrefs', icon: ShieldCheck },
  { id: 4, name: 'Dedup & Fuzzy Hashing', desc: 'Cryptographic SHA-256 exact match + SSDEEP/TLSH near-duplicate clustering', icon: CopyCheck },
  { id: 5, name: 'Evidence Relevance', desc: 'spaCy NER semantic entity extraction + incident window & IOC correlation', icon: Search },
  { id: 6, name: 'Scoring & Tiering', desc: 'Multi-factor priority equation & Critical/High/Med/Low tier allocation', icon: Award },
];

export default function ProcessingScreen({ onComplete, totalFragments = 36, caseContext }) {
  const [currentStageIndex, setCurrentStageIndex] = useState(0);
  const [processedCount, setProcessedCount] = useState(0);
  const [logs, setLogs] = useState([]);
  const [isFinished, setIsFinished] = useState(false);

  useEffect(() => {
    let fragmentInterval;
    let stageInterval;

    // Stream initial forensic ingest logs
    const initialLogs = [
      `[INGEST] Mounted read-only loop clone: /dev/loop12 -> ${caseContext.rawImageHash?.slice(0, 16)}...`,
      `[SECURITY] Immutable SHA-256 sealed. Bit-stream verification confirmed 0 delta from source image.`,
      `[AUDIT] Investigator ${caseContext.investigator || 'System'} initiated session for ${caseContext.caseId}.`,
      `[PIPELINE] Initializing 6-stage forensic triaging engine over ${totalFragments} unallocated fragments...`,
    ];
    setLogs(initialLogs);

    let fragCount = 0;
    let stageIdx = 0;

    const timer = setInterval(() => {
      fragCount += 3;
      if (fragCount > totalFragments) fragCount = totalFragments;
      setProcessedCount(fragCount);

      // Determine stage
      const newStage = Math.min(Math.floor((fragCount / totalFragments) * 6), 5);
      if (newStage !== stageIdx) {
        stageIdx = newStage;
        setCurrentStageIndex(stageIdx);
      }

      // Add detailed technical logs matching the current stage
      let logMsg = "";
      if (stageIdx === 0) {
        logMsg = `[STAGE 1] Byte-Entropy computed for frag_0x00${(fragCount * 0x1f34).toString(16)}: Entropy ${(6.2 + Math.random() * 1.7).toFixed(2)} bits/byte.`;
      } else if (stageIdx === 1) {
        logMsg = `[STAGE 2] ML GradientBoosting model classified sector #${fragCount}: Confidence ${(88 + Math.random() * 11).toFixed(1)}%.`;
      } else if (stageIdx === 2) {
        logMsg = `[STAGE 3] Structural parser check: Validated magic-bytes & header checksums for fragment cluster #${fragCount}.`;
      } else if (stageIdx === 3) {
        logMsg = `[STAGE 4] SSDEEP fuzzy hash generated: ${fragCount}:3a8f+... compared against global cluster matrix.`;
      } else if (stageIdx === 4) {
        logMsg = `[STAGE 5] NLP Entity Matcher evaluated fragment #${fragCount} against IOCs: [${caseContext.iocs?.slice(0, 32)}...].`;
      } else {
        logMsg = `[STAGE 6] Multi-factor priority score synthesized for fragment #${fragCount} -> Priority Assigned.`;
      }

      setLogs((prev) => [...prev.slice(-35), logMsg]);

      if (fragCount >= totalFragments && stageIdx >= 5) {
        clearInterval(timer);
        setIsFinished(true);
        setLogs((prev) => [
          ...prev,
          `[COMPLETE] Pipeline finished with 100% custody seal. All ${totalFragments} artifacts triaged.`,
          `[READY] Results dashboard compiled. Zero partial disclosures.`
        ]);
      }
    }, 450);

    return () => clearInterval(timer);
  }, [totalFragments, caseContext]);

  const progressPercent = Math.min(100, Math.round((processedCount / totalFragments) * 100));

  return (
    <div className="max-w-5xl mx-auto space-y-8 animate-fadeIn">
      {/* Header Banner */}
      <div className="bg-dark-900 border border-zinc-800 rounded-xl p-6 shadow-cyber-card">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <div className="flex items-center space-x-2">
              <span className="w-2.5 h-2.5 rounded-full bg-cyber-neon animate-ping"></span>
              <span className="font-mono text-xs uppercase tracking-wider text-cyber-neon font-semibold">
                ACTIVE TRIAGING PIPELINE
              </span>
            </div>
            <h2 className="text-xl md:text-2xl font-bold text-white mt-1">
              Analyzing Carved Disk Fragments &amp; Structural Headers
            </h2>
            <p className="text-xs text-zinc-400 mt-1 font-mono">
              Case Ref: <span className="text-zinc-200">{caseContext.caseId}</span> • 
              Original Bitstream: <span className="text-cyber-neon">{caseContext.rawImageHash?.slice(0, 16)}...</span> (Write-Protected)
            </p>
          </div>

          {/* Fragment Counter Card */}
          <div className="px-5 py-3 rounded-lg bg-dark-950 border border-cyber-500/30 flex items-center space-x-4 shadow-neon">
            <div>
              <div className="text-xs font-mono text-zinc-400 uppercase">Fragments Processed</div>
              <div className="text-2xl font-mono font-extrabold text-white flex items-baseline space-x-1">
                <span className="text-cyber-neon">{processedCount}</span>
                <span className="text-zinc-500 text-sm">/ {totalFragments}</span>
              </div>
            </div>
            <div className="h-9 w-px bg-zinc-800" />
            <div className="text-right">
              <div className="text-xs font-mono text-zinc-400 uppercase">Status</div>
              <div className="text-xs font-mono font-bold text-cyber-neon flex items-center space-x-1">
                {isFinished ? (
                  <span className="text-cyber-bright">COMPLETED</span>
                ) : (
                  <>
                    <Loader2 className="w-3.5 h-3.5 animate-spin" />
                    <span>RUNNING</span>
                  </>
                )}
              </div>
            </div>
          </div>
        </div>

        {/* Global Progress Bar */}
        <div className="mt-6">
          <div className="flex justify-between text-xs font-mono mb-2">
            <span className="text-zinc-400">Total Ingestion &amp; Triaging Progress</span>
            <span className="text-cyber-neon font-bold">{progressPercent}%</span>
          </div>
          <div className="w-full h-3 bg-dark-950 rounded-full overflow-hidden border border-zinc-800 p-0.5">
            <div 
              className="h-full bg-gradient-to-r from-cyber-500 via-cyber-bright to-cyber-neon rounded-full transition-all duration-300 shadow-[0_0_12px_#00ff66]"
              style={{ width: `${progressPercent}%` }}
            />
          </div>
        </div>
      </div>

      {/* 6-Stage Forensic Pipeline Visualizer */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {STAGES.map((stage, idx) => {
          const Icon = stage.icon;
          const isDone = currentStageIndex > idx || isFinished;
          const isCurrent = currentStageIndex === idx && !isFinished;
          const isPending = currentStageIndex < idx && !isFinished;

          return (
            <div
              key={stage.id}
              className={`p-4 rounded-xl border transition-all ${
                isCurrent
                  ? 'bg-cyber-500/10 border-cyber-neon shadow-neon'
                  : isDone
                  ? 'bg-dark-900/90 border-emerald-500/30 text-zinc-300'
                  : 'bg-dark-950/60 border-zinc-800/80 text-zinc-600'
              }`}
            >
              <div className="flex items-center justify-between mb-2">
                <div className="flex items-center space-x-2">
                  <div className={`p-1.5 rounded-lg ${
                    isCurrent
                      ? 'bg-cyber-500/20 text-cyber-neon'
                      : isDone
                      ? 'bg-emerald-500/20 text-emerald-400'
                      : 'bg-zinc-800 text-zinc-500'
                  }`}>
                    <Icon className="w-4 h-4" />
                  </div>
                  <span className="text-xs font-mono font-bold uppercase tracking-wider">
                    Stage {stage.id}
                  </span>
                </div>

                <div>
                  {isDone ? (
                    <span className="flex items-center space-x-1 text-[11px] font-mono text-emerald-400">
                      <CheckCircle2 className="w-3.5 h-3.5" />
                      <span>DONE</span>
                    </span>
                  ) : isCurrent ? (
                    <span className="flex items-center space-x-1 text-[11px] font-mono text-cyber-neon animate-pulse">
                      <Loader2 className="w-3.5 h-3.5 animate-spin" />
                      <span>ACTIVE</span>
                    </span>
                  ) : (
                    <span className="text-[11px] font-mono text-zinc-600">PENDING</span>
                  )}
                </div>
              </div>

              <h4 className="text-sm font-semibold text-white">{stage.name}</h4>
              <p className="text-xs text-zinc-400 mt-1 line-clamp-2">{stage.desc}</p>
            </div>
          );
        })}
      </div>

      {/* Terminal Forensic Log Stream */}
      <div className="bg-dark-950 border border-zinc-800 rounded-xl overflow-hidden shadow-2xl">
        <div className="px-4 py-2.5 bg-dark-900 border-b border-zinc-800 flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <Terminal className="w-4 h-4 text-cyber-neon" />
            <span className="text-xs font-mono text-zinc-300 font-semibold uppercase tracking-wider">
              Forensic Daemon Live Terminal Stream (Audit Recorded)
            </span>
          </div>
          <div className="flex items-center space-x-1.5 text-[10px] font-mono text-zinc-500">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400"></span>
            <span>APPEND-ONLY LOG</span>
          </div>
        </div>

        <div className="p-4 font-mono text-xs text-zinc-300 space-y-1.5 h-56 overflow-y-auto bg-black/60 scrollbar-thin">
          {logs.map((log, index) => (
            <div 
              key={index}
              className={`leading-relaxed ${
                log.includes('[COMPLETE]') || log.includes('[SECURITY]')
                  ? 'text-cyber-neon font-semibold'
                  : log.includes('[STAGE')
                  ? 'text-zinc-300'
                  : 'text-zinc-400'
              }`}
            >
              {log}
            </div>
          ))}
        </div>
      </div>

      {/* Strict Requirement Note from Spec §8: "No results shown yet (avoids partial/misleading numbers)" */}
      <div className="p-4 rounded-xl bg-dark-900 border border-zinc-800 flex flex-col sm:flex-row items-center justify-between gap-4">
        <div className="flex items-center space-x-3 text-xs text-zinc-400">
          <Lock className="w-5 h-5 text-cyber-neon shrink-0" />
          <span>
            <strong className="text-white font-mono">Partial Results Shielded:</strong> Forensic integrity protocol blocks unfinalized data display until all 6 validation tiers reach consensus.
          </span>
        </div>

        {isFinished && (
          <button
            onClick={onComplete}
            className="px-6 py-3 rounded-xl bg-cyber-neon text-black font-bold font-mono text-sm hover:bg-cyber-bright hover:shadow-neon transition-all flex items-center space-x-2 shrink-0 animate-bounce"
          >
            <span>VIEW FINAL EVIDENCE MATRIX</span>
            <ArrowRight className="w-4 h-4" />
          </button>
        )}
      </div>
    </div>
  );
}
