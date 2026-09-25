/**
 * AiVsRuleModal.jsx
 * Technical Architecture Presentation & AI Models Explainer
 * CALMSTACKS 24H Hackathon Deliverable:
 * "Technical architecture presentation explaining the AI and reconstruction models used"
 */

import React, { useState } from 'react';
import {
  X, Cpu, CheckSquare, Zap, Shield, HelpCircle, Layers,
  Filter, FileText, ArrowRight, BookOpen, Terminal, Sparkles, Award
} from 'lucide-react';
import { AI_VS_RULE_MATRIX } from '../data/mockForensicData';

export default function AiVsRuleModal({ onClose }) {
  const [activeTab, setActiveTab] = useState('models'); // 'models', 'matrix', 'compliance'
  const [matrixFilter, setMatrixFilter] = useState('All');

  const filteredMatrix = AI_VS_RULE_MATRIX.filter((item) => {
    if (matrixFilter === 'Rule-based') return item.approach.includes('Rule');
    if (matrixFilter === 'ML') return item.approach.includes('ML') || item.approach.includes('NLP');
    return true;
  });

  return (
    <div className="fixed inset-0 z-50 overflow-y-auto bg-black/80 backdrop-blur-sm flex items-center justify-center p-3 sm:p-6 animate-fadeIn">
      <div 
        className="relative bg-dark-900 border border-cyber-500/30 w-full max-w-5xl rounded-2xl shadow-2xl overflow-hidden flex flex-col max-h-[90vh]"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="px-6 py-4 bg-dark-950 border-b border-zinc-800 flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <div className="p-2 rounded-lg bg-cyber-500/10 border border-cyber-500/30 text-cyber-neon shadow-neon">
              <Cpu className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-base font-bold text-white font-mono flex items-center space-x-2">
                <span>TECHNICAL ARCHITECTURE &amp; AI MODELS PRESENTATION</span>
                <span className="px-2 py-0.5 rounded text-[10px] bg-cyber-500/20 text-cyber-neon border border-cyber-500/40">
                  DELIVERABLE 03
                </span>
              </h2>
              <p className="text-xs text-zinc-400 font-mono">
                CALMSTACKS 24H Hackathon // Dual-Engine Neuro-Symbolic Forensic Framework
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
        <div className="px-6 py-2.5 bg-dark-950/60 border-b border-zinc-800 flex items-center space-x-2 text-xs font-mono">
          <button
            onClick={() => setActiveTab('models')}
            className={`px-4 py-1.5 rounded-lg transition-all flex items-center space-x-1.5 ${
              activeTab === 'models'
                ? 'bg-cyber-500/20 text-cyber-neon border border-cyber-500/40 font-bold'
                : 'text-zinc-400 hover:text-white bg-dark-900 border border-zinc-800'
            }`}
          >
            <Sparkles className="w-3.5 h-3.5 text-cyber-neon" />
            <span>1. AI &amp; Reconstruction Models Used</span>
          </button>

          <button
            onClick={() => setActiveTab('matrix')}
            className={`px-4 py-1.5 rounded-lg transition-all flex items-center space-x-1.5 ${
              activeTab === 'matrix'
                ? 'bg-cyber-500/20 text-cyber-neon border border-cyber-500/40 font-bold'
                : 'text-zinc-400 hover:text-white bg-dark-900 border border-zinc-800'
            }`}
          >
            <Layers className="w-3.5 h-3.5 text-cyber-neon" />
            <span>2. AI vs Rule-Based Decision Matrix</span>
          </button>

          <button
            onClick={() => setActiveTab('compliance')}
            className={`px-4 py-1.5 rounded-lg transition-all flex items-center space-x-1.5 ${
              activeTab === 'compliance'
                ? 'bg-cyber-500/20 text-cyber-neon border border-cyber-500/40 font-bold'
                : 'text-zinc-400 hover:text-white bg-dark-900 border border-zinc-800'
            }`}
          >
            <Shield className="w-3.5 h-3.5 text-cyber-neon" />
            <span>3. Forensic Admissibility &amp; ISO/IEC 27037</span>
          </button>
        </div>

        {/* Content Area */}
        <div className="p-6 overflow-y-auto space-y-6 scrollbar-thin flex-1">

          {/* TAB 1: AI & RECONSTRUCTION MODELS */}
          {activeTab === 'models' && (
            <div className="space-y-6 animate-fadeIn">
              {/* Architecture Introduction */}
              <div className="p-4 rounded-xl bg-dark-950 border border-cyber-500/30 space-y-2 font-mono text-xs">
                <div className="text-cyber-neon font-bold text-sm flex items-center space-x-2">
                  <Award className="w-4 h-4" />
                  <span>The Neuro-Symbolic Forensic Solution</span>
                </div>
                <p className="text-zinc-300 leading-relaxed font-sans text-xs">
                  Black-box neural networks cannot testify in a courtroom, and traditional magic-byte recovery fails on damaged, out-of-order clusters. SAMDHAN AI pairs <strong>deterministic mathematical ground-truth</strong> (exact byte offsets, CRC-32 checksums, SHA-256 seals) with <strong>specialized machine learning models</strong> (Markov bi-gram boundary transitions, spaCy entity extraction, Isolation Forest anomaly scoring).
                </p>
              </div>

              {/* 4 Models Cards */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {/* Model 1 */}
                <div className="p-4 rounded-xl bg-dark-950 border border-zinc-800 space-y-2.5">
                  <div className="flex items-center justify-between">
                    <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-cyan-500/20 text-cyan-400 font-bold border border-cyan-500/30">
                      MODEL 01: RECONSTRUCTION
                    </span>
                    <span className="text-zinc-500 text-[10px] font-mono">Objective 01</span>
                  </div>
                  <h4 className="text-sm font-bold text-white font-mono">
                    DAG Greedy Boundary Optimizer &amp; Markov Bi-Gram Model
                  </h4>
                  <p className="text-xs text-zinc-400">
                    Calculates boundary transition probability across dangling fragments:
                  </p>
                  <div className="p-2.5 rounded bg-dark-900 font-mono text-[11px] text-cyan-300 border border-zinc-800">
                    Score(Fi &rarr; Fj) = w1&middot;Pointer + w2&middot;Markov_Ngram + w3&middot;&Delta;Entropy
                  </div>
                  <ul className="text-[11px] text-zinc-400 space-y-1 list-disc list-inside">
                    <li>Resolves out-of-order clusters and wipes dangling FAT entries.</li>
                    <li>Evaluates Deflate, SQLite, and JPEG continuity at sector borders.</li>
                  </ul>
                </div>

                {/* Model 2 */}
                <div className="p-4 rounded-xl bg-dark-950 border border-zinc-800 space-y-2.5">
                  <div className="flex items-center justify-between">
                    <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-emerald-500/20 text-emerald-400 font-bold border border-emerald-500/30">
                      MODEL 02: INTEGRITY
                    </span>
                    <span className="text-zinc-500 text-[10px] font-mono">Objective 02</span>
                  </div>
                  <h4 className="text-sm font-bold text-white font-mono">
                    13-Stage Decomposed Vector &amp; Isolation Forest
                  </h4>
                  <p className="text-xs text-zinc-400">
                    Replaces opaque single percentages with a transparent 4-vector:
                  </p>
                  <div className="p-2.5 rounded bg-dark-900 font-mono text-[11px] text-emerald-300 border border-zinc-800">
                    I_overall = 0.30&middot;Struct + 0.35&middot;Content + 0.15&middot;Meta + 0.20&middot;Cont
                  </div>
                  <ul className="text-[11px] text-zinc-400 space-y-1 list-disc list-inside">
                    <li>Deep format parsers for JPEG markers, PDF xref, SQLite B-Trees.</li>
                    <li>Unsupervised Isolation Forest flags anomalous zero-fills and bit-rot.</li>
                  </ul>
                </div>

                {/* Model 3 */}
                <div className="p-4 rounded-xl bg-dark-950 border border-zinc-800 space-y-2.5">
                  <div className="flex items-center justify-between">
                    <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-amber-500/20 text-amber-400 font-bold border border-amber-500/30">
                      MODEL 03: PRIORITIZATION
                    </span>
                    <span className="text-zinc-500 text-[10px] font-mono">Objective 03</span>
                  </div>
                  <h4 className="text-sm font-bold text-white font-mono">
                    spaCy NER &amp; Multi-Factor Priority Equation
                  </h4>
                  <p className="text-xs text-zinc-400">
                    Ranks high-value evidence out of thousands of unallocated fragments:
                  </p>
                  <div className="p-2.5 rounded bg-dark-900 font-mono text-[11px] text-amber-300 border border-zinc-800">
                    Priority = 0.40&middot;IOC_Match + 0.25&middot;Integrity + 0.20&middot;Window + 0.15&middot;Rarity
                  </div>
                  <ul className="text-[11px] text-zinc-400 space-y-1 list-disc list-inside">
                    <li>Extracts C2 IP addresses, onion domains, and ransom demand intent.</li>
                    <li>Gaussian decay prioritizes files modified during active breach window.</li>
                  </ul>
                </div>

                {/* Model 4 */}
                <div className="p-4 rounded-xl bg-dark-950 border border-zinc-800 space-y-2.5">
                  <div className="flex items-center justify-between">
                    <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-rose-500/20 text-rose-400 font-bold border border-rose-500/30">
                      MODEL 04: DECISION SUPPORT
                    </span>
                    <span className="text-zinc-500 text-[10px] font-mono">Objective 04</span>
                  </div>
                  <h4 className="text-sm font-bold text-white font-mono">
                    Deterministic 5-State Mapping &amp; Security Scan
                  </h4>
                  <p className="text-xs text-zinc-400">
                    Courtroom-defensible, 100% reproducible triage recommendation:
                  </p>
                  <div className="p-2.5 rounded bg-dark-900 font-mono text-[11px] text-rose-300 border border-zinc-800">
                    VERIFIED &bull; PARTIAL &bull; REVIEW &bull; UNRECOVERABLE &bull; BLOCKED
                  </div>
                  <ul className="text-[11px] text-zinc-400 space-y-1 list-disc list-inside">
                    <li>Disguised PE in JPG (<code className="text-rose-400">invoice.jpg</code>) blocked immediately.</li>
                    <li>Direct restore to USB pendrive with mandatory post-write SHA-256 match.</li>
                  </ul>
                </div>
              </div>
            </div>
          )}

          {/* TAB 2: AI VS RULE-BASED MATRIX */}
          {activeTab === 'matrix' && (
            <div className="space-y-4 animate-fadeIn">
              <div className="flex items-center justify-between text-xs font-mono">
                <span className="text-zinc-400">Filter Logic Approach:</span>
                <div className="flex items-center space-x-1">
                  {['All', 'Rule-based', 'ML'].map((f) => (
                    <button
                      key={f}
                      onClick={() => setMatrixFilter(f)}
                      className={`px-3 py-1 rounded text-xs transition-colors ${
                        matrixFilter === f
                          ? 'bg-cyber-500/20 text-cyber-neon border border-cyber-500/40 font-bold'
                          : 'text-zinc-400 hover:text-white bg-dark-900 border border-zinc-800'
                      }`}
                    >
                      {f === 'All' ? 'All (10 Components)' : f === 'Rule-based' ? 'Rule-Based Only' : 'ML / AI Only'}
                    </button>
                  ))}
                </div>
              </div>

              <div className="rounded-xl border border-zinc-800 overflow-hidden bg-dark-950">
                <table className="w-full text-left text-xs font-sans">
                  <thead className="bg-dark-900 border-b border-zinc-800 font-mono text-[11px] text-zinc-400 uppercase">
                    <tr>
                      <th className="py-3 px-4 font-semibold">Component</th>
                      <th className="py-3 px-3 font-semibold">Approach</th>
                      <th className="py-3 px-3 font-semibold">Tooling / Library</th>
                      <th className="py-3 px-4 font-semibold">Forensic Rationale (Why)</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-zinc-800/60 font-mono">
                    {filteredMatrix.map((item, index) => {
                      const isRule = item.approach.includes('Rule');
                      const isML = item.approach.includes('ML') || item.approach.includes('NLP');

                      return (
                        <tr key={index} className="hover:bg-dark-900/40 transition-colors">
                          <td className="py-3 px-4 font-semibold text-white font-sans">
                            {item.component}
                          </td>
                          <td className="py-3 px-3">
                            <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                              isRule 
                                ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30' 
                                : 'bg-purple-500/20 text-purple-400 border border-purple-500/30'
                            }`}>
                              {item.approach}
                            </span>
                          </td>
                          <td className="py-3 px-3 text-zinc-300 text-[11px]">
                            {item.tooling}
                          </td>
                          <td className="py-3 px-4 text-zinc-400 text-xs font-sans">
                            {item.rationale}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* TAB 3: COMPLIANCE & DEFENCIBILITY */}
          {activeTab === 'compliance' && (
            <div className="space-y-4 animate-fadeIn font-mono text-xs">
              <div className="p-4 rounded-xl bg-dark-950 border border-emerald-500/30 space-y-2">
                <div className="text-emerald-400 font-bold text-sm flex items-center space-x-2">
                  <Shield className="w-4 h-4" />
                  <span>ISO/IEC 27037 Forensic Digital Evidence Standards Compliance</span>
                </div>
                <p className="text-zinc-300 leading-relaxed font-sans text-xs">
                  SAMDHAN AI was engineered under strict forensic principles to guarantee that recovered evidence withstands adversarial cross-examination in court.
                </p>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div className="p-4 rounded-xl bg-dark-950 border border-zinc-800 space-y-2">
                  <div className="text-cyan-400 font-bold">1. Zero Delta Guarantee</div>
                  <p className="text-zinc-400 font-sans text-xs">
                    Original storage medium is mounted read-only (loop device with write-blocking). Raw input bitstream is never modified under any circumstances.
                  </p>
                </div>

                <div className="p-4 rounded-xl bg-dark-950 border border-zinc-800 space-y-2">
                  <div className="text-emerald-400 font-bold">2. Append-Only Audit Trail</div>
                  <p className="text-zinc-400 font-sans text-xs">
                    Every algorithm run, classification score, corruption boundary, and USB restore action is cryptographically signed and logged into <code className="text-emerald-300">samdhan_integrity.db</code>.
                  </p>
                </div>

                <div className="p-4 rounded-xl bg-dark-950 border border-zinc-800 space-y-2">
                  <div className="text-amber-400 font-bold">3. Re-Verification on Restore</div>
                  <p className="text-zinc-400 font-sans text-xs">
                    When restoring to physical USB drives (Feature 5), the system reads the written file back from the flash memory and compares SHA-256. Files are deleted on mismatch.
                  </p>
                </div>
              </div>
            </div>
          )}

        </div>

        {/* Footer */}
        <div className="px-6 py-3.5 bg-dark-950 border-t border-zinc-800 flex items-center justify-between text-xs font-mono">
          <span className="text-zinc-500">
            Document Reference: <code className="text-cyber-neon">TECHNICAL_ARCHITECTURE_PRESENTATION.md</code>
          </span>
          <button
            onClick={onClose}
            className="px-4 py-1.5 rounded-lg bg-cyber-neon hover:bg-cyber-bright text-black font-bold text-xs transition-colors"
          >
            Close Presentation
          </button>
        </div>
      </div>
    </div>
  );
}
