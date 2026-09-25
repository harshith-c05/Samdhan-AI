import React, { useState } from 'react';
import { X, Cpu, CheckSquare, Zap, Shield, HelpCircle, Layers, Filter } from 'lucide-react';
import { AI_VS_RULE_MATRIX } from '../data/mockForensicData';

export default function AiVsRuleModal({ onClose }) {
  const [filter, setFilter] = useState('All'); // All, Rule-based, ML

  const filteredItems = AI_VS_RULE_MATRIX.filter((item) => {
    if (filter === 'Rule-based') return item.approach.includes('Rule');
    if (filter === 'ML') return item.approach.includes('ML') || item.approach.includes('NLP');
    return true;
  });

  return (
    <div className="fixed inset-0 z-50 overflow-y-auto bg-black/80 backdrop-blur-sm flex items-center justify-center p-3 sm:p-6 animate-fadeIn">
      <div 
        className="relative bg-dark-900 border border-cyber-500/30 w-full max-w-4xl rounded-2xl shadow-2xl overflow-hidden flex flex-col max-h-[90vh]"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="px-6 py-4 bg-dark-950 border-b border-zinc-800 flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <div className="p-2 rounded-lg bg-cyber-500/10 border border-cyber-500/30 text-cyber-neon">
              <Cpu className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-base font-bold text-white font-mono flex items-center space-x-2">
                <span>SECTION 10: AI VS RULE-BASED FORENSIC LOGIC</span>
              </h2>
              <p className="text-xs text-zinc-400 font-mono">
                Deterministic Ground-Truth vs Probabilistic Machine Learning Architecture
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

        {/* Forensic Philosophy Callout */}
        <div className="p-5 bg-dark-950/70 border-b border-zinc-800 text-xs leading-relaxed space-y-2">
          <div className="flex items-center space-x-2 font-mono font-bold text-cyber-neon text-[11px] uppercase">
            <Shield className="w-4 h-4" />
            <span>Why AI is Genuinely Necessary (And Where It Must Be Avoided)</span>
          </div>
          <p className="text-zinc-300">
            Deterministic rules stop working exactly where an artifact is ambiguous, unknown, or requires interpreting human meaning — e.g. deciding whether a partially-recovered text chunk is <em>"about the incident"</em> cannot be hard-coded; the same is true for classifying a damaged fragment with no clean magic-header.
          </p>
          <p className="text-zinc-400 font-mono text-[11px]">
            Everything that <strong>can</strong> be exact (hashing, signature matching, structural format validation) stays rule-based on purpose, because exactness and auditability matter more than flexibility in a court of law.
          </p>
        </div>

        {/* Filter bar */}
        <div className="px-6 py-2.5 bg-dark-950/40 border-b border-zinc-800 flex items-center justify-between text-xs font-mono">
          <span className="text-zinc-400">Filter Logic Approach:</span>
          <div className="flex items-center space-x-1">
            {['All', 'Rule-based', 'ML'].map((f) => (
              <button
                key={f}
                onClick={() => setFilter(f)}
                className={`px-3 py-1 rounded text-xs transition-colors ${
                  filter === f
                    ? 'bg-cyber-500/20 text-cyber-neon border border-cyber-500/40 font-bold'
                    : 'text-zinc-400 hover:text-white bg-dark-900 border border-zinc-800'
                }`}
              >
                {f === 'All' ? 'All (10 Components)' : f === 'Rule-based' ? 'Rule-Based Only' : 'ML / AI Only'}
              </button>
            ))}
          </div>
        </div>

        {/* Matrix Table */}
        <div className="p-6 overflow-y-auto space-y-4 scrollbar-thin">
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
                {filteredItems.map((item, index) => {
                  const isRule = item.approach.includes('Rule');
                  const isML = item.approach.includes('ML') || item.approach.includes('NLP');

                  return (
                    <tr key={index} className="hover:bg-dark-900/40 transition-colors">
                      <td className="py-3 px-4 font-semibold text-white font-sans">
                        {item.component}
                      </td>

                      <td className="py-3 px-3 whitespace-nowrap">
                        <span className={`px-2 py-0.5 rounded text-[11px] font-bold ${
                          isRule && !isML
                            ? 'bg-blue-500/15 text-blue-300 border border-blue-500/40'
                            : isML && !isRule
                            ? 'bg-cyber-500/15 text-cyber-neon border border-cyber-500/40'
                            : 'bg-purple-500/15 text-purple-300 border border-purple-500/40'
                        }`}>
                          {item.approach}
                        </span>
                      </td>

                      <td className="py-3 px-3 text-zinc-300 text-[11px]">
                        {item.tooling}
                      </td>

                      <td className="py-3 px-4 text-zinc-300 text-xs font-sans leading-relaxed">
                        {item.why}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>

        {/* Footer */}
        <div className="px-6 py-3.5 bg-dark-950 border-t border-zinc-800 flex items-center justify-between text-xs font-mono text-zinc-500">
          <span>Forensic Architecture Specification (24h-Feasible Stack)</span>
          <button
            onClick={onClose}
            className="px-4 py-1.5 rounded-lg bg-zinc-800 hover:bg-zinc-700 text-white transition-colors"
          >
            Dismiss
          </button>
        </div>
      </div>
    </div>
  );
}
