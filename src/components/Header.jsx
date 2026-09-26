import React from 'react';
import { Shield, Lock, FileSearch, Database, Cpu, Terminal, Download, Layers, CheckCircle2 } from 'lucide-react';

export default function Header({ 
  currentScreen, 
  setCurrentScreen, 
  activeCase, 
  onOpenAiRules, 
  onOpenAuditLog, 
  onExportReport,
  isAnalyzed
}) {
  return (
    <header className="sticky top-0 z-40 border-b border-cyber-500/20 bg-dark-950/90 backdrop-blur-md">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          {/* Brand & Title */}
          <div className="flex items-center space-x-3 cursor-pointer" onClick={() => setCurrentScreen('input')}>
            <div className="relative p-2 rounded-lg bg-cyber-500/10 border border-cyber-500/30 text-cyber-neon shadow-neon">
              <Shield className="w-6 h-6 animate-pulse" />
              <div className="absolute -top-1 -right-1 w-2.5 h-2.5 bg-cyber-neon rounded-full animate-ping" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <span className="font-mono font-black text-xl tracking-wider text-white">
                  SAMDHAN<span className="text-cyber-neon font-sans">.AI</span>
                </span>
                <span className="px-2 py-0.5 text-[10px] font-mono font-semibold uppercase tracking-wider bg-cyber-500/20 text-cyber-neon border border-cyber-500/40 rounded">
                  v3.0 UNIFIED
                </span>
              </div>
              <p className="text-[11px] text-zinc-400 font-mono tracking-tight hidden sm:block">
                Digital Forensics &amp; Carved Fragment Triaging Platform
              </p>
            </div>
          </div>

          {/* 4 Key Engineering Objectives — Quick Anchor Jump Bar */}
          <div className="hidden lg:flex items-center space-x-1 bg-dark-900/90 p-1 rounded-lg border border-zinc-800">
            <a
              href="#section-01-reconstruction"
              onClick={() => { if (currentScreen !== 'dashboard') setCurrentScreen('dashboard'); }}
              className="px-2.5 py-1.5 rounded-md text-xs font-mono font-medium text-cyan-400 hover:bg-cyan-500/10 border border-transparent hover:border-cyan-500/30 transition-all flex items-center space-x-1.5"
            >
              <span className="w-1.5 h-1.5 rounded-full bg-cyan-400"></span>
              <span>01 Reconstruct</span>
            </a>
            <a
              href="#section-02-integrity"
              onClick={() => { if (currentScreen !== 'dashboard') setCurrentScreen('dashboard'); }}
              className="px-2.5 py-1.5 rounded-md text-xs font-mono font-medium text-emerald-400 hover:bg-emerald-500/10 border border-transparent hover:border-emerald-500/30 transition-all flex items-center space-x-1.5"
            >
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400"></span>
              <span>02 Integrity</span>
            </a>
            <a
              href="#section-03-prioritization"
              onClick={() => { if (currentScreen !== 'dashboard') setCurrentScreen('dashboard'); }}
              className="px-2.5 py-1.5 rounded-md text-xs font-mono font-medium text-cyber-neon hover:bg-cyber-500/10 border border-transparent hover:border-cyber-500/30 transition-all flex items-center space-x-1.5"
            >
              <span className="w-1.5 h-1.5 rounded-full bg-cyber-neon"></span>
              <span>03 Prioritize</span>
            </a>
            <a
              href="#section-04-decision"
              onClick={() => { if (currentScreen !== 'dashboard') setCurrentScreen('dashboard'); }}
              className="px-2.5 py-1.5 rounded-md text-xs font-mono font-medium text-purple-400 hover:bg-purple-500/10 border border-transparent hover:border-purple-500/30 transition-all flex items-center space-x-1.5"
            >
              <span className="w-1.5 h-1.5 rounded-full bg-purple-400"></span>
              <span>04 Decision</span>
            </a>
          </div>

          {/* Security & Forensic Actions */}
          <div className="flex items-center space-x-2">
            {/* Read-Only Guarantee badge */}
            <div className="hidden lg:flex items-center space-x-1.5 px-2.5 py-1 bg-dark-900 border border-emerald-500/30 rounded text-[11px] font-mono text-emerald-400">
              <Lock className="w-3.5 h-3.5 text-emerald-400" />
              <span>READ-ONLY COPY</span>
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span>
            </div>

            {/* AI vs Rule button */}
            <button
              onClick={onOpenAiRules}
              title="Technical Architecture Presentation &amp; AI Models (Deliverable 03)"
              className="px-2.5 py-1.5 text-xs font-mono rounded bg-dark-850 hover:bg-dark-800 text-zinc-300 hover:text-cyber-neon border border-zinc-700/60 hover:border-cyber-500/40 transition-colors flex items-center space-x-1.5"
            >
              <Cpu className="w-3.5 h-3.5 text-cyber-neon" />
              <span className="hidden sm:inline">Architecture &amp; AI</span>
            </button>

            {/* Audit Log button */}
            <button
              onClick={onOpenAuditLog}
              title="View Immutable Audit Trail"
              className="px-2.5 py-1.5 text-xs font-mono rounded bg-dark-850 hover:bg-dark-800 text-zinc-300 hover:text-white border border-zinc-700/60 transition-colors flex items-center space-x-1.5"
            >
              <Terminal className="w-3.5 h-3.5 text-zinc-400" />
              <span className="hidden sm:inline">Audit Log</span>
            </button>

            {/* Export Report button */}
            <button
              onClick={onExportReport}
              disabled={!isAnalyzed}
              title="Export Forensics Court-Admissible Dossier"
              className={`px-3 py-1.5 text-xs font-medium rounded transition-all flex items-center space-x-1.5 ${
                isAnalyzed
                  ? 'bg-cyber-500 text-black hover:bg-cyber-neon font-semibold shadow-neon cursor-pointer'
                  : 'bg-zinc-800 text-zinc-500 border border-zinc-700/50 cursor-not-allowed'
              }`}
            >
              <Download className="w-3.5 h-3.5" />
              <span>Export Dossier</span>
            </button>
          </div>
        </div>
      </div>
    </header>
  );
}
