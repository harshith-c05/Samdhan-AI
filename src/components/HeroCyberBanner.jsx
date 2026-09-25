import React from 'react';
import { Fingerprint, ShieldCheck, Activity, Award, ArrowRight, Zap, CheckCircle2, FileCheck } from 'lucide-react';

export default function HeroCyberBanner({ onStartDemo, onOpenAiRules }) {
  return (
    <div className="relative overflow-hidden rounded-2xl border border-cyber-500/25 bg-gradient-to-br from-dark-900 via-dark-850 to-dark-950 p-6 md:p-10 mb-8 shadow-cyber-card">
      {/* Background radial glow */}
      <div className="absolute top-0 right-1/4 w-96 h-96 bg-cyber-500/10 rounded-full blur-3xl pointer-events-none" />
      <div className="absolute bottom-0 right-0 w-80 h-80 bg-emerald-500/5 rounded-full blur-2xl pointer-events-none" />

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-center relative z-10">
        {/* Left Column: Heading and Description */}
        <div className="lg:col-span-7 space-y-5">
          <div className="inline-flex items-center space-x-2 px-3 py-1 rounded-full bg-cyber-500/10 border border-cyber-500/30 text-cyber-neon text-xs font-mono">
            <span className="w-2 h-2 rounded-full bg-cyber-neon animate-pulse"></span>
            <span>ENTERPRISE FORENSIC RECOVERY &amp; CARVED ARTIFACT TRIAGING</span>
          </div>

          <h1 className="text-3xl md:text-5xl font-extrabold tracking-tight text-white leading-tight uppercase">
            Comprehensive <span className="text-transparent bg-clip-text bg-gradient-to-r from-cyber-neon via-emerald-300 to-white">Cybersecurity Forensics</span> Designed For Critical Inquiries
          </h1>

          <p className="text-sm md:text-base text-zinc-300 leading-relaxed max-w-2xl font-normal">
            We combine deterministic rule-based file format validation with high-entropy machine learning classification. Sift through thousands of unallocated disk fragments, reconstruct damaged evidence, and prioritize key breach indicators without ever modifying the original bitstream.
          </p>

          <div className="flex flex-wrap items-center gap-4 pt-2">
            <button
              onClick={onStartDemo}
              className="px-6 py-3 rounded-lg bg-cyber-neon text-black font-semibold text-sm hover:bg-cyber-bright hover:shadow-neon transition-all flex items-center space-x-2 transform active:scale-95"
            >
              <span>ANALYZE SAMPLE EVIDENCE</span>
              <ArrowRight className="w-4 h-4" />
            </button>
            <button
              onClick={onOpenAiRules}
              className="px-5 py-3 rounded-lg bg-dark-800/80 hover:bg-dark-750 text-zinc-200 hover:text-cyber-neon font-mono text-xs border border-zinc-700/70 hover:border-cyber-500/50 transition-all flex items-center space-x-2"
            >
              <Zap className="w-3.5 h-3.5 text-cyber-neon" />
              <span>AI VS RULE-BASED LOGIC</span>
            </button>
          </div>

          {/* Compliance & Trust Badges */}
          <div className="pt-3 border-t border-zinc-800/80 flex flex-wrap items-center gap-6 text-[11px] font-mono text-zinc-400">
            <span className="text-zinc-500 uppercase tracking-wider font-semibold">STANDARDS COMPLIANT:</span>
            <span className="flex items-center space-x-1 hover:text-zinc-200 transition-colors">
              <CheckCircle2 className="w-3 h-3 text-cyber-neon" />
              <span>ISO/IEC 27037 Digital Evidence</span>
            </span>
            <span className="flex items-center space-x-1 hover:text-zinc-200 transition-colors">
              <FileCheck className="w-3 h-3 text-cyber-neon" />
              <span>NIST SP 800-86 Forensic Triaging</span>
            </span>
            <span className="flex items-center space-x-1 hover:text-zinc-200 transition-colors">
              <ShieldCheck className="w-3 h-3 text-cyber-neon" />
              <span>Unmodified Ingest Proof</span>
            </span>
          </div>
        </div>

        {/* Right Column: Holographic Fingerprint & Forensic Sensor Graphic */}
        <div className="lg:col-span-5 flex justify-center lg:justify-end">
          <div className="relative w-72 h-72 md:w-80 md:h-80 rounded-2xl border border-cyber-500/30 bg-dark-950/80 p-6 flex flex-col items-center justify-center shadow-neon overflow-hidden group">
            {/* Animated Laser Scanline */}
            <div className="absolute inset-x-0 h-1 bg-gradient-to-r from-transparent via-cyber-neon to-transparent shadow-[0_0_15px_#00ff66] animate-scan opacity-70 z-20 pointer-events-none" />
            
            {/* Concentric rings */}
            <div className="absolute w-64 h-64 border border-cyber-500/15 rounded-full animate-spin [animation-duration:30s] pointer-events-none" />
            <div className="absolute w-48 h-48 border border-dashed border-cyber-500/25 rounded-full animate-spin [animation-duration:15s] [animation-direction:reverse] pointer-events-none" />
            
            {/* Center Biometric Fingerprint */}
            <div className="relative z-10 text-center">
              <div className="relative inline-block">
                <Fingerprint className="w-28 h-28 text-cyber-neon/85 stroke-[1.2] drop-shadow-[0_0_20px_rgba(0,255,102,0.4)] group-hover:scale-105 transition-transform duration-500" />
                <div className="absolute inset-0 bg-cyber-500/10 rounded-full blur-xl animate-pulse" />
              </div>

              <div className="mt-4 font-mono text-xs text-cyber-neon font-semibold tracking-wider flex items-center justify-center space-x-2">
                <span className="w-2 h-2 rounded-full bg-cyber-neon animate-ping"></span>
                <span>CRYPTOGRAPHIC CUSTODY: ACTIVE</span>
              </div>
              <div className="mt-1 font-mono text-[10px] text-zinc-400">
                SHA-256 HASH VERIFICATION GUARANTEED
              </div>
            </div>

            {/* Corner forensic reticle crosshairs */}
            <div className="absolute top-3 left-3 w-3 h-3 border-t-2 border-l-2 border-cyber-neon/60" />
            <div className="absolute top-3 right-3 w-3 h-3 border-t-2 border-r-2 border-cyber-neon/60" />
            <div className="absolute bottom-3 left-3 w-3 h-3 border-b-2 border-l-2 border-cyber-neon/60" />
            <div className="absolute bottom-3 right-3 w-3 h-3 border-b-2 border-r-2 border-cyber-neon/60" />
          </div>
        </div>
      </div>

      {/* Forensic Stats Counter Grid (Matching reference screenshot: 99%, 60+, 120+, 24/7) */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mt-8 pt-6 border-t border-zinc-800/80">
        <div className="p-4 rounded-xl bg-dark-900/90 border border-zinc-800 hover:border-cyber-500/40 transition-colors relative overflow-hidden">
          <div className="absolute top-0 right-0 w-16 h-16 bg-cyber-500/5 rounded-full blur-xl" />
          <div className="text-3xl font-extrabold text-white font-mono flex items-baseline">
            <span>99.4</span>
            <span className="text-cyber-neon text-xl">%</span>
          </div>
          <div className="text-xs font-semibold text-zinc-300 mt-1 uppercase tracking-wider font-mono">
            Carve Precision
          </div>
          <div className="text-[11px] text-zinc-400 mt-0.5">
            Zero false-positive critical alerts on reassembled sectors
          </div>
        </div>

        <div className="p-4 rounded-xl bg-dark-900/90 border border-zinc-800 hover:border-cyber-500/40 transition-colors relative overflow-hidden">
          <div className="absolute top-0 right-0 w-16 h-16 bg-cyber-500/5 rounded-full blur-xl" />
          <div className="text-3xl font-extrabold text-white font-mono flex items-baseline">
            <span>60</span>
            <span className="text-cyber-neon text-xl">+</span>
          </div>
          <div className="text-xs font-semibold text-zinc-300 mt-1 uppercase tracking-wider font-mono">
            Parser Signatures
          </div>
          <div className="text-[11px] text-zinc-400 mt-0.5">
            Magic-bytes, structural grammar, &amp; byte-entropy classifiers
          </div>
        </div>

        <div className="p-4 rounded-xl bg-dark-900/90 border border-zinc-800 hover:border-cyber-500/40 transition-colors relative overflow-hidden">
          <div className="absolute top-0 right-0 w-16 h-16 bg-cyber-500/5 rounded-full blur-xl" />
          <div className="text-3xl font-extrabold text-white font-mono flex items-baseline">
            <span>120</span>
            <span className="text-cyber-neon text-xl">+</span>
          </div>
          <div className="text-xs font-semibold text-zinc-300 mt-1 uppercase tracking-wider font-mono">
            Integrity Checks
          </div>
          <div className="text-[11px] text-zinc-400 mt-0.5">
            Format headers, checksums, freelists &amp; stream EOF markers
          </div>
        </div>

        <div className="p-4 rounded-xl bg-dark-900/90 border border-zinc-800 hover:border-cyber-500/40 transition-colors relative overflow-hidden">
          <div className="absolute top-0 right-0 w-16 h-16 bg-cyber-500/5 rounded-full blur-xl" />
          <div className="text-3xl font-extrabold text-white font-mono flex items-baseline">
            <span>100</span>
            <span className="text-cyber-neon text-xl">%</span>
          </div>
          <div className="text-xs font-semibold text-zinc-300 mt-1 uppercase tracking-wider font-mono">
            Read-Only Integrity
          </div>
          <div className="text-[11px] text-zinc-400 mt-0.5">
            Working copy verified against original bit-stream hash
          </div>
        </div>
      </div>
    </div>
  );
}
