import React, { useState } from 'react';
import { 
  ShieldCheck, 
  AlertTriangle, 
  Activity, 
  FileSearch, 
  CheckCircle2, 
  XCircle, 
  Layers, 
  Cpu, 
  Maximize2, 
  ArrowRight, 
  HelpCircle,
  Hash,
  FileCheck
} from 'lucide-react';

export default function IntegrityAssessmentSection({ artifacts = [], onOpenIntegrityModal }) {
  // Select which artifact to showcase in the integrity assessment section
  const sampleArtifacts = artifacts.length > 0 ? artifacts.slice(0, 6) : [];
  const [selectedId, setSelectedId] = useState(sampleArtifacts[0]?.id || 'DEMO-001');

  const selectedArtifact = artifacts.find(a => a.id === selectedId) || sampleArtifacts[0] || {
    id: 'DEMO-001',
    filename: 'restored_evidence_photo.jpg',
    type: 'Photos',
    overallIntegrity: 82,
    structuralIntegrity: 90,
    contentIntegrity: 78,
    fragmentContinuity: 85,
    metadataIntegrity: 75,
    corruptionSeverity: 'Low',
    recoverability: 'RECOVERABLE_WITH_MINOR_ARTIFACTS',
    corruptionRegions: [
      { start: 0, end: 1024, status: 'intact', label: 'SOI / Exif Metadata Header' },
      { start: 1024, end: 4096, status: 'intact', label: 'DQT / DHT Quantization Tables' },
      { start: 4096, end: 8192, status: 'damaged', label: 'SOS Huffman Scanline Segment' },
      { start: 8192, end: 12288, status: 'intact', label: 'Mid-Frame Scanline Data' },
      { start: 12288, end: 14336, status: 'corrupted', label: 'Corrupted Unallocated Block' },
      { start: 14336, end: 16384, status: 'repaired', label: 'Repaired EOI Marker (FF D9)' },
    ]
  };

  // Generate 24 sector blocks for the byte corruption heatmap
  const heatmapSectors = [
    { idx: 0, status: 'intact', offset: '0x0000', label: 'SOI Magic FF D8 FF' },
    { idx: 1, status: 'intact', offset: '0x0200', label: 'JFIF App0 Marker' },
    { idx: 2, status: 'intact', offset: '0x0400', label: 'Exif Metadata Segment' },
    { idx: 3, status: 'intact', offset: '0x0600', label: 'DQT Luminance Table' },
    { idx: 4, status: 'intact', offset: '0x0800', label: 'DQT Chrominance Table' },
    { idx: 5, status: 'intact', offset: '0x0A00', label: 'SOF0 Baseline DCT' },
    { idx: 6, status: 'intact', offset: '0x0C00', label: 'DHT Huffman DC Table' },
    { idx: 7, status: 'damaged', offset: '0x0E00', label: 'DHT AC Table Bit-Flip' },
    { idx: 8, status: 'damaged', offset: '0x1000', label: 'Restart Marker RST0' },
    { idx: 9, status: 'intact', offset: '0x1200', label: 'SOS Scan Component 1' },
    { idx: 10, status: 'intact', offset: '0x1400', label: 'Entropy Scanline MCU 0-15' },
    { idx: 11, status: 'intact', offset: '0x1600', label: 'Entropy Scanline MCU 16-31' },
    { idx: 12, status: 'intact', offset: '0x1800', label: 'Entropy Scanline MCU 32-47' },
    { idx: 13, status: 'corrupted', offset: '0x1A00', label: 'Overwritten Sector Hole' },
    { idx: 14, status: 'corrupted', offset: '0x1C00', label: 'Dangling Non-Contiguous' },
    { idx: 15, status: 'repaired', offset: '0x1E00', label: 'Repaired Huffman Stream' },
    { idx: 16, status: 'intact', offset: '0x2000', label: 'Lower Scanline MCU 48-63' },
    { idx: 17, status: 'intact', offset: '0x2200', label: 'Lower Scanline MCU 64-79' },
    { idx: 18, status: 'intact', offset: '0x2400', label: 'Lower Scanline MCU 80-95' },
    { idx: 19, status: 'damaged', offset: '0x2600', label: 'Partial Truncation Gap' },
    { idx: 20, status: 'repaired', offset: '0x2800', label: 'Synthesized Pad Bytes' },
    { idx: 21, status: 'intact', offset: '0x2A00', label: 'Final Scanline Boundary' },
    { idx: 22, status: 'intact', offset: '0x2C00', label: 'EOI Pre-Trailer Padding' },
    { idx: 23, status: 'repaired', offset: '0x2E00', label: 'EOI Delimiter (FF D9)' },
  ];

  return (
    <section 
      id="section-02-integrity" 
      className="scroll-mt-24 rounded-2xl border border-emerald-500/30 bg-dark-900/90 backdrop-blur-md p-6 sm:p-8 shadow-2xl relative overflow-hidden"
    >
      {/* Background accent glow */}
      <div className="absolute -top-24 -right-24 w-80 h-80 bg-emerald-500/10 rounded-full blur-3xl pointer-events-none" />
      <div className="absolute -bottom-24 -left-24 w-80 h-80 bg-cyan-500/10 rounded-full blur-3xl pointer-events-none" />

      {/* Header with Title and Engineering Objective Number */}
      <div className="flex flex-col md:flex-row md:items-center justify-between pb-6 border-b border-zinc-800 gap-4 relative z-10">
        <div>
          <div className="inline-flex items-center space-x-2 px-3 py-1 rounded-md bg-emerald-500/15 border border-emerald-500/40 text-emerald-400 font-mono text-xs mb-2">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
            <span className="font-bold tracking-wider">OBJECTIVE 02</span>
            <span className="text-zinc-500">•</span>
            <span>DATA INTEGRITY &amp; CORRUPTION ASSESSMENT</span>
          </div>
          <h2 className="text-2xl sm:text-3xl font-extrabold text-white tracking-wide flex items-center space-x-3">
            <span>DATA INTEGRITY &amp; CORRUPTION ASSESSMENT</span>
          </h2>
          <p className="text-sm text-zinc-400 mt-1 max-w-3xl">
            Determine which portions of recovered data are intact, damaged, or corrupted using format-aware deep parsers and multi-factor integrity scoring.
          </p>
        </div>

        {/* AI & Model Specs Badge */}
        <div className="flex items-center space-x-2">
          <div className="px-3 py-2 rounded-lg bg-dark-950 border border-emerald-500/30 font-mono text-xs text-right">
            <div className="text-[10px] text-zinc-500 uppercase tracking-wider">ASSESSMENT ENGINE</div>
            <div className="text-emerald-400 font-semibold flex items-center justify-end space-x-1">
              <Cpu className="w-3.5 h-3.5 text-emerald-400" />
              <span>Format-Aware Parsers + ISO/IEC 27037</span>
            </div>
          </div>
          <button
            onClick={() => onOpenIntegrityModal && onOpenIntegrityModal(selectedArtifact)}
            className="px-4 py-2.5 rounded-lg bg-emerald-500 hover:bg-emerald-400 text-black font-semibold text-xs transition-all flex items-center space-x-2 shadow-lg shadow-emerald-500/20 active:scale-95 cursor-pointer"
          >
            <Maximize2 className="w-3.5 h-3.5" />
            <span>Launch Deep Parser</span>
          </button>
        </div>
      </div>

      {/* Artifact Quick Switcher Pills */}
      <div className="flex items-center space-x-2 overflow-x-auto py-4 border-b border-zinc-800 text-xs font-mono scrollbar-none">
        <span className="text-zinc-500 uppercase tracking-wider text-[11px] shrink-0">Select Evidence Artifact:</span>
        {sampleArtifacts.map(art => (
          <button
            key={art.id}
            onClick={() => setSelectedId(art.id)}
            className={`px-3 py-1.5 rounded-lg shrink-0 transition-all cursor-pointer ${
              selectedId === art.id
                ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 font-semibold shadow-sm'
                : 'bg-dark-950 text-zinc-400 hover:text-zinc-200 border border-zinc-800'
            }`}
          >
            <span>{art.filename}</span>
            <span className="ml-1.5 px-1.5 py-0.2 rounded text-[10px] bg-dark-900 border border-zinc-700">
              {art.overallIntegrity ?? art.integrity ?? 80}%
            </span>
          </button>
        ))}
      </div>

      {/* Main Grid: 4-Factor Integrity Scoreboard + Byte Corruption Heatmap */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 my-6 items-start">
        {/* Left Column (5 cols): 4-Dimensional Integrity Breakdown */}
        <div className="lg:col-span-5 space-y-4">
          <div className="p-5 rounded-xl bg-dark-950 border border-zinc-800 space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-zinc-800">
              <div className="font-mono text-xs uppercase tracking-wider text-zinc-300 font-semibold flex items-center space-x-2">
                <Activity className="w-4 h-4 text-emerald-400" />
                <span>COMPOSITE INTEGRITY SCORE</span>
              </div>
              <span className={`px-2.5 py-0.5 rounded text-xs font-mono font-bold ${
                (selectedArtifact.overallIntegrity || 80) >= 80 ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/40' :
                (selectedArtifact.overallIntegrity || 80) >= 50 ? 'bg-amber-500/20 text-amber-400 border border-amber-500/40' :
                'bg-rose-500/20 text-rose-400 border border-rose-500/40'
              }`}>
                {selectedArtifact.overallIntegrity || 82}% OVERALL
              </span>
            </div>

            {/* 4 Factor Sliders */}
            <div className="space-y-3 font-mono text-xs">
              <div>
                <div className="flex justify-between text-zinc-400 mb-1">
                  <span>1. Structural Integrity (Headers &amp; AST)</span>
                  <span className="text-white font-semibold">{selectedArtifact.structuralIntegrity || 90}%</span>
                </div>
                <div className="w-full h-2 rounded-full bg-dark-850 overflow-hidden">
                  <div 
                    className="h-full bg-emerald-400 rounded-full transition-all duration-500" 
                    style={{ width: `${selectedArtifact.structuralIntegrity || 90}%` }}
                  />
                </div>
              </div>

              <div>
                <div className="flex justify-between text-zinc-400 mb-1">
                  <span>2. Content Stream Integrity</span>
                  <span className="text-white font-semibold">{selectedArtifact.contentIntegrity || 78}%</span>
                </div>
                <div className="w-full h-2 rounded-full bg-dark-850 overflow-hidden">
                  <div 
                    className="h-full bg-cyan-400 rounded-full transition-all duration-500" 
                    style={{ width: `${selectedArtifact.contentIntegrity || 78}%` }}
                  />
                </div>
              </div>

              <div>
                <div className="flex justify-between text-zinc-400 mb-1">
                  <span>3. Fragment Cluster Continuity</span>
                  <span className="text-white font-semibold">{selectedArtifact.fragmentContinuity || 85}%</span>
                </div>
                <div className="w-full h-2 rounded-full bg-dark-850 overflow-hidden">
                  <div 
                    className="h-full bg-blue-400 rounded-full transition-all duration-500" 
                    style={{ width: `${selectedArtifact.fragmentContinuity || 85}%` }}
                  />
                </div>
              </div>

              <div>
                <div className="flex justify-between text-zinc-400 mb-1">
                  <span>4. Metadata &amp; Timestamps</span>
                  <span className="text-white font-semibold">{selectedArtifact.metadataIntegrity || 75}%</span>
                </div>
                <div className="w-full h-2 rounded-full bg-dark-850 overflow-hidden">
                  <div 
                    className="h-full bg-purple-400 rounded-full transition-all duration-500" 
                    style={{ width: `${selectedArtifact.metadataIntegrity || 75}%` }}
                  />
                </div>
              </div>
            </div>

            {/* Corruption Severity & Recommendation Banner */}
            <div className="p-3 rounded-lg bg-dark-900 border border-zinc-800 text-xs font-mono space-y-1.5">
              <div className="flex items-center justify-between">
                <span className="text-zinc-500">CORRUPTION SEVERITY:</span>
                <span className="text-emerald-400 font-bold uppercase">{selectedArtifact.corruptionSeverity || 'Low'}</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-zinc-500">RESTORABILITY:</span>
                <span className="text-cyan-300 font-bold truncate max-w-[200px]">{selectedArtifact.recoverability || 'RECOVERABLE'}</span>
              </div>
            </div>
          </div>
        </div>

        {/* Right Column (7 cols): Byte-Level Corruption Heatmap */}
        <div className="lg:col-span-7 space-y-4">
          <div className="p-5 rounded-xl bg-dark-950 border border-zinc-800 space-y-3">
            <div className="flex items-center justify-between pb-3 border-b border-zinc-800">
              <div className="font-mono text-xs uppercase tracking-wider text-zinc-300 font-semibold flex items-center space-x-2">
                <FileSearch className="w-4 h-4 text-emerald-400" />
                <span>BYTE-LEVEL CORRUPTION HEATMAP ({selectedArtifact.filename})</span>
              </div>
              <span className="text-[10px] font-mono text-zinc-500">512-BYTE SECTOR RESOLUTION</span>
            </div>

            {/* 24-Sector Visual Heatmap */}
            <div className="grid grid-cols-4 sm:grid-cols-6 gap-2">
              {heatmapSectors.map((sec) => {
                let color = 'bg-emerald-950/70 border-emerald-500/50 text-emerald-300';
                if (sec.status === 'damaged') color = 'bg-amber-950/70 border-amber-500/50 text-amber-300';
                if (sec.status === 'corrupted') color = 'bg-rose-950/70 border-rose-500/50 text-rose-300';
                if (sec.status === 'repaired') color = 'bg-blue-950/70 border-blue-500/50 text-blue-300';

                return (
                  <div
                    key={sec.idx}
                    title={`${sec.offset}: ${sec.label} (${sec.status.toUpperCase()})`}
                    className={`p-2 rounded-lg border text-left font-mono transition-transform hover:scale-105 cursor-pointer ${color}`}
                  >
                    <div className="text-[10px] font-bold">{sec.offset}</div>
                    <div className="text-[9px] uppercase tracking-wider opacity-80 mt-0.5">{sec.status}</div>
                  </div>
                );
              })}
            </div>

            {/* Heatmap Legend */}
            <div className="flex flex-wrap items-center gap-4 text-[11px] font-mono text-zinc-400 pt-2 border-t border-zinc-800/80">
              <span className="flex items-center space-x-1.5">
                <span className="w-2.5 h-2.5 rounded bg-emerald-500"></span>
                <span>Intact (Verified AST)</span>
              </span>
              <span className="flex items-center space-x-1.5">
                <span className="w-2.5 h-2.5 rounded bg-amber-500"></span>
                <span>Damaged (Partial Bit-flip)</span>
              </span>
              <span className="flex items-center space-x-1.5">
                <span className="w-2.5 h-2.5 rounded bg-rose-500"></span>
                <span>Corrupted / Overwritten</span>
              </span>
              <span className="flex items-center space-x-1.5">
                <span className="w-2.5 h-2.5 rounded bg-blue-500"></span>
                <span>Repaired Synthetic Marker</span>
              </span>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
