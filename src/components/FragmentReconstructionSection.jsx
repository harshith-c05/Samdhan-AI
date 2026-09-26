import React, { useState } from 'react';
import { 
  Binary, 
  Layers, 
  Cpu, 
  GitMerge, 
  ArrowRight, 
  CheckCircle2, 
  AlertTriangle, 
  RefreshCw, 
  Zap, 
  Terminal, 
  FileCode, 
  ShieldCheck, 
  Hash, 
  Maximize2 
} from 'lucide-react';

// 36 Forensic Sector Clusters representing carved disk fragments
const INITIAL_CLUSTERS = [
  { id: 'CL-01', offset: '0x00000000', type: 'BOOT_SECTOR', label: 'MBR / VBR', status: 'intact', entropy: 4.12, format: 'Filesystem Header', candidateNext: 'CL-02', edgeScore: 99.2 },
  { id: 'CL-02', offset: '0x00001000', type: 'MFT_FAT', label: '$MFT Record 0', status: 'intact', entropy: 5.68, format: 'NTFS Table', candidateNext: 'CL-03', edgeScore: 98.5 },
  { id: 'CL-03', offset: '0x00002000', type: 'HEADER', label: 'JPEG (FF D8 FF)', status: 'intact', entropy: 7.42, format: 'JPEG Header', candidateNext: 'CL-07', edgeScore: 96.4, artifact: 'photo.jpg' },
  { id: 'CL-04', offset: '0x00003000', type: 'HEADER', label: 'PDF (%PDF-1.7)', status: 'intact', entropy: 6.88, format: 'PDF Catalog', candidateNext: 'CL-09', edgeScore: 97.1, artifact: 'confidential_memo.pdf' },
  { id: 'CL-05', offset: '0x00004000', type: 'HEADER', label: 'SQLite (format 3)', status: 'intact', entropy: 6.15, format: 'Database Header', candidateNext: 'CL-11', edgeScore: 99.0, artifact: 'incident_audit.db' },
  { id: 'CL-06', offset: '0x00005000', type: 'HEADER', label: 'PE (MZ / 0x4D5A)', status: 'conflict', entropy: 7.82, format: 'PE Binary (Disguised)', candidateNext: 'CL-14', edgeScore: 94.2, artifact: 'invoice.jpg (Malware)' },
  { id: 'CL-07', offset: '0x00006000', type: 'DATA_BODY', label: 'JPEG DQT / SOF0', status: 'intact', entropy: 7.91, format: 'JPEG Quantization', candidateNext: 'CL-13', edgeScore: 95.8, artifact: 'photo.jpg' },
  { id: 'CL-08', offset: '0x00007000', type: 'DANGLING', label: 'Dangling Chunk A', status: 'dangling', entropy: 7.84, format: 'Orphan Data Stream', candidateNext: 'CL-17', edgeScore: 89.2 },
  { id: 'CL-09', offset: '0x00008000', type: 'DATA_BODY', label: 'PDF Object Stream', status: 'intact', entropy: 7.10, format: 'PDF FlateDecode', candidateNext: 'CL-15', edgeScore: 93.6, artifact: 'confidential_memo.pdf' },
  { id: 'CL-10', offset: '0x00009000', type: 'HEADER', label: 'EVTX (ElfFile)', status: 'intact', entropy: 5.92, format: 'Windows Event Log', candidateNext: 'CL-16', edgeScore: 98.7, artifact: 'Security.evtx' },
  { id: 'CL-11', offset: '0x0000A000', type: 'DATA_BODY', label: 'SQLite B-Tree Page', status: 'intact', entropy: 6.74, format: 'SQL Schema / Table', candidateNext: 'CL-21', edgeScore: 97.4, artifact: 'incident_audit.db' },
  { id: 'CL-12', offset: '0x0000B000', type: 'DANGLING', label: 'Dangling Chunk B', status: 'dangling', entropy: 7.92, format: 'Entropy Transition Gap', candidateNext: 'CL-19', edgeScore: 88.5 },
  { id: 'CL-13', offset: '0x0000C000', type: 'DATA_BODY', label: 'JPEG SOS Scan 1', status: 'intact', entropy: 7.98, format: 'Huffman Entropy Data', candidateNext: 'CL-18', edgeScore: 96.1, artifact: 'photo.jpg' },
  { id: 'CL-14', offset: '0x0000D000', type: 'DATA_BODY', label: 'PE .text Section', status: 'conflict', entropy: 6.45, format: 'x86_64 Opcode stream', candidateNext: 'CL-22', edgeScore: 95.0, artifact: 'invoice.jpg (Malware)' },
  { id: 'CL-15', offset: '0x0000E000', type: 'DATA_BODY', label: 'PDF Cross-Ref XRef', status: 'intact', entropy: 5.40, format: 'PDF Object Table', candidateNext: 'CL-24', edgeScore: 98.1, artifact: 'confidential_memo.pdf' },
  { id: 'CL-16', offset: '0x0000F000', type: 'DATA_BODY', label: 'EVTX Chunk Record', status: 'intact', entropy: 6.30, format: 'Binary XML Events', candidateNext: 'CL-26', edgeScore: 96.0, artifact: 'Security.evtx' },
  { id: 'CL-17', offset: '0x00010000', type: 'DANGLING', label: 'Dangling Chunk C', status: 'dangling', entropy: 7.89, format: 'Orphan JPEG Scanline', candidateNext: 'CL-27', edgeScore: 91.3 },
  { id: 'CL-18', offset: '0x00011000', type: 'DATA_BODY', label: 'JPEG SOS Scan 2', status: 'intact', entropy: 7.97, format: 'Scanline Segment', candidateNext: 'CL-28', edgeScore: 94.7, artifact: 'photo.jpg' },
  { id: 'CL-19', offset: '0x00012000', type: 'HEADER', label: 'PCAP (D4 C3 B2 A1)', status: 'intact', entropy: 5.12, format: 'Network Packet Header', candidateNext: 'CL-23', edgeScore: 99.5, artifact: 'traffic.pcap' },
  { id: 'CL-20', offset: '0x00013000', type: 'DANGLING', label: 'Dangling Chunk D', status: 'dangling', entropy: 7.75, format: 'Stitched Unallocated', candidateNext: 'CL-25', edgeScore: 87.9 },
  { id: 'CL-21', offset: '0x00014000', type: 'DATA_BODY', label: 'SQLite Free-list', status: 'intact', entropy: 6.05, format: 'Carved Deleted Rows', candidateNext: 'CL-29', edgeScore: 92.4, artifact: 'incident_audit.db' },
  { id: 'CL-22', offset: '0x00015000', type: 'DATA_BODY', label: 'PE .rdata / Imports', status: 'conflict', entropy: 5.80, format: 'Win32 IAT (Crypt32)', candidateNext: 'CL-32', edgeScore: 93.8, artifact: 'invoice.jpg (Malware)' },
  { id: 'CL-23', offset: '0x00016000', type: 'DATA_BODY', label: 'PCAP TCP Handshake', status: 'intact', entropy: 5.85, format: 'TCP/IP Frame', candidateNext: 'CL-30', edgeScore: 97.2, artifact: 'traffic.pcap' },
  { id: 'CL-24', offset: '0x00017000', type: 'TRAILER', label: 'PDF Trailer %%EOF', status: 'intact', entropy: 4.80, format: 'PDF End-of-File', candidateNext: 'END', edgeScore: 99.8, artifact: 'confidential_memo.pdf' },
  { id: 'CL-25', offset: '0x00018000', type: 'DANGLING', label: 'Dangling Chunk E', status: 'dangling', entropy: 7.60, format: 'Fragment Bridge', candidateNext: 'CL-31', edgeScore: 89.9 },
  { id: 'CL-26', offset: '0x00019000', type: 'TRAILER', label: 'EVTX Chunk End', status: 'intact', entropy: 4.90, format: 'EVTX Checksum', candidateNext: 'END', edgeScore: 98.9, artifact: 'Security.evtx' },
  { id: 'CL-27', offset: '0x0001A000', type: 'DATA_BODY', label: 'Stitched Scanline B', status: 'intact', entropy: 7.96, format: 'Reconstructed DCT', candidateNext: 'CL-28', edgeScore: 93.1, artifact: 'photo.jpg' },
  { id: 'CL-28', offset: '0x0001B000', type: 'TRAILER', label: 'JPEG Trailer (FF D9)', status: 'intact', entropy: 4.20, format: 'JPEG EOI', candidateNext: 'END', edgeScore: 99.9, artifact: 'photo.jpg' },
  { id: 'CL-29', offset: '0x0001C000', type: 'TRAILER', label: 'SQLite DB Commit EOF', status: 'intact', entropy: 4.10, format: 'DB Page Flush', candidateNext: 'END', edgeScore: 99.1, artifact: 'incident_audit.db' },
  { id: 'CL-30', offset: '0x0001D000', type: 'TRAILER', label: 'PCAP Epilogue EOF', status: 'intact', entropy: 4.40, format: 'Capture Stream End', candidateNext: 'END', edgeScore: 99.4, artifact: 'traffic.pcap' },
  { id: 'CL-31', offset: '0x0001E000', type: 'HEADER', label: 'DOCX / ZIP PK\x03\x04', status: 'intact', entropy: 7.88, format: 'OpenXML Archive', candidateNext: 'CL-34', edgeScore: 96.5, artifact: 'statement.docx' },
  { id: 'CL-32', offset: '0x0001F000', type: 'TRAILER', label: 'PE Certificate Table', status: 'conflict', entropy: 5.10, format: 'Self-Signed Tampered', candidateNext: 'END', edgeScore: 94.0, artifact: 'invoice.jpg (Malware)' },
  { id: 'CL-33', offset: '0x00020000', type: 'DANGLING', label: 'Orphan Slack Space', status: 'dangling', entropy: 3.20, format: 'Zero-Fill / Slack', candidateNext: 'END', edgeScore: 78.0 },
  { id: 'CL-34', offset: '0x00021000', type: 'DATA_BODY', label: 'DOCX document.xml', status: 'intact', entropy: 7.92, format: 'Compressed XML', candidateNext: 'CL-35', edgeScore: 97.8, artifact: 'statement.docx' },
  { id: 'CL-35', offset: '0x00022000', type: 'TRAILER', label: 'ZIP EOCD Record', status: 'intact', entropy: 5.25, format: 'ZIP Directory End', candidateNext: 'END', edgeScore: 99.6, artifact: 'statement.docx' },
  { id: 'CL-36', offset: '0x00023000', type: 'UNALLOCATED', label: 'Free Unallocated Space', status: 'free', entropy: 0.15, format: 'Unused Blocks', candidateNext: 'END', edgeScore: 99.9 },
];

export default function FragmentReconstructionSection({ onSelectArtifact }) {
  const [selectedCluster, setSelectedCluster] = useState(INITIAL_CLUSTERS[2]); // Default: JPEG Header
  const [isReassembling, setIsReassembling] = useState(false);
  const [reassemblyComplete, setReassemblyComplete] = useState(true);
  const [filterType, setFilterType] = useState('ALL');

  // Trigger simulated live TSP graph reassembly
  const handleTriggerReassembly = () => {
    setIsReassembling(true);
    setTimeout(() => {
      setIsReassembling(false);
      setReassemblyComplete(true);
    }, 1200);
  };

  const filteredClusters = filterType === 'ALL'
    ? INITIAL_CLUSTERS
    : filterType === 'DANGLING'
      ? INITIAL_CLUSTERS.filter(c => c.status === 'dangling')
      : filterType === 'HEADER'
        ? INITIAL_CLUSTERS.filter(c => c.type === 'HEADER')
        : INITIAL_CLUSTERS;

  // Active path sequence for selected cluster's artifact
  const pathSequence = selectedCluster.artifact
    ? INITIAL_CLUSTERS.filter(c => c.artifact === selectedCluster.artifact)
    : [selectedCluster];

  return (
    <section 
      id="section-01-reconstruction" 
      className="scroll-mt-24 rounded-2xl border border-cyan-500/30 bg-dark-900/90 backdrop-blur-md p-6 sm:p-8 shadow-2xl relative overflow-hidden"
    >
      {/* Background cyber accent glow */}
      <div className="absolute -top-24 -left-24 w-80 h-80 bg-cyan-500/10 rounded-full blur-3xl pointer-events-none" />
      <div className="absolute -bottom-24 -right-24 w-80 h-80 bg-cyber-500/10 rounded-full blur-3xl pointer-events-none" />

      {/* Header with Title and Engineering Objective Number */}
      <div className="flex flex-col md:flex-row md:items-center justify-between pb-6 border-b border-zinc-800 gap-4 relative z-10">
        <div>
          <div className="inline-flex items-center space-x-2 px-3 py-1 rounded-md bg-cyan-500/15 border border-cyan-500/40 text-cyan-400 font-mono text-xs mb-2">
            <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse"></span>
            <span className="font-bold tracking-wider">OBJECTIVE 01</span>
            <span className="text-zinc-500">•</span>
            <span>CORE FORENSIC ENGINE</span>
          </div>
          <h2 className="text-2xl sm:text-3xl font-extrabold text-white tracking-wide flex items-center space-x-3">
            <span>INTELLIGENT FRAGMENT RECONSTRUCTION</span>
          </h2>
          <p className="text-sm text-zinc-400 mt-1 max-w-3xl">
            Analyze and piece together fragmented file chunks, binary headers, and dangling clusters using bi-gram Markov transition scoring and TSP path optimization.
          </p>
        </div>

        {/* AI & Model Specs Badge */}
        <div className="flex items-center space-x-2">
          <div className="px-3 py-2 rounded-lg bg-dark-950 border border-cyan-500/30 font-mono text-xs text-right">
            <div className="text-[10px] text-zinc-500 uppercase tracking-wider">AI RECONSTRUCTION MODEL</div>
            <div className="text-cyan-400 font-semibold flex items-center justify-end space-x-1">
              <Cpu className="w-3.5 h-3.5 text-cyan-400" />
              <span>Bi-Gram Markov + Greedy TSP</span>
            </div>
          </div>
          <button
            onClick={handleTriggerReassembly}
            disabled={isReassembling}
            className="px-4 py-2.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-black font-semibold text-xs transition-all flex items-center space-x-2 shadow-lg shadow-cyan-500/20 active:scale-95 disabled:opacity-60 cursor-pointer"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isReassembling ? 'animate-spin' : ''}`} />
            <span>{isReassembling ? 'Reassembling...' : 'Re-Carve Clusters'}</span>
          </button>
        </div>
      </div>

      {/* KPI Status Strip */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 my-6">
        <div className="p-3.5 rounded-xl bg-dark-950/80 border border-zinc-800">
          <div className="text-[11px] font-mono text-zinc-400">Total Sectors Analyzed</div>
          <div className="text-xl font-mono font-bold text-white mt-1">36 / 36</div>
          <div className="text-[10px] text-emerald-400 font-mono mt-0.5">● 100% Coverage</div>
        </div>
        <div className="p-3.5 rounded-xl bg-dark-950/80 border border-zinc-800">
          <div className="text-[11px] font-mono text-zinc-400">Dangling Clusters Stitched</div>
          <div className="text-xl font-mono font-bold text-cyan-400 mt-1">14 Resolved</div>
          <div className="text-[10px] text-zinc-400 font-mono mt-0.5">0 Overwrites</div>
        </div>
        <div className="p-3.5 rounded-xl bg-dark-950/80 border border-zinc-800">
          <div className="text-[11px] font-mono text-zinc-400">Mean Edge Confidence</div>
          <div className="text-xl font-mono font-bold text-emerald-400 mt-1">96.8%</div>
          <div className="text-[10px] text-zinc-400 font-mono mt-0.5">Boundary Hamming Score</div>
        </div>
        <div className="p-3.5 rounded-xl bg-dark-950/80 border border-zinc-800">
          <div className="text-[11px] font-mono text-zinc-400">Original Bitstream Custody</div>
          <div className="text-xl font-mono font-bold text-white mt-1">UNMODIFIED</div>
          <div className="text-[10px] text-emerald-400 font-mono mt-0.5">SHA-256 Intact Proof</div>
        </div>
      </div>

      {/* Main Grid: Sector Cluster Map on Left, Reassembly Path & Details on Right */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        {/* Left (7 cols): Interactive 36-Cluster Grid */}
        <div className="lg:col-span-7 space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <Binary className="w-4 h-4 text-cyan-400" />
              <h3 className="font-mono text-xs uppercase tracking-wider text-zinc-300 font-semibold">
                RAW DISK SECTOR CLUSTERS (36 CHUNKS)
              </h3>
            </div>
            
            {/* Filter pills */}
            <div className="flex items-center space-x-1 bg-dark-950 p-1 rounded-lg border border-zinc-800 text-[11px] font-mono">
              <button
                onClick={() => setFilterType('ALL')}
                className={`px-2 py-0.5 rounded ${filterType === 'ALL' ? 'bg-cyan-500/20 text-cyan-400 font-semibold' : 'text-zinc-500 hover:text-zinc-300'}`}
              >
                All (36)
              </button>
              <button
                onClick={() => setFilterType('HEADER')}
                className={`px-2 py-0.5 rounded ${filterType === 'HEADER' ? 'bg-cyan-500/20 text-cyan-400 font-semibold' : 'text-zinc-500 hover:text-zinc-300'}`}
              >
                Headers
              </button>
              <button
                onClick={() => setFilterType('DANGLING')}
                className={`px-2 py-0.5 rounded ${filterType === 'DANGLING' ? 'bg-amber-500/20 text-amber-400 font-semibold' : 'text-zinc-500 hover:text-zinc-300'}`}
              >
                Dangling
              </button>
            </div>
          </div>

          {/* 36-cell Interactive Cluster Matrix */}
          <div className="p-4 rounded-xl bg-dark-950 border border-zinc-800 grid grid-cols-6 sm:grid-cols-9 gap-2">
            {filteredClusters.map((c) => {
              const isSelected = selectedCluster.id === c.id;
              const isPartOfPath = pathSequence.some(p => p.id === c.id);

              let badgeColor = 'bg-zinc-800/80 border-zinc-700 text-zinc-400';
              if (c.type === 'HEADER') badgeColor = 'bg-cyan-950/60 border-cyan-500/40 text-cyan-300';
              if (c.type === 'DATA_BODY') badgeColor = 'bg-emerald-950/60 border-emerald-500/40 text-emerald-300';
              if (c.type === 'DANGLING') badgeColor = 'bg-amber-950/60 border-amber-500/40 text-amber-300';
              if (c.type === 'TRAILER') badgeColor = 'bg-purple-950/60 border-purple-500/40 text-purple-300';
              if (c.type === 'BOOT_SECTOR' || c.type === 'MFT_FAT') badgeColor = 'bg-blue-950/60 border-blue-500/40 text-blue-300';

              return (
                <button
                  key={c.id}
                  onClick={() => setSelectedCluster(c)}
                  title={`${c.id}: ${c.label} (${c.format})`}
                  className={`relative p-2 rounded-lg border text-left transition-all duration-150 cursor-pointer ${badgeColor} ${
                    isSelected
                      ? 'ring-2 ring-cyan-400 shadow-lg shadow-cyan-500/30 scale-105 z-10'
                      : isPartOfPath
                        ? 'border-cyan-500/60 opacity-100'
                        : 'hover:border-zinc-500 opacity-80 hover:opacity-100'
                  }`}
                >
                  <div className="text-[10px] font-mono font-bold leading-tight truncate">{c.id}</div>
                  <div className="text-[9px] font-mono text-zinc-400 truncate mt-0.5">{c.type.slice(0, 4)}</div>
                  {c.status === 'dangling' && (
                    <span className="absolute -top-1 -right-1 w-2 h-2 rounded-full bg-amber-400 animate-ping"></span>
                  )}
                  {c.status === 'conflict' && (
                    <span className="absolute -top-1 -right-1 w-2 h-2 rounded-full bg-rose-500"></span>
                  )}
                </button>
              );
            })}
          </div>

          {/* Cluster Legend */}
          <div className="flex flex-wrap items-center gap-3 text-[11px] font-mono text-zinc-400 pt-1">
            <span className="flex items-center space-x-1.5">
              <span className="w-2.5 h-2.5 rounded bg-cyan-500/40 border border-cyan-400"></span>
              <span>Header Magic (FFD8/PDF/MZ)</span>
            </span>
            <span className="flex items-center space-x-1.5">
              <span className="w-2.5 h-2.5 rounded bg-emerald-500/40 border border-emerald-400"></span>
              <span>Carved Data Body</span>
            </span>
            <span className="flex items-center space-x-1.5">
              <span className="w-2.5 h-2.5 rounded bg-amber-500/40 border border-amber-400"></span>
              <span>Dangling Orphan</span>
            </span>
            <span className="flex items-center space-x-1.5">
              <span className="w-2.5 h-2.5 rounded bg-purple-500/40 border border-purple-400"></span>
              <span>Trailer (FFD9/EOF)</span>
            </span>
          </div>
        </div>

        {/* Right (5 cols): Cluster Inspector & Reassembled TSP Chain */}
        <div className="lg:col-span-5 space-y-4">
          {/* Selected Cluster Details Card */}
          <div className="p-4 rounded-xl bg-dark-950 border border-cyan-500/30 space-y-3">
            <div className="flex items-center justify-between border-b border-zinc-800 pb-2.5">
              <div className="flex items-center space-x-2">
                <span className="w-2 h-2 rounded-full bg-cyan-400"></span>
                <span className="font-mono text-xs font-bold text-white">{selectedCluster.id} DETAILS</span>
              </div>
              <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-dark-900 border border-zinc-700 text-cyan-300">
                {selectedCluster.offset}
              </span>
            </div>

            <div className="grid grid-cols-2 gap-2 text-xs font-mono">
              <div>
                <span className="text-zinc-500 text-[10px] block">CHUNK TYPE</span>
                <span className="text-zinc-200 font-semibold">{selectedCluster.type}</span>
              </div>
              <div>
                <span className="text-zinc-500 text-[10px] block">DETECTED GRAMMAR</span>
                <span className="text-cyan-300 font-semibold truncate block">{selectedCluster.format}</span>
              </div>
              <div>
                <span className="text-zinc-500 text-[10px] block">SHANNON ENTROPY</span>
                <span className="text-zinc-200">{selectedCluster.entropy} / 8.0</span>
              </div>
              <div>
                <span className="text-zinc-500 text-[10px] block">PREDICTED NEXT</span>
                <span className="text-emerald-400 font-semibold">{selectedCluster.candidateNext} ({selectedCluster.edgeScore}%)</span>
              </div>
            </div>

            {selectedCluster.artifact && (
              <div className="pt-2 border-t border-zinc-800/80 flex items-center justify-between text-xs">
                <span className="text-zinc-400 font-mono text-[11px]">Associated Artifact:</span>
                <span className="font-mono font-semibold text-white px-2 py-0.5 bg-dark-850 rounded border border-zinc-700">
                  {selectedCluster.artifact}
                </span>
              </div>
            )}
          </div>

          {/* Reassembly Path Graph (TSP / Markov Chain) */}
          <div className="p-4 rounded-xl bg-dark-950 border border-zinc-800 space-y-3">
            <div className="flex items-center justify-between border-b border-zinc-800 pb-2">
              <div className="flex items-center space-x-2">
                <GitMerge className="w-4 h-4 text-emerald-400" />
                <h4 className="font-mono text-xs uppercase tracking-wider text-zinc-300 font-semibold">
                  GREEDY TSP REASSEMBLY CHAIN
                </h4>
              </div>
              <span className="text-[10px] font-mono text-emerald-400 font-semibold">VERIFIED LOSSLESS</span>
            </div>

            <div className="space-y-2">
              {pathSequence.map((c, idx) => (
                <div key={c.id} className="flex items-center space-x-2 text-xs font-mono">
                  <div className="w-5 text-center text-zinc-500 text-[10px]">{idx + 1}.</div>
                  <div className={`px-2 py-1 rounded text-[11px] font-semibold flex-1 flex items-center justify-between ${
                    c.id === selectedCluster.id
                      ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                      : 'bg-dark-900 text-zinc-300 border border-zinc-800'
                  }`}>
                    <span>{c.id} • {c.label}</span>
                    <span className="text-zinc-400 text-[10px]">{c.edgeScore}%</span>
                  </div>
                  {idx < pathSequence.length - 1 && (
                    <ArrowRight className="w-3.5 h-3.5 text-zinc-600 shrink-0" />
                  )}
                </div>
              ))}
            </div>

            <div className="pt-2 border-t border-zinc-800/80 text-[11px] font-mono text-zinc-400 flex items-center justify-between">
              <span>Path Optimization Score:</span>
              <span className="text-emerald-400 font-bold">98.4% Markov Confidence</span>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
