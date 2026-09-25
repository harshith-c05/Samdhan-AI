import React, { useState, useMemo } from 'react';
import { 
  FileText, Database, Image as ImageIcon, Terminal, Binary, AlertOctagon, 
  Copy, CheckCircle, Percent, Filter, Search, RotateCcw, SlidersHorizontal, 
  Layers, BarChart2, ShieldAlert 
} from 'lucide-react';
import ArtifactTable from './ArtifactTable';
import { ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip, Cell } from 'recharts';

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

  // Compute summary stats dynamically
  const stats = useMemo(() => {
    const total = artifacts.length;
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

    artifacts.forEach(a => {
      const t = a.type?.toLowerCase();
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
  }, [artifacts]);

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
    return artifacts
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
  }, [artifacts, searchTerm, typeFilter, tierFilter, confFilter, hideDuplicates, incidentWindowOnly, sortField, sortOrder]);

  return (
    <div className="space-y-6 animate-fadeIn">
      {/* Top Banner with Case Info & Filter Status */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-4 rounded-xl bg-dark-900 border border-zinc-800">
        <div>
          <div className="flex items-center space-x-2">
            <span className="px-2 py-0.5 text-[10px] font-mono font-semibold bg-cyber-500/20 text-cyber-neon border border-cyber-500/40 rounded">
              EVIDENCE MATRIX ACTIVE
            </span>
            <span className="text-xs font-mono text-zinc-400">
              Case ID: <span className="text-white font-semibold">{caseContext.caseId || 'CASE-2026-NIGHTFALL'}</span>
            </span>
          </div>
          <h2 className="text-lg font-bold text-white mt-1">
            {caseContext.caseTitle || 'Carved Fragments Triaging & Relevance Assessment'}
          </h2>
        </div>

        <div className="flex items-center space-x-2">
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
          <button
            onClick={() => setShowCharts(!showCharts)}
            className={`px-3 py-1.5 rounded-lg text-xs font-mono border transition-all flex items-center space-x-1.5 ${
              showCharts 
                ? 'bg-cyber-500/20 text-cyber-neon border-cyber-500/40' 
                : 'bg-dark-950 text-zinc-400 border-zinc-700 hover:text-white'
            }`}
          >
            <BarChart2 className="w-3.5 h-3.5" />
            <span>{showCharts ? 'Hide Visual Analytics' : 'Show Visual Analytics'}</span>
          </button>
        </div>
      </div>

      {/* Summary Cards Grid (Conforming strictly to Spec §8) */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
        {/* Total Artifacts */}
        <div className="p-3.5 rounded-xl bg-dark-900 border border-zinc-800 shadow-cyber-card">
          <div className="text-[11px] font-mono text-zinc-400 uppercase tracking-wider">Total Artifacts</div>
          <div className="text-2xl font-mono font-extrabold text-white mt-1">{stats.total}</div>
          <div className="text-[10px] text-zinc-500 mt-1 font-mono">Unallocated Carves</div>
        </div>

        {/* Documents */}
        <div className="p-3.5 rounded-xl bg-dark-900 border border-zinc-800 shadow-cyber-card">
          <div className="text-[11px] font-mono text-blue-400 uppercase tracking-wider flex items-center space-x-1">
            <FileText className="w-3 h-3" />
            <span>Documents</span>
          </div>
          <div className="text-2xl font-mono font-extrabold text-white mt-1">{stats.docs}</div>
          <div className="text-[10px] text-zinc-500 mt-1 font-mono">PDF, DOCX, TXT</div>
        </div>

        {/* DB Logs */}
        <div className="p-3.5 rounded-xl bg-dark-900 border border-zinc-800 shadow-cyber-card">
          <div className="text-[11px] font-mono text-emerald-400 uppercase tracking-wider flex items-center space-x-1">
            <Database className="w-3 h-3" />
            <span>DB Logs</span>
          </div>
          <div className="text-2xl font-mono font-extrabold text-white mt-1">{stats.dbs}</div>
          <div className="text-[10px] text-zinc-500 mt-1 font-mono">SQLite, EVTX, Wal</div>
        </div>

        {/* Photos */}
        <div className="p-3.5 rounded-xl bg-dark-900 border border-zinc-800 shadow-cyber-card">
          <div className="text-[11px] font-mono text-amber-400 uppercase tracking-wider flex items-center space-x-1">
            <ImageIcon className="w-3 h-3" />
            <span>Photos</span>
          </div>
          <div className="text-2xl font-mono font-extrabold text-white mt-1">{stats.photos}</div>
          <div className="text-[10px] text-zinc-500 mt-1 font-mono">JPEG, PNG, EXIF</div>
        </div>

        {/* System Traces */}
        <div className="p-3.5 rounded-xl bg-dark-900 border border-zinc-800 shadow-cyber-card">
          <div className="text-[11px] font-mono text-purple-400 uppercase tracking-wider flex items-center space-x-1">
            <Terminal className="w-3 h-3" />
            <span>System Traces</span>
          </div>
          <div className="text-2xl font-mono font-extrabold text-white mt-1">{stats.traces}</div>
          <div className="text-[10px] text-zinc-500 mt-1 font-mono">PCAP, Bin, Regf</div>
        </div>

        {/* Avg Confidence */}
        <div className="p-3.5 rounded-xl bg-dark-900 border border-cyber-500/30 shadow-neon">
          <div className="text-[11px] font-mono text-cyber-neon uppercase tracking-wider flex items-center space-x-1">
            <Percent className="w-3 h-3" />
            <span>Avg. Confidence</span>
          </div>
          <div className="text-2xl font-mono font-extrabold text-cyber-bright mt-1">{stats.avgConf}%</div>
          <div className="text-[10px] text-zinc-500 mt-1 font-mono">ML + Spec Accuracy</div>
        </div>
      </div>

      {/* Tier & Quality Breakdown Row */}
      <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-6 gap-3">
        <div className="p-3 rounded-lg bg-dark-950 border border-red-500/30">
          <span className="text-[10px] font-mono uppercase text-red-400 font-semibold">Critical Priority</span>
          <div className="text-xl font-bold font-mono text-red-400">{stats.critical}</div>
        </div>

        <div className="p-3 rounded-lg bg-dark-950 border border-orange-500/30">
          <span className="text-[10px] font-mono uppercase text-orange-400 font-semibold">High Priority</span>
          <div className="text-xl font-bold font-mono text-orange-400">{stats.high}</div>
        </div>

        <div className="p-3 rounded-lg bg-dark-950 border border-amber-500/30">
          <span className="text-[10px] font-mono uppercase text-amber-400 font-semibold">Medium Priority</span>
          <div className="text-xl font-bold font-mono text-amber-400">{stats.medium}</div>
        </div>

        <div className="p-3 rounded-lg bg-dark-950 border border-zinc-700/40">
          <span className="text-[10px] font-mono uppercase text-zinc-400 font-semibold">Low Priority</span>
          <div className="text-xl font-bold font-mono text-zinc-400">{stats.low}</div>
        </div>

        <div className="p-3 rounded-lg bg-dark-950 border border-zinc-800">
          <span className="text-[10px] font-mono uppercase text-amber-300 font-semibold">Corrupted / Damaged</span>
          <div className="text-xl font-bold font-mono text-white">{stats.corrupted}</div>
        </div>

        <div className="p-3 rounded-lg bg-dark-950 border border-zinc-800">
          <span className="text-[10px] font-mono uppercase text-zinc-400 font-semibold">Deduplicated</span>
          <div className="text-xl font-bold font-mono text-zinc-400">{stats.duplicates}</div>
        </div>
      </div>

      {/* Optional Visual Chart Drawer */}
      {showCharts && (
        <div className="p-5 rounded-xl bg-dark-900 border border-zinc-800 space-y-4">
          <h3 className="text-xs font-mono font-bold text-white uppercase tracking-wider flex items-center space-x-2">
            <BarChart2 className="w-4 h-4 text-cyber-neon" />
            <span>Forensic Evidence Distribution by Priority Tier</span>
          </h3>
          <div className="h-44 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={tierChartData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <XAxis dataKey="name" stroke="#71717a" fontSize={11} fontFamily="monospace" />
                <YAxis stroke="#71717a" fontSize={11} fontFamily="monospace" />
                <Tooltip 
                  contentStyle={{ backgroundColor: '#090e13', borderColor: '#27272a', borderRadius: '8px', fontSize: '12px' }}
                  labelStyle={{ color: '#fff' }}
                />
                <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                  {tierChartData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.fill} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      )}

      {/* Filter and Sort Bar */}
      <div className="p-4 rounded-xl bg-dark-900 border border-zinc-800 space-y-3">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
          {/* Search Input */}
          <div className="relative flex-1 max-w-md">
            <Search className="w-4 h-4 text-zinc-500 absolute left-3 top-2.5" />
            <input
              type="text"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder="Filter by Filename, Sector (0x...), Hash, or Keyword..."
              className="w-full pl-9 pr-4 py-2 bg-dark-950 border border-zinc-700/80 rounded-lg text-xs font-mono text-white placeholder-zinc-500 focus:outline-none focus:border-cyber-neon"
            />
          </div>

          {/* Quick Toggles */}
          <div className="flex flex-wrap items-center gap-2 text-xs font-mono">
            <button
              onClick={() => setHideDuplicates(!hideDuplicates)}
              className={`px-3 py-1.5 rounded-lg border transition-all ${
                hideDuplicates 
                  ? 'bg-zinc-800 text-cyber-neon border-cyber-500/40' 
                  : 'bg-dark-950 text-zinc-400 border-zinc-700'
              }`}
            >
              {hideDuplicates ? '✓ Duplicates Hidden' : 'Hide Duplicates'}
            </button>

            <button
              onClick={() => setIncidentWindowOnly(!incidentWindowOnly)}
              className={`px-3 py-1.5 rounded-lg border transition-all ${
                incidentWindowOnly 
                  ? 'bg-red-500/20 text-red-400 border-red-500/50' 
                  : 'bg-dark-950 text-zinc-400 border-zinc-700'
              }`}
            >
              {incidentWindowOnly ? '✓ Incident Window Only' : 'Incident Window Filter'}
            </button>

            {(searchTerm || typeFilter !== 'All' || tierFilter !== 'All' || confFilter !== 'All' || hideDuplicates || incidentWindowOnly) && (
              <button
                onClick={() => {
                  setSearchTerm('');
                  setTypeFilter('All');
                  setTierFilter('All');
                  setConfFilter('All');
                  setHideDuplicates(false);
                  setIncidentWindowOnly(false);
                }}
                className="px-2.5 py-1.5 rounded bg-zinc-800 hover:bg-zinc-700 text-zinc-300 text-xs flex items-center space-x-1"
                title="Reset All Filters"
              >
                <RotateCcw className="w-3.5 h-3.5" />
                <span>Reset</span>
              </button>
            )}
          </div>
        </div>

        {/* Filter Pills: Type and Tier */}
        <div className="flex flex-wrap items-center justify-between gap-3 pt-2 border-t border-zinc-800/80 text-xs font-mono">
          {/* Type Filter Pills */}
          <div className="flex flex-wrap items-center gap-1.5">
            <span className="text-zinc-500 mr-1 text-[11px] uppercase">Type:</span>
            {['All', 'Document', 'DB log', 'Photos', 'System trace', 'Unknown/Fragment'].map((t) => (
              <button
                key={t}
                onClick={() => setTypeFilter(t)}
                className={`px-2.5 py-1 rounded text-[11px] transition-colors ${
                  typeFilter === t
                    ? 'bg-cyber-500/20 text-cyber-neon border border-cyber-500/40 font-semibold'
                    : 'bg-dark-950 text-zinc-400 hover:text-white border border-zinc-800'
                }`}
              >
                {t}
              </button>
            ))}
          </div>

          {/* Tier Filter Pills */}
          <div className="flex flex-wrap items-center gap-1.5">
            <span className="text-zinc-500 mr-1 text-[11px] uppercase">Tier:</span>
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
          </div>
        </div>
      </div>

      {/* Artifact Table */}
      <ArtifactTable
        artifacts={filteredArtifacts}
        onSelectArtifact={onSelectArtifact}
        onOpenIntegrity={onOpenIntegrity}
        sortField={sortField}
        sortOrder={sortOrder}
        onSort={handleSort}
      />
    </div>
  );
}
