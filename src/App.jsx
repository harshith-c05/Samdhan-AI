import React, { useState } from 'react';
import Header from './components/Header';
import HeroCyberBanner from './components/HeroCyberBanner';
import InputScreen from './components/InputScreen';
import ProcessingScreen from './components/ProcessingScreen';
import FragmentReconstructionSection from './components/FragmentReconstructionSection';
import IntegrityAssessmentSection from './components/IntegrityAssessmentSection';
import DashboardScreen from './components/DashboardScreen';
import ArtifactDetailModal from './components/ArtifactDetailModal';
import AiVsRuleModal from './components/AiVsRuleModal';
import AuditLogModal from './components/AuditLogModal';
import IntegrityDashboard from './components/IntegrityDashboard';
import InvestigationCenter from './components/InvestigationCenter';
import DEMO_ARTIFACTS, { computeDemoStats } from './data/demoArtifacts';
import { SAMPLE_CASES, MOCK_ARTIFACTS, INITIAL_AUDIT_LOG } from './data/mockForensicData';

export default function App() {
  const [currentScreen, setCurrentScreen] = useState('dashboard'); // 'dashboard' (vertical master view), 'input', 'processing'
  const [isAnalyzed, setIsAnalyzed] = useState(true);

  // Use the new 15-artifact demo dataset merged with mock artifacts
  const artifacts = [...DEMO_ARTIFACTS, ...MOCK_ARTIFACTS.filter(m =>
    !DEMO_ARTIFACTS.some(d => d.id === m.id)
  )];

  const [selectedArtifact, setSelectedArtifact] = useState(null);
  const [showIntegrity, setShowIntegrity] = useState(false);
  const [integrityArtifact, setIntegrityArtifact] = useState(null);
  const [showAiRules, setShowAiRules] = useState(false);
  const [showAuditLog, setShowAuditLog] = useState(false);
  const [auditLogs, setAuditLogs] = useState(INITIAL_AUDIT_LOG);

  const handleAddAuditLog = (entry) => {
    setAuditLogs(prev => [entry, ...prev]);
  };

  // Active Case Context
  const [caseContext, setCaseContext] = useState({
    caseId: SAMPLE_CASES.operation_nightfall.id,
    caseTitle: SAMPLE_CASES.operation_nightfall.title,
    investigator: SAMPLE_CASES.operation_nightfall.investigator,
    targetDevice: SAMPLE_CASES.operation_nightfall.targetDevice,
    incidentStart: SAMPLE_CASES.operation_nightfall.incidentStart.slice(0, 16),
    incidentEnd: SAMPLE_CASES.operation_nightfall.incidentEnd.slice(0, 16),
    iocs: SAMPLE_CASES.operation_nightfall.iocs.join(', '),
    rawImageHash: SAMPLE_CASES.operation_nightfall.rawImageHash,
    totalFragments: SAMPLE_CASES.operation_nightfall.totalFragments,
  });

  // Start analysis pipeline
  const handleStartPipeline = () => {
    setCurrentScreen('processing');
  };

  // Pipeline completed
  const handlePipelineComplete = () => {
    setIsAnalyzed(true);
    setCurrentScreen('dashboard');
  };

  // Open Integrity Dashboard for an artifact
  const handleOpenIntegrity = (artifact) => {
    setIntegrityArtifact(artifact);
    setShowIntegrity(true);
  };

  // Switch to related artifact
  const handleSelectRelated = (artifactId) => {
    const found = artifacts.find(a => a.id === artifactId);
    if (found) {
      setSelectedArtifact(found);
    }
  };

  // Export full forensic dossier
  const handleExportReport = () => {
    const stats = computeDemoStats(artifacts);
    const reportData = {
      platform: "SAMDHAN AI — Unified Forensic Platform v3.0",
      module: "Features: Reconstruction · Integrity · Classification · Decision Support · USB Restore · Security Scan",
      exportTimestamp: new Date().toISOString(),
      caseContext: {
        ...caseContext,
        custodyStatus: "DERIVED_FROM_READ_ONLY_IMAGE_UNMODIFIED",
        validationAlgorithm: "SHA-256 + Magic-byte + GradientBoosting + IsolationForest",
      },
      summary: stats,
      integrityWeights: { structural: 0.30, content: 0.35, fragment: 0.20, metadata: 0.15,
        note: "Prototype defaults — not forensically validated" },
      artifacts: artifacts.map(a => ({
        id: a.id,
        filename: a.filename,
        type: a.type,
        classificationConfidence: a.classificationConfidence,
        structuralIntegrity: a.structuralIntegrity,
        contentIntegrity: a.contentIntegrity,
        metadataIntegrity: a.metadataIntegrity,
        fragmentContinuity: a.fragmentContinuity,
        overallIntegrity: a.overallIntegrity,
        corruptionSeverity: a.corruptionSeverity,
        recoverability: a.recoverability,
        corruptionRegions: a.corruptionRegions,
        priorityScore: a.priorityScore,
        priorityTier: a.priorityTier,
        sha256: a.metadata?.sha256,
      }))
    };

    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(reportData, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute("href", dataStr);
    downloadAnchor.setAttribute("download", `INTEGRITY_REPORT_${caseContext.caseId}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  return (
    <div className="min-h-screen bg-dark-950 text-slate-100 flex flex-col font-sans selection:bg-cyber-neon selection:text-black">
      {/* Top Sticky Header */}
      <Header
        currentScreen={currentScreen}
        setCurrentScreen={setCurrentScreen}
        activeCase={caseContext}
        onOpenAiRules={() => setShowAiRules(true)}
        onOpenAuditLog={() => setShowAuditLog(true)}
        onExportReport={handleExportReport}
        isAnalyzed={isAnalyzed}
      />

      {/* Main Content Area */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {currentScreen === 'input' && (
          <div className="space-y-6">
            <HeroCyberBanner
              onStartDemo={handleStartPipeline}
              onOpenAiRules={() => setShowAiRules(true)}
            />
            <InputScreen
              onStartPipeline={handleStartPipeline}
              onNavigateToDecision={() => setCurrentScreen('dashboard')}
              caseContext={caseContext}
              setCaseContext={setCaseContext}
            />
          </div>
        )}

        {currentScreen === 'processing' && (
          <ProcessingScreen
            onComplete={handlePipelineComplete}
            totalFragments={caseContext.totalFragments || 36}
            caseContext={caseContext}
          />
        )}

        {currentScreen === 'dashboard' && (
          <div className="space-y-12">
            {/* Executive Case Context & Cyber Banner */}
            <HeroCyberBanner
              onStartDemo={handleStartPipeline}
              onOpenAiRules={() => setShowAiRules(true)}
            />

            {/* Quick Sticky Anchor Bar for all 4 Vertically Aligned Features */}
            <div className="sticky top-20 z-30 flex flex-wrap items-center justify-between gap-3 p-3.5 rounded-xl bg-dark-950/95 border border-zinc-800 shadow-2xl backdrop-blur-md">
              <div className="flex items-center space-x-2">
                <span className="w-2 h-2 rounded-full bg-cyber-neon animate-pulse" />
                <span className="font-mono text-xs text-zinc-300 font-semibold tracking-wider uppercase">
                  4 KEY ENGINEERING OBJECTIVES:
                </span>
              </div>
              <div className="flex flex-wrap items-center gap-2 text-xs font-mono">
                <a
                  href="#section-01-reconstruction"
                  className="px-3 py-1.5 rounded-lg bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 hover:bg-cyan-500/20 font-semibold transition-all flex items-center space-x-1.5"
                >
                  <span className="w-1.5 h-1.5 rounded-full bg-cyan-400"></span>
                  <span>01 Fragment Reconstruction</span>
                </a>
                <a
                  href="#section-02-integrity"
                  className="px-3 py-1.5 rounded-lg bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 hover:bg-emerald-500/20 font-semibold transition-all flex items-center space-x-1.5"
                >
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-400"></span>
                  <span>02 Integrity Assessment</span>
                </a>
                <a
                  href="#section-03-prioritization"
                  className="px-3 py-1.5 rounded-lg bg-cyber-500/10 text-cyber-neon border border-cyber-500/30 hover:bg-cyber-500/20 font-semibold transition-all flex items-center space-x-1.5"
                >
                  <span className="w-1.5 h-1.5 rounded-full bg-cyber-neon"></span>
                  <span>03 Prioritization</span>
                </a>
                <a
                  href="#section-04-decision"
                  className="px-3 py-1.5 rounded-lg bg-purple-500/10 text-purple-400 border border-purple-500/30 hover:bg-purple-500/20 font-semibold transition-all flex items-center space-x-1.5"
                >
                  <span className="w-1.5 h-1.5 rounded-full bg-purple-400"></span>
                  <span>04 Decision Support</span>
                </a>
              </div>
            </div>

            {/* ── VERTICAL SECTION 01: Intelligent Fragment Reconstruction ── */}
            <FragmentReconstructionSection
              onSelectArtifact={(art) => setSelectedArtifact(art)}
            />

            {/* ── VERTICAL SECTION 02: Data Integrity & Corruption Assessment ── */}
            <IntegrityAssessmentSection
              artifacts={artifacts}
              onOpenIntegrityModal={handleOpenIntegrity}
            />

            {/* ── VERTICAL SECTION 03: Classification & Prioritization ── */}
            <DashboardScreen
              artifacts={artifacts}
              onSelectArtifact={(art) => setSelectedArtifact(art)}
              onOpenIntegrity={handleOpenIntegrity}
              onNavigateToInvestigation={() => {
                const el = document.getElementById('section-04-decision');
                if (el) el.scrollIntoView({ behavior: 'smooth' });
              }}
              caseContext={caseContext}
              onAddAuditLog={handleAddAuditLog}
            />

            {/* ── VERTICAL SECTION 04: Investigative Decision Support ── */}
            <InvestigationCenter
              caseContext={caseContext}
              artifacts={artifacts}
              onAddAuditLog={handleAddAuditLog}
            />
          </div>
        )}

        {currentScreen === 'investigation' && (
          <InvestigationCenter
            caseContext={caseContext}
            artifacts={artifacts}
            onAddAuditLog={handleAddAuditLog}
          />
        )}
      </main>

      {/* Footer */}
      <footer className="border-t border-zinc-800/80 bg-dark-950 py-6 text-center text-xs font-mono text-zinc-500">
        <div className="max-w-7xl mx-auto px-4 flex flex-col sm:flex-row items-center justify-between gap-4">
          <div className="flex items-center space-x-2">
            <span className="w-2 h-2 rounded-full bg-cyber-neon animate-pulse"></span>
            <span>SAMDHAN AI v3.0 • 6-Feature Unified Forensic Platform</span>
          </div>
          <div className="flex items-center space-x-4 text-[11px] text-zinc-400">
            <span>CALMSTACKS 24H Hackathon</span>
            <span>•</span>
            <span>Reconstruction · Integrity · Classification · Decision · USB · Security</span>
            <span>•</span>
            <button
              onClick={() => setShowAiRules(true)}
              className="text-cyber-neon hover:underline"
            >
              AI vs Rule Architecture
            </button>
          </div>
        </div>
      </footer>

      {/* Modals */}
      {selectedArtifact && (
        <ArtifactDetailModal
          artifact={selectedArtifact}
          onClose={() => setSelectedArtifact(null)}
          onSelectRelated={handleSelectRelated}
          onOpenIntegrity={handleOpenIntegrity}
          caseContext={caseContext}
        />
      )}

      {showIntegrity && integrityArtifact && (
        <IntegrityDashboard
          artifact={integrityArtifact}
          onClose={() => { setShowIntegrity(false); setIntegrityArtifact(null); }}
        />
      )}

      {showAiRules && (
        <AiVsRuleModal
          onClose={() => setShowAiRules(false)}
        />
      )}

      {showAuditLog && (
        <AuditLogModal
          onClose={() => setShowAuditLog(false)}
          caseContext={caseContext}
          auditLogs={auditLogs}
        />
      )}
    </div>
  );
}
