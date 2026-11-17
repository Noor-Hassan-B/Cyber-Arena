import React, { useState, useEffect } from 'react';
import Navbar from './components/Navbar';
import OverviewStats from './components/OverviewStats';
import AttackPathGraph from './components/AttackPathGraph';
import TimelineView from './components/TimelineView';
import MitreMatrixView from './components/MitreMatrixView';
import AIAssistantPanel from './components/AIAssistantPanel';
import EvidenceDrawer from './components/EvidenceDrawer';
import ReportModal from './components/ReportModal';
import AiLimitationsModal from './components/AiLimitationsModal';
import IngestionPanel from './components/IngestionPanel';
import TerminalConsole from './components/TerminalConsole';
import KibanaDiscover from './components/KibanaDiscover';
import KibanaSearchBar from './components/KibanaSearchBar';
import DetectionStudio from './components/DetectionStudio';
import HitlGatingPanel from './components/HitlGatingPanel';
import AuditLedgerView from './components/AuditLedgerView';
import { api } from './services/api';
import { 
  GitCommit, 
  Clock, 
  Grid, 
  Sparkles, 
  Layers, 
  ShieldAlert,
  Terminal,
  Activity,
  ExternalLink,
  Flame,
  CheckCircle2,
  Lock,
  Search,
  LayoutDashboard,
  Compass,
  FileCode2,
  FileText,
  BookOpen,
  AlertOctagon,
  Shield
} from 'lucide-react';

export default function App() {
  const [scenarios, setScenarios] = useState([]);
  const [activeScenarioId, setActiveScenarioId] = useState('SCN-APT29-GHOST');
  const [backendStatus, setBackendStatus] = useState({ online: false, url: '' });
  const [activeTab, setActiveTab] = useState('discover'); // 'dashboard' | 'discover' | 'graph' | 'timeline' | 'mitre' | 'terminal' | 'ai' | 'detection' | 'gating' | 'audit'
  const [searchQuery, setSearchQuery] = useState('');

  // Scenario Data States
  const [events, setEvents] = useState([]);
  const [correlationData, setCorrelationData] = useState(null);
  const [graphData, setGraphData] = useState(null);
  const [mitreData, setMitreData] = useState(null);
  const [aiSummary, setAiSummary] = useState(null);
  const [querySuggestions, setQuerySuggestions] = useState([]);

  // UI Modal / Notification States
  const [selectedEventUuid, setSelectedEventUuid] = useState(null);
  const [selectedEvent, setSelectedEvent] = useState(null);
  const [showReportModal, setShowReportModal] = useState(false);
  const [showLimitationsModal, setShowLimitationsModal] = useState(false);
  const [showIngestModal, setShowIngestModal] = useState(false);
  const [containmentAlert, setContainmentAlert] = useState(null);
  const [loading, setLoading] = useState(true);

  // 1. Initial Load & Backend Check
  useEffect(() => {
    async function init() {
      const health = await api.checkBackendHealth();
      setBackendStatus(health);

      const scenarioList = await api.getScenarios();
      setScenarios(scenarioList);

      if (scenarioList.length > 0) {
        setActiveScenarioId(scenarioList[0].scenario_id);
      }
    }
    init();
  }, []);

  // 2. Load Active Scenario Data
  const loadScenarioData = async (scenarioId) => {
    setLoading(true);
    try {
      const [
        loadedEvents,
        loadedCorrelation,
        loadedGraph,
        loadedMitre,
        loadedAiSummary,
        loadedSuggestions
      ] = await Promise.all([
        api.getEvents(scenarioId),
        api.getCorrelation(scenarioId),
        api.getAttackPath(scenarioId),
        api.getMitreData(scenarioId),
        api.getAiSummary(scenarioId),
        api.getAiQuerySuggestions(scenarioId)
      ]);

      setEvents(loadedEvents);
      setCorrelationData(loadedCorrelation);
      setGraphData(loadedGraph);
      setMitreData(loadedMitre);
      setAiSummary(loadedAiSummary);
      setQuerySuggestions(loadedSuggestions);
    } catch (err) {
      console.error('Error loading scenario data:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (activeScenarioId) {
      loadScenarioData(activeScenarioId);
    }
  }, [activeScenarioId]);

  // Handle Event Selection to Open Evidence Drawer
  const handleSelectEvent = (eventUuid) => {
    setSelectedEventUuid(eventUuid);
    const found = events.find(e => e.event_uuid === eventUuid);
    if (found) {
      setSelectedEvent(found);
    } else {
      setSelectedEvent({
        event_uuid: eventUuid,
        timestamp: new Date().toISOString(),
        domain: 'endpoint',
        event_type: 'corroborated_alert',
        severity: 'high',
        source_host: 'WKSTN-FIN-04',
        user_id: 'sarah.connor',
        command_line: 'Evidence item linked from investigation hypothesis'
      });
    }
  };

  // Handle Terminal CLI Action / Attack Emulation
  const handleTerminalCommand = async (actionData) => {
    if (actionData.type === 'event') {
      await api.ingestEvent(actionData);
      await loadScenarioData(activeScenarioId);
      setContainmentAlert({
        title: 'Adversary Telemetry Ingested & Correlated',
        text: `Technique: ${actionData.mitre_technique_id} (${actionData.mitre_technique_name}) | Domain: ${actionData.domain.toUpperCase()}`
      });
      setTimeout(() => setContainmentAlert(null), 5000);
    } else if (actionData.type === 'containment') {
      setContainmentAlert({
        title: 'EDR Host Network Quarantine Active',
        text: `Network isolation signal dispatched for host: ${actionData.host}`
      });
      setTimeout(() => setContainmentAlert(null), 5000);
    }
  };

  const handleRefreshBackend = async () => {
    const health = await api.checkBackendHealth();
    setBackendStatus(health);
    loadScenarioData(activeScenarioId);
  };

  // Filter events based on Kibana KQL search query
  const filteredEvents = events.filter(evt => {
    if (!searchQuery) return true;
    const q = searchQuery.toLowerCase();
    const hay = `${evt.event_uuid} ${evt.domain} ${evt.event_type} ${evt.severity} ${evt.source_host || ''} ${evt.dest_host || ''} ${evt.source_ip || ''} ${evt.dest_ip || ''} ${evt.user_id || ''} ${evt.command_line || ''} ${evt.mitre_technique_id || ''} ${evt.mitre_tactic || ''}`.toLowerCase();
    return hay.includes(q);
  });

  const activeScenario = scenarios.find(s => s.scenario_id === activeScenarioId) || {
    scenario_id: activeScenarioId,
    name: 'Selected Cyber Attack Scenario',
    threat_actor: 'Advanced Adversary',
    description: 'Correlating security telemetry across endpoints, identity, network, and cloud.'
  };

  return (
    <div className="min-h-screen bg-[#070A12] text-slate-100 flex flex-col font-sans selection:bg-blue-600/30 selection:text-blue-300">
      
      {/* Top SOC Navbar */}
      <Navbar
        scenarios={scenarios}
        activeScenarioId={activeScenarioId}
        onSelectScenario={setActiveScenarioId}
        backendStatus={backendStatus}
        onRefreshBackend={handleRefreshBackend}
        onOpenReport={() => setShowReportModal(true)}
        onOpenLimitations={() => setShowLimitationsModal(true)}
        onOpenIngest={() => setShowIngestModal(true)}
        onOpenTerminal={() => setActiveTab('terminal')}
        activeTab={activeTab}
      />

      {/* Floating Containment Alert Toast */}
      {containmentAlert && (
        <div className="fixed top-16 right-4 z-50 bg-[#0F172A] border-2 border-emerald-500 rounded-xl p-4 shadow-2xl flex items-center gap-3 animate-slideLeft max-w-md">
          <div className="p-2 rounded-lg bg-emerald-950 text-emerald-400">
            <CheckCircle2 className="w-5 h-5 animate-pulse" />
          </div>
          <div>
            <div className="text-xs font-bold text-white uppercase font-mono">{containmentAlert.title}</div>
            <div className="text-xs text-slate-300">{containmentAlert.text}</div>
          </div>
        </div>
      )}

      {/* Main Elastic / Splunk Style Body */}
      <div className="flex-1 max-w-7xl w-full mx-auto p-3 sm:p-5 flex flex-col md:flex-row gap-4">
        
        {/* Left Sidebar: Elastic Security Navigation */}
        <aside className="w-full md:w-60 flex-shrink-0 space-y-3">
          
          {/* Elastic Navigation Menu */}
          <div className="bg-[#0B0F19] border border-slate-800 rounded-xl p-2.5 shadow-xl space-y-1">
            <span className="text-[10px] font-mono font-bold text-slate-500 uppercase px-2.5 py-1 block tracking-wider">
              Elastic / Splunk SOC
            </span>
            <button
              onClick={() => setActiveTab('discover')}
              className={`w-full flex items-center justify-between px-3 py-2 rounded-lg text-xs font-semibold transition ${
                activeTab === 'discover'
                  ? 'bg-blue-600 text-white shadow-md shadow-blue-600/30 font-bold'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
              }`}
            >
              <div className="flex items-center gap-2">
                <Search className="w-4 h-4 text-cyan-400" />
                <span>Discover (Logs)</span>
              </div>
              <span className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-slate-950/80 text-slate-400">
                {filteredEvents.length}
              </span>
            </button>

            <button
              onClick={() => setActiveTab('graph')}
              className={`w-full flex items-center justify-between px-3 py-2 rounded-lg text-xs font-semibold transition ${
                activeTab === 'graph'
                  ? 'bg-blue-600 text-white shadow-md shadow-blue-600/30 font-bold'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
              }`}
            >
              <div className="flex items-center gap-2">
                <GitCommit className="w-4 h-4 text-indigo-400" />
                <span>Attack Path Graph</span>
              </div>
            </button>

            <button
              onClick={() => setActiveTab('terminal')}
              className={`w-full flex items-center justify-between px-3 py-2 rounded-lg text-xs font-semibold transition ${
                activeTab === 'terminal'
                  ? 'bg-emerald-600 text-white shadow-md shadow-emerald-600/30 font-bold'
                  : 'text-slate-400 hover:text-emerald-400 hover:bg-slate-900'
              }`}
            >
              <div className="flex items-center gap-2">
                <Terminal className="w-4 h-4 text-emerald-400" />
                <span>EDR Attack CLI</span>
              </div>
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-ping" />
            </button>

            <button
              onClick={() => setActiveTab('mitre')}
              className={`w-full flex items-center justify-between px-3 py-2 rounded-lg text-xs font-semibold transition ${
                activeTab === 'mitre'
                  ? 'bg-blue-600 text-white shadow-md shadow-blue-600/30 font-bold'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
              }`}
            >
              <div className="flex items-center gap-2">
                <Grid className="w-4 h-4 text-amber-400" />
                <span>MITRE Heatmap</span>
              </div>
            </button>

            <button
              onClick={() => setActiveTab('timeline')}
              className={`w-full flex items-center justify-between px-3 py-2 rounded-lg text-xs font-semibold transition ${
                activeTab === 'timeline'
                  ? 'bg-blue-600 text-white shadow-md shadow-blue-600/30 font-bold'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
              }`}
            >
              <div className="flex items-center gap-2">
                <Clock className="w-4 h-4 text-rose-400" />
                <span>Timeline Stream</span>
              </div>
            </button>

            <button
              onClick={() => setActiveTab('ai')}
              className={`w-full flex items-center justify-between px-3 py-2 rounded-lg text-xs font-semibold transition ${
                activeTab === 'ai'
                  ? 'bg-indigo-600 text-white shadow-md shadow-indigo-600/30 font-bold'
                  : 'text-slate-400 hover:text-indigo-400 hover:bg-slate-900'
              }`}
            >
              <div className="flex items-center gap-2">
                <Sparkles className="w-4 h-4 text-indigo-400" />
                <span>AI Threat Copilot</span>
              </div>
            </button>

            <button
              onClick={() => setActiveTab('dashboard')}
              className={`w-full flex items-center justify-between px-3 py-2 rounded-lg text-xs font-semibold transition ${
                activeTab === 'dashboard'
                  ? 'bg-blue-600 text-white shadow-md shadow-blue-600/30 font-bold'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
              }`}
            >
              <div className="flex items-center gap-2">
                <LayoutDashboard className="w-4 h-4 text-slate-400" />
                <span>Overview KPIs</span>
              </div>
            </button>
          </div>

          {/* SOCForge Section */}
          <div className="bg-[#0B0F19] border border-slate-800 rounded-xl p-2.5 shadow-xl space-y-1">
            <span className="text-[10px] font-mono font-bold text-slate-500 uppercase px-2.5 py-1 block tracking-wider">
              SOCForge — Detection
            </span>

            <button
              onClick={() => setActiveTab('detection')}
              className={`w-full flex items-center justify-between px-3 py-2 rounded-lg text-xs font-semibold transition ${
                activeTab === 'detection'
                  ? 'bg-blue-600 text-white shadow-md shadow-blue-600/30 font-bold'
                  : 'text-slate-400 hover:text-blue-400 hover:bg-slate-900'
              }`}
            >
              <div className="flex items-center gap-2">
                <Shield className="w-4 h-4 text-blue-400" />
                <span>Detection Studio</span>
              </div>
            </button>

            <button
              onClick={() => setActiveTab('gating')}
              className={`w-full flex items-center justify-between px-3 py-2 rounded-lg text-xs font-semibold transition ${
                activeTab === 'gating'
                  ? 'bg-amber-600 text-white shadow-md shadow-amber-600/30 font-bold'
                  : 'text-slate-400 hover:text-amber-400 hover:bg-slate-900'
              }`}
            >
              <div className="flex items-center gap-2">
                <AlertOctagon className="w-4 h-4 text-amber-400" />
                <span>HITL Gating</span>
              </div>
              <span className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-amber-500/20 text-amber-300 border border-amber-500/30 animate-pulse">
                2
              </span>
            </button>

            <button
              onClick={() => setActiveTab('audit')}
              className={`w-full flex items-center justify-between px-3 py-2 rounded-lg text-xs font-semibold transition ${
                activeTab === 'audit'
                  ? 'bg-emerald-600 text-white shadow-md shadow-emerald-600/30 font-bold'
                  : 'text-slate-400 hover:text-emerald-400 hover:bg-slate-900'
              }`}
            >
              <div className="flex items-center gap-2">
                <BookOpen className="w-4 h-4 text-emerald-400" />
                <span>Audit Ledger</span>
              </div>
            </button>
          </div>

          {/* Quick Actions Card */}
          <div className="bg-[#0B0F19] border border-slate-800 rounded-xl p-3 shadow-xl space-y-2">
            <span className="text-[10px] font-mono font-bold text-slate-500 uppercase block tracking-wider">
              Investigation Controls
            </span>
            <button
              onClick={() => setShowReportModal(true)}
              className="w-full flex items-center gap-2 px-2.5 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold shadow transition"
            >
              <FileText className="w-3.5 h-3.5" />
              <span>Export Incident Report</span>
            </button>
            <button
              onClick={() => setShowIngestModal(true)}
              className="w-full flex items-center gap-2 px-2.5 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-200 border border-slate-800 text-xs font-medium transition"
            >
              <Flame className="w-3.5 h-3.5 text-cyan-400" />
              <span>Simulate Telemetry Log</span>
            </button>
          </div>

        </aside>

        {/* Center / Right Column: Kibana KQL Bar & Active Viewport */}
        <div className="flex-1 space-y-4 overflow-hidden">
          
          {/* Elastic / Kibana KQL Search Bar & Time Histogram */}
          <KibanaSearchBar
            searchQuery={searchQuery}
            onSearchChange={setSearchQuery}
            events={events}
            onRefresh={() => loadScenarioData(activeScenarioId)}
          />

          {/* Active Tab View */}
          {loading ? (
            <div className="bg-slate-900/40 border border-slate-800 rounded-xl p-16 flex flex-col items-center justify-center gap-3 text-slate-400">
              <div className="w-6 h-6 border-2 border-cyan-500 border-t-transparent rounded-full animate-spin" />
              <span className="text-xs font-mono">Querying security telemetry from datastore...</span>
            </div>
          ) : (
            <div>
              {activeTab === 'discover' && (
                <KibanaDiscover
                  events={filteredEvents}
                  onSelectEvent={handleSelectEvent}
                  selectedEventUuid={selectedEventUuid}
                />
              )}

              {activeTab === 'graph' && (
                <div className="space-y-4">
                  <AttackPathGraph
                    graphData={graphData}
                    onSelectEvent={handleSelectEvent}
                    selectedEventUuid={selectedEventUuid}
                  />
                  <TerminalConsole
                    onCommandExecuted={handleTerminalCommand}
                    activeScenarioId={activeScenarioId}
                  />
                </div>
              )}

              {activeTab === 'terminal' && (
                <div className="space-y-4">
                  <TerminalConsole
                    onCommandExecuted={handleTerminalCommand}
                    activeScenarioId={activeScenarioId}
                  />
                  <AttackPathGraph
                    graphData={graphData}
                    onSelectEvent={handleSelectEvent}
                    selectedEventUuid={selectedEventUuid}
                  />
                </div>
              )}

              {activeTab === 'timeline' && (
                <TimelineView
                  events={filteredEvents}
                  onSelectEvent={handleSelectEvent}
                  selectedEventUuid={selectedEventUuid}
                />
              )}

              {activeTab === 'mitre' && (
                <MitreMatrixView
                  mitreData={mitreData}
                  onSelectEvent={handleSelectEvent}
                />
              )}

              {activeTab === 'ai' && (
                <AIAssistantPanel
                  aiSummary={aiSummary}
                  querySuggestions={querySuggestions}
                  onAskCustomQuery={(q) => api.askAiCustomQuery(q, activeScenarioId)}
                  onSelectEvent={handleSelectEvent}
                  onOpenLimitations={() => setShowLimitationsModal(true)}
                />
              )}

              {activeTab === 'dashboard' && (
                <div className="space-y-4">
                  <OverviewStats
                    correlationData={correlationData}
                    scenario={activeScenario}
                    events={events}
                  />
                  <AttackPathGraph
                    graphData={graphData}
                    onSelectEvent={handleSelectEvent}
                    selectedEventUuid={selectedEventUuid}
                  />
                </div>
              )}

              {activeTab === 'detection' && <DetectionStudio />}
              {activeTab === 'gating' && <HitlGatingPanel />}
              {activeTab === 'audit' && <AuditLedgerView />}
            </div>
          )}

        </div>

      </div>

      {/* Forensic Evidence Drawer */}
      {selectedEvent && (
        <EvidenceDrawer
          event={selectedEvent}
          onClose={() => {
            setSelectedEvent(null);
            setSelectedEventUuid(null);
          }}
          onContainmentAction={(action) => {
            setContainmentAlert({
              title: 'EDR Action Dispatched',
              text: action.message
            });
            setTimeout(() => setContainmentAlert(null), 5000);
          }}
        />
      )}

      {/* Formal Investigation Report Modal */}
      {showReportModal && (
        <ReportModal
          scenarioId={activeScenarioId}
          onClose={() => setShowReportModal(false)}
        />
      )}

      {/* AI Limitations & Governance Modal */}
      {showLimitationsModal && (
        <AiLimitationsModal
          onClose={() => setShowLimitationsModal(false)}
        />
      )}

      {/* Telemetry Ingestion Workbench Modal */}
      {showIngestModal && (
        <IngestionPanel
          scenarioId={activeScenarioId}
          onEventIngested={() => loadScenarioData(activeScenarioId)}
          onClose={() => setShowIngestModal(false)}
        />
      )}

      {/* Footer */}
      <footer className="border-t border-slate-800/80 bg-[#070A12] p-3 mt-auto">
        <div className="max-w-7xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-3 text-xs text-slate-500 font-mono">
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
            <span>AegisHunt EDR & SIEM Platform</span>
            <span>&bull;</span>
            <span>Elastic Security / Kibana / Splunk Interface</span>
          </div>
          <div>
            REST API: http://localhost:8000 &bull; Web UI: http://localhost:3000
          </div>
        </div>
      </footer>

    </div>
  );
}
