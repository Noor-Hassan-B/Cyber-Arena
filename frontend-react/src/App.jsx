import React, { useState, useEffect } from 'react';
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
import OffensiveTerminal from './components/OffensiveTerminal';
import KibanaDiscover from './components/KibanaDiscover';
import DetectionStudio from './components/DetectionStudio';
import HitlGatingPanel from './components/HitlGatingPanel';
import AuditLedgerView from './components/AuditLedgerView';
import EvidenceVault from './components/EvidenceVault';
import ThreatHuntingWorkspace from './components/ThreatHuntingWorkspace';
import { api } from './services/api';
import {
  ShieldCheck, LayoutDashboard, Search, GitCommit, Terminal,
  Grid, Clock, Sparkles, Shield, AlertOctagon, BookOpen,
  FileText, Flame, AlertTriangle, CheckCircle2, Database,
  RefreshCw, Layers, Bell, User, ChevronDown, Zap, Radio,
  Activity, Eye, Settings, ChevronLeft, ChevronRight, Menu,
  Globe, Crosshair, Wifi, Share2, Lock, Fingerprint,
  Sun, Moon
} from 'lucide-react';

// ─── Sidebar Nav Item ─────────────────────────────────────────────────────────
function NavItem({ icon: Icon, label, tabId, activeTab, onClick, badge, iconColor, activeColor, isDark = true }) {
  const isActive = activeTab === tabId;
  const ac = activeColor || (isDark ? 'bg-blue-600/15 text-blue-300 border-blue-500/30' : 'bg-blue-50 text-blue-700 border-blue-300 shadow-sm');

  return (
    <button
      onClick={() => onClick(tabId)}
      className={`w-full flex items-center space-x-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-all ${
        isActive
          ? `${ac} border shadow-sm`
          : isDark
          ? 'text-gray-400 hover:bg-gray-800/60 hover:text-gray-200 border border-transparent'
          : 'text-gray-600 hover:bg-slate-100 hover:text-gray-900 border border-transparent'
      }`}
    >
      <Icon className={`w-4.5 h-4.5 shrink-0 ${isActive ? '' : iconColor || (isDark ? 'text-gray-500' : 'text-gray-400')}`} />
      <span className="truncate">{label}</span>
      {badge !== undefined && (
        <span className={`ml-auto text-xs font-bold px-2 py-0.5 rounded-full border ${
          typeof badge === 'number' && badge > 0
            ? 'bg-red-500/20 text-red-400 border-red-500/30'
            : typeof badge === 'string' && badge === 'ACTIVE'
            ? 'bg-indigo-500/20 text-indigo-300 border-indigo-500/30'
            : typeof badge === 'string' && badge === 'SHA-256'
            ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30'
            : isDark ? 'bg-gray-700/50 text-gray-400 border-gray-600/30' : 'bg-slate-200 text-slate-700 border-slate-300'
        }`}>
          {badge}
        </span>
      )}
    </button>
  );
}

// ─── DEFCON Threat Level Badge ────────────────────────────────────────────────
function DefconBadge() {
  return (
    <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-red-950/40 border border-red-500/40 shadow-inner">
      <span className="relative flex h-2.5 w-2.5">
        <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-red-400 opacity-75" />
        <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-red-500" />
      </span>
      <span className="text-[11px] font-mono font-bold text-red-400 tracking-wider">DEFCON 2</span>
    </div>
  );
}

export default function App() {
  const [scenarios, setScenarios] = useState([]);
  const [activeScenarioId, setActiveScenarioId] = useState('SCN-APT29-GHOST');
  const [backendStatus, setBackendStatus] = useState({ online: false, url: '' });
  const [activeTab, setActiveTab] = useState('dashboard');
  const [searchQuery, setSearchQuery] = useState('');
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);

  // Scenario Data States
  const [events, setEvents] = useState([]);
  const [correlationData, setCorrelationData] = useState(null);
  const [graphData, setGraphData] = useState(null);
  const [mitreData, setMitreData] = useState(null);
  const [aiSummary, setAiSummary] = useState(null);
  const [querySuggestions, setQuerySuggestions] = useState([]);

  // UI States
  const [selectedEventUuid, setSelectedEventUuid] = useState(null);
  const [selectedEvent, setSelectedEvent] = useState(null);
  const [showReportModal, setShowReportModal] = useState(false);
  const [showLimitationsModal, setShowLimitationsModal] = useState(false);
  const [showIngestModal, setShowIngestModal] = useState(false);
  const [containmentAlert, setContainmentAlert] = useState(null);
  const [loading, setLoading] = useState(true);

  // Theme Management (Dark / Light)
  const [theme, setTheme] = useState(() => localStorage.getItem('aegis_theme') || 'dark');

  useEffect(() => {
    const root = document.documentElement;
    if (theme === 'dark') {
      root.classList.add('dark');
      root.classList.remove('light');
    } else {
      root.classList.remove('dark');
      root.classList.add('light');
    }
    localStorage.setItem('aegis_theme', theme);
  }, [theme]);

  const toggleTheme = () => setTheme(prev => (prev === 'dark' ? 'light' : 'dark'));
  const isDark = theme === 'dark';

  // 1. Init
  useEffect(() => {
    async function init() {
      const health = await api.checkBackendHealth();
      setBackendStatus(health);
      const scenarioList = await api.getScenarios();
      setScenarios(scenarioList);
      if (scenarioList.length > 0) setActiveScenarioId(scenarioList[0].scenario_id);
    }
    init();
  }, []);

  // 2. Load Scenario
  const loadScenarioData = async (scenarioId) => {
    setLoading(true);
    try {
      const [e, c, g, m, a, s] = await Promise.all([
        api.getEvents(scenarioId), api.getCorrelation(scenarioId),
        api.getAttackPath(scenarioId), api.getMitreData(scenarioId),
        api.getAiSummary(scenarioId), api.getAiQuerySuggestions(scenarioId)
      ]);
      setEvents(e); setCorrelationData(c); setGraphData(g);
      setMitreData(m); setAiSummary(a); setQuerySuggestions(s);
    } catch (err) { console.error(err); }
    finally { setLoading(false); }
  };

  useEffect(() => { if (activeScenarioId) loadScenarioData(activeScenarioId); }, [activeScenarioId]);

  const handleSelectEvent = (eventUuid) => {
    setSelectedEventUuid(eventUuid);
    const found = events.find(e => e.event_uuid === eventUuid);
    setSelectedEvent(found || {
      event_uuid: eventUuid, timestamp: new Date().toISOString(),
      domain: 'endpoint', event_type: 'corroborated_alert', severity: 'high',
      source_host: 'WKSTN-FIN-04', user_id: 'sarah.connor',
      command_line: 'Evidence item linked from investigation hypothesis'
    });
  };

  const handleTerminalCommand = async (actionData) => {
    if (actionData.type === 'event') {
      await api.ingestEvent(actionData);
      await loadScenarioData(activeScenarioId);
      setContainmentAlert({
        title: 'Adversary Telemetry Ingested',
        text: `${actionData.mitre_technique_id} — ${actionData.domain.toUpperCase()}`
      });
      setTimeout(() => setContainmentAlert(null), 5000);
    } else if (actionData.type === 'containment') {
      setContainmentAlert({
        title: 'EDR Quarantine Active',
        text: `Host isolation dispatched: ${actionData.host}`
      });
      setTimeout(() => setContainmentAlert(null), 5000);
    }
  };

  const handleRefreshBackend = async () => {
    const health = await api.checkBackendHealth();
    setBackendStatus(health);
    loadScenarioData(activeScenarioId);
  };

  const filteredEvents = events.filter(evt => {
    if (!searchQuery) return true;
    const q = searchQuery.toLowerCase();
    return `${evt.event_uuid} ${evt.domain} ${evt.event_type} ${evt.severity} ${evt.source_host || ''} ${evt.dest_host || ''} ${evt.source_ip || ''} ${evt.dest_ip || ''} ${evt.user_id || ''} ${evt.command_line || ''} ${evt.mitre_technique_id || ''} ${evt.mitre_tactic || ''}`.toLowerCase().includes(q);
  });

  const activeScenario = scenarios.find(s => s.scenario_id === activeScenarioId) || {
    scenario_id: activeScenarioId, name: 'Cyber Attack Scenario',
    threat_actor: 'Advanced Adversary', description: 'Correlating telemetry...'
  };

  const severityCounts = {
    critical: events.filter(e => e.severity === 'critical').length,
    high: events.filter(e => e.severity === 'high').length,
    medium: events.filter(e => e.severity === 'medium').length,
  };

  // Page titles for top header
  const PAGE_TITLES = {
    dashboard: 'Command Center & KPI Metrics',
    vault: 'Evidence Vault & Relational Graph Centerpiece',
    hunting: 'Hypothesis-Driven Threat Hunting & Triage Verdict',
    discover: 'Multi-Vendor Alert Triage (Wazuh / Sentinel / Splunk)',
    graph: 'Attack Path Topology & Lateral Spread Visualizer',
    terminal: 'Adversary Attack Simulation Console (CLI)',
    mitre: 'MITRE ATT&CK Matrix & Blindspot Heatmap',
    timeline: 'Incident Chronology & Telemetry Reconstruction',
    ai: 'AI Threat Copilot (Evidence-Grounded Insights)',
    detection: 'Detection Engineering Studio (Sigma / SPL / KQL)',
    gating: 'Human-in-the-Loop Dual-Gated Response Console',
    audit: 'Append-Only Audit Ledger (Cryptographic SHA-256 Proof)',
  };

  return (
    <div className={`h-screen overflow-hidden ${isDark ? 'bg-[#0b0f17] text-gray-100' : 'bg-[#f8fafc] text-slate-800'} font-sans antialiased flex transition-colors`}>

      {/* ═══════════════════════════════════════════════════════════════════════
          LEFT SIDEBAR — High-density SOCForge Layout
         ═══════════════════════════════════════════════════════════════════════ */}
      <aside className={`${sidebarCollapsed ? 'w-16' : 'w-64'} ${isDark ? 'bg-[#111827] border-[#1f293d]' : 'bg-white border-slate-200 shadow-sm'} border-r flex flex-col z-30 transition-all duration-300 select-none shrink-0`}>

        {/* Brand Header */}
        <div className={`h-16 flex items-center px-4 border-b ${isDark ? 'border-[#1f293d]' : 'border-slate-200'} gap-3`}>
          <div className="w-9 h-9 rounded-lg bg-gradient-to-br from-blue-600 to-indigo-900 flex items-center justify-center shadow-inner shadow-blue-400/30 shrink-0">
            <ShieldCheck className="w-5 h-5 text-blue-300" />
          </div>
          {!sidebarCollapsed && (
            <div className="min-w-0">
              <span className={`font-bold tracking-wider text-base ${isDark ? 'bg-gradient-to-r from-white via-gray-200 to-blue-400 bg-clip-text text-transparent' : 'text-slate-900 font-bold'} block`}>
                SOCForge
              </span>
              <span className="text-[9px] font-mono text-gray-500 uppercase tracking-widest block -mt-0.5">
                Evidence-Driven SOC
              </span>
            </div>
          )}
          <button
            onClick={() => setSidebarCollapsed(v => !v)}
            className={`ml-auto p-1 rounded transition ${isDark ? 'hover:bg-gray-700/50 text-gray-500 hover:text-gray-300' : 'hover:bg-slate-100 text-slate-400 hover:text-slate-700'}`}
          >
            {sidebarCollapsed ? <ChevronRight className="w-4 h-4" /> : <ChevronLeft className="w-4 h-4" />}
          </button>
        </div>

        {/* Navigation Section */}
        <nav className={`flex-1 overflow-y-auto py-3 space-y-5 ${sidebarCollapsed ? 'px-2' : 'px-3'}`}>

          {/* 1. OPERATIONS */}
          {!sidebarCollapsed && (
            <div className="text-[10px] font-mono font-bold text-gray-500 uppercase tracking-widest px-3">
              Operations & Triage
            </div>
          )}
          <div className="space-y-1">
            <NavItem 
              icon={LayoutDashboard} 
              label="Command Center" 
              tabId="dashboard" 
              activeTab={activeTab} 
              onClick={setActiveTab} 
              iconColor="text-blue-400" 
            />
            <NavItem 
              icon={Database} 
              label="Evidence Vault" 
              tabId="vault" 
              activeTab={activeTab} 
              onClick={setActiveTab} 
              badge="GRAPH"
              iconColor="text-cyan-400"
              activeColor="bg-cyan-600/15 text-cyan-300 border-cyan-500/30"
            />
            <NavItem 
              icon={Crosshair} 
              label="Threat Hunting" 
              tabId="hunting" 
              activeTab={activeTab} 
              onClick={setActiveTab} 
              badge="ACTIVE"
              iconColor="text-indigo-400"
              activeColor="bg-indigo-600/15 text-indigo-300 border-indigo-500/30"
            />
            <NavItem 
              icon={Search} 
              label="Alert Triage" 
              tabId="discover" 
              activeTab={activeTab} 
              onClick={setActiveTab} 
              badge={filteredEvents.length} 
              iconColor="text-blue-400" 
            />
            <NavItem 
              icon={GitCommit} 
              label="Attack Path" 
              tabId="graph" 
              activeTab={activeTab} 
              onClick={setActiveTab} 
              iconColor="text-purple-400" 
            />
            <NavItem 
              icon={Clock} 
              label="Timeline Stream" 
              tabId="timeline" 
              activeTab={activeTab} 
              onClick={setActiveTab} 
              iconColor="text-rose-400" 
            />
          </div>

          {/* 2. DETECTION & GATING */}
          {!sidebarCollapsed && (
            <div className="text-[10px] font-mono font-bold text-gray-500 uppercase tracking-widest px-3 pt-1">
              Detection & Response
            </div>
          )}
          <div className="space-y-1">
            <NavItem 
              icon={Shield} 
              label="Detection Studio" 
              tabId="detection" 
              activeTab={activeTab} 
              onClick={setActiveTab} 
              badge="SIGMA"
              iconColor="text-sky-400" 
            />
            <NavItem 
              icon={AlertOctagon} 
              label="Response Gating" 
              tabId="gating" 
              activeTab={activeTab} 
              onClick={setActiveTab} 
              badge={2} 
              iconColor="text-amber-400" 
              activeColor="bg-amber-600/15 text-amber-300 border-amber-500/30" 
            />
            <NavItem 
              icon={Terminal} 
              label="Simulation CLI" 
              tabId="terminal" 
              activeTab={activeTab} 
              onClick={setActiveTab} 
              iconColor="text-emerald-400" 
              activeColor="bg-emerald-600/15 text-emerald-300 border-emerald-500/30" 
            />
            <NavItem 
              icon={Grid} 
              label="MITRE ATT&CK" 
              tabId="mitre" 
              activeTab={activeTab} 
              onClick={setActiveTab} 
              iconColor="text-amber-400" 
            />
            <NavItem 
              icon={BookOpen} 
              label="Audit Ledger" 
              tabId="audit" 
              activeTab={activeTab} 
              onClick={setActiveTab} 
              badge="SHA-256"
              iconColor="text-emerald-400" 
              activeColor="bg-emerald-600/15 text-emerald-300 border-emerald-500/30" 
            />
            <NavItem 
              icon={Sparkles} 
              label="AI Threat Copilot" 
              tabId="ai" 
              activeTab={activeTab} 
              onClick={setActiveTab} 
              iconColor="text-purple-400" 
              activeColor="bg-purple-600/15 text-purple-300 border-purple-500/30" 
            />
          </div>
        </nav>

        {/* Sidebar Bottom: Scenario + Engine Indicator */}
        {!sidebarCollapsed && (
          <div className="border-t border-[#1f293d] p-3 space-y-2">
            <div className="bg-[#0b0f17] rounded-lg border border-[#1f293d] p-2.5">
              <div className="text-[9px] font-mono text-gray-500 uppercase tracking-wider mb-1">
                Active Incident Scenario
              </div>
              <select
                value={activeScenarioId}
                onChange={(e) => setActiveScenarioId(e.target.value)}
                className="w-full bg-transparent text-xs text-gray-200 font-semibold focus:outline-none cursor-pointer truncate"
              >
                {scenarios.map(s => (
                  <option key={s.scenario_id} value={s.scenario_id} className="bg-gray-900 text-gray-200">
                    {s.name}
                  </option>
                ))}
              </select>
            </div>

            <button
              onClick={handleRefreshBackend}
              className={`w-full flex items-center gap-2 px-2.5 py-2 rounded-lg border text-xs font-mono transition ${
                backendStatus.online
                  ? 'bg-emerald-950/30 border-emerald-500/25 text-emerald-400 hover:bg-emerald-900/30'
                  : 'bg-indigo-950/30 border-indigo-500/25 text-indigo-300 hover:bg-indigo-900/30'
              }`}
            >
              <Database className="w-3.5 h-3.5 shrink-0" />
              <span className="truncate">{backendStatus.online ? 'REST API: Live (8000)' : 'In-Memory Engine'}</span>
              <RefreshCw className="w-3 h-3 ml-auto shrink-0 opacity-50 hover:opacity-100" />
            </button>
          </div>
        )}
      </aside>

      {/* ═══════════════════════════════════════════════════════════════════════
          RIGHT SIDE: Top Header + Main Content
         ═══════════════════════════════════════════════════════════════════════ */}
      <div className="flex-1 flex flex-col overflow-hidden">

        {/* ─── TOP HEADER BAR ────────────────────────────────────────────── */}
        <header className={`h-16 ${isDark ? 'bg-[#111827] border-[#1f293d]' : 'bg-white border-slate-200 shadow-sm'} border-b flex items-center px-6 gap-4 shrink-0 z-20 transition-colors`}>
          
          {/* Page Title & Breadcrumb */}
          <div className="flex items-center gap-3 min-w-0">
            <h1 className={`text-base font-bold tracking-wide truncate font-mono ${isDark ? 'text-white' : 'text-slate-900'}`}>
              {PAGE_TITLES[activeTab] || 'Command Center'}
            </h1>
          </div>

          {/* Connectors Status Ribbon */}
          <div className={`hidden xl:flex items-center gap-2 border px-3 py-1.5 rounded-lg text-[10px] font-mono ${
            isDark ? 'bg-[#0b0f17] border-[#1f293d] text-gray-400' : 'bg-slate-100 border-slate-200 text-slate-600'
          }`}>
            <span className="flex items-center gap-1 text-emerald-500 font-semibold">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" /> Wazuh
            </span>
            <span className="text-gray-400">&bull;</span>
            <span className="flex items-center gap-1 text-emerald-500 font-semibold">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" /> Sentinel
            </span>
            <span className="text-gray-400">&bull;</span>
            <span className="flex items-center gap-1 text-emerald-500 font-semibold">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" /> Splunk
            </span>
            <span className="text-gray-400">&bull;</span>
            <span className="flex items-center gap-1 text-cyan-500 font-semibold">
              <span className="w-1.5 h-1.5 rounded-full bg-cyan-500" /> Sysmon
            </span>
          </div>

          {/* Global IOC Search */}
          <div className="flex-1 max-w-md mx-2">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" />
              <input
                value={searchQuery}
                onChange={e => setSearchQuery(e.target.value)}
                placeholder="Search IOCs, hashes, IPs, hosts, TTPs..."
                className={`w-full pl-9 pr-4 py-1.5 border rounded-lg text-xs font-mono transition ${
                  isDark
                    ? 'bg-[#0b0f17] border-[#1f293d] text-gray-200 placeholder-gray-600 focus:border-blue-500/50'
                    : 'bg-slate-50 border-slate-300 text-slate-800 placeholder-slate-400 focus:border-blue-500'
                }`}
              />
            </div>
          </div>

          {/* DEFCON + Alert Badges + User */}
          <div className="flex items-center gap-3 shrink-0">
            <DefconBadge />

            {/* Severity Mini Counts */}
            <div className="hidden lg:flex items-center gap-1.5">
              {severityCounts.critical > 0 && (
                <span className="px-2 py-1 rounded bg-red-950/50 border border-red-500/30 text-red-400 text-[10px] font-mono font-bold">
                  {severityCounts.critical} CRIT
                </span>
              )}
              {severityCounts.high > 0 && (
                <span className="px-2 py-1 rounded bg-orange-950/50 border border-orange-500/30 text-orange-400 text-[10px] font-mono font-bold">
                  {severityCounts.high} HIGH
                </span>
              )}
            </div>

            {/* Quick Actions */}
            <button
              onClick={() => setShowIngestModal(true)}
              className={`p-2 rounded-lg transition ${
                isDark ? 'hover:bg-gray-800/60 text-gray-400 hover:text-cyan-400' : 'hover:bg-slate-100 text-slate-500 hover:text-cyan-600'
              }`}
              title="Ingest Telemetry Log"
            >
              <Flame className="w-4 h-4" />
            </button>
            <button
              onClick={() => setShowReportModal(true)}
              className={`p-2 rounded-lg transition ${
                isDark ? 'hover:bg-gray-800/60 text-gray-400 hover:text-blue-400' : 'hover:bg-slate-100 text-slate-500 hover:text-blue-600'
              }`}
              title="Export Incident Dossier"
            >
              <FileText className="w-4 h-4" />
            </button>
            <button
              onClick={() => setShowLimitationsModal(true)}
              className={`p-2 rounded-lg transition ${
                isDark ? 'hover:bg-gray-800/60 text-gray-400 hover:text-amber-400' : 'hover:bg-slate-100 text-slate-500 hover:text-amber-600'
              }`}
              title="AI Limitations & Governance"
            >
              <AlertTriangle className="w-4 h-4" />
            </button>

            {/* Dark / Light Theme Changer Button */}
            <button
              onClick={toggleTheme}
              className={`px-3 py-1.5 rounded-lg border flex items-center gap-1.5 font-mono text-xs font-semibold transition shadow-sm ${
                isDark
                  ? 'bg-gray-800/90 border-gray-700 text-amber-300 hover:bg-gray-700 hover:border-gray-600'
                  : 'bg-slate-100 border-slate-300 text-indigo-700 hover:bg-slate-200 hover:border-slate-400'
              }`}
              title={isDark ? "Switch to Light Mode" : "Switch to Dark Mode"}
            >
              {isDark ? (
                <>
                  <Sun className="w-4 h-4 text-amber-400" />
                  <span className="hidden sm:inline">Light</span>
                </>
              ) : (
                <>
                  <Moon className="w-4 h-4 text-indigo-600" />
                  <span className="hidden sm:inline">Dark</span>
                </>
              )}
            </button>

            {/* Analyst Avatar with RBAC Role */}
            <div className={`flex items-center gap-2 pl-2 border-l ${isDark ? 'border-[#1f293d]' : 'border-slate-200'}`}>
              <div className="w-8 h-8 rounded-full bg-gradient-to-br from-blue-600 to-indigo-700 flex items-center justify-center text-white text-xs font-bold border border-blue-400/30 shadow-md">
                SM
              </div>
              <div className="hidden md:block text-left">
                <div className={`text-xs font-bold leading-tight ${isDark ? 'text-gray-200' : 'text-slate-800'}`}>Sandeep M.</div>
                <div className="text-[9px] font-mono text-gray-500">L2 Sr. Hunter</div>
              </div>
            </div>
          </div>
        </header>

        {/* ─── MAIN CONTENT VIEWPORT ─────────────────────────────────────── */}
        <main className={`flex-1 overflow-y-auto p-6 transition-colors ${isDark ? 'bg-[#0b0f17]' : 'bg-[#f8fafc]'}`}>
          {/* Floating Toast Notification */}
          {containmentAlert && (
            <div className="fixed top-20 right-6 z-50 bg-[#111827] border-2 border-emerald-500/60 rounded-xl p-4 shadow-2xl flex items-center gap-3 max-w-md animate-pulse">
              <div className="p-2 rounded-lg bg-emerald-950 text-emerald-400">
                <CheckCircle2 className="w-5 h-5" />
              </div>
              <div>
                <div className="text-xs font-bold text-white uppercase font-mono">{containmentAlert.title}</div>
                <div className="text-xs text-gray-400">{containmentAlert.text}</div>
              </div>
            </div>
          )}

          {/* Loading Indicator */}
          {loading ? (
            <div className="flex flex-col items-center justify-center h-full gap-4 text-gray-500">
              <div className="w-8 h-8 border-2 border-blue-500 border-t-transparent rounded-full animate-spin" />
              <span className="text-sm font-mono">Querying security datastore & correlation engine...</span>
            </div>
          ) : (
            <div className="max-w-[1600px] mx-auto">

              {/* ══ 1. COMMAND CENTER / OVERVIEW ══ */}
              {activeTab === 'dashboard' && (
                <div className="space-y-6">
                  {/* Status Bar */}
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                    {[
                      { label: 'Correlated Telemetry', value: events.length, icon: Activity, color: 'text-blue-400', border: 'border-blue-500/20', bg: 'bg-blue-950/20' },
                      { label: 'Critical Alert Count', value: severityCounts.critical, icon: AlertTriangle, color: 'text-red-400', border: 'border-red-500/20', bg: 'bg-red-950/20' },
                      { label: 'High Threat Events', value: severityCounts.high, icon: Zap, color: 'text-orange-400', border: 'border-orange-500/20', bg: 'bg-orange-950/20' },
                      { label: 'Kill Chain Coverage', value: '86%', icon: Crosshair, color: 'text-emerald-400', border: 'border-emerald-500/20', bg: 'bg-emerald-950/20' },
                    ].map(s => (
                      <div key={s.label} className={`${s.bg} border ${s.border} rounded-xl p-4 flex items-center gap-4`}>
                        <div className={`p-2.5 rounded-lg bg-[#111827] border border-[#1f293d]`}>
                          <s.icon className={`w-5 h-5 ${s.color}`} />
                        </div>
                        <div>
                          <div className={`text-2xl font-mono font-bold ${s.color}`}>{s.value}</div>
                          <div className="text-[11px] text-gray-500 font-medium">{s.label}</div>
                        </div>
                      </div>
                    ))}
                  </div>

                  {/* Row 1: Attack Path Topology (Full Width in a Straight Line) */}
                  <div className={`border rounded-xl p-5 shadow-xl transition-colors ${
                    isDark ? 'bg-[#111827] border-[#1f293d]' : 'bg-white border-slate-200'
                  }`}>
                    <AttackPathGraph graphData={graphData} onSelectEvent={handleSelectEvent} selectedEventUuid={selectedEventUuid} theme={theme} />
                  </div>

                  {/* Row 2: Incident Overview & Correlation Stats (Directly Below, Full Width in a Straight Line) */}
                  <div className={`border rounded-xl p-5 shadow-xl transition-colors ${
                    isDark ? 'bg-[#111827] border-[#1f293d]' : 'bg-white border-slate-200'
                  }`}>
                    <OverviewStats correlationData={correlationData} scenario={activeScenario} events={events} />
                  </div>

                  {/* Telemetry Log Stream */}
                  <div className={`border rounded-xl p-5 transition-colors ${
                    isDark ? 'bg-[#111827] border-[#1f293d]' : 'bg-white border-slate-200'
                  }`}>
                    <div className="flex items-center justify-between mb-4">
                      <div className="flex items-center gap-2">
                        <Radio className="w-4 h-4 text-cyan-400" />
                        <h2 className="text-sm font-semibold text-gray-200">Live Ingested Telemetry Feed</h2>
                      </div>
                      <span className="text-[10px] font-mono text-gray-500">{events.length} security events</span>
                    </div>
                    <div className="space-y-1 max-h-60 overflow-y-auto">
                      {events.slice(0, 8).map((evt) => (
                        <button
                          key={evt.event_uuid}
                          onClick={() => handleSelectEvent(evt.event_uuid)}
                          className="w-full flex items-center gap-3 px-3 py-2 rounded-lg hover:bg-gray-800/40 text-left transition group"
                        >
                          <span className={`w-2 h-2 rounded-full shrink-0 ${
                            evt.severity === 'critical' ? 'bg-red-500' :
                            evt.severity === 'high' ? 'bg-orange-500' :
                            evt.severity === 'medium' ? 'bg-amber-500' : 'bg-blue-500'
                          }`} />
                          <span className="text-[11px] font-mono text-gray-500 w-32 shrink-0 truncate">{new Date(evt.timestamp).toLocaleTimeString()}</span>
                          <span className={`text-[10px] font-mono font-bold w-16 shrink-0 uppercase ${
                            evt.severity === 'critical' ? 'text-red-400' :
                            evt.severity === 'high' ? 'text-orange-400' :
                            evt.severity === 'medium' ? 'text-amber-400' : 'text-blue-400'
                          }`}>{evt.severity}</span>
                          <span className="text-xs text-gray-300 truncate flex-1 font-mono">{evt.event_type}</span>
                          <span className="text-[10px] text-gray-500 font-mono truncate max-w-32">{evt.source_host || evt.source_ip || ''}</span>
                          <Eye className="w-3.5 h-3.5 text-gray-600 group-hover:text-blue-400 shrink-0 transition" />
                        </button>
                      ))}
                    </div>
                  </div>
                </div>
              )}

              {/* ══ 2. EVIDENCE VAULT & RELATIONAL GRAPH ══ */}
              {activeTab === 'vault' && (
                <EvidenceVault 
                  events={events} 
                  onSelectEvent={handleSelectEvent} 
                  selectedEventUuid={selectedEventUuid} 
                />
              )}

              {/* ══ 3. THREAT HUNTING WORKSPACE ══ */}
              {activeTab === 'hunting' && (
                <ThreatHuntingWorkspace 
                  events={events} 
                  scenario={activeScenario} 
                  onSelectEvent={handleSelectEvent} 
                />
              )}

              {/* ══ 4. ALERT TRIAGE DISCOVERY ══ */}
              {activeTab === 'discover' && (
                <KibanaDiscover 
                  events={filteredEvents} 
                  onSelectEvent={handleSelectEvent} 
                  selectedEventUuid={selectedEventUuid} 
                />
              )}

              {/* ══ 5. ATTACK PATH GRAPH ══ */}
              {activeTab === 'graph' && (
                <div className="space-y-6">
                  <div className={`border rounded-xl p-5 transition-colors ${
                    isDark ? 'bg-[#111827] border-[#1f293d]' : 'bg-white border-slate-200'
                  }`}>
                    <div className="flex items-center gap-2 mb-4">
                      <GitCommit className="w-4 h-4 text-indigo-400" />
                      <h2 className={`text-sm font-semibold ${isDark ? 'text-gray-200' : 'text-slate-800'}`}>Relational Evidence Graph Topology</h2>
                      <span className="text-[10px] font-mono text-gray-500">Entity-linked IOC path</span>
                    </div>
                    <AttackPathGraph graphData={graphData} onSelectEvent={handleSelectEvent} selectedEventUuid={selectedEventUuid} theme={theme} />
                  </div>
                  <div className={`border rounded-xl p-5 transition-colors ${
                    isDark ? 'bg-[#111827] border-[#1f293d]' : 'bg-white border-slate-200'
                  }`}>
                    <TerminalConsole onCommandExecuted={handleTerminalCommand} activeScenarioId={activeScenarioId} />
                  </div>
                </div>
              )}

              {/* ══ 6. ATTACK SIMULATION TERMINAL (Offensive Arsenal from Noor-Hassan-B/hackathone) ══ */}
              {activeTab === 'terminal' && (
                <OffensiveTerminal onCommandExecuted={handleTerminalCommand} activeScenarioId={activeScenarioId} />
              )}

              {/* ══ 7. TIMELINE STREAM ══ */}
              {activeTab === 'timeline' && (
                <TimelineView events={filteredEvents} onSelectEvent={handleSelectEvent} selectedEventUuid={selectedEventUuid} />
              )}

              {/* ══ 8. MITRE ATT&CK MATRIX ══ */}
              {activeTab === 'mitre' && (
                <MitreMatrixView mitreData={mitreData} onSelectEvent={handleSelectEvent} />
              )}

              {/* ══ 9. AI COPILOT ══ */}
              {activeTab === 'ai' && (
                <AIAssistantPanel
                  aiSummary={aiSummary} querySuggestions={querySuggestions}
                  onAskCustomQuery={(q) => api.askAiCustomQuery(q, activeScenarioId)}
                  onSelectEvent={handleSelectEvent}
                  onOpenLimitations={() => setShowLimitationsModal(true)}
                />
              )}

              {/* ══ 10. DETECTION STUDIO ══ */}
              {activeTab === 'detection' && <DetectionStudio />}

              {/* ══ 11. RESPONSE GATING ══ */}
              {activeTab === 'gating' && <HitlGatingPanel />}

              {/* ══ 12. AUDIT LEDGER ══ */}
              {activeTab === 'audit' && <AuditLedgerView />}

            </div>
          )}
        </main>

        {/* ─── FOOTER STATUS BAR ─────────────────────────────────────────── */}
        <footer className="h-8 bg-[#111827] border-t border-[#1f293d] flex items-center px-4 gap-4 text-[10px] font-mono text-gray-500 shrink-0">
          <div className="flex items-center gap-2">
            <span className="relative flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75" />
              <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500" />
            </span>
            <span>SOCForge Platform — Operational</span>
          </div>
          <span className="text-gray-600">|</span>
          <span>REST API: http://localhost:8000</span>
          <span className="text-gray-600">|</span>
          <span>Web UI: http://localhost:3000</span>
          <span className="ml-auto text-gray-600">Evidence-Driven SOC Platform v2.5 &bull; Sandeep Mothukuri Arch</span>
        </footer>
      </div>

      {/* ═══════════════════════════════════════════════════════════════════════
          OVERLAYS / MODALS / DRAWERS
         ═══════════════════════════════════════════════════════════════════════ */}
      {selectedEvent && (
        <EvidenceDrawer
          event={selectedEvent}
          onClose={() => { setSelectedEvent(null); setSelectedEventUuid(null); }}
          onContainmentAction={(action) => {
            setContainmentAlert({ title: 'EDR Action Dispatched', text: action.message });
            setTimeout(() => setContainmentAlert(null), 5000);
          }}
        />
      )}

      {showReportModal && <ReportModal scenarioId={activeScenarioId} onClose={() => setShowReportModal(false)} />}
      {showLimitationsModal && <AiLimitationsModal onClose={() => setShowLimitationsModal(false)} />}
      {showIngestModal && (
        <IngestionPanel
          scenarioId={activeScenarioId}
          onEventIngested={() => loadScenarioData(activeScenarioId)}
          onClose={() => setShowIngestModal(false)}
        />
      )}
    </div>
  );
}
