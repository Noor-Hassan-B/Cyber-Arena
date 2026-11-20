import React, { useState, useEffect, useMemo } from 'react';
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
import GlobeVisualization from './components/GlobeVisualization';
import { api } from './services/api';
import {
  ShieldCheck, LayoutDashboard, Search, GitCommit, Terminal,
  Grid, Clock, Sparkles, Shield, AlertOctagon, BookOpen,
  FileText, Flame, AlertTriangle, CheckCircle2, Database,
  RefreshCw, Layers, Bell, User, ChevronDown, Zap, Radio,
  Activity, Eye, Settings, ChevronLeft, ChevronRight,
  Globe, Crosshair, Wifi, Share2, Lock, Fingerprint,
  Sun, Moon, Network, Cpu, BarChart2, Radar, Target,
  ArrowUpRight, TrendingUp, ArrowRight, Satellite, RotateCcw, Trash2
} from 'lucide-react';

// ─── Sh4d0w_Br0k3rs Top Nav Tabs ─────────────────────────────────────────────
const TABS = [
  { id: 'globe',     icon: Globe,       label: 'Overview & Globe' },
  { id: 'graph',     icon: Network,     label: 'Attack Path Visualizer', dot: true },
  { id: 'discover',  icon: Radar,       label: 'CIM Telemetry (All Logs)' },
  { id: 'mitre',     icon: Grid,        label: 'MITRE Matrix' },
  { id: 'terminal',  icon: Terminal,    label: 'Attack Sequences' },
  { id: 'ai',        icon: Sparkles,    label: 'AI Copilot' },
  { id: 'audit',     icon: BookOpen,    label: 'Investigation Reports' },
  { id: 'detection', icon: Shield,      label: 'Detection Studio' },
];

// ─── Sidebar icon items ───────────────────────────────────────────────────────
const SIDEBAR_ICONS = [
  { id: 'globe',    Icon: Globe,         tooltip: 'Overview & Globe' },
  { id: 'graph',    Icon: Network,       tooltip: 'Attack Path' },
  { id: 'discover', Icon: BarChart2,     tooltip: 'CIM Telemetry (All Logs)' },
  { id: 'mitre',    Icon: Grid,          tooltip: 'MITRE Matrix' },
  { id: 'terminal', Icon: Zap,           tooltip: 'Attack Sequences' },
  { id: 'ai',       Icon: Sparkles,      tooltip: 'AI Copilot' },
  { id: 'audit',    Icon: FileText,      tooltip: 'Reports' },
  { id: 'settings', Icon: Settings,      tooltip: 'Settings' },
];

// ─── Telemetry bar ────────────────────────────────────────────────────────────
function TelemetryBar({ label, value, pct, color, isDark }) {
  return (
    <div className="flex items-center gap-3 py-1.5">
      <span className="w-2 h-2 rounded-full shrink-0" style={{ backgroundColor: color }} />
      <span className={`text-xs w-44 truncate ${isDark ? 'text-slate-300' : 'text-slate-700 font-medium'}`}>{label}</span>
      <span className={`text-xs font-mono w-20 text-right ${isDark ? 'text-slate-200' : 'text-slate-900 font-bold'}`}>{value.toLocaleString()}</span>
      <div className={`flex-1 rounded-full h-1.5 mx-2 min-w-[60px] ${isDark ? 'bg-white/5' : 'bg-slate-200/80'}`}>
        <div className="h-1.5 rounded-full transition-all" style={{ width: `${pct}%`, backgroundColor: color }} />
      </div>
      <span className="text-xs font-bold w-8 text-right font-mono" style={{ color }}>{pct}%</span>
    </div>
  );
}

// ─── Metric mini card ─────────────────────────────────────────────────────────
function MetricCard({ label, value, sub, trend, color = '#00D4FF', isDark }) {
  return (
    <div className={`rounded-xl p-4 flex-1 min-w-0 transition-all ${
      isDark
        ? 'bg-white/[0.03] border border-white/[0.07]'
        : 'bg-white border border-slate-200 shadow-xs hover:shadow-sm'
    }`}>
      <div className={`text-[10px] uppercase tracking-widest font-mono mb-1 ${isDark ? 'text-slate-500' : 'text-slate-500 font-semibold'}`}>{label}</div>
      {trend && (
        <div className="flex items-center gap-1 text-[10px] text-emerald-600 dark:text-emerald-400 font-semibold mb-1">
          <TrendingUp className="w-3 h-3" />
          <span>{trend}</span>
        </div>
      )}
      <div className="text-2xl font-bold font-mono" style={{ color }}>{value}</div>
      {sub && <div className={`text-[10px] mt-0.5 ${isDark ? 'text-slate-500' : 'text-slate-500'}`}>{sub}</div>}
    </div>
  );
}

export default function App() {
  const [scenarios, setScenarios] = useState([]);
  const [activeScenarioId, setActiveScenarioId] = useState('SCN-APT29-GHOST');
  const [backendStatus, setBackendStatus] = useState({ online: false, url: '' });
  const [activeTab, setActiveTab] = useState('globe');
  const [searchQuery, setSearchQuery] = useState('');

  // Scenario Data
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
  const [correlating, setCorrelating] = useState(false);
  const [isResetToZero, setIsResetToZero] = useState(false);
  const [resetTimestamp, setResetTimestamp] = useState(null);
  const [activeSimulation, setActiveSimulation] = useState(null);

  const handleToggleResetStats = () => {
    setIsResetToZero(prev => {
      const next = !prev;
      if (next) {
        setResetTimestamp(Date.now());
      } else {
        setResetTimestamp(null);
      }
      setContainmentAlert({
        title: next ? 'Counters Reset to Zero (0)' : 'Scenario Baseline Restored',
        text: next ? 'All metrics reset to 0. Any new attack executed will start counting up and stream live.' : 'Full scenario baseline restored.'
      });
      setTimeout(() => setContainmentAlert(null), 4000);
      return next;
    });
  };

  // Theme - Defaults to pristine White Theme as requested
  const [theme, setTheme] = useState(() => localStorage.getItem('aegis_theme') || 'light');
  const isDark = theme === 'dark';

  useEffect(() => {
    document.documentElement.classList.toggle('dark', isDark);
    document.documentElement.classList.toggle('light', !isDark);
    localStorage.setItem('aegis_theme', theme);
  }, [theme, isDark]);

  // Init
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

  const loadScenarioData = async (scenarioId, silent = false) => {
    if (!silent) setLoading(true);
    setCorrelating(true);
    try {
      const [e, c, g, m, a, s] = await Promise.all([
        api.getEvents(scenarioId), api.getCorrelation(scenarioId),
        api.getAttackPath(scenarioId), api.getMitreData(scenarioId),
        api.getAiSummary(scenarioId), api.getAiQuerySuggestions(scenarioId)
      ]);
      const sortedEvents = (e || []).slice().sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
      setEvents(sortedEvents); setCorrelationData(c); setGraphData(g);
      setMitreData(m); setAiSummary(a); setQuerySuggestions(Array.isArray(s) ? s : []);
    } catch (err) { console.error(err); }
    finally {
      if (!silent) setLoading(false);
      setTimeout(() => setCorrelating(false), 800);
    }
  };

  useEffect(() => {
    if (activeScenarioId) {
      loadScenarioData(activeScenarioId);
    }
  }, [activeScenarioId]);

  // Real-time background sync interval for live telemetry
  useEffect(() => {
    if (!activeScenarioId) return;
    const interval = setInterval(() => {
      loadScenarioData(activeScenarioId, true);
    }, 3500);
    return () => clearInterval(interval);
  }, [activeScenarioId]);

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
      const newEventUuid = actionData.event_uuid || ('EVT-ATK-' + Math.random().toString(36).substring(2, 8).toUpperCase());
      const eventWithScenario = {
        scenario_id: activeScenarioId,
        event_uuid: newEventUuid,
        timestamp: actionData.timestamp || new Date().toISOString(),
        is_live_attack: true,
        ...actionData
      };

      // Optimistic instant UI update: prepend to events immediately so logs update with 0ms latency
      setEvents(prev => [eventWithScenario, ...prev.filter(e => e.event_uuid !== eventWithScenario.event_uuid)]);

      // Ingest into datastore / API
      await api.ingestEvent(eventWithScenario);

      // Re-correlate silently in background (keeps UI & Kali terminal fully intact)
      await loadScenarioData(activeScenarioId, true);

      if (actionData.is_simulation) {
        setActiveSimulation({
          event: eventWithScenario,
          step: actionData.simulation_step || 4,
          timestamp: Date.now()
        });
      }

      setContainmentAlert({
        title: 'Adversary Telemetry Ingested (Live)',
        text: `${eventWithScenario.mitre_technique_id || 'T1059'} — ${eventWithScenario.mitre_technique_name || eventWithScenario.domain?.toUpperCase() || 'ENDPOINT'} (Logged to CIM Telemetry & Live Stream)`
      });
      setTimeout(() => setContainmentAlert(null), 4000);
    } else if (actionData.type === 'containment') {
      setContainmentAlert({ title: 'EDR Quarantine Active', text: `Host isolation dispatched: ${actionData.host}` });
      setTimeout(() => setContainmentAlert(null), 5000);
    }
  };

  // Active events: when in "Reset to 0" mode, start counting fresh from 0!
  // Any event that occurred after resetTimestamp is included.
  const activeEvents = useMemo(() => {
    if (!isResetToZero) return events;
    if (!resetTimestamp) return [];
    return events.filter(e => {
      const t = new Date(e.timestamp).getTime();
      return !isNaN(t) && t >= resetTimestamp;
    });
  }, [events, isResetToZero, resetTimestamp]);

  const filteredEvents = useMemo(() => {
    return activeEvents.filter(evt => {
      if (!searchQuery) return true;
      const q = searchQuery.toLowerCase();
      return `${evt.event_uuid} ${evt.domain} ${evt.event_type} ${evt.severity} ${evt.source_host || ''} ${evt.dest_host || ''} ${evt.user_id || ''} ${evt.mitre_technique_id || ''}`.toLowerCase().includes(q);
    });
  }, [activeEvents, searchQuery]);

  const activeScenario = scenarios.find(s => s.scenario_id === activeScenarioId) || {
    scenario_id: activeScenarioId, name: 'Operation CloudSteal (Multi-Domain)',
    threat_actor: 'APT29 / Cozy Bear', description: 'Multi-domain intrusion...'
  };

  const severityCounts = {
    critical: activeEvents.filter(e => e.severity === 'critical').length,
    high: activeEvents.filter(e => e.severity === 'high').length,
  };

  // Telemetry breakdown stats
  const totalEvents = Math.max(activeEvents.length, isResetToZero ? 0 : 1);
  const telemetryBreakdown = [
    { 
      label: 'Endpoint Telemetry',    
      value: activeEvents.filter(e => e.domain === 'endpoint').length || (isResetToZero ? 0 : Math.round(totalEvents * 0.55)), 
      pct: totalEvents > 0 ? Math.round(((activeEvents.filter(e => e.domain === 'endpoint').length || (isResetToZero ? 0 : Math.round(totalEvents * 0.55))) / totalEvents) * 100) : 0, 
      color: '#0284C7' 
    },
    { 
      label: 'Network Flows (Zeek)',  
      value: activeEvents.filter(e => e.domain === 'network').length || (isResetToZero ? 0 : Math.round(totalEvents * 0.25)), 
      pct: totalEvents > 0 ? Math.round(((activeEvents.filter(e => e.domain === 'network').length || (isResetToZero ? 0 : Math.round(totalEvents * 0.25))) / totalEvents) * 100) : 0, 
      color: '#7C3AED' 
    },
    { 
      label: 'Cloud Infrastructure',  
      value: activeEvents.filter(e => e.domain === 'cloud').length || (isResetToZero ? 0 : Math.round(totalEvents * 0.15)), 
      pct: totalEvents > 0 ? Math.round(((activeEvents.filter(e => e.domain === 'cloud').length || (isResetToZero ? 0 : Math.round(totalEvents * 0.15))) / totalEvents) * 100) : 0, 
      color: '#DB2777' 
    },
    { 
      label: 'Active Directory Auth', 
      value: activeEvents.filter(e => e.domain === 'auth').length || (isResetToZero ? 0 : Math.round(totalEvents * 0.10)), 
      pct: totalEvents > 0 ? Math.round(((activeEvents.filter(e => e.domain === 'auth').length || (isResetToZero ? 0 : Math.round(totalEvents * 0.10))) / totalEvents) * 100) : 0, 
      color: '#059669' 
    },
  ];

  return (
    <div className={`h-screen flex flex-col overflow-hidden font-sans antialiased select-none transition-colors duration-200 ${
      isDark ? 'bg-[#07070F] text-white' : 'bg-slate-100 text-slate-900'
    }`}>

      {/* ══ STATUS BAR ════════════════════════════════════════════════════════ */}
      <div className={`h-7 flex items-center px-5 gap-6 text-[10px] font-mono shrink-0 border-b backdrop-blur-md transition-colors ${
        isDark
          ? 'bg-black/80 border-purple-900/30 text-slate-300'
          : 'bg-white/95 border-slate-200/90 text-slate-700 shadow-xs'
      }`}>
        <div className="flex items-center gap-2">
          <span className="relative flex h-2 w-2">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75" />
            <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500" />
          </span>
          <span className="text-emerald-600 dark:text-emerald-400 font-bold tracking-widest">DEFCON 2: ELEVATED THREAT HUNTING</span>
        </div>
        <span className={isDark ? 'text-purple-800' : 'text-slate-300'}>|</span>
        <div className="flex items-center gap-2">
          <span className="relative flex h-2 w-2">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyan-400 opacity-75" />
            <span className="relative inline-flex rounded-full h-2 w-2 bg-cyan-500" />
          </span>
          <span className="text-cyan-600 dark:text-cyan-400 font-semibold tracking-widest">CIM NORMALIZATION: ACTIVE</span>
        </div>

        <div className="ml-auto flex items-center gap-4">
          <button
            onClick={() => setTheme(t => t === 'dark' ? 'light' : 'dark')}
            className={`flex items-center gap-1.5 px-2 py-0.5 rounded transition ${
              isDark
                ? 'text-slate-400 hover:text-slate-100 hover:bg-white/5'
                : 'text-slate-700 hover:text-slate-900 hover:bg-slate-100 font-medium'
            }`}
            title="Toggle White / Dark Theme"
          >
            {isDark ? <Sun className="w-3.5 h-3.5 text-amber-400" /> : <Moon className="w-3.5 h-3.5 text-indigo-600" />}
            <span className="font-sans font-semibold">{isDark ? 'Dark Theme' : 'White Theme'}</span>
          </button>
          <span className={isDark ? 'text-purple-800' : 'text-slate-300'}>|</span>
          <div className="flex items-center gap-1.5 text-emerald-600 dark:text-emerald-400 font-medium">
            <Database className="w-3 h-3" />
            <span>DB: Dual-Engine (SQLite)</span>
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />
          </div>
          <span className={isDark ? 'text-purple-800' : 'text-slate-300'}>|</span>
          <span className={isDark ? 'text-slate-500' : 'text-slate-500 font-medium'}>Node 22 &amp; React 19</span>
        </div>
      </div>

      <div className="flex flex-1 overflow-hidden">

        {/* ══ LEFT ICON SIDEBAR ══════════════════════════════════════════════ */}
        <aside className={`w-14 flex flex-col items-center pt-4 pb-4 gap-1 shrink-0 z-30 transition-colors ${
          isDark
            ? 'bg-[#09091A] border-r border-purple-900/20'
            : 'bg-white border-r border-slate-200/90 shadow-xs'
        }`}>
          {/* Logo */}
          <div className="w-9 h-9 rounded-xl bg-gradient-to-br from-indigo-600 to-purple-600 flex items-center justify-center shadow-md mb-4 shrink-0 border border-purple-400/30">
            <ShieldCheck className="w-5 h-5 text-white" />
          </div>

          {/* Nav icons */}
          {SIDEBAR_ICONS.map(({ id, Icon, tooltip }) => (
            <button
              key={id}
              onClick={() => id !== 'settings' && setActiveTab(id)}
              title={tooltip}
              className={`w-9 h-9 rounded-xl flex items-center justify-center transition-all group relative ${
                activeTab === id
                  ? isDark
                    ? 'bg-purple-600/30 text-purple-300 border border-purple-500/50 shadow-md shadow-purple-900/40'
                    : 'bg-purple-100 text-purple-700 border border-purple-300 shadow-xs font-bold'
                  : isDark
                    ? 'text-slate-600 hover:text-slate-300 hover:bg-white/5 border border-transparent'
                    : 'text-slate-400 hover:text-slate-800 hover:bg-slate-100 border border-transparent'
              }`}
            >
              <Icon className="w-4 h-4" />
              {/* Tooltip */}
              <span className={`absolute left-12 text-[10px] px-2 py-1 rounded-md whitespace-nowrap opacity-0 group-hover:opacity-100 pointer-events-none transition-opacity z-50 font-mono shadow-md ${
                isDark
                  ? 'bg-[#1A1A3A] text-white border border-purple-900/50'
                  : 'bg-slate-900 text-white border border-slate-700'
              }`}>
                {tooltip}
              </span>
            </button>
          ))}

          <div className="mt-auto space-y-1">
            <button
              title="Ingest Telemetry"
              onClick={() => setShowIngestModal(true)}
              className={`w-9 h-9 rounded-xl flex items-center justify-center transition border border-transparent ${
                isDark
                  ? 'text-slate-500 hover:text-cyan-400 hover:bg-cyan-900/20 hover:border-cyan-900/40'
                  : 'text-slate-500 hover:text-cyan-700 hover:bg-cyan-50 hover:border-cyan-200'
              }`}
            >
              <Flame className="w-4 h-4 text-amber-500" />
            </button>
            <button
              title="Export Report"
              onClick={() => setShowReportModal(true)}
              className={`w-9 h-9 rounded-xl flex items-center justify-center transition border border-transparent ${
                isDark
                  ? 'text-slate-500 hover:text-purple-400 hover:bg-purple-900/20 hover:border-purple-900/40'
                  : 'text-slate-500 hover:text-purple-700 hover:bg-purple-50 hover:border-purple-200'
              }`}
            >
              <FileText className="w-4 h-4 text-purple-600" />
            </button>
          </div>
        </aside>

        {/* ══ MAIN CONTENT AREA ══════════════════════════════════════════════ */}
        <div className="flex-1 flex flex-col overflow-hidden">

          {/* ── HEADER BAR ───────────────────────────────────────────────── */}
          <header className={`h-14 flex items-center px-5 gap-5 shrink-0 transition-colors ${
            isDark
              ? 'bg-[#0B0B1E] border-b border-purple-900/25'
              : 'bg-white border-b border-slate-200/90 shadow-xs'
          }`}>

            {/* Logo & Brand: Sh4d0w_Br0k3rs */}
            <div className="flex items-center gap-2.5 shrink-0">
              <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-purple-600 to-indigo-700 flex items-center justify-center shadow-md border border-purple-400/30">
                <Shield className="w-4 h-4 text-white" />
              </div>
              <div>
                <div className="flex items-center gap-1.5">
                  <span className={`font-black text-base tracking-wide font-mono ${
                    isDark ? 'text-white' : 'text-slate-900'
                  }`}>
                    Sh4d0w_Br0k3rs
                  </span>
                  <span className="px-1.5 py-0.5 text-[9px] font-bold bg-purple-600/10 border border-purple-500/40 rounded text-purple-600 dark:text-purple-300 font-mono">
                    AI-SOC
                  </span>
                </div>
                <div className={`text-[9px] font-mono leading-none ${isDark ? 'text-slate-500' : 'text-slate-500'}`}>
                  AI-Assisted Cyber Threat Hunting Platform
                </div>
              </div>
            </div>

            {/* Scenario Selector */}
            <div className={`flex items-center gap-2 rounded-lg px-3 py-1.5 ml-4 transition ${
              isDark
                ? 'bg-white/[0.04] border border-white/[0.08]'
                : 'bg-slate-100 border border-slate-200 hover:bg-slate-200/50'
            }`}>
              <span className={`text-[10px] font-mono shrink-0 ${isDark ? 'text-slate-500' : 'text-slate-500 font-semibold'}`}>
                Scenario:
              </span>
              <select
                value={activeScenarioId}
                onChange={e => setActiveScenarioId(e.target.value)}
                className={`bg-transparent text-xs font-semibold focus:outline-none cursor-pointer truncate max-w-[210px] ${
                  isDark ? 'text-purple-300' : 'text-purple-900'
                }`}
              >
                {scenarios.map(s => (
                  <option key={s.scenario_id} value={s.scenario_id} className={isDark ? 'bg-[#0D0D1E] text-white' : 'bg-white text-slate-900'}>
                    {s.name}
                  </option>
                ))}
                <option value="SCN-APT29-GHOST" className={isDark ? 'bg-[#0D0D1E] text-white' : 'bg-white text-slate-900'}>
                  Operation CloudSteal (Multi-Domain)
                </option>
              </select>
              <ChevronDown className={`w-3 h-3 shrink-0 ${isDark ? 'text-slate-500' : 'text-slate-500'}`} />
            </div>

            {/* IOC Search */}
            <div className="flex-1 max-w-sm mx-2">
              <div className="relative">
                <Search className={`absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 ${isDark ? 'text-slate-600' : 'text-slate-400'}`} />
                <input
                  value={searchQuery}
                  onChange={e => setSearchQuery(e.target.value)}
                  placeholder="Search IOCs, hashes, IPs, TTPs..."
                  className={`w-full pl-8 pr-4 py-1.5 rounded-lg text-xs font-mono transition focus:outline-none ${
                    isDark
                      ? 'bg-white/[0.04] border border-white/[0.07] text-slate-300 placeholder-slate-600 focus:border-purple-500/50'
                      : 'bg-slate-100 border border-slate-200 text-slate-800 placeholder-slate-400 focus:bg-white focus:border-purple-500'
                  }`}
                />
              </div>
            </div>

            {/* Right side controls */}
            <div className="ml-auto flex items-center gap-2 shrink-0">
              {/* Severity badges */}
              {severityCounts.critical > 0 && (
                <span className="px-2 py-1 rounded-md bg-red-100 dark:bg-red-900/40 border border-red-300 dark:border-red-500/40 text-red-700 dark:text-red-400 text-[10px] font-mono font-bold animate-pulse">
                  {severityCounts.critical} CRIT
                </span>
              )}
              {severityCounts.high > 0 && (
                <span className="px-2 py-1 rounded-md bg-amber-100 dark:bg-orange-900/40 border border-amber-300 dark:border-orange-500/40 text-amber-800 dark:text-orange-400 text-[10px] font-mono font-bold">
                  {severityCounts.high} HIGH
                </span>
              )}

              {/* Reset to Zero Button */}
              <button
                onClick={handleToggleResetStats}
                title={isResetToZero ? "Restore Baseline Statistics" : "Reset all statistics to zero (0)"}
                className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition shadow-xs ${
                  isResetToZero
                    ? 'bg-emerald-600 hover:bg-emerald-700 text-white font-bold animate-pulse'
                    : isDark
                      ? 'bg-red-500/10 border border-red-500/30 hover:bg-red-500/25 text-red-400'
                      : 'bg-red-50 border border-red-200 hover:bg-red-100 text-red-700'
                }`}
              >
                <RotateCcw className="w-3.5 h-3.5" />
                {isResetToZero ? 'Restore Stats' : 'Reset to 0'}
              </button>

              {isResetToZero && activeEvents.length > 0 && (
                <button
                  onClick={() => {
                    setResetTimestamp(Date.now());
                    setContainmentAlert({
                      title: 'Live Telemetry Cleared to 0',
                      text: 'Attack counters reset to 0.'
                    });
                    setTimeout(() => setContainmentAlert(null), 4000);
                  }}
                  title="Clear live attack counter back to 0"
                  className="flex items-center gap-1 px-2.5 py-1.5 rounded-lg text-xs font-mono font-bold bg-amber-500/10 text-amber-600 dark:text-amber-400 border border-amber-500/30 hover:bg-amber-500/20 transition"
                >
                  <Trash2 className="w-3.5 h-3.5" />
                  Clear to 0
                </button>
              )}

              {/* Ingest Telemetry button */}
              <button
                onClick={() => setShowIngestModal(true)}
                className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition ${
                  isDark
                    ? 'bg-purple-600/20 border border-purple-500/40 hover:bg-purple-600/35 text-purple-300'
                    : 'bg-purple-600 hover:bg-purple-700 text-white shadow-xs font-semibold'
                }`}
              >
                <Flame className="w-3.5 h-3.5" />
                Ingest Telemetry
              </button>

              {/* Correlating indicator */}
              <button
                onClick={() => loadScenarioData(activeScenarioId)}
                className={`flex items-center gap-1.5 px-3 py-1.5 border rounded-lg text-xs font-semibold transition ${
                  correlating
                    ? isDark
                      ? 'bg-cyan-900/30 border-cyan-500/40 text-cyan-300 animate-pulse'
                      : 'bg-cyan-50 border-cyan-300 text-cyan-700 animate-pulse'
                    : isDark
                      ? 'bg-white/[0.04] border-white/[0.08] text-slate-400 hover:text-slate-200'
                      : 'bg-slate-100 border-slate-200 text-slate-700 hover:bg-slate-200/60'
                }`}
              >
                <span className={`w-1.5 h-1.5 rounded-full ${correlating ? 'bg-cyan-500 animate-ping' : 'bg-slate-400'}`} />
                {correlating ? 'Correlating...' : 'Idle'}
              </button>

              {/* Avatar */}
              <div className={`flex items-center gap-2 pl-2 ml-1 ${isDark ? 'border-l border-purple-900/30' : 'border-l border-slate-200'}`}>
                <div className="w-7 h-7 rounded-full bg-gradient-to-br from-purple-600 to-indigo-700 flex items-center justify-center text-white text-[10px] font-bold border border-purple-400/30 shadow-xs">
                  NH
                </div>
                <div className="hidden md:block text-left">
                  <div className={`text-xs font-bold leading-tight ${isDark ? 'text-slate-200' : 'text-slate-800'}`}>Noor Hassan</div>
                  <div className={`text-[9px] font-mono ${isDark ? 'text-slate-500' : 'text-slate-500 font-medium'}`}>L2 Sr. Hunter</div>
                </div>
              </div>
            </div>
          </header>

          {/* ── TAB NAVIGATION BAR ───────────────────────────────────────── */}
          <nav className={`flex px-4 overflow-x-auto shrink-0 scrollbar-none transition-colors ${
            isDark
              ? 'bg-[#0B0B1E] border-b border-purple-900/20'
              : 'bg-white border-b border-slate-200 shadow-xs'
          }`}>
            {TABS.map(tab => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`flex items-center gap-2 px-4 py-3 text-xs font-semibold whitespace-nowrap border-b-2 transition-all ${
                  activeTab === tab.id
                    ? isDark
                      ? 'border-purple-500 text-purple-300 bg-purple-500/5'
                      : 'border-purple-600 text-purple-700 bg-purple-50/80 font-bold'
                    : isDark
                      ? 'border-transparent text-slate-500 hover:text-slate-300 hover:bg-white/[0.03]'
                      : 'border-transparent text-slate-600 hover:text-slate-900 hover:bg-slate-100/70'
                }`}
              >
                <tab.icon className="w-3.5 h-3.5" />
                {tab.label}
                {tab.dot && (
                  <span className="w-1.5 h-1.5 rounded-full bg-purple-600 dark:bg-purple-400 animate-pulse" />
                )}
              </button>
            ))}
          </nav>

          {/* ── MAIN CONTENT VIEWPORT ────────────────────────────────────── */}
          <main className={`flex-1 overflow-y-auto transition-colors ${
            isDark ? 'bg-[#07070F]' : 'bg-slate-100/70'
          }`}>

            {/* Toast */}
            {containmentAlert && (
              <div className={`fixed top-24 right-6 z-50 rounded-xl p-4 shadow-2xl flex items-center gap-3 max-w-sm animate-pulse border-2 ${
                isDark
                  ? 'bg-[#0F0F25] border-emerald-500/60 shadow-emerald-900/40'
                  : 'bg-white border-emerald-500 shadow-emerald-500/20'
              }`}>
                <div className="p-2 rounded-lg bg-emerald-100 dark:bg-emerald-900/50 text-emerald-600 dark:text-emerald-400">
                  <CheckCircle2 className="w-5 h-5" />
                </div>
                <div>
                  <div className={`text-xs font-bold uppercase font-mono ${isDark ? 'text-white' : 'text-slate-900'}`}>{containmentAlert.title}</div>
                  <div className={`text-xs ${isDark ? 'text-slate-400' : 'text-slate-600'}`}>{containmentAlert.text}</div>
                </div>
              </div>
            )}

            {loading ? (
              <div className="flex flex-col items-center justify-center h-full gap-4 text-slate-500">
                <div className="w-8 h-8 border-2 border-purple-600 border-t-transparent rounded-full animate-spin" />
                <span className="text-sm font-mono font-medium">Correlating telemetry across data sources...</span>
              </div>
            ) : (
              <div className="p-6 max-w-[1800px] mx-auto">

                {/* ══ OVERVIEW & GLOBE ══════════════════════════════════════ */}
                {activeTab === 'globe' && (
                  <div className="space-y-5">
                    {/* Top KPI bar */}
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                      {[
                        { 
                          label: 'Correlated Events', 
                          value: isResetToZero ? activeEvents.length.toLocaleString() : events.length.toLocaleString(), 
                          icon: Activity, 
                          color: '#0284C7', 
                          trend: isResetToZero ? (activeEvents.length > 0 ? `+${activeEvents.length}` : null) : '+14%' 
                        },
                        { 
                          label: 'Critical Alerts', 
                          value: severityCounts.critical, 
                          icon: AlertTriangle, 
                          color: '#DC2626' 
                        },
                        { 
                          label: 'High Severity', 
                          value: severityCounts.high, 
                          icon: Zap, 
                          color: '#D97706' 
                        },
                        { 
                          label: 'Kill Chain Coverage', 
                          value: isResetToZero ? (activeEvents.length > 0 ? `${Math.min(100, activeEvents.length * 20)}%` : '0%') : '86%', 
                          icon: Crosshair, 
                          color: '#059669', 
                          trend: isResetToZero ? null : '+3%' 
                        },
                      ].map(stat => (
                        <div key={stat.label} className={`rounded-xl p-4 flex items-center gap-4 transition group ${
                          isDark
                            ? 'bg-white/[0.03] border border-white/[0.06] hover:border-purple-500/20'
                            : 'bg-white border border-slate-200/90 shadow-xs hover:shadow-md hover:border-purple-300'
                        }`}>
                          <div className={`p-2.5 rounded-lg transition ${
                            isDark
                              ? 'bg-white/[0.04] border border-white/[0.05] group-hover:border-purple-500/20'
                              : 'bg-slate-50 border border-slate-100 group-hover:bg-purple-50'
                          }`}>
                            <stat.icon className="w-5 h-5" style={{ color: stat.color }} />
                          </div>
                          <div>
                            {stat.trend && (
                              <div className="flex items-center gap-1 text-[9px] text-emerald-600 dark:text-emerald-400 font-semibold mb-0.5">
                                <ArrowUpRight className="w-2.5 h-2.5" />{stat.trend}
                              </div>
                            )}
                            <div className="text-xl font-mono font-bold" style={{ color: stat.color }}>{stat.value}</div>
                            <div className={`text-[10px] ${isDark ? 'text-slate-500' : 'text-slate-500 font-medium'}`}>{stat.label}</div>
                          </div>
                        </div>
                      ))}
                    </div>

                    {/* Main Globe + Stats */}
                    <div className="grid grid-cols-1 xl:grid-cols-5 gap-5">

                      {/* Left: Telemetry Stats */}
                      <div className="xl:col-span-2 space-y-4">
                        <div className={`rounded-2xl p-5 ${
                          isDark
                            ? 'bg-white/[0.03] border border-white/[0.06]'
                            : 'bg-white border border-slate-200/90 shadow-xs'
                        }`}>
                          {/* Header */}
                          <div className="flex items-center justify-between mb-5">
                            <div>
                              <div className={`text-[10px] font-mono tracking-widest uppercase ${
                                isDark ? 'text-slate-500' : 'text-slate-500 font-semibold'
                              }`}>
                                General statistics
                              </div>
                              <button className={`text-[10px] font-mono flex items-center gap-1 mt-0.5 transition ${
                                isDark ? 'text-cyan-400 hover:text-cyan-300' : 'text-cyan-700 hover:text-cyan-800 font-semibold'
                              }`}>
                                ALL TELEMETRY DETAIL <ArrowRight className="w-3 h-3" />
                              </button>
                            </div>
                            <div className="flex items-center gap-2">
                              <button
                                onClick={handleToggleResetStats}
                                title={isResetToZero ? "Restore Baseline Statistics" : "Reset statistics to zero"}
                                className={`text-[10px] font-mono flex items-center gap-1.5 px-2.5 py-1 rounded-lg border font-semibold transition ${
                                  isResetToZero
                                    ? 'bg-emerald-50 dark:bg-emerald-950/40 border-emerald-300 text-emerald-700 dark:text-emerald-400'
                                    : 'bg-slate-100 dark:bg-white/5 border-slate-200 dark:border-white/10 text-slate-700 dark:text-slate-300 hover:bg-red-50 hover:text-red-700 hover:border-red-200'
                                }`}
                              >
                                <RotateCcw className="w-3 h-3" />
                                {isResetToZero ? 'Restore' : 'Reset to 0'}
                              </button>
                              <div className={`flex items-center gap-1.5 text-[10px] font-mono rounded-lg px-2.5 py-1 ${
                                isResetToZero
                                  ? activeEvents.length > 0
                                    ? 'text-purple-600 bg-purple-50 dark:bg-purple-950/40 border border-purple-200 dark:border-purple-800 font-semibold'
                                    : 'text-amber-700 bg-amber-50 dark:bg-amber-950/40 border border-amber-200 dark:border-amber-800 font-semibold'
                                  : isDark
                                    ? 'text-emerald-400 bg-emerald-900/20 border border-emerald-900/40'
                                    : 'text-emerald-700 bg-emerald-50 border border-emerald-200 font-semibold'
                              }`}>
                                <span className={`w-1.5 h-1.5 rounded-full ${isResetToZero ? (activeEvents.length > 0 ? 'bg-purple-500 animate-pulse' : 'bg-amber-500') : 'bg-emerald-500 animate-pulse'}`} />
                                {isResetToZero ? (activeEvents.length > 0 ? `LIVE (${activeEvents.length} ATK)` : 'CLEARED (0)') : 'LIVE'}
                              </div>
                            </div>
                          </div>

                          {/* Big number */}
                          <div className="mb-1">
                            <div className={`text-5xl font-black font-mono tracking-tighter ${
                              isDark ? 'text-white' : 'text-slate-900'
                            }`}>
                              {isResetToZero ? (activeEvents.length > 0 ? activeEvents.length.toLocaleString() : '0') : (events.length * 487 + 4951485).toLocaleString()}
                            </div>
                          </div>
                          <div className={`text-[11px] font-mono uppercase tracking-widest mb-5 ${
                            isDark ? 'text-slate-500' : 'text-slate-500 font-semibold'
                          }`}>
                            CURRENT TELEMETRY ACTIVITY
                          </div>

                          {/* Breakdown */}
                          <div className="space-y-1">
                            {telemetryBreakdown.map(t => (
                              <TelemetryBar key={t.label} {...t} isDark={isDark} />
                            ))}
                          </div>
                        </div>

                        {/* Metric cards row */}
                        <div className="flex gap-3">
                          <MetricCard
                            label="Telemetry Velocity"
                            value={isResetToZero ? (activeEvents.length > 0 ? "1.2 ms" : "0.0 ms") : "18.4 ms"}
                            sub="Avg correlation latency"
                            trend={isResetToZero ? (activeEvents.length > 0 ? `+${activeEvents.length}` : null) : "+14%"}
                            color="#0284C7"
                            isDark={isDark}
                          />
                          <MetricCard
                            label="Incident Trend"
                            value={isResetToZero ? activeEvents.length.toLocaleString() : "92,980"}
                            sub="Compared to baseline"
                            color="#DB2777"
                            isDark={isDark}
                          />
                        </div>
                        <div className="flex gap-3">
                          <MetricCard
                            label="Total Coverage"
                            value={isResetToZero ? (activeEvents.length > 0 ? `${Math.min(100, activeEvents.length * 15)}%` : "0%") : "53,430,001"}
                            sub="Verified threat vectors"
                            color="#7C3AED"
                            isDark={isDark}
                          />
                          <div className={`rounded-xl p-4 flex-1 min-w-0 flex flex-col items-center justify-center ${
                            isDark
                              ? 'bg-white/[0.03] border border-white/[0.06]'
                              : 'bg-white border border-slate-200/90 shadow-xs'
                          }`}>
                            <div className={`text-[10px] uppercase font-mono tracking-widest mb-2 ${
                              isDark ? 'text-slate-500' : 'text-slate-500 font-semibold'
                            }`}>
                              Coverage
                            </div>
                            <div className="relative w-16 h-16">
                              <svg viewBox="0 0 36 36" className="w-full h-full -rotate-90">
                                <circle cx="18" cy="18" r="15" fill="none" stroke={isDark ? "rgba(255,255,255,0.05)" : "#E2E8F0"} strokeWidth="3" />
                                <circle cx="18" cy="18" r="15" fill="none" stroke="#7C3AED" strokeWidth="3"
                                  strokeDasharray={isResetToZero ? (activeEvents.length > 0 ? `${Math.min(100, activeEvents.length * 20) * 94.2 / 100} 94.2` : "0 94.2") : `${23 * 94.2 / 100} 94.2`} strokeLinecap="round" />
                              </svg>
                              <div className={`absolute inset-0 flex items-center justify-center text-sm font-bold font-mono ${
                                isDark ? 'text-purple-300' : 'text-purple-700'
                              }`}>
                                {isResetToZero ? (activeEvents.length > 0 ? `${Math.min(100, activeEvents.length * 20)}%` : '0%') : '23%'}
                              </div>
                            </div>
                            <div className="text-[9px] text-emerald-600 dark:text-emerald-400 mt-1 font-mono font-semibold">● Verified</div>
                          </div>
                        </div>

                        {/* Active scenario info */}
                        {correlationData && (
                          <div className={`rounded-2xl p-4 border ${
                            isDark
                              ? 'bg-gradient-to-br from-purple-900/20 to-indigo-900/10 border-purple-500/20'
                              : 'bg-gradient-to-br from-purple-50 to-indigo-50/50 border-purple-200/90 shadow-xs'
                          }`}>
                            <div className="flex items-center gap-2 mb-2">
                              <span className="px-2 py-0.5 rounded text-[9px] font-mono font-bold bg-red-600 text-white shadow-xs">
                                THREAT LEVEL: CRITICAL
                              </span>
                              <span className={`text-[10px] font-mono ${isDark ? 'text-purple-400' : 'text-purple-700 font-semibold'}`}>
                                ID: {activeScenarioId}
                              </span>
                            </div>
                            <div className={`text-sm font-bold mb-1 leading-tight ${isDark ? 'text-white' : 'text-slate-900'}`}>
                              {correlationData.incident_title || activeScenario.name}
                            </div>
                            <div className={`text-[11px] mb-3 ${isDark ? 'text-slate-400' : 'text-slate-600'}`}>
                              {correlationData.correlation_summary?.substring(0, 120) || 'Multi-domain intrusion correlation active...'}
                            </div>
                            <div className="flex items-center justify-between text-[10px] font-mono">
                              <span className={isDark ? 'text-slate-500' : 'text-slate-500 font-semibold'}>Confidence</span>
                              <div className="flex items-center gap-2">
                                <div className={`w-20 rounded-full h-1.5 ${isDark ? 'bg-white/5' : 'bg-slate-200'}`}>
                                  <div className="h-1.5 rounded-full bg-gradient-to-r from-purple-600 to-cyan-500"
                                    style={{ width: `${(correlationData.confidence_score || 0.98) * 100}%` }} />
                                </div>
                                <span className={`font-bold ${isDark ? 'text-cyan-400' : 'text-cyan-700'}`}>
                                  {Math.round((correlationData.confidence_score || 0.98) * 100)}%
                                </span>
                              </div>
                            </div>
                          </div>
                        )}
                      </div>

                      {/* Right: Globe Card */}
                      <div className={`xl:col-span-3 rounded-2xl flex items-center justify-center p-4 min-h-[480px] relative overflow-hidden ${
                        isDark
                          ? 'bg-white/[0.02] border border-white/[0.05]'
                          : 'bg-white border border-slate-200/90 shadow-xs'
                      }`}>
                        {/* Background glow */}
                        <div className={`absolute inset-0 pointer-events-none ${
                          isDark
                            ? 'bg-gradient-radial from-purple-900/10 via-transparent to-transparent'
                            : 'bg-gradient-radial from-purple-100/40 via-transparent to-transparent'
                        }`} />
                        <div className={`absolute top-0 right-0 w-64 h-64 rounded-full blur-3xl pointer-events-none ${
                          isDark ? 'bg-purple-600/5' : 'bg-purple-200/30'
                        }`} />
                        <div className={`absolute bottom-0 left-0 w-48 h-48 rounded-full blur-3xl pointer-events-none ${
                          isDark ? 'bg-cyan-600/5' : 'bg-cyan-200/30'
                        }`} />

                        <div className="relative z-10 flex flex-col items-center">
                          <div className={`text-[10px] font-mono uppercase tracking-widest mb-3 ${
                            isDark ? 'text-slate-500' : 'text-slate-500 font-semibold'
                          }`}>
                            Global Threat Origin Map
                          </div>
                          <GlobeVisualization width={360} height={360} events={events} theme={theme} />
                          <div className="flex items-center gap-6 mt-3 text-[10px] font-mono">
                            <div className="flex items-center gap-1.5">
                              <span className="w-2.5 h-2.5 rounded-full bg-[#FF1493]" />
                              <span className={isDark ? 'text-slate-400' : 'text-slate-600 font-medium'}>Attack Origin</span>
                            </div>
                            <div className="flex items-center gap-1.5">
                              <span className="w-2.5 h-2.5 rounded-full bg-[#10B981]" />
                              <span className={isDark ? 'text-slate-400' : 'text-slate-600 font-medium'}>Exfil Target</span>
                            </div>
                            <div className="flex items-center gap-1.5">
                              <span className="w-2.5 h-2.5 rounded-full bg-[#00D4FF]" />
                              <span className={isDark ? 'text-slate-400' : 'text-slate-600 font-medium'}>Pivot Node</span>
                            </div>
                          </div>
                        </div>
                      </div>
                    </div>

                    {/* Live telemetry feed */}
                    <div className={`rounded-2xl p-5 ${
                      isDark
                        ? 'bg-white/[0.02] border border-white/[0.05]'
                        : 'bg-white border border-slate-200/90 shadow-xs'
                    }`}>
                      <div className="flex items-center justify-between mb-4">
                        <div className="flex items-center gap-2">
                          <Radio className="w-4 h-4 text-cyan-600 dark:text-cyan-400 animate-pulse" />
                          <h2 className={`text-sm font-bold ${isDark ? 'text-slate-200' : 'text-slate-800'}`}>
                            Live Correlated Event Stream
                          </h2>
                          <span className={`px-2 py-0.5 rounded-full text-[9px] font-mono font-semibold ${
                            isDark
                              ? 'bg-cyan-900/30 border border-cyan-900/50 text-cyan-400'
                              : 'bg-cyan-50 border border-cyan-200 text-cyan-700'
                          }`}>
                            REAL-TIME
                          </span>
                        </div>
                        <div className="flex items-center gap-3">
                          <button
                            onClick={() => setActiveTab('discover')}
                            className="text-[11px] font-mono text-purple-600 dark:text-cyan-400 hover:underline flex items-center gap-1 font-bold"
                          >
                            Open in CIM Telemetry (All Logs) &rarr;
                          </button>
                          <span className={`text-[10px] font-mono ${isDark ? 'text-slate-500' : 'text-slate-500 font-medium'}`}>
                            {activeEvents.length} security events correlated
                          </span>
                        </div>
                      </div>
                      <div className="space-y-1.5 max-h-64 overflow-y-auto pr-1">
                        {isResetToZero && activeEvents.length === 0 ? (
                          <div className="py-8 text-center text-slate-400 font-mono text-xs flex flex-col items-center justify-center gap-2">
                            <div className="w-8 h-8 rounded-full bg-slate-100 dark:bg-white/5 flex items-center justify-center text-slate-400">
                              <CheckCircle2 className="w-4 h-4 text-emerald-500" />
                            </div>
                            <span className="font-semibold text-slate-700 dark:text-slate-300">All Statistics and Telemetry Cleared to 0</span>
                            <span className="text-[11px] text-slate-500">Go to the &ldquo;Attack Sequences&rdquo; tab to launch attacks, and live telemetry will stream here starting from 0.</span>
                          </div>
                        ) : (
                          activeEvents.slice(0, 40).map(evt => {
                            const isLiveAttack = evt.event_uuid?.startsWith('EVT-ATK') || evt.event_uuid?.startsWith('EVT-PBK') || evt.event_uuid?.startsWith('EVT-CLI') || evt.event_uuid?.startsWith('EVT-ING');
                            return (
                              <button
                                key={evt.event_uuid}
                                onClick={() => handleSelectEvent(evt.event_uuid)}
                                className={`w-full flex items-center gap-3 px-3 py-2 rounded-lg text-left transition group ${
                                  isLiveAttack
                                    ? isDark
                                      ? 'bg-purple-950/40 border border-purple-500/50 hover:bg-purple-900/50 shadow-sm'
                                      : 'bg-purple-50 border border-purple-300 hover:bg-purple-100 shadow-sm'
                                    : isDark
                                      ? 'hover:bg-white/[0.04]'
                                      : 'hover:bg-slate-50 border-b border-slate-100/70'
                                }`}
                              >
                                <span className={`w-2 h-2 rounded-full shrink-0 ${
                                  evt.severity === 'critical' ? 'bg-red-500 animate-pulse' :
                                  evt.severity === 'high' ? 'bg-orange-500' :
                                  evt.severity === 'medium' ? 'bg-amber-500' : 'bg-blue-500'
                                }`} />
                                <span className={`text-[10px] font-mono w-28 shrink-0 truncate ${
                                  isDark ? 'text-slate-400' : 'text-slate-600'
                                }`}>
                                  {new Date(evt.timestamp).toLocaleTimeString()}
                                </span>
                                {isLiveAttack && (
                                  <span className="px-1.5 py-0.2 rounded text-[8px] font-mono font-bold bg-purple-600 text-white animate-pulse shrink-0">
                                    LIVE ATTACK
                                  </span>
                                )}
                                <span className={`text-[9px] font-mono font-bold w-14 shrink-0 uppercase ${
                                  evt.severity === 'critical' ? 'text-red-500 dark:text-red-400' :
                                  evt.severity === 'high' ? 'text-orange-500 dark:text-orange-400' :
                                  evt.severity === 'medium' ? 'text-amber-500 dark:text-amber-400' : 'text-blue-500 dark:text-blue-400'
                                }`}>
                                  {evt.severity}
                                </span>
                                <span className={`text-xs truncate flex-1 font-mono font-medium ${
                                  isDark ? 'text-slate-200' : 'text-slate-800'
                                }`}>
                                  {evt.mitre_technique_id ? `[${evt.mitre_technique_id}] ` : ''}{evt.event_type}
                                </span>
                                <span className={`text-[10px] font-mono truncate max-w-[140px] ${
                                  isDark ? 'text-cyan-400' : 'text-cyan-700 font-semibold'
                                }`}>
                                  {evt.source_host || evt.source_ip || ''} &rarr; {evt.dest_host || evt.dest_ip || 'target'}
                                </span>
                                <Eye className={`w-3.5 h-3.5 shrink-0 transition ${
                                  isDark
                                    ? 'text-slate-600 group-hover:text-purple-400'
                                    : 'text-slate-400 group-hover:text-purple-600'
                                }`} />
                              </button>
                            );
                          })
                        )}
                      </div>
                    </div>
                  </div>
                )}

                {/* ══ ATTACK PATH VISUALIZER ════════════════════════════════ */}
                {activeTab === 'graph' && (
                  <div className="space-y-5">
                    <div id="cisco-canvas-container" className={`rounded-2xl p-5 ${
                      isDark ? 'bg-white/[0.02] border border-white/[0.05]' : 'bg-white border border-slate-200/90 shadow-xs'
                    }`}>
                      <AttackPathGraph 
                        graphData={graphData} 
                        activeSimulation={activeSimulation}
                        onSelectEvent={handleSelectEvent} 
                        selectedEventUuid={selectedEventUuid} 
                        theme={theme} 
                      />
                    </div>
                    <div className={`rounded-2xl p-5 ${
                      isDark ? 'bg-white/[0.02] border border-white/[0.05]' : 'bg-white border border-slate-200/90 shadow-xs'
                    }`}>
                      <TerminalConsole 
                        onCommandExecuted={handleTerminalCommand} 
                        activeScenarioId={activeScenarioId} 
                        onScrollToCanvas={() => {
                          const el = document.getElementById('cisco-canvas-container');
                          if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' });
                        }}
                      />
                    </div>
                  </div>
                )}

                {/* ══ CIM TELEMETRY (ALL LOGS) ════════════════════════════ */}
                {activeTab === 'discover' && (
                  <div className={`rounded-2xl overflow-hidden ${
                    isDark ? '' : 'shadow-xs border border-slate-200/90'
                  }`}>
                    <KibanaDiscover
                      events={filteredEvents}
                      allEvents={events}
                      isResetToZero={isResetToZero}
                      onRestoreStats={handleToggleResetStats}
                      onSelectEvent={handleSelectEvent}
                      selectedEventUuid={selectedEventUuid}
                    />
                  </div>
                )}

                {/* ══ EVIDENCE VAULT ════════════════════════════════════════ */}
                {activeTab === 'vault' && (
                  <div className={`rounded-2xl p-5 ${
                    isDark ? 'bg-white/[0.02] border border-white/[0.05]' : 'bg-white border border-slate-200/90 shadow-xs'
                  }`}>
                    <EvidenceVault events={events} onSelectEvent={handleSelectEvent} selectedEventUuid={selectedEventUuid} />
                  </div>
                )}

                {/* ══ THREAT HUNTING ════════════════════════════════════════ */}
                {activeTab === 'hunting' && (
                  <div className={`rounded-2xl p-5 ${
                    isDark ? 'bg-white/[0.02] border border-white/[0.05]' : 'bg-white border border-slate-200/90 shadow-xs'
                  }`}>
                    <ThreatHuntingWorkspace events={events} scenario={activeScenario} onSelectEvent={handleSelectEvent} />
                  </div>
                )}

                {/* ══ ATTACK SEQUENCES / TERMINAL ══════════════════════════ */}
                {activeTab === 'terminal' && (
                  <div className={`rounded-2xl p-5 ${
                    isDark ? 'bg-white/[0.02] border border-white/[0.05]' : 'bg-white border border-slate-200/90 shadow-xs'
                  }`}>
                    <OffensiveTerminal
                      onCommandExecuted={handleTerminalCommand}
                      activeScenarioId={activeScenarioId}
                      events={activeEvents}
                      allEvents={events}
                      onSelectEvent={handleSelectEvent}
                      onOpenCimLogs={() => setActiveTab('discover')}
                      theme={theme}
                    />
                  </div>
                )}

                {/* ══ TIMELINE ════════════════════════════════════════════ */}
                {activeTab === 'timeline' && (
                  <div className={`rounded-2xl p-5 ${
                    isDark ? 'bg-white/[0.02] border border-white/[0.05]' : 'bg-white border border-slate-200/90 shadow-xs'
                  }`}>
                    <TimelineView events={filteredEvents} onSelectEvent={handleSelectEvent} selectedEventUuid={selectedEventUuid} />
                  </div>
                )}

                {/* ══ MITRE MATRIX ════════════════════════════════════════ */}
                {activeTab === 'mitre' && (
                  <div className={`rounded-2xl p-5 ${
                    isDark ? 'bg-white/[0.02] border border-white/[0.05]' : 'bg-white border border-slate-200/90 shadow-xs'
                  }`}>
                    <MitreMatrixView mitreData={mitreData} onSelectEvent={handleSelectEvent} />
                  </div>
                )}

                {/* ══ AI COPILOT ══════════════════════════════════════════ */}
                {activeTab === 'ai' && (
                  <div className={`rounded-2xl p-5 ${
                    isDark ? 'bg-white/[0.02] border border-white/[0.05]' : 'bg-white border border-slate-200/90 shadow-xs'
                  }`}>
                    <AIAssistantPanel
                      aiSummary={aiSummary} querySuggestions={Array.isArray(querySuggestions) ? querySuggestions : []}
                      onAskCustomQuery={(q) => api.askAiCustomQuery(q, activeScenarioId)}
                      onSelectEvent={handleSelectEvent}
                      onOpenLimitations={() => setShowLimitationsModal(true)}
                    />
                  </div>
                )}

                {/* ══ DETECTION STUDIO ════════════════════════════════════ */}
                {activeTab === 'detection' && (
                  <div className={`rounded-2xl p-5 ${
                    isDark ? 'bg-white/[0.02] border border-white/[0.05]' : 'bg-white border border-slate-200/90 shadow-xs'
                  }`}>
                    <DetectionStudio />
                  </div>
                )}

                {/* ══ RESPONSE GATING ════════════════════════════════════ */}
                {activeTab === 'gating' && (
                  <div className={`rounded-2xl p-5 ${
                    isDark ? 'bg-white/[0.02] border border-white/[0.05]' : 'bg-white border border-slate-200/90 shadow-xs'
                  }`}>
                    <HitlGatingPanel />
                  </div>
                )}

                {/* ══ INVESTIGATION REPORTS / AUDIT LEDGER ═══════════════ */}
                {activeTab === 'audit' && (
                  <div className="space-y-5">
                    <div className="flex gap-3">
                      <button
                        onClick={() => setShowReportModal(true)}
                        className="flex items-center gap-2 px-4 py-2.5 bg-purple-600 hover:bg-purple-700 text-white rounded-xl text-sm font-semibold shadow-xs transition"
                      >
                        <FileText className="w-4 h-4" />
                        Export Full Incident Report
                      </button>
                      <button
                        onClick={() => setShowLimitationsModal(true)}
                        className={`flex items-center gap-2 px-4 py-2.5 rounded-xl text-sm font-semibold transition ${
                          isDark
                            ? 'bg-white/[0.04] border border-white/[0.08] hover:bg-white/[0.07] text-slate-300'
                            : 'bg-white border border-slate-200 hover:bg-slate-50 text-slate-700 shadow-xs'
                        }`}
                      >
                        <AlertTriangle className="w-4 h-4 text-amber-500" />
                        AI Limitations
                      </button>
                    </div>
                    <div className={`rounded-2xl p-5 ${
                      isDark ? 'bg-white/[0.02] border border-white/[0.05]' : 'bg-white border border-slate-200/90 shadow-xs'
                    }`}>
                      <AuditLedgerView />
                    </div>
                  </div>
                )}

              </div>
            )}
          </main>

          {/* ── FOOTER ───────────────────────────────────────────────────── */}
          <footer className={`h-7 flex items-center px-5 gap-4 text-[9px] font-mono shrink-0 transition-colors ${
            isDark
              ? 'bg-black/40 border-t border-purple-900/20 text-slate-500'
              : 'bg-white border-t border-slate-200/90 text-slate-600 shadow-xs'
          }`}>
            <div className="flex items-center gap-1.5">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />
              <span className="text-emerald-600 dark:text-emerald-400 font-semibold">Sh4d0w_Br0k3rs Platform — Operational</span>
            </div>
            <span className={isDark ? 'text-purple-900' : 'text-slate-300'}>|</span>
            <span>API: {backendStatus.url || '/api'}</span>
            <span className={isDark ? 'text-purple-900' : 'text-slate-300'}>|</span>
            <span>Origin: {typeof window !== 'undefined' ? window.location.origin : 'http://localhost:3000'}</span>
            <span className="ml-auto font-medium">Evidence-Driven SOC Platform v3.0 • Noor Hassan Arch</span>
          </footer>
        </div>
      </div>

      {/* ══ MODALS / OVERLAYS ═════════════════════════════════════════════ */}
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
          onEventIngested={() => loadScenarioData(activeScenarioId, true)}
          onClose={() => setShowIngestModal(false)}
        />
      )}
    </div>
  );
}
