import { useEffect, useMemo, useRef, useState, useCallback } from "react";
import { useAuth } from "@/context/AuthContext";
import { api, API, WS_URL } from "@/lib/api";
import { toast } from "sonner";
import {
  Shield,
  Radio,
  Terminal,
  LogOut,
  Sliders,
  Play,
  RotateCcw,
  ChevronRight,
  Download,
  X,
  Activity,
  AlertTriangle,
  Search,
  Globe,
  BarChart3,
  Sparkles,
  Cpu,
  Layers,
  Server,
  Bug,
  Clock,
  LayoutGrid,
  Columns,
  ShieldCheck,
  Zap,
  Lock
} from "lucide-react";
import ScenarioCard from "@/components/ScenarioCard";
import KpiTile from "@/components/KpiTile";
import EventStream from "@/components/EventStream";
import AlertFeed from "@/components/AlertFeed";
import Leaderboard from "@/components/Leaderboard";
import ThreatOrigins from "@/components/ThreatOrigins";
import AlertDrilldown from "@/components/AlertDrilldown";
import KaliConsole from "@/components/KaliConsole";

const MITRE_KILL_CHAIN = [
  { id: "T1595.001", tactic: "Reconnaissance", name: "Port Scanning", tool: "Nmap" },
  { id: "T1190", tactic: "Initial Access", name: "Public App Exploit", tool: "SQLMap" },
  { id: "T1110.003", tactic: "Credential Access", name: "Password Spraying", tool: "Hydra" },
  { id: "T1110.004", tactic: "Credential Access", name: "Cluster Stuffing", tool: "Proxy Cluster" },
  { id: "T1078", tactic: "Defense Evasion", name: "Valid Accounts / Ghost TX", tool: "API Replay" },
];

export default function Dashboard() {
  const { user, logout } = useAuth();
  const [scenario, setScenario] = useState("brute_force");
  const [summary, setSummary] = useState({
    events_ingested: 0,
    throughput: 0,
    active_threats: 0,
    max_risk: 0,
    acknowledged: 0,
  });
  const [events, setEvents] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [severityFilter, setSeverityFilter] = useState("all");
  const [riskThreshold, setRiskThreshold] = useState(50);
  const [leaderboard, setLeaderboard] = useState([]);
  const [origins, setOrigins] = useState([]);
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [kaliOpen, setKaliOpen] = useState(true);
  const [viewMode, setViewMode] = useState("console"); // "console" | "split"
  const [isDocked, setIsDocked] = useState(false);
  const [wsAlive, setWsAlive] = useState(false);
  const [running, setRunning] = useState(false);
  const [currentTime, setCurrentTime] = useState("");

  const [terminalLines, setTerminalLines] = useState([
    { t: "[redteam-vm]", v: "Offensive Security Terminal initialized (IP: 192.168.1.105 / tun0: 10.42.0.5)" },
    { t: "[redteam-vm]", v: "Target subnet active: TARGET-VM (10.42.0.10) [SSH, HTTP, HTTPS, PGSQL]" },
    { t: "[redteam-vm]", v: "Type 'help' or execute an offensive tool (nmap, hydra, sqlmap, curl, whoami)." },
  ]);
  const [progress, setProgress] = useState(0);
  const [labEvents, setLabEvents] = useState(0);
  const wsRef = useRef(null);

  // Live UTC Clock
  useEffect(() => {
    const updateTime = () => {
      const now = new Date();
      setCurrentTime(now.toUTCString().slice(17, 25) + " UTC");
    };
    updateTime();
    const interval = setInterval(updateTime, 1000);
    return () => clearInterval(interval);
  }, []);

  const refetchAll = useCallback(async () => {
    try {
      const [s, e, a, lb, og] = await Promise.all([
        api.summary(),
        api.eventStream(),
        api.alerts(severityFilter),
        api.leaderboard(),
        api.origins(),
      ]);
      setSummary(s);
      setEvents(e.events);
      setAlerts(a.alerts);
      setLeaderboard(lb.entities);
      setOrigins(og.origins);
    } catch (err) {
      console.warn("Dashboard refetch skipped:", err?.message);
    }
  }, [severityFilter]);

  useEffect(() => {
    refetchAll();
  }, [refetchAll]);

  // WebSocket Ingestion & Command Broadcast
  useEffect(() => {
    let alive = true;
    let retry = null;

    const connect = () => {
      const token = localStorage.getItem("threatlens_token");
      const url = token ? `${WS_URL}?token=${encodeURIComponent(token)}` : WS_URL;
      const ws = new WebSocket(url);
      wsRef.current = ws;

      ws.onopen = () => alive && setWsAlive(true);
      ws.onclose = () => {
        if (!alive) return;
        setWsAlive(false);
        retry = setTimeout(connect, 2500);
      };
      ws.onerror = () => ws.close();

      ws.onmessage = (m) => {
        try {
          const msg = JSON.parse(m.data);
          if (msg.type === "event") {
            setEvents(prev => [msg.event, ...prev].slice(0, 40));
            setSummary(prev => ({ ...prev, events_ingested: prev.events_ingested + 1 }));
            setLabEvents(x => x + 1);
          } else if (msg.type === "attacker_cmd") {
            if (msg.action === "clear") {
              setTerminalLines([]);
            } else {
              setTerminalLines(prev => [...prev.slice(-200), { t: "", v: msg.line }]);
              if (msg.progress) setProgress(msg.progress);
            }
          } else if (msg.type === "alert_created") {
            setAlerts(prev => [msg.alert, ...prev].slice(0, 100));
            toast.error(msg.alert.title, {
              description: `MITRE ${msg.alert.mitre?.id || "ALERT"} · Risk score: ${msg.alert.risk_score}/100`,
            });
            refetchAll();
          } else if (msg.type === "sim_start") {
            setRunning(true);
            setProgress(0);
            setLabEvents(0);
            setTerminalLines(prev => [
              ...prev,
              { t: "[redteam-vm]", v: `[+] Launching ${msg.scenario} playbook → ${msg.target}` },
            ]);
          } else if (msg.type === "sim_end") {
            setRunning(false);
            setProgress(100);
          } else if (msg.type === "alert_updated" || msg.type === "reset") {
            refetchAll();
            if (msg.type === "reset") {
              setEvents([]);
              setTerminalLines([
                { t: "[redteam-vm]", v: "Pipeline state reset. Telemetry buffer and alerts flushed." },
                { t: "[redteam-vm]", v: "Ready for threat intelligence processing." },
              ]);
              setLabEvents(0);
              setProgress(0);
            }
          }
        } catch (e) {}
      };
    };

    connect();
    return () => {
      alive = false;
      clearTimeout(retry);
      wsRef.current && wsRef.current.close();
    };
  }, [refetchAll]);

  // Polling fallback
  useEffect(() => {
    const id = setInterval(() => {
      if (!wsAlive) refetchAll();
    }, 4000);
    return () => clearInterval(id);
  }, [wsAlive, refetchAll]);

  const startSim = async (intensity = "normal") => {
    setRunning(true);
    try {
      await api.startSim(scenario, intensity);
      toast.success(`Offensive playbook '${scenario}' initialized`);
    } catch (e) {
      setRunning(false);
      toast.error("Failed to start playbook simulation");
    }
  };

  const reset = async () => {
    await api.resetSim();
    setAlerts([]);
    setEvents([]);
    setLabEvents(0);
    setProgress(0);
    toast.success("Enclave reset: telemetry buffers and alert logs purged");
  };

  const filteredAlerts = useMemo(() => {
    return alerts.filter(a => {
      const matchSev = severityFilter === "all" || a.severity === severityFilter;
      const matchRisk = (a.risk_score || 0) >= riskThreshold;
      return matchSev && matchRisk;
    });
  }, [alerts, severityFilter, riskThreshold]);

  // Active MITRE techniques from live alerts
  const activeMitreIds = useMemo(() => {
    const ids = new Set();
    alerts.forEach(a => {
      if (a.mitre?.id) ids.add(a.mitre.id);
    });
    return ids;
  }, [alerts]);

  return (
    <div className="min-h-screen relative z-10 bg-[#06090E] text-slate-100 font-sans">
      {/* Enterprise SOC Header */}
      <header
        className="sticky top-0 z-30 border-b border-slate-800/90 bg-[#0B0F17]/95 backdrop-blur-md"
        data-testid="dashboard-header"
      >
        <div className="px-6 py-3 flex items-center justify-between flex-wrap gap-3">
          <div className="flex items-center gap-4">
            <div className="w-9 h-9 rounded-lg bg-cyan-950/70 border border-cyan-500/50 flex items-center justify-center text-cyan-400 shadow-lg shadow-cyan-950/50">
              <Shield className="w-5 h-5" />
            </div>
            <div>
              <div className="text-sm tracking-wider uppercase font-extrabold text-slate-100 flex items-center gap-2">
                <span>ThreatLens</span>
                <span className="text-cyan-400 font-black">SOC</span>
                <span className="text-[10px] px-2 py-0.5 rounded bg-slate-800/90 text-slate-300 font-mono font-semibold border border-slate-700/80">
                  ENTERPRISE v2.4
                </span>
              </div>
              <div className="text-[11px] text-slate-400 flex items-center gap-2 mt-0.5 font-mono">
                <span className="text-slate-300 font-semibold">PROD-US-EAST-1</span>
                <span className="text-slate-600">·</span>
                <span>Enclave: 10.42.0.0/24</span>
              </div>
            </div>
          </div>

          <div className="flex items-center gap-3">
            {/* Real-time Ingestion & Pipeline Stats */}
            <div
              className="hidden lg:flex items-center gap-3 px-3.5 py-1.5 rounded-lg bg-slate-900/80 border border-slate-800 text-xs font-mono"
              data-testid="ws-status"
            >
              <div className="flex items-center gap-1.5 text-slate-300">
                <Radio className="w-3.5 h-3.5 text-cyan-400" />
                <span>Ingestion: <strong className="text-cyan-300">14.2 eps</strong></span>
              </div>
              <span className="text-slate-700">|</span>
              <div className="flex items-center gap-1.5 text-slate-400">
                <Clock className="w-3.5 h-3.5 text-slate-500" />
                <span>{currentTime || "13:42:19 UTC"}</span>
              </div>
              <span className="text-slate-700">|</span>
              <span className="flex items-center gap-1.5 text-emerald-400 font-semibold">
                <span className={`pulse-dot ${wsAlive ? "" : "amber"}`} />
                {wsAlive ? "HEALTHY" : "CONNECTING"}
              </span>
            </div>

            {/* View Mode Toggle */}
            <div className="hidden sm:flex items-center gap-1 bg-slate-900/80 p-1 rounded-lg border border-slate-800">
              <button
                onClick={() => {
                  setViewMode("console");
                  setKaliOpen(true);
                }}
                className={`px-3 py-1 rounded text-xs font-semibold transition ${
                  viewMode === "console"
                    ? "bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 font-bold shadow-sm"
                    : "text-slate-400 hover:text-slate-200"
                }`}
                title="Full SOC Overview with floating/dockable Attacker VM"
              >
                <LayoutGrid className="w-3.5 h-3.5 inline mr-1.5" /> Full Dashboard
              </button>
              <button
                onClick={() => {
                  setViewMode("split");
                  setKaliOpen(true);
                }}
                className={`px-3 py-1 rounded text-xs font-semibold transition ${
                  viewMode === "split"
                    ? "bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 font-bold shadow-sm"
                    : "text-slate-400 hover:text-slate-200"
                }`}
                title="Side-by-side view: SOC alerts on left, Attacker VM on right"
              >
                <Columns className="w-3.5 h-3.5 inline mr-1.5" /> Split Screen
              </button>
            </div>

            {/* Attacker Lab Terminal Toggle */}
            <button
              data-testid="toggle-kali-button"
              onClick={() => setKaliOpen(v => !v)}
              className={`px-3.5 py-1.5 rounded-lg text-xs font-mono font-bold border flex items-center gap-2 transition ${
                kaliOpen
                  ? "bg-cyan-500/20 text-cyan-300 border-cyan-500/40 shadow-sm"
                  : "bg-slate-900 text-slate-300 border-slate-800 hover:border-slate-700"
              }`}
            >
              <Terminal className="w-4 h-4 text-cyan-400" />
              <span className="hidden md:inline">Attacker VM</span>
              {running && <span className="w-2 h-2 rounded-full bg-red-400 animate-pulse" />}
            </button>

            {/* Reset / Flush Pipeline Button */}
            <button
              data-testid="reset-lab-button"
              onClick={reset}
              className="px-3 py-1.5 rounded-lg text-xs font-mono text-slate-400 hover:text-slate-200 bg-slate-900 border border-slate-800 hover:border-slate-700 flex items-center gap-1.5 transition"
              title="Flush telemetry buffer and reset alert state"
            >
              <RotateCcw className="w-3.5 h-3.5" />
              <span className="hidden sm:inline">Flush Buffer</span>
            </button>

            {/* User Profile */}
            <div className="flex items-center gap-2.5 pl-2.5 border-l border-slate-800">
              <div className="w-8 h-8 rounded-lg bg-slate-800 border border-slate-700 flex items-center justify-center text-xs font-bold text-cyan-300 font-mono">
                {(user?.name || "AM").split(" ").map(x => x[0]).slice(0, 2).join("")}
              </div>
              <div className="hidden xl:block text-right">
                <div className="text-xs text-slate-200 font-semibold leading-none">
                  {user?.name || "Mushfiqul Alam"}
                </div>
                <button
                  data-testid="signout-button"
                  onClick={logout}
                  className="text-[10px] uppercase font-bold text-slate-500 hover:text-red-400 flex items-center gap-1 mt-0.5 font-mono"
                >
                  <LogOut className="w-2.5 h-2.5" /> Sign out
                </button>
              </div>
            </div>
          </div>
        </div>

        {/* MITRE ATT&CK Kill-Chain Matrix Strip */}
        <div className="px-6 py-2 bg-[#06090F] border-t border-slate-800/80 flex items-center gap-2 overflow-x-auto text-xs font-mono select-none">
          <span className="text-slate-500 uppercase tracking-widest text-[10px] mr-1 flex items-center gap-1 font-sans flex-shrink-0 font-bold">
            <Layers className="w-3.5 h-3.5 text-cyan-400" /> MITRE ATT&CK Matrix:
          </span>
          {MITRE_KILL_CHAIN.map((m) => {
            const isActive = activeMitreIds.has(m.id);
            return (
              <div
                key={m.id}
                className={`px-2.5 py-1 rounded-md border flex items-center gap-2 transition whitespace-nowrap ${
                  isActive
                    ? "bg-red-950/40 border-red-500/60 text-red-300 font-bold"
                    : "bg-slate-900/80 border-slate-800 text-slate-400"
                }`}
              >
                <span className={`w-1.5 h-1.5 rounded-full ${isActive ? "bg-red-400 animate-ping" : "bg-slate-600"}`} />
                <span className="font-bold">{m.id}</span>
                <span className="text-slate-600">·</span>
                <span>{m.name}</span>
                <span className="text-slate-500 text-[10px]">({m.tool})</span>
              </div>
            );
          })}
        </div>
      </header>

      {/* Main Container */}
      <main className="px-6 py-6 max-w-[1720px] mx-auto space-y-6" data-testid="dashboard-main">
        {/* Split Screen Layout (if activated) */}
        {viewMode === "split" && kaliOpen ? (
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
            {/* Left 7 Columns: SOC Overview & Alerts */}
            <div className="lg:col-span-7 space-y-6">
              {/* KPIs */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                <KpiTile
                  label="Events Ingested"
                  value={summary.events_ingested.toLocaleString()}
                  unit="events"
                  caption="normalized audit stream"
                  trend="+14% stream"
                  icon={Activity}
                  tone="cyan"
                />
                <KpiTile
                  label="Active Incidents"
                  value={summary.active_threats}
                  unit="alerts"
                  caption={`${summary.acknowledged || 0} triaged / ack`}
                  tone={summary.active_threats > 0 ? "amber" : "emerald"}
                  icon={AlertTriangle}
                />
                <KpiTile
                  label="Peak Risk Score"
                  value={summary.max_risk}
                  unit="/ 100"
                  caption="target: 10.42.0.10"
                  tone={summary.max_risk >= 90 ? "red" : "cyan"}
                  icon={Zap}
                />
                <KpiTile
                  label="Mean Time to Detect"
                  value="42.4s"
                  unit="mttd"
                  caption="EWMA + DBSCAN ensemble"
                  tone="emerald"
                  icon={Clock}
                />
              </div>

              {/* Raw Event Stream */}
              <div className="tl-card p-5">
                <div className="flex items-center justify-between mb-3">
                  <div className="flex items-center gap-2">
                    <Activity className="w-4 h-4 text-cyan-400" />
                    <span className="text-xs font-bold uppercase tracking-wider text-slate-100">
                      Raw Telemetry Stream (Live Tail)
                    </span>
                  </div>
                  <span className="badge badge-medium">Target Subnet 10.42.0.0/24</span>
                </div>
                <EventStream events={events} />
              </div>

              {/* Correlated Alerts */}
              <AlertFeed
                alerts={filteredAlerts}
                allCount={alerts.length}
                severity={severityFilter}
                setSeverity={setSeverityFilter}
                onOpen={a => setSelectedAlert(a)}
                exportUrl={api.exportCsv()}
                exportReportUrl={api.exportReport()}
              />
            </div>

            {/* Right 5 Columns: Embedded Kali Linux Terminal */}
            <div className="lg:col-span-5 h-[840px] sticky top-24">
              <KaliConsole
                lines={terminalLines}
                progress={progress}
                labEvents={labEvents}
                running={running}
                onClose={() => setKaliOpen(false)}
                onRun={(scenarioKey, intensity) => {
                  setScenario(scenarioKey);
                  api.startSim(scenarioKey, intensity);
                }}
                onCommand={async line => {
                  try {
                    await api.attackerCmd(line);
                  } catch (e) {
                    toast.error("Command execution failed");
                  }
                }}
                isEmbedded={true}
              />
            </div>
          </div>
        ) : (
          /* Standard Console Layout */
          <>
            {/* KPI Tiles */}
            <section className="grid grid-cols-2 lg:grid-cols-4 gap-4" data-testid="kpi-tiles">
              <KpiTile
                label="Events Ingested"
                value={summary.events_ingested.toLocaleString()}
                unit="events"
                caption="synthetic attacker → baseline audit pipeline"
                trend="+12% vs baseline"
                icon={Activity}
                tone="cyan"
              />
              <KpiTile
                label="Active Incidents"
                value={summary.active_threats}
                unit="alerts"
                caption={`${summary.acknowledged || 0} acknowledged / triaged`}
                tone={summary.active_threats > 0 ? "amber" : "emerald"}
                icon={AlertTriangle}
              />
              <KpiTile
                label="Max Entity Risk"
                value={summary.max_risk}
                unit="/ 100"
                caption="10.42.0.10 (TARGET-VM)"
                tone={summary.max_risk >= 90 ? "red" : "cyan"}
                icon={Zap}
              />
              <KpiTile
                label="Mean Time to Detect"
                value="42.4s"
                unit="mttd"
                caption="EWMA & DBSCAN ensemble voting"
                tone="emerald"
                icon={Clock}
              />
            </section>

            {/* Offensive Playbook Launcher */}
            <section className="tl-card p-5" data-testid="scenario-launcher">
              <div className="flex items-center justify-between mb-4 flex-wrap gap-2">
                <div>
                  <div className="label-caps mb-0.5 text-slate-100 font-bold">Offensive Playbook Launcher</div>
                  <div className="text-xs text-slate-400">
                    Execute approved offensive playbooks against TARGET-VM (10.42.0.10) to generate live telemetry.
                  </div>
                </div>
                <div className="flex items-center gap-2 font-mono">
                  <span className="badge badge-medium">
                    <span className="pulse-dot" /> Subnet: 10.42.0.0/24 (Airgapped)
                  </span>
                </div>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3">
                <ScenarioCard
                  active={scenario === "brute_force"}
                  onClick={() => setScenario("brute_force")}
                  k="brute_force"
                  title="Brute Force"
                  sub="T1110.003 · Hydra Spray"
                  icon={Shield}
                />
                <ScenarioCard
                  active={scenario === "credential_stuffing"}
                  onClick={() => setScenario("credential_stuffing")}
                  k="credential_stuffing"
                  title="Cred Stuffing"
                  sub="T1110.004 · Proxy Cluster"
                  icon={AlertTriangle}
                />
                <ScenarioCard
                  active={scenario === "port_scan"}
                  onClick={() => setScenario("port_scan")}
                  k="port_scan"
                  title="Port Recon"
                  sub="T1595.001 · Nmap SYN"
                  icon={Search}
                />
                <ScenarioCard
                  active={scenario === "ghost_tx"}
                  onClick={() => setScenario("ghost_tx")}
                  k="ghost_tx"
                  title="Ghost TX"
                  sub="T1078 · Latency Spike"
                  icon={Activity}
                />
                <ScenarioCard
                  active={scenario === "sql_injection"}
                  onClick={() => setScenario("sql_injection")}
                  k="sql_injection"
                  title="SQL Injection"
                  sub="T1190 · SQLMap Schema Probe"
                  icon={Bug}
                />
              </div>

              <div className="mt-4 flex items-center gap-2.5 flex-wrap">
                <button
                  data-testid="start-sim-button"
                  onClick={() => startSim("normal")}
                  disabled={running}
                  className="btn-primary flex items-center justify-center gap-2 text-xs"
                >
                  <Play className="w-3.5 h-3.5 fill-current" />
                  {running ? "Executing Playbook..." : "Launch Selected Attack"}
                  <ChevronRight className="w-3.5 h-3.5" />
                </button>
                <button
                  data-testid="fast-demo-button"
                  onClick={() => startSim("fast")}
                  disabled={running}
                  className="btn-ghost flex items-center justify-center gap-2 text-xs font-mono"
                >
                  <Zap className="w-3.5 h-3.5 text-cyan-400" /> Turbo Ingestion
                </button>
                <button
                  onClick={() => {
                    setKaliOpen(true);
                    toast.info("Opened Attacker VM Console");
                  }}
                  className="btn-ghost flex items-center justify-center gap-2 text-xs font-mono"
                >
                  <Terminal className="w-3.5 h-3.5 text-cyan-400" /> Open in Kali CLI
                </button>
              </div>
            </section>

            {/* Live Raw Telemetry Stream */}
            <section className="tl-card p-5" data-testid="raw-event-stream">
              <div className="flex items-center justify-between mb-3">
                <div className="flex items-center gap-2.5">
                  <Activity className="w-4 h-4 text-cyan-400" />
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="text-slate-100 text-sm font-bold uppercase tracking-wider">
                        Raw Telemetry Ingestion Log
                      </span>
                      <span className="badge badge-medium">Live Stream</span>
                    </div>
                    <div className="text-[11px] text-slate-400">
                      Normalized security audit telemetry from target endpoints and hypervisor taps
                    </div>
                  </div>
                </div>
              </div>
              <EventStream events={events} />
            </section>

            {/* Dynamic Risk Alerting Threshold & Noise Suppression Strip */}
            <section className="tl-card p-3.5 flex items-center justify-between gap-4 flex-wrap text-xs bg-[#090D17] border-slate-800" data-testid="threshold-config-strip">
              <div className="flex items-center gap-2.5">
                <Sliders className="w-4 h-4 text-cyan-400" />
                <div>
                  <div className="text-xs font-semibold text-slate-200 flex items-center gap-2">
                    <span>Dynamic Risk Alerting Threshold</span>
                    <span className="badge badge-medium text-[10px]">{riskThreshold}+ pts</span>
                  </div>
                  <div className="text-[11px] text-slate-400">
                    Configurable sensitivity threshold to suppress false positive noise and eliminate Tier-1 alert fatigue
                  </div>
                </div>
              </div>

              <div className="flex items-center gap-3.5 flex-wrap font-mono text-xs">
                <div className="flex items-center gap-2">
                  <span className="text-[11px] text-slate-500">50</span>
                  <input
                    type="range"
                    min="50"
                    max="90"
                    step="5"
                    value={riskThreshold}
                    onChange={e => setRiskThreshold(Number(e.target.value))}
                    className="w-28 accent-cyan-400 cursor-pointer"
                    data-testid="risk-threshold-slider"
                  />
                  <span className="text-[11px] text-slate-500">90</span>
                </div>

                <div className="flex items-center gap-1">
                  <button
                    onClick={() => setRiskThreshold(50)}
                    className={`px-2 py-0.5 rounded text-[10px] transition ${
                      riskThreshold === 50 ? "bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 font-semibold" : "bg-slate-800/80 text-slate-400 hover:text-slate-200"
                    }`}
                  >
                    50+ All
                  </button>
                  <button
                    onClick={() => setRiskThreshold(70)}
                    className={`px-2 py-0.5 rounded text-[10px] transition ${
                      riskThreshold === 70 ? "bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 font-semibold" : "bg-slate-800/80 text-slate-400 hover:text-slate-200"
                    }`}
                  >
                    70+ Balanced
                  </button>
                  <button
                    onClick={() => setRiskThreshold(85)}
                    className={`px-2 py-0.5 rounded text-[10px] transition ${
                      riskThreshold === 85 ? "bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 font-semibold" : "bg-slate-800/80 text-slate-400 hover:text-slate-200"
                    }`}
                  >
                    85+ Strict
                  </button>
                </div>
              </div>
            </section>

            {/* Two Column: Correlated Alert Feed + Right Telemetry Rail */}
            <section className="grid grid-cols-1 lg:grid-cols-[1.6fr_1fr] gap-6">
              <AlertFeed
                alerts={filteredAlerts}
                allCount={alerts.length}
                severity={severityFilter}
                setSeverity={setSeverityFilter}
                onOpen={a => setSelectedAlert(a)}
                exportUrl={api.exportCsv()}
                exportReportUrl={api.exportReport()}
              />
              <div className="space-y-6">
                <Leaderboard rows={leaderboard} />
                <ThreatOrigins origins={origins} />
                <div className="tl-card p-4" data-testid="detection-ensemble-card">
                  <div className="flex items-center gap-2 mb-2">
                    <BarChart3 className="w-4 h-4 text-cyan-400" />
                    <span className="label-caps text-slate-200">ML Detection Ensemble</span>
                  </div>
                  <p className="text-xs text-slate-400 leading-relaxed">
                    Multimodal consensus voting combining EWMA moving baselines, Isolation Forest outlier trees, DBSCAN density clustering, and deterministic MITRE ATT&CK correlation rules.
                  </p>
                </div>
              </div>
            </section>
          </>
        )}

        {/* Enterprise Footer */}
        <footer className="pt-6 pb-12 flex items-center justify-between text-xs text-slate-500 border-t border-slate-800/80 font-mono">
          <span>ThreatLens SOC · Zero external network egress · Isolated enclave simulation</span>
          <span>Analyst: {user?.email || "themushfiqulalam@gmail.com"}</span>
        </footer>
      </main>

      {/* Slide-over Incident Drilldown */}
      {selectedAlert && (
        <AlertDrilldown
          alert={selectedAlert}
          onClose={() => setSelectedAlert(null)}
          onChange={() => refetchAll()}
        />
      )}

      {/* Floating or Docked Kali Linux Attacker Console (when not in split view) */}
      {kaliOpen && viewMode !== "split" && (
        <KaliConsole
          lines={terminalLines}
          progress={progress}
          labEvents={labEvents}
          running={running}
          onClose={() => setKaliOpen(false)}
          onRun={(scenarioKey, intensity) => {
            setScenario(scenarioKey);
            api.startSim(scenarioKey, intensity);
          }}
          onCommand={async line => {
            try {
              await api.attackerCmd(line);
            } catch (e) {
              toast.error("Command execution failed");
            }
          }}
          isDocked={isDocked}
          onToggleDock={() => setIsDocked(d => !d)}
        />
      )}

      {/* Minimized Dock Button for Attacker Console */}
      {!kaliOpen && (
        <button
          onClick={() => setKaliOpen(true)}
          className="fixed bottom-5 right-5 z-40 px-3.5 py-2.5 rounded-lg bg-[#0B0F17] border border-cyan-500/40 text-cyan-300 hover:bg-[#121A28] shadow-2xl flex items-center gap-2.5 text-xs font-mono font-bold transition"
        >
          <Terminal className="w-4 h-4 text-cyan-400" />
          <span>KALI ATTACKER VM (192.168.1.105)</span>
          <span className="w-2 h-2 rounded-full bg-emerald-400" />
        </button>
      )}
    </div>
  );
}