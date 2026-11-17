import React from 'react';
import { 
  ShieldAlert, 
  Terminal, 
  FileText, 
  Server, 
  RefreshCw, 
  AlertTriangle,
  HelpCircle,
  Database,
  Cpu,
  Layers,
  Flame,
  Radio
} from 'lucide-react';

export default function Navbar({ 
  scenarios, 
  activeScenarioId, 
  onSelectScenario, 
  backendStatus, 
  onRefreshBackend,
  onOpenReport,
  onOpenLimitations,
  onOpenIngest,
  onOpenTerminal,
  activeTab
}) {
  const currentScenario = scenarios.find(s => s.scenario_id === activeScenarioId);

  return (
    <header className="sticky top-0 z-40 bg-[#070B14]/90 backdrop-blur-md border-b border-slate-800 px-4 py-3">
      <div className="max-w-7xl mx-auto flex flex-col md:flex-row items-center justify-between gap-4">
        
        {/* Logo and Brand */}
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-blue-600/20 border border-blue-500/40 flex items-center justify-center text-blue-400 shadow-lg shadow-blue-500/10">
            <ShieldAlert className="w-6 h-6 animate-pulse" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="font-extrabold text-lg tracking-tight bg-gradient-to-r from-blue-400 via-indigo-300 to-cyan-400 bg-clip-text text-transparent">
                AegisHunt
              </span>
              <span className="px-2 py-0.5 text-[10px] font-mono uppercase tracking-wider rounded bg-blue-500/10 border border-blue-500/30 text-blue-400 font-bold">
                SOC v2.5
              </span>
              <span className="flex items-center gap-1 px-1.5 py-0.5 rounded text-[9px] font-mono bg-red-950/80 border border-red-500/40 text-red-400 font-bold">
                <span className="w-1.5 h-1.5 rounded-full bg-red-400 animate-ping" />
                ACTIVE HUNT
              </span>
            </div>
            <p className="text-xs text-slate-400 hidden sm:block">
              AI Cyber Threat Hunting, Correlation & Attack Path Visualization
            </p>
          </div>
        </div>

        {/* Scenario Switcher & Controls */}
        <div className="flex flex-wrap items-center gap-2.5">
          <div className="flex items-center bg-slate-900/90 border border-slate-700/80 rounded-lg px-2.5 py-1.5 shadow-inner">
            <Layers className="w-4 h-4 text-slate-400 mr-2" />
            <span className="text-xs text-slate-400 mr-2 font-medium hidden lg:inline">Scenario:</span>
            <select
              value={activeScenarioId}
              onChange={(e) => onSelectScenario(e.target.value)}
              className="bg-transparent text-xs text-slate-200 font-semibold focus:outline-none cursor-pointer pr-1"
            >
              {scenarios.map(s => (
                <option key={s.scenario_id} value={s.scenario_id} className="bg-slate-900 text-slate-200">
                  {s.name}
                </option>
              ))}
            </select>
          </div>

          {/* Backend Status indicator */}
          <button
            onClick={onRefreshBackend}
            title={backendStatus.online ? "PHP + MySQL API connected" : "Using local embedded correlation engine. Click to recheck PHP API"}
            className={`flex items-center gap-1.5 px-2.5 py-1.5 text-xs rounded-lg border font-mono transition-all ${
              backendStatus.online 
                ? 'bg-emerald-950/40 border-emerald-500/30 text-emerald-400 hover:bg-emerald-900/40' 
                : 'bg-indigo-950/40 border-indigo-500/30 text-indigo-300 hover:bg-indigo-900/40'
            }`}
          >
            <Database className="w-3.5 h-3.5" />
            <span className="hidden sm:inline">
              {backendStatus.online ? 'PHP MySQL: Live' : 'Engine: In-Memory'}
            </span>
            <RefreshCw className="w-3 h-3 text-slate-400 hover:rotate-180 transition-transform duration-300" />
          </button>

          {/* Threat Terminal Quick-Action */}
          <button
            onClick={onOpenTerminal}
            className={`flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-lg border transition ${
              activeTab === 'terminal'
                ? 'bg-emerald-600 text-white border-emerald-400 shadow-lg shadow-emerald-600/20'
                : 'bg-slate-800 hover:bg-slate-700 text-emerald-400 border-emerald-500/30'
            }`}
          >
            <Terminal className="w-3.5 h-3.5" />
            <span>SOC Terminal</span>
          </button>

          {/* Ingest Log Button */}
          <button
            onClick={onOpenIngest}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition"
          >
            <Flame className="w-3.5 h-3.5 text-cyan-400" />
            <span className="hidden sm:inline">Ingest Log</span>
          </button>

          {/* AI Limitations Button */}
          <button
            onClick={onOpenLimitations}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg bg-slate-800 hover:bg-slate-700 text-amber-300 border border-amber-500/30 transition"
          >
            <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
            <span className="hidden md:inline">AI Limits</span>
          </button>

          {/* Incident Report Button */}
          <button
            onClick={onOpenReport}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-lg bg-blue-600 hover:bg-blue-500 text-white shadow-md shadow-blue-600/30 transition"
          >
            <FileText className="w-3.5 h-3.5" />
            <span>Report</span>
          </button>
        </div>

      </div>
    </header>
  );
}
