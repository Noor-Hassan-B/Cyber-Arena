import React from 'react';
import { 
  ShieldCheck, 
  Activity, 
  Target, 
  Users, 
  Zap, 
  Radio, 
  CloudRain, 
  Server,
  Lock,
  Compass
} from 'lucide-react';

export default function OverviewStats({ correlationData, scenario, events }) {
  if (!correlationData) return null;

  const {
    incident_title,
    confidence_score,
    kill_chain_coverage,
    entities_involved
  } = correlationData;

  const domainCounts = events.reduce((acc, e) => {
    acc[e.domain] = (acc[e.domain] || 0) + 1;
    return acc;
  }, {});

  return (
    <div className="space-y-4">
      {/* Incident Header Banner */}
      <div className="bg-gradient-to-r from-slate-900 via-slate-900/90 to-blue-950/40 border border-slate-800 rounded-xl p-4 sm:p-5 shadow-lg relative overflow-hidden">
        <div className="absolute top-0 right-0 w-64 h-64 bg-blue-500/5 rounded-full blur-3xl pointer-events-none" />
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div className="space-y-1.5">
            <div className="flex items-center gap-2 flex-wrap">
              <span className="px-2.5 py-0.5 rounded-full text-xs font-mono font-semibold bg-red-500/10 border border-red-500/30 text-red-400">
                THREAT LEVEL: CRITICAL
              </span>
              <span className="text-xs text-slate-400 font-mono">
                ID: {scenario.scenario_id}
              </span>
              <span className="text-xs text-slate-400 font-mono">
                Actor: <strong className="text-slate-200">{scenario.threat_actor}</strong>
              </span>
            </div>
            <h1 className="text-lg sm:text-xl font-bold text-white tracking-tight">
              {incident_title}
            </h1>
            <p className="text-xs sm:text-sm text-slate-300 max-w-4xl line-clamp-2">
              {scenario.description}
            </p>
          </div>

          <div className="flex items-center gap-3 bg-slate-950/60 border border-slate-800 rounded-lg p-3 self-start lg:self-auto min-w-[200px]">
            <div className="relative w-12 h-12 flex items-center justify-center">
              <svg className="w-12 h-12 transform -rotate-90">
                <circle
                  cx="24"
                  cy="24"
                  r="20"
                  stroke="currentColor"
                  strokeWidth="4"
                  className="text-slate-800"
                  fill="transparent"
                />
                <circle
                  cx="24"
                  cy="24"
                  r="20"
                  stroke="currentColor"
                  strokeWidth="4"
                  className="text-blue-500"
                  fill="transparent"
                  strokeDasharray={125.6}
                  strokeDashoffset={125.6 - (125.6 * (confidence_score || 0.85))}
                  strokeLinecap="round"
                />
              </svg>
              <span className="absolute text-xs font-mono font-bold text-blue-400">
                {Math.round((confidence_score || 0.85) * 100)}%
              </span>
            </div>
            <div>
              <div className="text-[11px] uppercase font-mono text-slate-400">Correlation</div>
              <div className="text-sm font-bold text-slate-200">High Confidence</div>
              <div className="text-[10px] text-slate-400">Cross-domain link</div>
            </div>
          </div>
        </div>
      </div>

      {/* KPI Cards Grid */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3 sm:gap-4">
        
        {/* Metric 1: Correlated Events */}
        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-3.5 hover:border-slate-700 transition">
          <div className="flex items-center justify-between text-slate-400 mb-1.5">
            <span className="text-xs font-medium">Correlated Events</span>
            <Activity className="w-4 h-4 text-blue-400" />
          </div>
          <div className="text-xl sm:text-2xl font-bold font-mono text-white">
            {events.length}
          </div>
          <div className="flex items-center gap-1.5 mt-2 flex-wrap text-[10px] font-mono">
            {domainCounts.endpoint && (
              <span className="px-1.5 py-0.5 rounded bg-blue-900/40 text-blue-300 border border-blue-800">
                EP: {domainCounts.endpoint}
              </span>
            )}
            {domainCounts.auth && (
              <span className="px-1.5 py-0.5 rounded bg-amber-900/40 text-amber-300 border border-amber-800">
                AUTH: {domainCounts.auth}
              </span>
            )}
            {domainCounts.network && (
              <span className="px-1.5 py-0.5 rounded bg-emerald-900/40 text-emerald-300 border border-emerald-800">
                NET: {domainCounts.network}
              </span>
            )}
            {domainCounts.cloud && (
              <span className="px-1.5 py-0.5 rounded bg-purple-900/40 text-purple-300 border border-purple-800">
                CLD: {domainCounts.cloud}
              </span>
            )}
          </div>
        </div>

        {/* Metric 2: Kill Chain Tactics Traversed */}
        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-3.5 hover:border-slate-700 transition">
          <div className="flex items-center justify-between text-slate-400 mb-1.5">
            <span className="text-xs font-medium">MITRE Tactics</span>
            <Compass className="w-4 h-4 text-indigo-400" />
          </div>
          <div className="text-xl sm:text-2xl font-bold font-mono text-white">
            {kill_chain_coverage?.length || 0} <span className="text-xs text-slate-500 font-normal">/ 12 stages</span>
          </div>
          <p className="text-[11px] text-slate-400 mt-2 truncate">
            {kill_chain_coverage?.slice(0, 3).join(', ') || 'Multi-stage'}...
          </p>
        </div>

        {/* Metric 3: Assets in Blast Radius */}
        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-3.5 hover:border-slate-700 transition">
          <div className="flex items-center justify-between text-slate-400 mb-1.5">
            <span className="text-xs font-medium">Blast Radius (Assets)</span>
            <Server className="w-4 h-4 text-rose-400" />
          </div>
          <div className="text-xl sm:text-2xl font-bold font-mono text-white">
            {entities_involved?.hosts?.length || 0}
          </div>
          <p className="text-[11px] text-slate-400 mt-2 truncate">
            {entities_involved?.hosts?.join(', ') || 'Zero hosts'}
          </p>
        </div>

        {/* Metric 4: Compromised Identities */}
        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-3.5 hover:border-slate-700 transition">
          <div className="flex items-center justify-between text-slate-400 mb-1.5">
            <span className="text-xs font-medium">Compromised Users</span>
            <Users className="w-4 h-4 text-amber-400" />
          </div>
          <div className="text-xl sm:text-2xl font-bold font-mono text-white">
            {entities_involved?.users?.length || 0}
          </div>
          <p className="text-[11px] text-slate-400 mt-2 truncate font-mono">
            {entities_involved?.users?.join(', ') || 'None identified'}
          </p>
        </div>

      </div>
    </div>
  );
}
