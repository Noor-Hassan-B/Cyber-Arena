import React, { useState } from 'react';
import { 
  Search, 
  Calendar, 
  RefreshCw, 
  X, 
  Sparkles, 
  Filter, 
  Clock,
  Activity,
  Layers,
  BarChart2
} from 'lucide-react';

const QUICK_FILTERS = [
  { label: 'domain: endpoint', key: 'domain', val: 'endpoint' },
  { label: 'domain: auth', key: 'domain', val: 'auth' },
  { label: 'domain: network', key: 'domain', val: 'network' },
  { label: 'domain: cloud', key: 'domain', val: 'cloud' },
  { label: 'severity: critical', key: 'severity', val: 'critical' },
  { label: 'tactic: Credential Access', key: 'search', val: 'Credential Access' },
  { label: 'technique: T1059*', key: 'search', val: 'T1059' }
];

export default function KibanaSearchBar({ 
  searchQuery, 
  onSearchChange, 
  activeFilter, 
  onFilterChange, 
  events,
  onRefresh
}) {
  const [timeRange, setTimeRange] = useState('All Time (Investigation Horizon)');

  // Build a mini time-series distribution histogram from events
  const domainHistogram = events.reduce((acc, e) => {
    acc[e.domain] = (acc[e.domain] || 0) + 1;
    return acc;
  }, {});

  const total = events.length || 1;

  return (
    <div className="bg-[#0B0F19] border border-slate-800 rounded-xl p-3.5 space-y-3 shadow-xl">
      
      {/* Top Search Bar (Kibana KQL / Splunk Search Bar) */}
      <div className="flex flex-col md:flex-row items-stretch md:items-center gap-2.5">
        <div className="relative flex-1">
          <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-500">
            <Search className="w-4 h-4 text-cyan-400" />
          </div>
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => onSearchChange(e.target.value)}
            placeholder='KQL: domain: "endpoint" AND process.name: powershell* (or type any host, IP, user, hash)...'
            className="w-full bg-[#050811] border border-slate-700/80 rounded-lg pl-9 pr-8 py-2 text-xs font-mono text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500/30 transition"
          />
          {searchQuery && (
            <button
              onClick={() => onSearchChange('')}
              className="absolute inset-y-0 right-0 pr-3 flex items-center text-slate-400 hover:text-slate-200"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          )}
        </div>

        {/* Date Range Selector */}
        <div className="flex items-center gap-2">
          <div className="flex items-center gap-1.5 bg-[#050811] border border-slate-800 rounded-lg px-2.5 py-2 text-xs text-slate-300 font-mono">
            <Calendar className="w-3.5 h-3.5 text-blue-400" />
            <select
              value={timeRange}
              onChange={(e) => setTimeRange(e.target.value)}
              className="bg-transparent focus:outline-none cursor-pointer text-slate-200 text-xs"
            >
              <option value="All Time" className="bg-slate-900">All Timeline Horizon</option>
              <option value="15m" className="bg-slate-900">Last 15 minutes</option>
              <option value="1h" className="bg-slate-900">Last 1 hour</option>
              <option value="24h" className="bg-slate-900">Last 24 hours</option>
            </select>
          </div>

          {/* Refresh Button */}
          <button
            onClick={onRefresh}
            className="p-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-800 transition"
            title="Refresh query results"
          >
            <RefreshCw className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Quick KQL / Filter Chips */}
      <div className="flex items-center gap-1.5 overflow-x-auto pb-1 scrollbar-thin text-xs">
        <span className="text-[10px] font-mono font-bold text-slate-500 uppercase flex-shrink-0 flex items-center gap-1">
          <Filter className="w-3 h-3 text-cyan-400" /> Quick KQL:
        </span>
        {QUICK_FILTERS.map((chip, idx) => {
          const isActive = searchQuery.toLowerCase().includes(chip.val.toLowerCase());
          return (
            <button
              key={idx}
              onClick={() => {
                if (isActive) {
                  onSearchChange('');
                } else {
                  onSearchChange(chip.val);
                }
              }}
              className={`flex-shrink-0 px-2 py-0.5 rounded text-[11px] font-mono border transition ${
                isActive
                  ? 'bg-cyan-950/80 border-cyan-400 text-cyan-300 font-bold glow-blue'
                  : 'bg-slate-950/80 border-slate-800 text-slate-400 hover:text-slate-200 hover:bg-slate-900'
              }`}
            >
              {chip.label}
            </button>
          );
        })}
      </div>

      {/* Elastic / Splunk Style Time-Series Alert Spike Histogram */}
      <div className="bg-[#050811] border border-slate-800/80 rounded-lg p-2.5 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <BarChart2 className="w-4 h-4 text-indigo-400" />
          <span className="text-[11px] font-mono font-bold text-slate-300 uppercase">
            Alert Volume Distribution by Ingestion Domain:
          </span>
        </div>

        {/* Multi-Domain Stacked Distribution Bar */}
        <div className="flex items-center gap-2 flex-1 max-w-md">
          <div className="w-full h-3 rounded-full bg-slate-900 overflow-hidden flex shadow-inner">
            {domainHistogram.endpoint && (
              <div 
                style={{ width: `${(domainHistogram.endpoint / total) * 100}%` }}
                className="bg-blue-500 hover:opacity-80 transition-all"
                title={`Endpoint: ${domainHistogram.endpoint} events`}
              />
            )}
            {domainHistogram.auth && (
              <div 
                style={{ width: `${(domainHistogram.auth / total) * 100}%` }}
                className="bg-amber-500 hover:opacity-80 transition-all"
                title={`Auth: ${domainHistogram.auth} events`}
              />
            )}
            {domainHistogram.network && (
              <div 
                style={{ width: `${(domainHistogram.network / total) * 100}%` }}
                className="bg-emerald-500 hover:opacity-80 transition-all"
                title={`Network: ${domainHistogram.network} events`}
              />
            )}
            {domainHistogram.cloud && (
              <div 
                style={{ width: `${(domainHistogram.cloud / total) * 100}%` }}
                className="bg-purple-500 hover:opacity-80 transition-all"
                title={`Cloud: ${domainHistogram.cloud} events`}
              />
            )}
          </div>
          <span className="text-[10px] font-mono text-slate-400 flex-shrink-0">
            {events.length} total
          </span>
        </div>

        <div className="flex items-center gap-3 text-[10px] font-mono text-slate-400 flex-wrap">
          <span className="flex items-center gap-1">
            <span className="w-2 h-2 rounded bg-blue-500" /> EP: {domainHistogram.endpoint || 0}
          </span>
          <span className="flex items-center gap-1">
            <span className="w-2 h-2 rounded bg-amber-500" /> AUTH: {domainHistogram.auth || 0}
          </span>
          <span className="flex items-center gap-1">
            <span className="w-2 h-2 rounded bg-emerald-500" /> NET: {domainHistogram.network || 0}
          </span>
          <span className="flex items-center gap-1">
            <span className="w-2 h-2 rounded bg-purple-500" /> CLD: {domainHistogram.cloud || 0}
          </span>
        </div>
      </div>

    </div>
  );
}
