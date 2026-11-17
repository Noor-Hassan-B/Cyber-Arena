import React, { useState } from 'react';
import { 
  Clock, 
  Search, 
  Filter, 
  ExternalLink, 
  ShieldAlert, 
  Terminal, 
  Globe, 
  Cloud, 
  Key,
  ChevronRight,
  ChevronDown
} from 'lucide-react';

export default function TimelineView({ events, onSelectEvent, selectedEventUuid }) {
  const [domainFilter, setDomainFilter] = useState('ALL');
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [searchTerm, setSearchTerm] = useState('');

  const filteredEvents = events.filter(evt => {
    if (domainFilter !== 'ALL' && evt.domain !== domainFilter) return false;
    if (severityFilter !== 'ALL' && evt.severity !== severityFilter) return false;
    if (searchTerm) {
      const q = searchTerm.toLowerCase();
      const matchText = `${evt.event_uuid} ${evt.event_type} ${evt.source_host || ''} ${evt.dest_host || ''} ${evt.user_id || ''} ${evt.command_line || ''} ${evt.mitre_technique_id || ''}`.toLowerCase();
      if (!matchText.includes(q)) return false;
    }
    return true;
  });

  const getDomainIcon = (domain) => {
    switch (domain) {
      case 'endpoint':
        return <Terminal className="w-3.5 h-3.5 text-blue-400" />;
      case 'auth':
        return <Key className="w-3.5 h-3.5 text-amber-400" />;
      case 'network':
        return <Globe className="w-3.5 h-3.5 text-emerald-400" />;
      case 'cloud':
        return <Cloud className="w-3.5 h-3.5 text-purple-400" />;
      default:
        return <ShieldAlert className="w-3.5 h-3.5 text-slate-400" />;
    }
  };

  const getSeverityBadge = (severity) => {
    switch (severity) {
      case 'critical':
        return 'bg-red-500/10 border-red-500/30 text-red-400';
      case 'high':
        return 'bg-amber-500/10 border-amber-500/30 text-amber-400';
      case 'medium':
        return 'bg-yellow-500/10 border-yellow-500/30 text-yellow-300';
      default:
        return 'bg-blue-500/10 border-blue-500/30 text-blue-300';
    }
  };

  return (
    <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-4 sm:p-5 shadow-xl space-y-4">
      {/* Top Header & Filters */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 border-b border-slate-800/80 pb-3">
        <div>
          <div className="flex items-center gap-2">
            <Clock className="w-4 h-4 text-blue-400" />
            <h2 className="text-sm font-bold text-slate-100">
              Correlated Incident Event Timeline & Causality Stream
            </h2>
            <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300">
              {filteredEvents.length} events
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-0.5">
            Chronological attack reconstruction with multi-domain telemetry linkage.
          </p>
        </div>

        {/* Filter Controls */}
        <div className="flex flex-wrap items-center gap-2">
          {/* Search Box */}
          <div className="relative">
            <Search className="w-3.5 h-3.5 text-slate-400 absolute left-2.5 top-2.5" />
            <input
              type="text"
              placeholder="Search telemetry..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="bg-slate-950/80 border border-slate-800 rounded-lg pl-8 pr-3 py-1 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-blue-500"
            />
          </div>

          {/* Domain Dropdown */}
          <select
            value={domainFilter}
            onChange={(e) => setDomainFilter(e.target.value)}
            className="bg-slate-950/80 border border-slate-800 rounded-lg px-2.5 py-1 text-xs text-slate-300 focus:outline-none focus:border-blue-500"
          >
            <option value="ALL">All Domains</option>
            <option value="endpoint">Endpoint (EDR)</option>
            <option value="auth">Identity / Auth</option>
            <option value="network">Network (Zeek/Netflow)</option>
            <option value="cloud">Cloud (CloudTrail/S3)</option>
          </select>

          {/* Severity Dropdown */}
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="bg-slate-950/80 border border-slate-800 rounded-lg px-2.5 py-1 text-xs text-slate-300 focus:outline-none focus:border-blue-500"
          >
            <option value="ALL">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
        </div>
      </div>

      {/* Timeline Stream */}
      <div className="relative pl-6 space-y-4 before:absolute before:left-2.5 before:top-3 before:bottom-3 before:w-0.5 before:bg-slate-800 max-h-[520px] overflow-y-auto pr-1">
        {filteredEvents.map((evt, idx) => {
          const isSelected = selectedEventUuid === evt.event_uuid;

          return (
            <div
              key={evt.event_uuid}
              onClick={() => onSelectEvent(evt.event_uuid)}
              className={`relative group cursor-pointer transition-all duration-200 ${
                isSelected ? 'scale-[1.01]' : ''
              }`}
            >
              {/* Timeline Marker Dot */}
              <div
                className={`absolute -left-[27px] top-3.5 w-3.5 h-3.5 rounded-full border-2 transition-all ${
                  isSelected
                    ? 'bg-blue-500 border-white ring-4 ring-blue-500/30'
                    : evt.severity === 'critical'
                    ? 'bg-red-500 border-slate-900 group-hover:ring-2 group-hover:ring-red-400'
                    : evt.severity === 'high'
                    ? 'bg-amber-500 border-slate-900'
                    : 'bg-slate-600 border-slate-900'
                }`}
              />

              {/* Event Card */}
              <div
                className={`p-3.5 rounded-xl border transition-all ${
                  isSelected
                    ? 'bg-blue-950/40 border-blue-500 shadow-lg shadow-blue-500/10'
                    : 'bg-slate-950/60 border-slate-800/90 hover:border-slate-700 hover:bg-slate-900/60'
                }`}
              >
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="font-mono text-xs font-bold text-slate-300">
                      {evt.timestamp}
                    </span>
                    <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-400">
                      {evt.event_uuid}
                    </span>
                    <span className={`flex items-center gap-1 text-[11px] font-mono uppercase px-2 py-0.5 rounded border ${
                      getSeverityBadge(evt.severity)
                    }`}>
                      {getDomainIcon(evt.domain)}
                      {evt.domain}
                    </span>
                    <span className={`text-[10px] font-mono uppercase px-1.5 py-0.5 rounded border ${
                      getSeverityBadge(evt.severity)
                    }`}>
                      {evt.severity}
                    </span>
                  </div>

                  {evt.mitre_technique_id && (
                    <div className="flex items-center gap-1 text-xs font-mono text-indigo-400 self-start sm:self-auto">
                      <span className="px-2 py-0.5 rounded bg-indigo-950/50 border border-indigo-800/60">
                        {evt.mitre_technique_id} &bull; {evt.mitre_tactic}
                      </span>
                    </div>
                  )}
                </div>

                {/* Primary Action / Command Line */}
                <div className="mt-2 text-xs text-slate-200">
                  <div className="font-semibold text-slate-100 mb-0.5">
                    {evt.mitre_technique_name || evt.event_type}
                  </div>
                  {evt.command_line && (
                    <div className="font-mono text-[11px] bg-slate-900 p-2 rounded border border-slate-800/80 text-slate-300 break-all select-all">
                      {evt.command_line}
                    </div>
                  )}
                </div>

                {/* Entity Context Footprint */}
                <div className="flex flex-wrap items-center gap-3 mt-2 text-[11px] text-slate-400 font-mono">
                  {evt.user_id && (
                    <span>
                      User: <strong className="text-slate-300">{evt.user_id}</strong>
                    </span>
                  )}
                  {evt.source_host && (
                    <span>
                      Source: <strong className="text-slate-300">{evt.source_host}</strong>
                    </span>
                  )}
                  {evt.dest_host && (
                    <span>
                      Target: <strong className="text-slate-300">{evt.dest_host}</strong>
                    </span>
                  )}
                  {evt.source_ip && (
                    <span>
                      SrcIP: <strong className="text-slate-300">{evt.source_ip}</strong>
                    </span>
                  )}
                  {evt.dest_ip && (
                    <span>
                      DstIP: <strong className="text-slate-300">{evt.dest_ip}</strong>
                    </span>
                  )}
                  {evt.cloud_service && (
                    <span>
                      Cloud: <strong className="text-purple-300">{evt.cloud_service}::{evt.cloud_action}</strong>
                    </span>
                  )}
                </div>

                <div className="mt-2 pt-2 border-t border-slate-800/60 flex items-center justify-between text-[11px]">
                  <span className="text-slate-400 italic">
                    Click card to drill into raw JSON payload and forensic evidence.
                  </span>
                  <span className="text-blue-400 flex items-center gap-1 font-medium group-hover:translate-x-0.5 transition-transform">
                    Inspect Evidence <ChevronRight className="w-3.5 h-3.5" />
                  </span>
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
