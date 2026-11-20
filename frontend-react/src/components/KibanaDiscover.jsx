import React, { useState } from 'react';
import { 
  Search, 
  Filter, 
  ChevronRight, 
  ChevronDown, 
  Copy, 
  Check, 
  Plus, 
  Minus, 
  Calendar, 
  Clock, 
  FileText, 
  ExternalLink,
  Layers,
  Terminal,
  ShieldAlert,
  Key,
  Globe,
  Cloud
} from 'lucide-react';

export default function KibanaDiscover({ 
  events, 
  allEvents = [], 
  isResetToZero = false, 
  onRestoreStats, 
  onSelectEvent, 
  selectedEventUuid 
}) {
  const [expandedRow, setExpandedRow] = useState(null);
  const [selectedFields, setSelectedFields] = useState(['domain', 'event_type', 'source_host', 'user_id', 'mitre_technique_id']);
  const [copiedUuid, setCopiedUuid] = useState(null);

  const availableFields = [
    { name: 'timestamp', type: 'date', label: '@timestamp' },
    { name: 'domain', type: 'keyword', label: 'event.domain' },
    { name: 'event_type', type: 'keyword', label: 'event.category' },
    { name: 'severity', type: 'keyword', label: 'event.severity' },
    { name: 'source_host', type: 'keyword', label: 'host.name' },
    { name: 'dest_host', type: 'keyword', label: 'destination.host' },
    { name: 'source_ip', type: 'ip', label: 'source.ip' },
    { name: 'dest_ip', type: 'ip', label: 'destination.ip' },
    { name: 'user_id', type: 'keyword', label: 'user.name' },
    { name: 'process_name', type: 'keyword', label: 'process.name' },
    { name: 'mitre_technique_id', type: 'keyword', label: 'threat.technique.id' },
    { name: 'mitre_tactic', type: 'keyword', label: 'threat.tactic.name' }
  ];

  const toggleField = (field) => {
    if (selectedFields.includes(field)) {
      setSelectedFields(selectedFields.filter(f => f !== field));
    } else {
      setSelectedFields([...selectedFields, field]);
    }
  };

  const handleCopyJson = (evt, e) => {
    e.stopPropagation();
    navigator.clipboard.writeText(JSON.stringify(evt, null, 2));
    setCopiedUuid(evt.event_uuid);
    setTimeout(() => setCopiedUuid(null), 2000);
  };

  const getDomainIcon = (domain) => {
    switch (domain) {
      case 'endpoint': return <Terminal className="w-3.5 h-3.5 text-blue-400" />;
      case 'auth': return <Key className="w-3.5 h-3.5 text-amber-400" />;
      case 'network': return <Globe className="w-3.5 h-3.5 text-emerald-400" />;
      case 'cloud': return <Cloud className="w-3.5 h-3.5 text-purple-400" />;
      default: return <ShieldAlert className="w-3.5 h-3.5 text-slate-400" />;
    }
  };

  const getSeverityBadge = (sev) => {
    switch (sev) {
      case 'critical': return 'bg-red-500/10 text-red-400 border border-red-500/30';
      case 'high': return 'bg-amber-500/10 text-amber-400 border border-amber-500/30';
      case 'medium': return 'bg-yellow-500/10 text-yellow-300 border border-yellow-500/30';
      default: return 'bg-blue-500/10 text-blue-300 border border-blue-500/30';
    }
  };

  return (
    <div className="bg-[#0D1117] border border-slate-800 rounded-xl overflow-hidden shadow-2xl flex flex-col">
      
      {/* Elastic / Kibana Discover Sub-header */}
      <div className="p-3 bg-slate-900/90 border-b border-slate-800 flex flex-wrap items-center justify-between gap-3 text-xs">
        <div className="flex items-center gap-3">
          <span className="font-bold text-slate-200 uppercase font-mono tracking-wide flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded bg-cyan-400" />
            Elastic Discover / Log Explorer
          </span>
          <span className="text-slate-400 font-mono text-[11px]">
            Showing <strong>{events.length}</strong> {isResetToZero ? 'live attack logs' : 'hits'}
          </span>
          {isResetToZero && (
            <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-amber-500/20 text-amber-300 border border-amber-500/40">
              Fresh Capture Mode
            </span>
          )}
        </div>
        <div className="text-[11px] text-slate-400 font-mono flex items-center gap-3">
          {isResetToZero && onRestoreStats && (
            <button
              onClick={onRestoreStats}
              className="text-cyan-400 hover:text-cyan-300 underline font-semibold flex items-center gap-1"
            >
              Restore All Historical Logs ({allEvents.length || 542}) &rarr;
            </button>
          )}
          <span>Index: <strong className="text-slate-300">security-events-*</strong></span>
          <span>&bull;</span>
          <span>Timefield: <strong className="text-slate-300">@timestamp</strong></span>
        </div>
      </div>

      {/* Main Discover Two-Column Layout */}
      <div className="flex flex-col md:flex-row min-h-[500px]">
        
        {/* Left Column: Field Selector Sidebar */}
        <div className="w-full md:w-56 bg-[#090D16] border-r border-slate-800 p-3 space-y-3 flex-shrink-0">
          <div>
            <span className="text-[10px] font-mono font-bold text-slate-400 uppercase tracking-wider block mb-1.5">
              Available Fields ({availableFields.length})
            </span>
            <div className="space-y-1">
              {availableFields.map(f => {
                const isSelected = selectedFields.includes(f.name);
                return (
                  <button
                    key={f.name}
                    onClick={() => toggleField(f.name)}
                    className={`w-full flex items-center justify-between px-2 py-1 rounded text-[11px] font-mono transition text-left ${
                      isSelected 
                        ? 'bg-blue-950/60 text-blue-300 border border-blue-800/80 font-bold' 
                        : 'text-slate-400 hover:bg-slate-900 hover:text-slate-200'
                    }`}
                  >
                    <span className="truncate">{f.label}</span>
                    <span className="text-[10px] opacity-70">
                      {isSelected ? '✓' : '+'}
                    </span>
                  </button>
                );
              })}
            </div>
          </div>
        </div>

        {/* Right Column: Elastic Data Table */}
        <div className="flex-1 overflow-x-auto bg-[#0B0F19]">
          <table className="w-full text-left border-collapse text-[11px] font-mono">
            <thead>
              <tr className="bg-slate-900 text-slate-400 border-b border-slate-800 select-none">
                <th className="p-2.5 w-8"></th>
                <th className="p-2.5">Time</th>
                {selectedFields.map(f => (
                  <th key={f} className="p-2.5">
                    {availableFields.find(af => af.name === f)?.label || f}
                  </th>
                ))}
                <th className="p-2.5 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-slate-300">
              {events.length === 0 ? (
                <tr>
                  <td colSpan={selectedFields.length + 3} className="p-8 text-center text-slate-400 font-mono text-xs">
                    <div className="flex flex-col items-center justify-center gap-2">
                      <ShieldAlert className="w-8 h-8 text-slate-500" />
                      <span className="font-semibold text-slate-300">No logs found matching current view</span>
                      {isResetToZero ? (
                        <span className="text-[11px] text-slate-500">
                          Baseline was reset to 0. Execute an attack in &ldquo;Attack Sequences&rdquo; to see new logs stream here, or click &ldquo;Restore All Historical Logs&rdquo; above.
                        </span>
                      ) : (
                        <span className="text-[11px] text-slate-500">
                          Try adjusting your search query or selecting a different scenario.
                        </span>
                      )}
                    </div>
                  </td>
                </tr>
              ) : (
                events.map((evt) => {
                const isExpanded = expandedRow === evt.event_uuid;
                const isSelected = selectedEventUuid === evt.event_uuid;

                return (
                  <React.Fragment key={evt.event_uuid}>
                    <tr
                      onClick={() => setExpandedRow(isExpanded ? null : evt.event_uuid)}
                      className={`hover:bg-slate-900/80 cursor-pointer transition ${
                        isSelected ? 'bg-blue-950/40' : ''
                      }`}
                    >
                      <td className="p-2.5 text-slate-500">
                        {isExpanded ? (
                          <ChevronDown className="w-3.5 h-3.5 text-blue-400" />
                        ) : (
                          <ChevronRight className="w-3.5 h-3.5" />
                        )}
                      </td>
                      <td className="p-2.5 whitespace-nowrap text-slate-400 font-semibold">
                        {evt.timestamp}
                      </td>

                      {selectedFields.map(f => (
                        <td key={f} className="p-2.5 max-w-xs truncate">
                          {f === 'domain' ? (
                            <span className="inline-flex items-center gap-1 uppercase font-bold text-slate-300">
                              {getDomainIcon(evt[f])}
                              {evt[f]}
                            </span>
                          ) : f === 'severity' ? (
                            <span className={`px-1.5 py-0.5 rounded text-[10px] uppercase font-bold ${getSeverityBadge(evt[f])}`}>
                              {evt[f]}
                            </span>
                          ) : f === 'mitre_technique_id' ? (
                            <span className="text-indigo-400 font-bold">
                              {evt[f] || '—'}
                            </span>
                          ) : (
                            <span>{evt[f] || '—'}</span>
                          )}
                        </td>
                      ))}

                      <td className="p-2.5 text-right whitespace-nowrap">
                        <div className="flex items-center justify-end gap-1.5" onClick={(e) => e.stopPropagation()}>
                          <button
                            onClick={() => onSelectEvent(evt.event_uuid)}
                            className="px-2 py-0.5 rounded bg-blue-600/30 hover:bg-blue-600/50 text-blue-300 border border-blue-500/40 text-[10px] font-bold"
                          >
                            Inspect
                          </button>
                          <button
                            onClick={(e) => handleCopyJson(evt, e)}
                            className="p-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300"
                            title="Copy JSON"
                          >
                            {copiedUuid === evt.event_uuid ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                          </button>
                        </div>
                      </td>
                    </tr>

                    {/* Expandable Kibana Document Detail Row */}
                    {isExpanded && (
                      <tr className="bg-slate-950">
                        <td colSpan={selectedFields.length + 3} className="p-4 border-b border-slate-800">
                          <div className="space-y-3">
                            <div className="flex items-center justify-between text-xs border-b border-slate-800/80 pb-2">
                              <span className="font-bold text-blue-400 flex items-center gap-1.5 font-mono">
                                <FileText className="w-3.5 h-3.5" />
                                Document ID: {evt.event_uuid}
                              </span>
                              <div className="flex items-center gap-2">
                                <button
                                  onClick={() => onSelectEvent(evt.event_uuid)}
                                  className="px-2.5 py-1 text-xs rounded bg-blue-600 hover:bg-blue-500 text-white font-sans font-semibold flex items-center gap-1"
                                >
                                  Open in Forensic Inspector <ExternalLink className="w-3 h-3" />
                                </button>
                              </div>
                            </div>

                            {/* Key-Value Breakdown Table */}
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-[11px] font-mono">
                              {Object.entries(evt).map(([k, v]) => {
                                if (k === 'raw_payload') return null;
                                return (
                                  <div key={k} className="flex items-start gap-2 p-1.5 rounded bg-slate-900 border border-slate-800/80">
                                    <span className="text-slate-500 w-32 flex-shrink-0 truncate">{k}:</span>
                                    <span className="text-slate-200 break-all select-all font-semibold">
                                      {typeof v === 'object' ? JSON.stringify(v) : String(v || 'null')}
                                    </span>
                                  </div>
                                );
                              })}
                            </div>

                            {/* Command Line highlight */}
                            {evt.command_line && (
                              <div className="space-y-1">
                                <span className="text-[10px] uppercase font-mono text-slate-500">process.command_line:</span>
                                <div className="p-2 rounded bg-slate-900 border border-slate-800 font-mono text-amber-300 text-xs break-all select-all">
                                  {evt.command_line}
                                </div>
                              </div>
                            )}

                            {/* Raw JSON Tree */}
                            <div className="space-y-1">
                              <span className="text-[10px] uppercase font-mono text-slate-500">raw_document_source:</span>
                              <pre className="p-3 rounded-lg bg-[#050811] border border-slate-800 text-emerald-400 text-[10px] overflow-x-auto max-h-48 select-all">
                                {JSON.stringify(evt, null, 2)}
                              </pre>
                            </div>
                          </div>
                        </td>
                      </tr>
                    )}
                  </React.Fragment>
                );
              }))}
            </tbody>
          </table>
        </div>

      </div>

    </div>
  );
}
