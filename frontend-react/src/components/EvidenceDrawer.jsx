import React, { useState } from 'react';
import { 
  X, 
  ShieldAlert, 
  Terminal, 
  Key, 
  Globe, 
  Cloud, 
  Copy, 
  Check, 
  ExternalLink, 
  Fingerprint, 
  Calendar, 
  User, 
  Server,
  Lock,
  Radio,
  CheckCircle2,
  AlertOctagon
} from 'lucide-react';

export default function EvidenceDrawer({ event, onClose, onContainmentAction }) {
  const [copied, setCopied] = useState(false);
  const [containmentStatus, setContainmentStatus] = useState(null);

  if (!event) return null;

  const handleCopy = () => {
    navigator.clipboard.writeText(JSON.stringify(event, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleRemediate = (actionType) => {
    let msg = '';
    if (actionType === 'isolate') {
      msg = `Host ${event.source_host || 'Endpoint'} isolated via EDR agent. Network quarantine active.`;
    } else if (actionType === 'revoke') {
      msg = `Credentials for ${event.user_id || 'User'} revoked. Active tokens & Kerberos tickets invalidated.`;
    } else if (actionType === 'block_ip') {
      msg = `IP ${event.dest_ip || event.source_ip || 'C2 Node'} null-routed at perimeter firewall.`;
    }
    setContainmentStatus(msg);
    if (onContainmentAction) {
      onContainmentAction({ action: actionType, event, message: msg });
    }
    setTimeout(() => setContainmentStatus(null), 4000);
  };

  const getDomainIcon = (domain) => {
    switch (domain) {
      case 'endpoint':
        return <Terminal className="w-4 h-4 text-blue-400" />;
      case 'auth':
        return <Key className="w-4 h-4 text-amber-400" />;
      case 'network':
        return <Globe className="w-4 h-4 text-emerald-400" />;
      case 'cloud':
        return <Cloud className="w-4 h-4 text-purple-400" />;
      default:
        return <ShieldAlert className="w-4 h-4 text-slate-400" />;
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-end bg-black/60 backdrop-blur-sm animate-fadeIn">
      <div 
        className="w-full max-w-xl h-full bg-[#0B0F19] border-l border-slate-800 shadow-2xl flex flex-col overflow-hidden animate-slideLeft"
      >
        {/* Drawer Header */}
        <div className="p-4 sm:p-5 border-b border-slate-800 flex items-center justify-between bg-slate-900/90">
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <span className="p-1.5 rounded-lg bg-blue-600/20 border border-blue-500/30">
                {getDomainIcon(event.domain)}
              </span>
              <span className="font-mono text-sm font-bold text-white">
                {event.event_uuid}
              </span>
              <span className="px-2 py-0.5 rounded text-[10px] font-mono uppercase bg-red-500/10 border border-red-500/30 text-red-400 font-bold">
                {event.severity}
              </span>
            </div>
            <p className="text-xs text-slate-400">
              Verified Forensic Telemetry Evidence Item
            </p>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={handleCopy}
              className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 transition text-xs flex items-center gap-1 font-mono"
              title="Copy JSON Payload"
            >
              {copied ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
            </button>
            <button
              onClick={onClose}
              className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 transition"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Remediation Action Banner if triggered */}
        {containmentStatus && (
          <div className="p-3 bg-emerald-950/80 border-b border-emerald-500/50 text-emerald-300 text-xs flex items-center gap-2 animate-fadeIn">
            <CheckCircle2 className="w-4 h-4 text-emerald-400 flex-shrink-0" />
            <span>{containmentStatus}</span>
          </div>
        )}

        {/* Drawer Body */}
        <div className="flex-1 overflow-y-auto p-4 sm:p-5 space-y-4 text-xs">
          
          {/* Containment Fast-Action Bar */}
          <div className="p-3.5 rounded-xl bg-slate-950 border border-red-500/30 space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-[11px] font-mono font-bold text-red-400 flex items-center gap-1.5 uppercase tracking-wide">
                <AlertOctagon className="w-4 h-4" /> EDR / SOC Containment Playbook
              </span>
              <span className="text-[10px] text-slate-500 font-mono">Immediate Action</span>
            </div>
            <div className="flex flex-wrap gap-2 pt-1">
              {event.source_host && (
                <button
                  onClick={() => handleRemediate('isolate')}
                  className="px-2.5 py-1 text-xs font-semibold rounded bg-red-600/80 hover:bg-red-500 text-white flex items-center gap-1 shadow transition"
                >
                  <Lock className="w-3 h-3" /> Isolate Host ({event.source_host})
                </button>
              )}
              {event.user_id && (
                <button
                  onClick={() => handleRemediate('revoke')}
                  className="px-2.5 py-1 text-xs font-semibold rounded bg-amber-600/80 hover:bg-amber-500 text-white flex items-center gap-1 shadow transition"
                >
                  <Key className="w-3 h-3" /> Revoke Account ({event.user_id})
                </button>
              )}
              {(event.dest_ip || event.source_ip) && (
                <button
                  onClick={() => handleRemediate('block_ip')}
                  className="px-2.5 py-1 text-xs font-semibold rounded bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 flex items-center gap-1 transition"
                >
                  <Radio className="w-3 h-3 text-red-400" /> Block IP ({event.dest_ip || event.source_ip})
                </button>
              )}
            </div>
          </div>

          {/* Metadata Grid */}
          <div className="grid grid-cols-2 gap-2.5 bg-slate-950/70 p-3.5 rounded-xl border border-slate-800">
            <div>
              <span className="text-[10px] font-mono text-slate-400 uppercase">Timestamp</span>
              <div className="font-mono text-slate-200 mt-0.5">{event.timestamp}</div>
            </div>
            <div>
              <span className="text-[10px] font-mono text-slate-400 uppercase">Domain</span>
              <div className="font-mono text-slate-200 uppercase mt-0.5">{event.domain}</div>
            </div>
            <div>
              <span className="text-[10px] font-mono text-slate-400 uppercase">Actor Identity</span>
              <div className="font-mono text-blue-400 mt-0.5">{event.user_id || 'System / N/A'}</div>
            </div>
            <div>
              <span className="text-[10px] font-mono text-slate-400 uppercase">Event Class</span>
              <div className="font-mono text-slate-200 mt-0.5">{event.event_type}</div>
            </div>
          </div>

          {/* MITRE Mapping */}
          {event.mitre_technique_id && (
            <div className="bg-indigo-950/30 border border-indigo-500/30 rounded-xl p-3.5 space-y-1">
              <span className="text-[10px] font-mono text-indigo-300 uppercase tracking-wider">
                MITRE ATT&CK Classification
              </span>
              <div className="flex items-center justify-between">
                <span className="font-mono font-bold text-indigo-200">
                  {event.mitre_technique_id} &bull; {event.mitre_technique_name}
                </span>
                <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-indigo-900/60 text-indigo-300">
                  Tactic: {event.mitre_tactic}
                </span>
              </div>
            </div>
          )}

          {/* Network / Endpoint Entities */}
          <div className="bg-slate-950/70 border border-slate-800 rounded-xl p-3.5 space-y-2">
            <span className="text-[10px] font-mono text-slate-400 uppercase">
              Host & Socket Topology
            </span>
            <div className="grid grid-cols-2 gap-3 font-mono text-[11px]">
              <div>
                <span className="text-slate-500">Source:</span>
                <div className="text-slate-200 font-semibold">{event.source_host || 'N/A'}</div>
                <div className="text-slate-400">{event.source_ip || ''}</div>
              </div>
              <div>
                <span className="text-slate-500">Destination:</span>
                <div className="text-slate-200 font-semibold">{event.dest_host || 'N/A'}</div>
                <div className="text-slate-400">{event.dest_ip || ''}</div>
              </div>
            </div>
          </div>

          {/* Process / Command Line */}
          {event.command_line && (
            <div className="bg-slate-950/70 border border-slate-800 rounded-xl p-3.5 space-y-1.5">
              <span className="text-[10px] font-mono text-slate-400 uppercase">
                Executed Command Line Telemetry
              </span>
              <div className="font-mono text-[11px] p-2.5 rounded bg-slate-900 border border-slate-800 text-amber-200 break-all select-all">
                {event.command_line}
              </div>
              {event.parent_process && (
                <div className="text-[11px] text-slate-400 font-mono">
                  Parent Process: <span className="text-slate-200">{event.parent_process}</span>
                </div>
              )}
            </div>
          )}

          {/* Cloud Specifics */}
          {event.cloud_service && (
            <div className="bg-purple-950/30 border border-purple-500/30 rounded-xl p-3.5 space-y-1">
              <span className="text-[10px] font-mono text-purple-300 uppercase">
                Cloud Telemetry (AWS CloudTrail / STS / S3)
              </span>
              <div className="font-mono text-slate-200">
                Service: <strong className="text-purple-300">{event.cloud_service}</strong> &bull; Action: <strong className="text-purple-300">{event.cloud_action}</strong>
              </div>
            </div>
          )}

          {/* Raw Payload JSON */}
          <div className="space-y-1.5">
            <span className="text-[10px] font-mono text-slate-400 uppercase">
              Raw Forensic Payload (JSON Telemetry)
            </span>
            <pre className="p-3 rounded-xl bg-slate-950 border border-slate-800 font-mono text-[11px] text-emerald-400 overflow-x-auto max-h-64 select-all">
              {JSON.stringify(event.raw_payload || event, null, 2)}
            </pre>
          </div>

        </div>

        {/* Footer */}
        <div className="p-4 border-t border-slate-800 bg-slate-900/80 flex items-center justify-between text-[11px] text-slate-400 font-mono">
          <span>Custody: Cryptographically Verified</span>
          <button
            onClick={onClose}
            className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-white font-medium"
          >
            Close Inspector
          </button>
        </div>
      </div>
    </div>
  );
}
