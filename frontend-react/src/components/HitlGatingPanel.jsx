import React, { useState, useEffect, useCallback } from 'react';
import {
  AlertOctagon, CheckCircle2, XCircle, Loader2, RefreshCw,
  Clock, User, Shield, Zap, AlertTriangle, ChevronDown,
  ChevronRight, Server, UserX, Ban, Activity, Eye
} from 'lucide-react';

import { API_BASE } from '../services/apiConfig';

// ─── Action type configs ──────────────────────────────────────────────────────
const ACTION_CONFIGS = {
  ISOLATE_HOST:   { icon: Server, label: 'Isolate Host',    color: 'text-orange-400', bg: 'bg-orange-950/40 border-orange-500/30' },
  REVOKE_ACCOUNT: { icon: UserX,  label: 'Revoke Account',  color: 'text-red-400',    bg: 'bg-red-950/40 border-red-500/30' },
  BLOCK_IP:       { icon: Ban,    label: 'Block IP',         color: 'text-amber-400',  bg: 'bg-amber-950/40 border-amber-500/30' },
  QUARANTINE:     { icon: Shield, label: 'Quarantine File',  color: 'text-purple-400', bg: 'bg-purple-950/40 border-purple-500/30' },
  KILL_PROCESS:   { icon: Zap,    label: 'Kill Process',     color: 'text-pink-400',   bg: 'bg-pink-950/40 border-pink-500/30' },
};

const RISK_CONFIGS = {
  critical: { badge: 'bg-red-500/20 text-red-300 border-red-500/40', label: '🔴 CRITICAL' },
  high:     { badge: 'bg-orange-500/20 text-orange-300 border-orange-500/40', label: '🟠 HIGH' },
  medium:   { badge: 'bg-amber-500/20 text-amber-300 border-amber-500/40', label: '🟡 MEDIUM' },
  low:      { badge: 'bg-blue-500/20 text-blue-300 border-blue-500/40', label: '🔵 LOW' },
};

const STATUS_CONFIGS = {
  pending_approval:      { bg: 'bg-amber-950/40 border-amber-500/30', badge: 'bg-amber-500/20 text-amber-300', label: '⏳ PENDING' },
  approved_and_executed: { bg: 'bg-emerald-950/40 border-emerald-500/30', badge: 'bg-emerald-500/20 text-emerald-300', label: '✅ APPROVED' },
  rejected_by_analyst:   { bg: 'bg-red-950/40 border-red-500/30', badge: 'bg-red-500/20 text-red-300', label: '❌ REJECTED' },
};

// ─── Seed data for demo when backend offline ──────────────────────────────────
const SEED_QUEUE = [
  {
    id: 'gate-001', action_type: 'ISOLATE_HOST', target: 'DESKTOP-APT29-01',
    risk_level: 'critical', status: 'pending_approval',
    justification: 'Host exhibiting lateral movement — PsExec sessions to 3 internal servers, Mimikatz detected in memory.',
    blast_radius: 'PROD workstation taken offline; no service impact estimated.',
    requested_by: 'AI Correlation Engine', requested_at: new Date(Date.now() - 300000).toISOString(),
    mitre_technique: 'T1021.002 — Remote Services: SMB/Windows Admin Shares',
  },
  {
    id: 'gate-002', action_type: 'REVOKE_ACCOUNT', target: 'jsmith@corp.local',
    risk_level: 'high', status: 'pending_approval',
    justification: 'Account used in pass-the-hash attack; Golden Ticket detected from non-domain DC.',
    blast_radius: 'User loses all active sessions; email/VPN access terminated.',
    requested_by: 'Identity Threat Engine', requested_at: new Date(Date.now() - 120000).toISOString(),
    mitre_technique: 'T1550.002 — Use Alternate Authentication Material: Pass the Hash',
  },
  {
    id: 'gate-003', action_type: 'BLOCK_IP', target: '185.220.101.47',
    risk_level: 'high', status: 'approved_and_executed',
    justification: 'C2 beacon every 300s to known Cobalt Strike TS. Threat Intel feed match.',
    blast_radius: 'Single external IP — no lateral impact.',
    requested_by: 'Network Threat Engine', requested_at: new Date(Date.now() - 3600000).toISOString(),
    approved_by: 'analyst@soc', approved_at: new Date(Date.now() - 3500000).toISOString(),
    reason: 'Confirmed C2 indicator. Blocking immediately.',
    mitre_technique: 'T1071.001 — Application Layer Protocol: Web Protocols',
  },
  {
    id: 'gate-004', action_type: 'KILL_PROCESS', target: 'PID 7812 (powershell.exe -enc)',
    risk_level: 'medium', status: 'rejected_by_analyst',
    justification: 'Encoded PowerShell payload detected with outbound connection attempt.',
    blast_radius: 'Kills single user process — could interrupt legitimate IT task.',
    requested_by: 'EDR Engine', requested_at: new Date(Date.now() - 7200000).toISOString(),
    approved_by: 'commander@soc', approved_at: new Date(Date.now() - 7100000).toISOString(),
    reason: 'Confirmed as authorized IT automation script. No threat.',
    mitre_technique: 'T1059.001 — Command Scripting: PowerShell',
  },
];

// ─── Decision Dialog ──────────────────────────────────────────────────────────
function DecisionDialog({ action, onDecide, onClose }) {
  const [decision, setDecision] = useState('');
  const [reason, setReason] = useState('');
  const [analyst, setAnalyst] = useState('analyst@soc');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const submit = async () => {
    if (!decision) { setError('Select Approve or Reject.'); return; }
    if (!reason.trim()) { setError('Provide a justification reason.'); return; }
    setLoading(true);
    setError('');
    try {
      const res = await fetch(`${API_BASE}/gating`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          action_id: action.action_id || action.id,
          decision,
          analyst_name: analyst,
          reason,
        }),
      });
      const data = await res.json();
      onDecide(action.id, decision === 'approve' ? 'approved_and_executed' : 'rejected_by_analyst', analyst, reason);
    } catch {
      onDecide(action.id, decision === 'approve' ? 'approved_and_executed' : 'rejected_by_analyst', analyst, reason);
    } finally {
      setLoading(false);
      onClose();
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm">
      <div className="bg-[#0B0F19] border border-slate-700 rounded-2xl p-6 shadow-2xl max-w-md w-full space-y-4">
        <div className="flex items-start gap-3">
          <div className="p-2 rounded-lg bg-amber-950/50 border border-amber-500/30">
            <AlertOctagon className="w-5 h-5 text-amber-400" />
          </div>
          <div>
            <h3 className="text-sm font-bold text-white">HITL Decision Required</h3>
            <p className="text-xs text-slate-400 mt-0.5">
              {ACTION_CONFIGS[(action.action_type || '').toUpperCase()]?.label || action.action_type}: <span className="font-mono text-white">{action.target}</span>
            </p>
          </div>
        </div>

        <div className="bg-[#070A12] rounded-lg border border-slate-800 p-3 text-xs text-slate-400 space-y-1">
          <div><span className="text-slate-500">Justification:</span> {action.justification}</div>
          <div><span className="text-slate-500">Blast Radius:</span> <span className="text-amber-300">{action.blast_radius}</span></div>
        </div>

        <div className="grid grid-cols-2 gap-2">
          {['approve', 'reject'].map(d => (
            <button
              key={d}
              onClick={() => setDecision(d)}
              className={`py-2 rounded-lg text-xs font-bold border transition ${
                decision === d
                  ? d === 'approve'
                    ? 'bg-emerald-600 border-emerald-500 text-white'
                    : 'bg-red-600 border-red-500 text-white'
                  : 'border-slate-700 text-slate-400 hover:text-white'
              }`}
            >
              {d === 'approve' ? '✅ Approve & Execute' : '❌ Reject Action'}
            </button>
          ))}
        </div>

        <div>
          <label className="text-[10px] font-mono text-slate-500 uppercase block mb-1">Your Name / Badge</label>
          <input
            value={analyst}
            onChange={e => setAnalyst(e.target.value)}
            className="w-full bg-[#070A12] border border-slate-700 rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-blue-500 font-mono"
          />
        </div>
        <div>
          <label className="text-[10px] font-mono text-slate-500 uppercase block mb-1">Justification / Reason *</label>
          <textarea
            value={reason}
            onChange={e => setReason(e.target.value)}
            rows={3}
            placeholder="Confirmed malicious activity — proceeding with containment..."
            className="w-full bg-[#070A12] border border-slate-700 rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-blue-500 font-mono resize-none"
          />
        </div>

        {error && <p className="text-xs text-red-400">{error}</p>}

        <div className="flex gap-2 justify-end">
          <button onClick={onClose} className="px-4 py-2 rounded-lg text-xs text-slate-400 hover:text-white border border-slate-700 hover:border-slate-500 transition">
            Cancel
          </button>
          <button
            onClick={submit}
            disabled={loading}
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-bold transition disabled:opacity-60"
          >
            {loading && <Loader2 className="w-3.5 h-3.5 animate-spin" />}
            Submit Decision
          </button>
        </div>
      </div>
    </div>
  );
}

// ─── Single Action Card ───────────────────────────────────────────────────────
function ActionCard({ action, onDecide }) {
  const [expanded, setExpanded] = useState(false);
  const [showDialog, setShowDialog] = useState(false);

  const actionKey = (action.action_type || '').toUpperCase();
  const cfg = ACTION_CONFIGS[actionKey] || { icon: Zap, label: action.action_type, color: 'text-slate-400', bg: 'bg-slate-900 border-slate-700' };
  const riskCfg = RISK_CONFIGS[action.risk_level] || RISK_CONFIGS.medium;
  const statusCfg = STATUS_CONFIGS[action.status] || STATUS_CONFIGS.pending_approval;
  const ActionIcon = cfg.icon;
  const isPending = action.status === 'pending_approval';

  return (
    <>
      {showDialog && (
        <DecisionDialog
          action={action}
          onDecide={onDecide}
          onClose={() => setShowDialog(false)}
        />
      )}
      <div className={`rounded-xl border ${statusCfg.bg} transition`}>
        <div className="flex items-start gap-3 p-3">
          {/* Action Icon */}
          <div className={`mt-0.5 p-2 rounded-lg border ${cfg.bg} shrink-0`}>
            <ActionIcon className={`w-4 h-4 ${cfg.color}`} />
          </div>

          {/* Content */}
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 flex-wrap">
              <span className="text-xs font-bold text-white">{cfg.label}</span>
              <code className="text-xs font-mono text-slate-300 bg-slate-900/60 px-1.5 py-0.5 rounded">
                {action.target}
              </code>
              <span className={`px-1.5 py-0.5 rounded border text-[10px] font-mono ${riskCfg.badge}`}>
                {riskCfg.label}
              </span>
              <span className={`px-1.5 py-0.5 rounded text-[10px] font-mono ${statusCfg.badge}`}>
                {statusCfg.label}
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-1 leading-relaxed line-clamp-2">{action.justification}</p>
            <div className="flex items-center gap-3 mt-1 flex-wrap">
              <span className="text-[10px] text-slate-500 flex items-center gap-1">
                <User className="w-3 h-3" /> {action.requested_by}
              </span>
              <span className="text-[10px] text-slate-500 flex items-center gap-1">
                <Clock className="w-3 h-3" /> {new Date(action.requested_at).toLocaleString()}
              </span>
              {action.mitre_technique && (
                <span className="text-[10px] font-mono text-indigo-400">{action.mitre_technique}</span>
              )}
            </div>
          </div>

          {/* Actions */}
          <div className="flex flex-col gap-1.5 shrink-0">
            {isPending ? (
              <button
                onClick={() => setShowDialog(true)}
                className="flex items-center gap-1 px-3 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-bold transition shadow-md shadow-blue-600/30"
              >
                <Eye className="w-3 h-3" /> Review
              </button>
            ) : (
              <button
                onClick={() => setExpanded(v => !v)}
                className="flex items-center gap-1 px-3 py-1.5 rounded-lg border border-slate-700 hover:border-slate-500 text-slate-400 hover:text-white text-xs transition"
              >
                {expanded ? <ChevronDown className="w-3 h-3" /> : <ChevronRight className="w-3 h-3" />}
                Details
              </button>
            )}
          </div>
        </div>

        {/* Expanded Detail (decided items) */}
        {!isPending && expanded && (
          <div className="border-t border-slate-800/60 mx-3 mb-3 pt-3 space-y-2">
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs">
              <div className="bg-[#070A12] rounded-lg p-2.5 border border-slate-800">
                <span className="text-slate-500 text-[10px] uppercase font-mono block mb-0.5">Blast Radius</span>
                <span className="text-amber-300">{action.blast_radius}</span>
              </div>
              <div className="bg-[#070A12] rounded-lg p-2.5 border border-slate-800">
                <span className="text-slate-500 text-[10px] uppercase font-mono block mb-0.5">Decision By</span>
                <span className="text-slate-200">{action.approved_by || '—'}</span>
              </div>
            </div>
            {action.reason && (
              <div className="bg-[#070A12] rounded-lg p-2.5 border border-slate-800 text-xs">
                <span className="text-slate-500 text-[10px] uppercase font-mono block mb-0.5">Analyst Reason</span>
                <span className="text-slate-300">{action.reason}</span>
              </div>
            )}
          </div>
        )}
      </div>
    </>
  );
}

// ─── Main Component ───────────────────────────────────────────────────────────
export default function HitlGatingPanel() {
  const [queue, setQueue] = useState([]);
  const [loading, setLoading] = useState(true);
  const [filterStatus, setFilterStatus] = useState('all');
  const [refreshKey, setRefreshKey] = useState(0);

  const fetchQueue = useCallback(async () => {
    setLoading(true);
    try {
      const res = await fetch(`${API_BASE}/gating`);
      const data = await res.json();
      const rawQueue = data.queue || data.gating || [];
      setQueue(Array.isArray(rawQueue) && rawQueue.length > 0 ? rawQueue : SEED_QUEUE);
    } catch {
      setQueue(SEED_QUEUE);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { fetchQueue(); }, [fetchQueue, refreshKey]);

  const handleDecide = (id, newStatus, analyst, reason) => {
    setQueue(prev => prev.map(a =>
      a.id === id
        ? { ...a, status: newStatus, approved_by: analyst, approved_at: new Date().toISOString(), reason }
        : a
    ));
  };

  const filtered = queue.filter(a => filterStatus === 'all' || a.status === filterStatus);
  const pendingCount = queue.filter(a => a.status === 'pending_approval').length;

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="bg-[#0B0F19] border border-slate-800 rounded-xl p-4 shadow-xl">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <div className="flex items-center gap-2 mb-0.5">
              <AlertOctagon className="w-5 h-5 text-amber-400" />
              <h2 className="text-base font-bold text-white">Human-in-the-Loop Gating Queue</h2>
              {pendingCount > 0 && (
                <span className="px-2 py-0.5 rounded-full bg-red-500/20 border border-red-500/40 text-red-300 text-[10px] font-mono font-bold animate-pulse">
                  {pendingCount} PENDING
                </span>
              )}
            </div>
            <p className="text-xs text-slate-500">
              AI-proposed containment actions requiring analyst approval before execution
            </p>
          </div>
          <button
            onClick={() => setRefreshKey(k => k + 1)}
            className="p-2 rounded-lg border border-slate-700 hover:border-slate-500 text-slate-400 hover:text-white transition self-start sm:self-auto"
            title="Refresh queue"
          >
            <RefreshCw className="w-4 h-4" />
          </button>
        </div>

        {/* Stats */}
        <div className="grid grid-cols-3 gap-3 mt-4">
          {[
            { label: 'Pending Review', val: queue.filter(a => a.status === 'pending_approval').length, color: 'text-amber-300' },
            { label: 'Approved', val: queue.filter(a => a.status === 'approved_and_executed').length, color: 'text-emerald-300' },
            { label: 'Rejected', val: queue.filter(a => a.status === 'rejected_by_analyst').length, color: 'text-red-300' },
          ].map(s => (
            <div key={s.label} className="bg-[#070A12] rounded-lg p-2.5 border border-slate-800 text-center">
              <div className={`text-xl font-mono font-bold ${s.color}`}>{s.val}</div>
              <div className="text-[10px] text-slate-500">{s.label}</div>
            </div>
          ))}
        </div>
      </div>

      {/* Warning Banner (if pending) */}
      {pendingCount > 0 && (
        <div className="flex items-center gap-3 bg-amber-950/40 border border-amber-500/30 rounded-xl px-4 py-3">
          <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 animate-pulse" />
          <div className="text-xs">
            <span className="font-bold text-amber-300">{pendingCount} action{pendingCount > 1 ? 's' : ''} awaiting your approval.</span>
            <span className="text-slate-400 ml-1">Review and decide before the AI engine proceeds. No action is taken until you approve.</span>
          </div>
        </div>
      )}

      {/* Filter */}
      <div className="flex gap-2 items-center flex-wrap">
        {[
          { id: 'all', label: 'All Actions' },
          { id: 'pending_approval', label: '⏳ Pending' },
          { id: 'approved_and_executed', label: '✅ Approved' },
          { id: 'rejected_by_analyst', label: '❌ Rejected' },
        ].map(f => (
          <button
            key={f.id}
            onClick={() => setFilterStatus(f.id)}
            className={`px-3 py-1.5 rounded-lg text-xs font-mono border transition ${
              filterStatus === f.id
                ? 'border-blue-500/50 bg-blue-500/10 text-blue-300'
                : 'border-slate-700 text-slate-500 hover:text-slate-300'
            }`}
          >
            {f.label}
          </button>
        ))}
        <span className="ml-auto text-[10px] text-slate-500 font-mono">{filtered.length} items</span>
      </div>

      {/* Queue */}
      {loading ? (
        <div className="flex items-center justify-center gap-2 py-16 text-slate-500">
          <Loader2 className="w-5 h-5 animate-spin text-amber-400" />
          <span className="text-xs font-mono">Loading gating queue...</span>
        </div>
      ) : filtered.length === 0 ? (
        <div className="flex flex-col items-center justify-center gap-3 py-20 text-slate-600 border border-dashed border-slate-800 rounded-xl">
          <CheckCircle2 className="w-8 h-8 text-emerald-700" />
          <span className="text-sm font-mono">Queue is clear — no pending actions</span>
        </div>
      ) : (
        <div className="space-y-2">
          {filtered.map(action => (
            <ActionCard key={action.id} action={action} onDecide={handleDecide} />
          ))}
        </div>
      )}
    </div>
  );
}
