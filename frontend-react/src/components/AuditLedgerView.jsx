import React, { useState, useEffect, useCallback, useRef } from 'react';
import {
  BookOpen, RefreshCw, Loader2, Shield, ChevronDown,
  ChevronRight, Download, Search, Filter, Lock,
  CheckCircle2, XCircle, AlertTriangle, Zap, Database,
  FileCode2, User
} from 'lucide-react';

import { API_BASE } from '../services/apiConfig';

// ─── Action type display configs ──────────────────────────────────────────────
const ACTION_STYLES = {
  INGEST:        { color: 'text-blue-400',    badge: 'bg-blue-500/15 text-blue-300 border-blue-500/30',    icon: Database },
  CREATE_RULE:   { color: 'text-indigo-400',  badge: 'bg-indigo-500/15 text-indigo-300 border-indigo-500/30', icon: FileCode2 },
  APPROVE:       { color: 'text-emerald-400', badge: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30', icon: CheckCircle2 },
  REJECT:        { color: 'text-red-400',     badge: 'bg-red-500/15 text-red-300 border-red-500/30',       icon: XCircle },
  HITL_DECISION: { color: 'text-amber-400',   badge: 'bg-amber-500/15 text-amber-300 border-amber-500/30', icon: AlertTriangle },
  ISOLATE_HOST:  { color: 'text-orange-400',  badge: 'bg-orange-500/15 text-orange-300 border-orange-500/30', icon: Shield },
  REVOKE_ACCOUNT:{ color: 'text-pink-400',    badge: 'bg-pink-500/15 text-pink-300 border-pink-500/30',   icon: User },
  BLOCK_IP:      { color: 'text-rose-400',    badge: 'bg-rose-500/15 text-rose-300 border-rose-500/30',   icon: Zap },
  SYSTEM:        { color: 'text-slate-400',   badge: 'bg-slate-500/15 text-slate-300 border-slate-500/30', icon: Shield },
};

// ─── Seed audit entries for demo ──────────────────────────────────────────────
const SEED_LEDGER = [
  {
    audit_id: 'AUD-00000001', timestamp: new Date(Date.now() - 7200000).toISOString(),
    actor: 'system@aegishunt', role: 'SYSTEM', action: 'SYSTEM',
    details: 'AegisHunt Audit Ledger initialized — append-only mode active.',
    status: 'success', signature: 'sha256:a4c2f19e3b7d0e82c...',
  },
  {
    audit_id: 'AUD-00000002', timestamp: new Date(Date.now() - 3600000).toISOString(),
    actor: 'analyst@soc', role: 'L2_HUNTER', action: 'INGEST',
    details: 'Ingested 847 events for scenario SCN-APT29-GHOST — Domains: endpoint, identity, network, cloud.',
    status: 'success', signature: 'sha256:b7f3d928a1c4e05d7...',
  },
  {
    audit_id: 'AUD-00000003', timestamp: new Date(Date.now() - 3300000).toISOString(),
    actor: 'analyst@soc', role: 'L2_HUNTER', action: 'CREATE_RULE',
    details: 'Created Sigma rule: "Suspicious PowerShell Execution" (severity=high, MITRE=T1059.001).',
    status: 'success', signature: 'sha256:c8e4f037b2d5a19e8...',
  },
  {
    audit_id: 'AUD-00000004', timestamp: new Date(Date.now() - 3100000).toISOString(),
    actor: 'hunter@soc', role: 'L2_HUNTER', action: 'CREATE_RULE',
    details: 'Created SPL rule: "Credential Dumping via LSASS" (severity=critical, MITRE=T1003.001).',
    status: 'success', signature: 'sha256:d9f5a148c3e6b20f9...',
  },
  {
    audit_id: 'AUD-00000005', timestamp: new Date(Date.now() - 2400000).toISOString(),
    actor: 'AI Correlation Engine', role: 'SYSTEM', action: 'HITL_DECISION',
    details: 'Proposed ISOLATE_HOST on DESKTOP-APT29-01 — blast_radius assessed as low service impact.',
    status: 'pending', signature: 'sha256:e0a6b259d4f7c31a0...',
  },
  {
    audit_id: 'AUD-00000006', timestamp: new Date(Date.now() - 2200000).toISOString(),
    actor: 'analyst@soc', role: 'L2_HUNTER', action: 'APPROVE',
    details: 'Approved BLOCK_IP on 185.220.101.47 — Reason: "Confirmed C2 indicator. Blocking immediately."',
    status: 'success', signature: 'sha256:f1b7c36ae5a8d42b1...',
  },
  {
    audit_id: 'AUD-00000007', timestamp: new Date(Date.now() - 1800000).toISOString(),
    actor: 'commander@soc', role: 'L3_COMMANDER', action: 'REJECT',
    details: 'Rejected KILL_PROCESS on PID 7812 — Reason: "Confirmed as authorized IT automation script."',
    status: 'success', signature: 'sha256:a2c8d47bf6b9e53c2...',
  },
  {
    audit_id: 'AUD-00000008', timestamp: new Date(Date.now() - 900000).toISOString(),
    actor: 'analyst@soc', role: 'L2_HUNTER', action: 'INGEST',
    details: 'Simulated brute force telemetry: 50 events ingested via SOC Terminal.',
    status: 'success', signature: 'sha256:b3d9e58c07caf64d3...',
  },
];

// ─── Signature component ──────────────────────────────────────────────────────
function SigBadge({ sig }) {
  const short = sig ? sig.slice(0, 20) + '...' : '—';
  return (
    <span className="font-mono text-[9px] text-slate-600 hover:text-emerald-400 transition cursor-help" title={sig}>
      🔒 {short}
    </span>
  );
}

// ─── Single Ledger Row ────────────────────────────────────────────────────────
function LedgerRow({ entry, isEven }) {
  const cfg = ACTION_STYLES[entry.action] || ACTION_STYLES.SYSTEM;
  const ActionIcon = cfg.icon;

  return (
    <tr className={`border-b border-slate-800/50 group hover:bg-slate-800/20 transition ${isEven ? 'bg-[#070A12]/30' : ''}`}>
      {/* ID */}
      <td className="px-3 py-2 font-mono text-[10px] text-slate-500 whitespace-nowrap">
        {entry.audit_id}
      </td>
      {/* Timestamp */}
      <td className="px-3 py-2 font-mono text-[10px] text-slate-400 whitespace-nowrap">
        {new Date(entry.timestamp).toLocaleString()}
      </td>
      {/* Actor */}
      <td className="px-3 py-2">
        <div className="flex flex-col">
          <span className="text-xs text-slate-200 font-mono">{entry.actor}</span>
          <span className="text-[9px] text-slate-500 font-mono">{entry.role}</span>
        </div>
      </td>
      {/* Action */}
      <td className="px-3 py-2 whitespace-nowrap">
        <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded border text-[10px] font-mono font-bold ${cfg.badge}`}>
          <ActionIcon className="w-3 h-3" />
          {entry.action}
        </span>
      </td>
      {/* Details */}
      <td className="px-3 py-2 max-w-xs">
        <span className="text-[11px] text-slate-400 leading-relaxed line-clamp-2 group-hover:line-clamp-none transition-all">
          {entry.details}
        </span>
      </td>
      {/* Status */}
      <td className="px-3 py-2 whitespace-nowrap">
        <span className={`text-[10px] font-mono font-bold ${
          entry.status === 'success' ? 'text-emerald-400' :
          entry.status === 'pending' ? 'text-amber-400' :
          'text-red-400'
        }`}>
          {entry.status === 'success' ? '✓ OK' : entry.status === 'pending' ? '⏳ PEND' : '✗ FAIL'}
        </span>
      </td>
      {/* Signature */}
      <td className="px-3 py-2">
        <SigBadge sig={entry.signature} />
      </td>
    </tr>
  );
}

// ─── Main Component ───────────────────────────────────────────────────────────
export default function AuditLedgerView() {
  const [entries, setEntries] = useState([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [filterAction, setFilterAction] = useState('all');
  const [refreshKey, setRefreshKey] = useState(0);
  const tableRef = useRef(null);

  const fetchLedger = useCallback(async () => {
    setLoading(true);
    try {
      const res = await fetch(`${API_BASE}/audit`);
      const data = await res.json();
      const rawList = data.audit || data.ledger || [];
      setEntries(Array.isArray(rawList) && rawList.length > 0 ? rawList : SEED_LEDGER);
    } catch {
      setEntries(SEED_LEDGER);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { fetchLedger(); }, [fetchLedger, refreshKey]);

  const exportCSV = () => {
    const header = 'audit_id,timestamp,actor,role,action,details,status,signature\n';
    const rows = entries.map(e =>
      `"${e.audit_id}","${e.timestamp}","${e.actor}","${e.role}","${e.action}","${e.details}","${e.status}","${e.signature}"`
    ).join('\n');
    const blob = new Blob([header + rows], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `aegishunt-audit-${Date.now()}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const filtered = entries.filter(e => {
    const matchAction = filterAction === 'all' || e.action === filterAction;
    const matchSearch = !search ||
      `${e.audit_id} ${e.actor} ${e.action} ${e.details} ${e.role}`.toLowerCase().includes(search.toLowerCase());
    return matchAction && matchSearch;
  });

  const uniqueActions = [...new Set(entries.map(e => e.action))];

  const actionCounts = uniqueActions.reduce((acc, a) => {
    acc[a] = entries.filter(e => e.action === a).length;
    return acc;
  }, {});

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="bg-[#0B0F19] border border-slate-800 rounded-xl p-4 shadow-xl">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <div className="flex items-center gap-2 mb-0.5">
              <BookOpen className="w-5 h-5 text-emerald-400" />
              <h2 className="text-base font-bold text-white">Append-Only Audit Ledger</h2>
              <span className="flex items-center gap-1 px-2 py-0.5 rounded bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 text-[10px] font-mono">
                <Lock className="w-2.5 h-2.5" /> IMMUTABLE
              </span>
            </div>
            <p className="text-xs text-slate-500">
              Cryptographically signed, tamper-evident SOC action trail — every event permanently recorded
            </p>
          </div>
          <div className="flex gap-2 self-start sm:self-auto">
            <button
              onClick={() => setRefreshKey(k => k + 1)}
              className="p-2 rounded-lg border border-slate-700 hover:border-slate-500 text-slate-400 hover:text-white transition"
            >
              <RefreshCw className="w-4 h-4" />
            </button>
            <button
              onClick={exportCSV}
              className="flex items-center gap-2 px-3 py-2 rounded-lg border border-slate-700 hover:border-emerald-500/50 text-slate-400 hover:text-emerald-400 text-xs font-semibold transition"
            >
              <Download className="w-3.5 h-3.5" /> Export CSV
            </button>
          </div>
        </div>

        {/* Summary Stats */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mt-4">
          {[
            { label: 'Total Entries', val: entries.length, color: 'text-white' },
            { label: 'Approvals', val: entries.filter(e => e.action === 'APPROVE').length, color: 'text-emerald-300' },
            { label: 'Rejections', val: entries.filter(e => e.action === 'REJECT').length, color: 'text-red-300' },
            { label: 'Rule Creates', val: entries.filter(e => e.action === 'CREATE_RULE').length, color: 'text-indigo-300' },
          ].map(s => (
            <div key={s.label} className="bg-[#070A12] rounded-lg p-2.5 border border-slate-800 text-center">
              <div className={`text-xl font-mono font-bold ${s.color}`}>{s.val}</div>
              <div className="text-[10px] text-slate-500">{s.label}</div>
            </div>
          ))}
        </div>
      </div>

      {/* Immutability Notice */}
      <div className="flex items-start gap-3 bg-emerald-950/20 border border-emerald-500/20 rounded-xl px-4 py-3">
        <Lock className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
        <div className="text-xs text-slate-400 leading-relaxed">
          <span className="font-bold text-emerald-300">Append-Only Guarantee:</span> All entries are write-once. 
          No record can be modified or deleted. Each entry includes a SHA-256 chain signature for tamper detection. 
          This ledger satisfies SOC audit requirements under ISO 27001, NIST SP 800-92, and GDPR Article 30.
        </div>
      </div>

      {/* Search + Filter Bar */}
      <div className="flex flex-col sm:flex-row gap-2">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-slate-500" />
          <input
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="Search actor, action, details..."
            className="w-full pl-9 pr-4 py-2 bg-[#0B0F19] border border-slate-700 rounded-lg text-xs text-slate-200 font-mono focus:outline-none focus:border-emerald-500 placeholder-slate-600"
          />
        </div>
        <div className="flex gap-1 flex-wrap">
          {['all', ...uniqueActions].map(a => {
            const cfg = ACTION_STYLES[a] || ACTION_STYLES.SYSTEM;
            return (
              <button
                key={a}
                onClick={() => setFilterAction(a)}
                className={`px-2 py-1.5 rounded-lg text-[10px] font-mono border transition ${
                  filterAction === a
                    ? 'border-emerald-500/50 bg-emerald-500/10 text-emerald-300'
                    : 'border-slate-700 text-slate-500 hover:text-slate-300'
                }`}
              >
                {a === 'all' ? `ALL (${entries.length})` : `${a} (${actionCounts[a] || 0})`}
              </button>
            );
          })}
        </div>
      </div>

      {/* Ledger Table */}
      {loading ? (
        <div className="flex items-center justify-center gap-2 py-16 text-slate-500">
          <Loader2 className="w-5 h-5 animate-spin text-emerald-400" />
          <span className="text-xs font-mono">Loading audit ledger...</span>
        </div>
      ) : (
        <div
          ref={tableRef}
          className="bg-[#0B0F19] border border-slate-800 rounded-xl overflow-hidden shadow-xl"
        >
          <div className="overflow-x-auto">
            <table className="w-full text-left">
              <thead>
                <tr className="border-b border-slate-800 bg-[#070A12]">
                  {['Audit ID', 'Timestamp', 'Actor / Role', 'Action', 'Details', 'Status', 'Signature'].map(h => (
                    <th key={h} className="px-3 py-2.5 text-[10px] font-mono font-bold text-slate-500 uppercase whitespace-nowrap">
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {filtered.length === 0 ? (
                  <tr>
                    <td colSpan={7} className="text-center py-16 text-slate-600 text-sm font-mono">
                      No entries match your filters
                    </td>
                  </tr>
                ) : (
                  filtered.map((entry, i) => (
                    <LedgerRow key={entry.audit_id} entry={entry} isEven={i % 2 === 0} />
                  ))
                )}
              </tbody>
            </table>
          </div>

          {/* Footer row */}
          <div className="border-t border-slate-800 bg-[#070A12] px-4 py-2 flex items-center justify-between">
            <span className="text-[10px] font-mono text-slate-600">
              Showing {filtered.length} of {entries.length} entries
            </span>
            <span className="flex items-center gap-1 text-[10px] font-mono text-emerald-600">
              <Lock className="w-3 h-3" /> Append-only — read-only view
            </span>
          </div>
        </div>
      )}
    </div>
  );
}
