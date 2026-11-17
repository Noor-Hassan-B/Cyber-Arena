import React, { useState, useEffect, useCallback } from 'react';
import {
  Shield, Plus, ChevronDown, ChevronRight, AlertTriangle,
  CheckCircle2, XCircle, Loader2, FileCode2, RefreshCw,
  Copy, Trash2, Eye, EyeOff, Zap, Tag, Clock, Filter
} from 'lucide-react';

const API_BASE = 'http://localhost:8000/api';

// ─── Sample rule templates ───────────────────────────────────────────────────
const RULE_TEMPLATES = {
  sigma: `title: Suspicious PowerShell Execution
id: a1b2c3d4-0001-0001-0001-000000000001
status: experimental
description: Detects obfuscated PowerShell commands often used in fileless attacks
author: SOC Analyst
date: 2024/01/15
tags:
  - attack.execution
  - attack.t1059.001
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\\powershell.exe'
    CommandLine|contains:
      - '-EncodedCommand'
      - '-enc '
      - 'bypass'
      - 'hidden'
  condition: selection
level: high
falsepositives:
  - Administrative scripts`,

  spl: `index=windows_events EventCode=4688
| where match(CommandLine, "(?i)(encodedcommand|bypass|iex|invoke-expression)")
| stats count by ComputerName, SubjectUserName, CommandLine, _time
| where count > 0
| sort -_time
| table _time, ComputerName, SubjectUserName, CommandLine, count`,

  kql: `process where event.type == "start"
  and process.name == "powershell.exe"
  and (
    process.args : ("-EncodedCommand", "-enc", "-bypass", "-hidden")
    or process.command_line : ("*iex*", "*invoke-expression*", "*DownloadString*")
  )
| keep @timestamp, host.name, user.name, process.name, process.command_line`
};

const SEVERITY_COLORS = {
  critical: { bg: 'bg-red-950/60', border: 'border-red-500/40', badge: 'bg-red-500/20 text-red-300', dot: 'bg-red-500' },
  high:     { bg: 'bg-orange-950/60', border: 'border-orange-500/40', badge: 'bg-orange-500/20 text-orange-300', dot: 'bg-orange-500' },
  medium:   { bg: 'bg-amber-950/60', border: 'border-amber-500/40', badge: 'bg-amber-500/20 text-amber-300', dot: 'bg-amber-500' },
  low:      { bg: 'bg-blue-950/60', border: 'border-blue-500/40', badge: 'bg-blue-500/20 text-blue-300', dot: 'bg-blue-400' },
};

const FORMAT_COLORS = {
  sigma: 'bg-purple-500/20 text-purple-300 border-purple-500/30',
  spl:   'bg-cyan-500/20 text-cyan-300 border-cyan-500/30',
  kql:   'bg-indigo-500/20 text-indigo-300 border-indigo-500/30',
};

// ─── Inline Syntax Highlighter ────────────────────────────────────────────────
function RuleCodeBlock({ content, format }) {
  const [copied, setCopied] = useState(false);

  const copy = () => {
    navigator.clipboard.writeText(content);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const highlighted = content
    .split('\n')
    .map((line, i) => {
      let cls = 'text-slate-300';
      if (format === 'sigma') {
        if (/^(title|id|status|description|author|date|logsource|detection|tags|level|falsepositives):/.test(line.trim())) cls = 'text-cyan-400';
        else if (/^\s+\w+(\|.*)?:/.test(line)) cls = 'text-blue-300';
        else if (/^\s+-/.test(line)) cls = 'text-emerald-300';
        else if (/^\s+#/.test(line)) cls = 'text-slate-500 italic';
      } else if (format === 'spl') {
        if (/^\|/.test(line.trim())) cls = 'text-cyan-400';
        else if (/^(index|source|sourcetype)=/.test(line.trim())) cls = 'text-amber-300';
        else if (/\b(where|stats|sort|table|eval|search|rex)\b/.test(line)) cls = 'text-purple-300';
      } else if (format === 'kql') {
        if (/\b(where|and|or|not|by|keep|sort|limit|asc|desc)\b/.test(line)) cls = 'text-cyan-300';
        else if (/\b(process|network|file|registry|event)\b/.test(line)) cls = 'text-amber-300';
        else if (/".*?"/.test(line) || /'.*?'/.test(line)) cls = 'text-emerald-300';
      }
      return { line, cls };
    });

  return (
    <div className="relative group">
      <div className="absolute top-2 right-2 opacity-0 group-hover:opacity-100 transition z-10">
        <button onClick={copy} className="flex items-center gap-1 px-2 py-1 rounded bg-slate-700 hover:bg-slate-600 text-xs text-slate-300 transition">
          <Copy className="w-3 h-3" />
          {copied ? 'Copied!' : 'Copy'}
        </button>
      </div>
      <div className="bg-[#070A12] rounded-lg border border-slate-800 overflow-auto max-h-48 font-mono text-xs leading-5 p-3">
        {highlighted.map((h, i) => (
          <div key={i} className="flex">
            <span className="select-none w-7 text-right mr-3 text-slate-600 shrink-0">{i + 1}</span>
            <span className={h.cls}>{h.line}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

// ─── Single Rule Card ─────────────────────────────────────────────────────────
function RuleCard({ rule, onDelete }) {
  const [expanded, setExpanded] = useState(false);
  const sev = SEVERITY_COLORS[rule.severity] || SEVERITY_COLORS.medium;
  const fmt = FORMAT_COLORS[rule.format] || FORMAT_COLORS.sigma;

  return (
    <div className={`rounded-xl border ${sev.border} ${sev.bg} transition hover:border-opacity-70`}>
      <button
        className="w-full flex items-center gap-3 p-3 text-left"
        onClick={() => setExpanded(v => !v)}
      >
        <div className={`w-2 h-2 rounded-full shrink-0 ${sev.dot} animate-pulse`} />
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-xs font-bold text-white truncate">{rule.title}</span>
            <span className={`px-1.5 py-0.5 rounded border text-[10px] font-mono font-bold uppercase ${fmt}`}>
              {rule.format}
            </span>
            <span className={`px-1.5 py-0.5 rounded text-[10px] font-mono uppercase ${sev.badge}`}>
              {rule.severity}
            </span>
          </div>
          <div className="flex items-center gap-3 mt-0.5 flex-wrap">
            <span className="text-[10px] font-mono text-slate-500">{rule.mitre_technique}</span>
            <span className="text-[10px] text-slate-500 flex items-center gap-1">
              <Clock className="w-3 h-3" />
              {new Date(rule.created_at).toLocaleString()}
            </span>
            {rule.analyst && (
              <span className="text-[10px] text-slate-500">by {rule.analyst}</span>
            )}
          </div>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          <span className="px-2 py-0.5 rounded bg-emerald-950/60 border border-emerald-500/30 text-emerald-400 text-[10px] font-mono">
            DEPLOYED
          </span>
          {expanded ? <ChevronDown className="w-4 h-4 text-slate-500" /> : <ChevronRight className="w-4 h-4 text-slate-500" />}
        </div>
      </button>

      {expanded && (
        <div className="px-3 pb-3 space-y-2">
          <RuleCodeBlock content={rule.rule_content} format={rule.format} />
          <div className="flex justify-end">
            <button
              onClick={() => onDelete(rule.id)}
              className="flex items-center gap-1 px-2 py-1 rounded bg-red-950/50 hover:bg-red-900/50 border border-red-700/30 text-red-400 text-xs transition"
            >
              <Trash2 className="w-3 h-3" /> Remove Rule
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

// ─── Create Rule Form ─────────────────────────────────────────────────────────
function CreateRuleForm({ onCreate, onCancel }) {
  const [form, setForm] = useState({
    title: '',
    format: 'sigma',
    mitre_technique: 'T1059.001',
    severity: 'high',
    analyst: 'analyst@soc',
    rule_content: RULE_TEMPLATES.sigma,
  });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const setField = (k, v) => setForm(f => ({ ...f, [k]: v }));

  const handleFormatChange = (fmt) => {
    setField('format', fmt);
    setField('rule_content', RULE_TEMPLATES[fmt] || '');
  };

  const handleSubmit = async () => {
    if (!form.title.trim() || !form.rule_content.trim()) {
      setError('Title and rule content are required.');
      return;
    }
    setLoading(true);
    setError('');
    try {
      const res = await fetch(`${API_BASE}/detections`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(form),
      });
      const data = await res.json();
      if (data.status === 'success') {
        onCreate(data.detection);
      } else {
        setError(data.error || 'Failed to deploy rule.');
      }
    } catch (e) {
      setError('API unreachable – rule saved locally.');
      onCreate({ ...form, id: `local-${Date.now()}`, created_at: new Date().toISOString() });
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="bg-[#0B0F19] border border-blue-500/30 rounded-xl p-4 space-y-4 shadow-2xl">
      <div className="flex items-center gap-2 mb-1">
        <FileCode2 className="w-4 h-4 text-blue-400" />
        <span className="text-sm font-bold text-white">New Detection Rule</span>
      </div>

      {/* Row 1: Title + Analyst */}
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
        <div>
          <label className="text-[10px] font-mono text-slate-500 uppercase block mb-1">Rule Title *</label>
          <input
            value={form.title}
            onChange={e => setField('title', e.target.value)}
            placeholder="Suspicious PowerShell Execution..."
            className="w-full bg-[#070A12] border border-slate-700 rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-blue-500 font-mono"
          />
        </div>
        <div>
          <label className="text-[10px] font-mono text-slate-500 uppercase block mb-1">Analyst</label>
          <input
            value={form.analyst}
            onChange={e => setField('analyst', e.target.value)}
            placeholder="analyst@soc"
            className="w-full bg-[#070A12] border border-slate-700 rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-blue-500 font-mono"
          />
        </div>
      </div>

      {/* Row 2: Format + MITRE + Severity */}
      <div className="grid grid-cols-3 gap-3">
        <div>
          <label className="text-[10px] font-mono text-slate-500 uppercase block mb-1">Format</label>
          <div className="flex gap-1">
            {['sigma', 'spl', 'kql'].map(f => (
              <button
                key={f}
                onClick={() => handleFormatChange(f)}
                className={`flex-1 py-1.5 rounded-lg text-[10px] font-mono font-bold uppercase border transition ${
                  form.format === f
                    ? FORMAT_COLORS[f] + ' shadow-sm'
                    : 'border-slate-700 text-slate-500 hover:text-slate-300'
                }`}
              >
                {f}
              </button>
            ))}
          </div>
        </div>
        <div>
          <label className="text-[10px] font-mono text-slate-500 uppercase block mb-1">MITRE Technique</label>
          <input
            value={form.mitre_technique}
            onChange={e => setField('mitre_technique', e.target.value)}
            placeholder="T1059.001"
            className="w-full bg-[#070A12] border border-slate-700 rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-blue-500 font-mono"
          />
        </div>
        <div>
          <label className="text-[10px] font-mono text-slate-500 uppercase block mb-1">Severity</label>
          <select
            value={form.severity}
            onChange={e => setField('severity', e.target.value)}
            className="w-full bg-[#070A12] border border-slate-700 rounded-lg px-2 py-2 text-xs text-slate-200 focus:outline-none focus:border-blue-500 font-mono"
          >
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
        </div>
      </div>

      {/* Rule Content */}
      <div>
        <label className="text-[10px] font-mono text-slate-500 uppercase block mb-1">Rule Content *</label>
        <textarea
          value={form.rule_content}
          onChange={e => setField('rule_content', e.target.value)}
          rows={10}
          spellCheck={false}
          className="w-full bg-[#070A12] border border-slate-700 rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-blue-500 font-mono leading-5 resize-y"
        />
      </div>

      {error && (
        <div className="flex items-center gap-2 text-xs text-red-400 bg-red-950/30 border border-red-700/30 rounded-lg px-3 py-2">
          <AlertTriangle className="w-3.5 h-3.5 shrink-0" /> {error}
        </div>
      )}

      <div className="flex gap-2 justify-end">
        <button onClick={onCancel} className="px-4 py-2 rounded-lg text-xs text-slate-400 hover:text-slate-200 border border-slate-700 hover:border-slate-500 transition">
          Cancel
        </button>
        <button
          onClick={handleSubmit}
          disabled={loading}
          className="flex items-center gap-2 px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-bold transition disabled:opacity-60"
        >
          {loading ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Zap className="w-3.5 h-3.5" />}
          Deploy Rule
        </button>
      </div>
    </div>
  );
}

// ─── Main Component ───────────────────────────────────────────────────────────
export default function DetectionStudio() {
  const [rules, setRules] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);
  const [filterFmt, setFilterFmt] = useState('all');
  const [filterSev, setFilterSev] = useState('all');
  const [refreshKey, setRefreshKey] = useState(0);

  const fetchRules = useCallback(async () => {
    setLoading(true);
    try {
      const res = await fetch(`${API_BASE}/detections`);
      const data = await res.json();
      setRules(data.detections || []);
    } catch {
      // Seed with example rules if backend unreachable
      setRules([
        {
          id: 'local-1', title: 'Suspicious PowerShell Execution', format: 'sigma',
          mitre_technique: 'T1059.001', severity: 'high',
          analyst: 'analyst@soc', created_at: new Date(Date.now() - 86400000).toISOString(),
          rule_content: RULE_TEMPLATES.sigma,
        },
        {
          id: 'local-2', title: 'Credential Dumping via LSASS', format: 'spl',
          mitre_technique: 'T1003.001', severity: 'critical',
          analyst: 'hunter@soc', created_at: new Date(Date.now() - 3600000).toISOString(),
          rule_content: `index=sysmon EventCode=10\n| where TargetImage LIKE "%lsass.exe%"\n| stats count by SourceImage, SourceUser, _time\n| sort -count`,
        },
        {
          id: 'local-3', title: 'Lateral Movement — PsExec Detection', format: 'kql',
          mitre_technique: 'T1021.002', severity: 'high',
          analyst: 'analyst@soc', created_at: new Date().toISOString(),
          rule_content: `process where event.type == "start"\n  and process.name == "psexec.exe"\n  or process.name == "psexesvc.exe"\n| keep @timestamp, host.name, user.name, process.command_line`,
        },
      ]);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { fetchRules(); }, [fetchRules, refreshKey]);

  const handleCreate = (rule) => {
    setRules(prev => [rule, ...prev]);
    setShowForm(false);
  };

  const handleDelete = (id) => {
    setRules(prev => prev.filter(r => r.id !== id));
  };

  const filtered = rules.filter(r => {
    if (filterFmt !== 'all' && r.format !== filterFmt) return false;
    if (filterSev !== 'all' && r.severity !== filterSev) return false;
    return true;
  });

  const counts = {
    sigma: rules.filter(r => r.format === 'sigma').length,
    spl:   rules.filter(r => r.format === 'spl').length,
    kql:   rules.filter(r => r.format === 'kql').length,
  };

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="bg-[#0B0F19] border border-slate-800 rounded-xl p-4 shadow-xl">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <div className="flex items-center gap-2 mb-0.5">
              <Shield className="w-5 h-5 text-blue-400" />
              <h2 className="text-base font-bold text-white">Detection Engineering Studio</h2>
              <span className="px-2 py-0.5 rounded bg-blue-500/10 border border-blue-500/20 text-blue-400 text-[10px] font-mono">
                SOCForge
              </span>
            </div>
            <p className="text-xs text-slate-500">
              Author, deploy and manage detection rules — Sigma · SPL · KQL
            </p>
          </div>
          <div className="flex gap-2">
            <button
              onClick={() => setRefreshKey(k => k + 1)}
              className="p-2 rounded-lg border border-slate-700 hover:border-slate-500 text-slate-400 hover:text-white transition"
              title="Refresh"
            >
              <RefreshCw className="w-4 h-4" />
            </button>
            <button
              onClick={() => setShowForm(v => !v)}
              className={`flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-bold transition ${
                showForm
                  ? 'bg-slate-700 text-slate-200'
                  : 'bg-blue-600 hover:bg-blue-500 text-white shadow-md shadow-blue-600/30'
              }`}
            >
              <Plus className="w-3.5 h-3.5" />
              {showForm ? 'Cancel' : 'New Rule'}
            </button>
          </div>
        </div>

        {/* Stats Row */}
        <div className="grid grid-cols-4 gap-3 mt-4">
          {[
            { label: 'Total Rules', val: rules.length, color: 'text-white' },
            { label: 'Sigma', val: counts.sigma, color: 'text-purple-300' },
            { label: 'SPL (Splunk)', val: counts.spl, color: 'text-cyan-300' },
            { label: 'KQL (Elastic)', val: counts.kql, color: 'text-indigo-300' },
          ].map(s => (
            <div key={s.label} className="bg-[#070A12] rounded-lg p-2.5 border border-slate-800 text-center">
              <div className={`text-xl font-mono font-bold ${s.color}`}>{s.val}</div>
              <div className="text-[10px] text-slate-500">{s.label}</div>
            </div>
          ))}
        </div>
      </div>

      {/* Create Form */}
      {showForm && (
        <CreateRuleForm onCreate={handleCreate} onCancel={() => setShowForm(false)} />
      )}

      {/* Filter Bar */}
      <div className="flex items-center gap-2 flex-wrap">
        <Filter className="w-3.5 h-3.5 text-slate-500" />
        <span className="text-[10px] text-slate-500 font-mono">FORMAT:</span>
        {['all', 'sigma', 'spl', 'kql'].map(f => (
          <button
            key={f}
            onClick={() => setFilterFmt(f)}
            className={`px-2 py-0.5 rounded text-[10px] font-mono uppercase border transition ${
              filterFmt === f
                ? 'border-blue-500/50 bg-blue-500/10 text-blue-300'
                : 'border-slate-700 text-slate-500 hover:text-slate-300'
            }`}
          >
            {f}
          </button>
        ))}
        <span className="text-[10px] text-slate-500 font-mono ml-2">SEV:</span>
        {['all', 'critical', 'high', 'medium', 'low'].map(s => (
          <button
            key={s}
            onClick={() => setFilterSev(s)}
            className={`px-2 py-0.5 rounded text-[10px] font-mono uppercase border transition ${
              filterSev === s
                ? 'border-blue-500/50 bg-blue-500/10 text-blue-300'
                : 'border-slate-700 text-slate-500 hover:text-slate-300'
            }`}
          >
            {s}
          </button>
        ))}
        <span className="ml-auto text-[10px] text-slate-500 font-mono">{filtered.length} rules</span>
      </div>

      {/* Rules List */}
      {loading ? (
        <div className="flex items-center justify-center gap-2 py-16 text-slate-500">
          <Loader2 className="w-5 h-5 animate-spin text-blue-400" />
          <span className="text-xs font-mono">Loading detection rules...</span>
        </div>
      ) : filtered.length === 0 ? (
        <div className="flex flex-col items-center justify-center gap-3 py-20 text-slate-600 border border-dashed border-slate-800 rounded-xl">
          <Shield className="w-8 h-8" />
          <span className="text-sm font-mono">No detection rules match filters</span>
          <button onClick={() => setShowForm(true)} className="text-xs text-blue-400 hover:text-blue-300 underline underline-offset-2">
            Create the first rule
          </button>
        </div>
      ) : (
        <div className="space-y-2">
          {filtered.map(rule => (
            <RuleCard key={rule.id} rule={rule} onDelete={handleDelete} />
          ))}
        </div>
      )}
    </div>
  );
}
