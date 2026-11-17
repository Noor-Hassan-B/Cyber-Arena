import { useState, useMemo } from "react";
import { AlertTriangle, ChevronRight, Download, Radio, Search, X, ShieldAlert, ArrowUpRight, FileText } from "lucide-react";

const TABS = ["all", "critical", "high", "medium", "low"];

export default function AlertFeed({ alerts = [], allCount, severity, setSeverity, onOpen, exportUrl, exportReportUrl }) {
  const [search, setSearch] = useState("");

  const visibleAlerts = useMemo(() => {
    const q = search.trim().toLowerCase();
    if (!q) return alerts;
    return alerts.filter(a =>
      (a.title && a.title.toLowerCase().includes(q)) ||
      (a.summary && a.summary.toLowerCase().includes(q)) ||
      (a.source_ip && a.source_ip.toLowerCase().includes(q)) ||
      (a.mitre?.id && a.mitre.id.toLowerCase().includes(q)) ||
      (a.mitre?.name && a.mitre.name.toLowerCase().includes(q))
    );
  }, [alerts, search]);

  return (
    <div className="tl-card p-5 font-sans" data-testid="alert-feed">
      {/* Header Bar */}
      <div className="flex items-center justify-between mb-4 gap-4 flex-wrap">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <ShieldAlert className="w-4 h-4 text-cyan-400" />
            <span className="text-slate-100 text-sm font-extrabold uppercase tracking-wider">
              Correlated Security Alerts
            </span>
            <span className="badge badge-medium">{visibleAlerts.length} Active</span>
          </div>
          <div className="text-[11px] text-slate-400">
            Real-time multi-detector correlation and anomaly scoring
          </div>
        </div>

        <div className="flex items-center gap-2">
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg border border-slate-800 bg-slate-950/70 text-slate-400 focus-within:border-cyan-500/50 transition">
            <Search className="w-3.5 h-3.5 text-slate-500" />
            <input
              value={search}
              onChange={e => setSearch(e.target.value)}
              placeholder="Filter by indicator, IP, MITRE..."
              className="bg-transparent text-xs font-mono outline-none placeholder:text-slate-600 w-36 sm:w-56 text-slate-200"
            />
            {search && (
              <button onClick={() => setSearch("")} className="text-slate-500 hover:text-slate-300">
                <X className="w-3.5 h-3.5" />
              </button>
            )}
          </div>
        </div>
      </div>

      {/* Severity Filter Tabs */}
      <div className="flex items-center gap-1 border-b border-slate-800/80 mb-3 overflow-x-auto">
        {TABS.map(t => (
          <button
            key={t}
            onClick={() => setSeverity(t)}
            data-testid={`sev-tab-${t}`}
            className={`px-3.5 py-2 text-xs font-semibold uppercase tracking-wider border-b-2 -mb-px transition-colors ${
              severity === t
                ? "border-cyan-400 text-cyan-300 font-bold"
                : "border-transparent text-slate-400 hover:text-slate-200"
            }`}
          >
            {t}
          </button>
        ))}
      </div>

      {/* Alerts Feed */}
      {visibleAlerts.length === 0 ? (
        <div
          className="py-12 text-center text-xs text-slate-500 border border-dashed border-slate-800/80 rounded-lg bg-slate-950/40"
          data-testid="alert-feed-empty"
        >
          {search ? "No matching alerts found" : "No active alerts in current severity tier · launch an attack scenario"}
        </div>
      ) : (
        <div className="divide-y divide-slate-800/60 max-h-[520px] overflow-y-auto pr-1">
          {visibleAlerts.map(a => {
            const isCrit = a.severity === "critical";
            const isHigh = a.severity === "high";

            return (
              <div
                key={a.id}
                onClick={() => onOpen(a)}
                data-testid={`alert-row-${a.id}`}
                className="w-full text-left flex items-start gap-3.5 py-3 hover:bg-slate-900/80 transition px-3 -mx-1 rounded-lg cursor-pointer group"
              >
                <div className="mt-1 p-1.5 rounded bg-slate-900/60 border border-slate-800">
                  <AlertTriangle
                    className={`w-4 h-4 flex-shrink-0 ${
                      isCrit ? "text-red-400" : isHigh ? "text-amber-400" : "text-cyan-400"
                    }`}
                  />
                </div>

                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap mb-1">
                    <span className="text-xs font-bold text-slate-100 group-hover:text-cyan-300 transition truncate">
                      {a.title}
                    </span>
                    <span className={`badge badge-${a.severity}`}>{a.severity}</span>
                    <span
                      className={`badge badge-${
                        a.status === "open" ? "open" : a.status === "acknowledged" ? "ack" : "resolved"
                      }`}
                    >
                      {a.status}
                    </span>
                    {a.contained && <span className="badge badge-critical text-[9px]">CONTAINED</span>}
                  </div>

                  <div className="text-[11px] text-slate-400 line-clamp-1 leading-relaxed">
                    {a.summary}
                  </div>

                  <div className="flex items-center gap-3 mt-1.5 text-[11px] font-mono text-slate-400">
                    <span className="font-semibold text-slate-300">
                      Risk <span className={a.risk_score >= 90 ? "text-red-400 font-bold" : a.risk_score >= 75 ? "text-amber-400 font-bold" : "text-cyan-400 font-bold"}>{a.risk_score}</span>
                    </span>
                    <span className="text-slate-600">·</span>
                    <span className="text-slate-300 font-semibold">{a.source_ip}</span>
                    <span className="text-slate-600">·</span>
                    <span className="px-1.5 py-0.5 rounded bg-cyan-950/60 border border-cyan-800/40 text-cyan-300 text-[10px]">
                      {a.mitre?.id || "T1078"}
                    </span>
                    <span className="text-slate-600 hidden sm:inline">·</span>
                    <span className="text-slate-500 hidden sm:inline">
                      {new Date(a.triggered_at).toLocaleTimeString()}
                    </span>
                  </div>
                </div>

                <div className="self-center flex items-center gap-1 opacity-60 group-hover:opacity-100 transition">
                  <span className="text-[11px] text-cyan-400 font-semibold hidden group-hover:inline">Triage</span>
                  <ChevronRight className="w-4 h-4 text-slate-500 group-hover:text-cyan-400" />
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* Footer Bar */}
      <div className="mt-4 pt-3.5 border-t border-slate-800/80 flex items-center justify-between text-xs text-slate-500 flex-wrap gap-2">
        <div className="text-[11px]">Active Telemetry Pipeline · Tier-1 Neo-Bank Hybrid Enclave (10.42.0.0/24)</div>
        <div className="flex items-center gap-3">
          <a
            href={exportReportUrl}
            data-testid="export-report-link"
            className="text-xs font-mono font-semibold text-emerald-400 hover:text-emerald-300 flex items-center gap-1.5 transition"
            title="Download formatted Incident Response Triage Report (Markdown)"
          >
            <FileText className="w-3.5 h-3.5" /> Threat Triage Report (.md)
          </a>
          <span className="text-slate-700">|</span>
          <a
            href={exportUrl}
            data-testid="export-csv-link"
            className="text-xs font-mono font-semibold text-cyan-400 hover:text-cyan-300 flex items-center gap-1.5 transition"
          >
            <Download className="w-3.5 h-3.5" /> Export Alerts CSV
          </a>
        </div>
      </div>
    </div>
  );
}