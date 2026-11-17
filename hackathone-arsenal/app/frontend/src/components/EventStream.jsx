import { useState, useMemo } from "react";
import { Eye, Pause, Play, X, Terminal, Filter, ShieldCheck, AlertCircle, Copy, Check, Search } from "lucide-react";
import { toast } from "sonner";

export default function EventStream({ events = [] }) {
  const [selectedEvent, setSelectedEvent] = useState(null);
  const [filterType, setFilterType] = useState("ALL");
  const [searchQuery, setSearchQuery] = useState("");
  const [paused, setPaused] = useState(false);
  const [copied, setCopied] = useState(false);

  const filteredEvents = useMemo(() => {
    if (!events?.length) return [];
    let list = events;
    if (filterType !== "ALL") {
      list = list.filter(e => (e.type || "").toUpperCase() === filterType);
    }
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase().trim();
      list = list.filter(e =>
        (e.src && e.src.toLowerCase().includes(q)) ||
        (e.dst && e.dst.toLowerCase().includes(q)) ||
        (e.service && e.service.toLowerCase().includes(q)) ||
        (e.ip && e.ip.toLowerCase().includes(q)) ||
        (e.user && e.user.toLowerCase().includes(q)) ||
        (e.status && e.status.toLowerCase().includes(q))
      );
    }
    return list;
  }, [events, filterType, searchQuery]);

  const typeCounts = useMemo(() => {
    const counts = { ALL: events.length, AUTH: 0, NETWORK: 0, EXPLOIT: 0, TRANSACTION: 0 };
    events.forEach(e => {
      const t = (e.type || "").toUpperCase();
      if (counts[t] !== undefined) counts[t]++;
    });
    return counts;
  }, [events]);

  const copyJson = (data) => {
    navigator.clipboard.writeText(JSON.stringify(data, null, 2));
    setCopied(true);
    toast.success("Event JSON copied to clipboard");
    setTimeout(() => setCopied(false), 2000);
  };

  if (!events?.length) {
    return (
      <div className="border border-slate-800/80 rounded-md bg-[#090C14] p-10 text-center" data-testid="event-stream-empty">
        <div className="inline-flex items-center justify-center w-10 h-10 rounded-full bg-slate-900 border border-slate-800 text-slate-500 mb-3">
          <Terminal className="w-5 h-5" />
        </div>
        <div className="text-xs font-semibold uppercase tracking-wider text-slate-300">Telemetry Pipeline Standby</div>
        <div className="text-[11px] text-slate-500 mt-1 max-w-sm mx-auto">
          No events in sliding buffer. Launch an offensive playbook from the console or quick actions above.
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-3 font-sans">
      {/* Stream Controls & Category Filter */}
      <div className="flex items-center justify-between gap-3 flex-wrap text-xs">
        <div className="flex items-center gap-1.5 flex-wrap">
          <div className="flex items-center gap-1 bg-[#090D16] p-1 rounded border border-slate-800/90">
            {["ALL", "AUTH", "NETWORK", "EXPLOIT", "TRANSACTION"].map((t) => (
              <button
                key={t}
                onClick={() => setFilterType(t)}
                className={`px-2.5 py-1 rounded text-[11px] font-mono font-medium transition ${
                  filterType === t
                    ? "bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 font-semibold"
                    : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/60"
                }`}
              >
                {t} <span className="text-[10px] text-slate-500 tabular-nums ml-1">({typeCounts[t] || 0})</span>
              </button>
            ))}
          </div>

          {/* Quick Filter Input */}
          <div className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-[#090D16] border border-slate-800/90 text-slate-400 text-xs">
            <Search className="w-3.5 h-3.5 text-slate-500" />
            <input
              value={searchQuery}
              onChange={e => setSearchQuery(e.target.value)}
              placeholder="Search IP, host, service..."
              className="bg-transparent outline-none text-[11px] font-mono text-slate-200 placeholder:text-slate-600 w-36 sm:w-44"
            />
            {searchQuery && (
              <button onClick={() => setSearchQuery("")} className="text-slate-500 hover:text-slate-300">
                <X className="w-3 h-3" />
              </button>
            )}
          </div>
        </div>

        <div className="flex items-center gap-2 font-mono">
          <button
            onClick={() => setPaused(p => !p)}
            className={`px-2.5 py-1 rounded text-[11px] font-medium border flex items-center gap-1.5 transition ${
              paused
                ? "bg-amber-950/40 text-amber-300 border-amber-500/40 font-semibold"
                : "bg-slate-900 text-slate-300 border-slate-800 hover:border-slate-700"
            }`}
          >
            {paused ? <Play className="w-3 h-3 fill-current" /> : <Pause className="w-3 h-3 fill-current" />}
            {paused ? "PAUSED" : "LIVE TAIL"}
          </button>
          <span className="text-[10px] text-slate-500">Buffer: 40 max</span>
        </div>
      </div>

      {/* Table Header */}
      <div className="hidden sm:grid grid-cols-[85px_1fr_190px_90px_100px_85px] px-3.5 py-2 bg-[#0A0E18] rounded-t border border-slate-800/90 text-[10px] font-mono uppercase tracking-wider text-slate-400 font-semibold">
        <div>Type</div>
        <div>Flow (Source → Target)</div>
        <div>Service & IP</div>
        <div>Subject</div>
        <div className="text-right">Verdict</div>
        <div className="text-right">Risk Score</div>
      </div>

      {/* Events List */}
      <div className="divide-y divide-slate-800/60 max-h-[380px] overflow-y-auto bg-[#070A12] rounded-b border border-slate-800/90" data-testid="event-stream-list">
        {filteredEvents.map((e, i) => {
          const isAnomalous = e.status === "failure" || e.status === "anomalous" || e.score >= 80;
          return (
            <div
              key={e.id || `${e.timestamp || ""}-${e.src}-${e.dst}-${i}`}
              onClick={() => setSelectedEvent(e)}
              className="row-in grid grid-cols-1 sm:grid-cols-[85px_1fr_190px_90px_100px_85px] items-center px-3.5 py-2.5 text-xs font-mono hover:bg-[#101726] cursor-pointer transition group"
            >
              <div>
                <span
                  className={`badge ${
                    e.type === "exploit"
                      ? "badge-critical"
                      : e.type === "auth"
                      ? "badge-high"
                      : e.type === "transaction"
                      ? "badge-medium"
                      : "badge-low"
                  }`}
                >
                  {(e.type || "EVT").toUpperCase()}
                </span>
              </div>
              <div className="flex items-center gap-1.5 text-slate-300 truncate">
                <span className="text-slate-400 group-hover:text-slate-200">{e.src}</span>
                <span className="text-cyan-400 text-xs">→</span>
                <span className="text-slate-100 font-medium">{e.dst}</span>
              </div>
              <div className="text-slate-400 truncate text-[11px]">
                {e.service} <span className="text-slate-600">·</span> {e.ip}
              </div>
              <div className="text-slate-400 truncate text-[11px]">{e.user || "—"}</div>
              <div className="text-right">
                <span className={`text-[11px] font-semibold uppercase ${isAnomalous ? "text-red-400" : "text-emerald-400"}`}>
                  {e.status}
                </span>
              </div>
              <div className="text-right tabular-nums font-bold">
                <span className={e.score >= 90 ? "text-red-400" : e.score >= 70 ? "text-amber-400" : "text-cyan-400"}>
                  {e.score}
                </span>
                <span className="text-slate-500 text-[10px] font-normal ml-1">pts</span>
              </div>
            </div>
          );
        })}
      </div>

      {/* Raw Event Detail Modal */}
      {selectedEvent && (
        <div
          className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4"
          onClick={() => setSelectedEvent(null)}
        >
          <div
            className="w-full max-w-xl bg-[#0B0F18] border border-slate-700/80 rounded-lg p-5 shadow-2xl space-y-4 font-mono text-xs"
            onClick={e => e.stopPropagation()}
          >
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse" />
                <span className="font-bold text-slate-200 font-sans text-sm">Security Telemetry Inspector</span>
              </div>
              <div className="flex items-center gap-2">
                <button
                  onClick={() => copyJson(selectedEvent)}
                  className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white flex items-center gap-1.5 text-[11px] transition"
                  title="Copy full JSON payload"
                >
                  {copied ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                  <span>{copied ? "Copied" : "Copy JSON"}</span>
                </button>
                <button
                  onClick={() => setSelectedEvent(null)}
                  className="text-slate-400 hover:text-slate-200 p-1"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>
            </div>

            <div className="grid grid-cols-2 gap-3 text-[11px]">
              <div className="bg-[#070A11] p-2.5 rounded border border-slate-800">
                <div className="text-slate-500 text-[10px] uppercase tracking-wider mb-1 font-sans">Source Node</div>
                <div className="text-cyan-300 font-semibold">{selectedEvent.src} ({selectedEvent.ip})</div>
              </div>
              <div className="bg-[#070A11] p-2.5 rounded border border-slate-800">
                <div className="text-slate-500 text-[10px] uppercase tracking-wider mb-1 font-sans">Target Service</div>
                <div className="text-emerald-300 font-semibold">{selectedEvent.dst} ({selectedEvent.service})</div>
              </div>
            </div>

            <div>
              <div className="text-slate-400 text-[10px] uppercase tracking-wider mb-1.5 flex items-center justify-between font-sans">
                <span>Normalized CEF / ECS Event Object</span>
                <span className="text-slate-500">Schema v2.4</span>
              </div>
              <pre className="bg-[#05070C] p-3.5 rounded border border-slate-800/80 text-emerald-400 font-mono text-[11px] overflow-x-auto max-h-56 leading-relaxed">
                {JSON.stringify(selectedEvent, null, 2)}
              </pre>
            </div>

            <div className="flex items-center justify-between pt-2 border-t border-slate-800 text-[11px] text-slate-500">
              <span>Event Hash: {selectedEvent.id || "EVT-" + Math.abs((selectedEvent.score || 70) * 991).toString(16)}</span>
              <button
                onClick={() => setSelectedEvent(null)}
                className="px-3 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 font-sans"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}