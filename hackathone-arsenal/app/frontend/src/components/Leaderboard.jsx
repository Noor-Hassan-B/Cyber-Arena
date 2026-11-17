import { BarChart3 } from "lucide-react";

export default function Leaderboard({ rows = [] }) {
  const list = rows || [];
  const max = Math.max(1, ...list.map(r => r.risk || 0));

  return (
    <div className="tl-card p-4 font-sans" data-testid="risk-leaderboard">
      <div className="flex items-center justify-between mb-3">
        <div>
          <div className="text-xs font-bold uppercase tracking-wider text-slate-200">
            High-Risk Entities
          </div>
          <div className="text-[10px] text-slate-400">
            Correlated suspicious talkers
          </div>
        </div>
        <BarChart3 className="w-4 h-4 text-cyan-400" />
      </div>

      {list.length === 0 ? (
        <div className="text-xs text-slate-500 py-6 text-center">
          No flagged entities in current window
        </div>
      ) : (
        <div className="space-y-2.5">
          {rows.slice(0, 5).map((r, i) => (
            <div key={r.ip} data-testid={`leaderboard-row-${i}`}>
              <div className="flex items-center justify-between text-xs font-mono mb-1">
                <span className="text-slate-500 text-[10px] w-4">{String(i + 1).padStart(2, "0")}</span>
                <span className="text-slate-200 flex-1 ml-1.5 truncate">{r.ip}</span>
                <span
                  className={`tabular-nums font-semibold ${
                    r.risk >= 90 ? "text-red-400" : r.risk >= 70 ? "text-amber-400" : "text-cyan-400"
                  }`}
                >
                  {r.risk} pts
                </span>
              </div>
              <div className="h-1.5 bg-slate-800 rounded-full overflow-hidden">
                <div
                  className={`h-full rounded-full transition-all duration-500 ${
                    r.risk >= 90 ? "bg-red-500" : r.risk >= 70 ? "bg-amber-400" : "bg-cyan-500"
                  }`}
                  style={{ width: `${(r.risk / max) * 100}%` }}
                />
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}