export default function KpiTile({ label, value, unit, caption, tone = "cyan", trend, icon: Icon }) {
  const toneColor =
    tone === "red"
      ? "text-red-400"
      : tone === "amber"
      ? "text-amber-400"
      : tone === "emerald"
      ? "text-emerald-400"
      : "text-cyan-300";

  const glowBorder =
    tone === "red"
      ? "hover:border-red-500/40"
      : tone === "amber"
      ? "hover:border-amber-500/40"
      : tone === "emerald"
      ? "hover:border-emerald-500/40"
      : "hover:border-cyan-500/40";

  return (
    <div
      className={`tl-card p-4 relative overflow-hidden group ${glowBorder}`}
      data-testid={`kpi-${label.replace(/\s+/g, "-").toLowerCase()}`}
    >
      <div className="flex items-center justify-between mb-2">
        <span className="label-caps text-slate-400 font-semibold">{label}</span>
        <div className="flex items-center gap-2">
          {Icon && <Icon className={`w-3.5 h-3.5 ${toneColor} opacity-80`} />}
          <span
            className={`pulse-dot ${
              tone === "red" ? "critical" : tone === "amber" ? "amber" : ""
            }`}
          />
        </div>
      </div>

      <div className="flex items-baseline gap-2 mt-1">
        <div className={`text-3xl font-mono font-extrabold ${toneColor} tabular-nums tracking-tight`}>
          {value}
        </div>
        {unit && (
          <div className="text-[11px] font-mono font-semibold text-slate-400 uppercase tracking-wider">
            {unit}
          </div>
        )}
      </div>

      <div className="flex items-center justify-between mt-3 pt-2.5 border-t border-slate-800/80 text-[11px]">
        <span className="text-slate-400 truncate font-sans">{caption}</span>
        {trend && (
          <span className="text-[10px] font-mono text-cyan-400 font-semibold ml-2 px-1.5 py-0.5 rounded bg-cyan-500/10 border border-cyan-500/20 flex-shrink-0">
            {trend}
          </span>
        )}
      </div>
    </div>
  );
}