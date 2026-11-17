export default function ScenarioCard({ active, onClick, k, title, sub, icon: Icon }) {
  return (
    <button
      data-testid={`scenario-${k}`}
      onClick={onClick}
      className={`text-left p-3.5 rounded-lg border transition-all duration-200 relative group ${
        active
          ? "border-cyan-400 bg-cyan-950/30 shadow-lg shadow-cyan-950/40 ring-1 ring-cyan-400/40"
          : "border-slate-800/80 bg-slate-900/60 hover:border-slate-700 hover:bg-slate-800/50"
      }`}
    >
      <div className="flex items-start justify-between mb-2">
        <div
          className={`w-8 h-8 rounded-md flex items-center justify-center border transition-colors ${
            active
              ? "bg-cyan-500/20 border-cyan-400/50 text-cyan-300"
              : "bg-slate-950/60 border-slate-800 text-slate-400 group-hover:text-slate-200"
          }`}
        >
          <Icon className="w-4 h-4" />
        </div>
        <span
          className={`w-2.5 h-2.5 rounded-full transition-all ${
            active ? "bg-cyan-400 ring-4 ring-cyan-500/20" : "bg-slate-700 opacity-60"
          }`}
        />
      </div>

      <div className={`text-xs font-bold font-sans tracking-wide ${active ? "text-cyan-200" : "text-slate-200"}`}>
        {title}
      </div>

      <div className="text-[11px] text-slate-400 font-mono mt-1 truncate">
        {sub}
      </div>
    </button>
  );
}