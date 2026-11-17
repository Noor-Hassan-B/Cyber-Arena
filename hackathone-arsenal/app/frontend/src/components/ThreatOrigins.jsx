import { Globe } from "lucide-react";

export default function ThreatOrigins({ origins = [] }) {
  const hash = (s) => {
    let h = 0;
    const str = s || "";
    for (let i = 0; i < str.length; i++) h = ((h << 5) - h + str.charCodeAt(i)) | 0;
    return Math.abs(h);
  };
  const list = origins || [];

  return (
    <div className="tl-card p-4 font-sans" data-testid="threat-origins">
      <div className="flex items-center justify-between mb-3">
        <div>
          <div className="text-xs font-bold uppercase tracking-wider text-slate-200">
            Threat Origin Geolocation
          </div>
          <div className="text-[10px] text-slate-400">
            Ingress origin anomaly map
          </div>
        </div>
        <Globe className="w-4 h-4 text-cyan-400" />
      </div>

      <div className="relative h-36 rounded border border-slate-800/80 overflow-hidden bg-[#070A11]">
        {/* World dots grid */}
        <div
          className="absolute inset-0 opacity-20"
          style={{
            backgroundImage: "radial-gradient(rgba(56, 189, 248, 0.4) 1px, transparent 1px)",
            backgroundSize: "16px 16px",
          }}
        />

        {list.slice(0, 6).map((o, i) => {
          const h = hash(o.geo || o.ip);
          const x = 10 + (h % 78);
          const y = 14 + ((h >> 4) % 65);
          return (
            <div
              key={i}
              className="absolute"
              style={{ left: `${x}%`, top: `${y}%` }}
              data-testid={`origin-${i}`}
            >
              <span className={`pulse-dot ${o.risk >= 90 ? "critical" : o.risk >= 70 ? "amber" : ""}`} />
              <div className="text-[9px] text-slate-400 font-mono translate-x-2.5 -translate-y-2.5 absolute whitespace-nowrap bg-black/70 px-1 py-0.2 rounded">
                {o.geo || o.ip}
              </div>
            </div>
          );
        })}
      </div>

      <div className="flex items-center justify-between mt-3 text-[11px] text-slate-500 font-mono">
        <span>Origins Detected: {list.length}</span>
        <span className="flex items-center gap-1.5 text-emerald-400 font-medium">
          <span className="pulse-dot" /> Tracking Live
        </span>
      </div>
    </div>
  );
}