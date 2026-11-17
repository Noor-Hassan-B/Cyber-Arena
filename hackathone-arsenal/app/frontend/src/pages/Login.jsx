import { useState } from "react";
import { useAuth } from "@/context/AuthContext";
import { formatDetail } from "@/lib/api";
import { Shield, Terminal, Lock, ArrowRight } from "lucide-react";

export default function Login() {
  const { login } = useAuth();
  const [email, setEmail] = useState("analyst@threatlens.io");
  const [password, setPassword] = useState("threatlens2026");
  const [err, setErr] = useState("");
  const [loading, setLoading] = useState(false);

  const submit = async (e) => {
    e.preventDefault(); setErr(""); setLoading(true);
    try { await login(email, password); }
    catch (e) { setErr(formatDetail(e.response?.data?.detail) || e.message); }
    finally { setLoading(false); }
  };

  return (
    <div className="min-h-screen relative overflow-hidden" data-testid="login-page">
      <div className="absolute inset-0 grid-bg opacity-40" />
      <div className="absolute inset-0 bg-gradient-to-br from-transparent via-transparent to-cyan-950/20" />
      <div className="relative z-10 min-h-screen grid grid-cols-1 lg:grid-cols-[1.15fr_1fr]">
        {/* Left panel — brand */}
        <div className="flex flex-col justify-between p-8 lg:p-14 border-r border-cyan-500/10">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-sm border border-cyan-500/40 flex items-center justify-center glow-cyan">
              <Shield className="w-5 h-5 text-cyan-400" />
            </div>
            <div>
              <div className="text-sm tracking-[0.28em] uppercase font-bold text-slate-100">ThreatLens <span className="text-cyan-400">SOC</span></div>
              <div className="text-[10px] tracking-[0.24em] uppercase text-slate-500">Obsidian Command Center · Enterprise Edition</div>
            </div>
          </div>

          <div className="max-w-xl">
            <div className="label-caps mb-6">Tier-1 Digital Neo-Bank · SecOps Enclave</div>
            <h1 className="tl-hero text-5xl sm:text-6xl lg:text-7xl mb-6">
              Threat operations,<br/>
              <span className="tl-accent term-glow">observed in real time.</span>
            </h1>
            <p className="text-slate-400 text-sm leading-relaxed max-w-md">
              Autonomous security telemetry pipeline with multi-detector anomaly heuristics, dynamic risk scoring, and real-time MITRE ATT&CK correlation across high-throughput hybrid cloud infrastructure.
            </p>

            <div className="grid grid-cols-3 gap-3 mt-10 max-w-lg">
              {["EWMA baseline","Isolation Forest","DBSCAN outlier"].map((d,i)=>(
                <div key={i} className="tl-card p-3">
                  <div className="text-[10px] tracking-[0.2em] uppercase text-slate-500 mb-1">Detector</div>
                  <div className="text-xs text-cyan-300 font-mono">{d}</div>
                </div>
              ))}
            </div>
          </div>

          <div className="flex items-center gap-4 text-[10px] tracking-[0.24em] uppercase text-slate-600">
            <span className="flex items-center gap-2"><span className="pulse-dot" /> SOC Pipeline Active</span>
            <span>·</span>
            <span>Zero-Trust Enclave</span>
            <span>·</span>
            <span>MITRE ATT&CK · T1110 · T1595 · T1078</span>
          </div>
        </div>

        {/* Right panel — auth */}
        <div className="flex items-center justify-center p-8 lg:p-14 bg-[#08090C]/60">
          <form onSubmit={submit} className="w-full max-w-sm tl-card p-8" data-testid="login-form">
            <div className="flex items-center gap-2 mb-8">
              <Terminal className="w-4 h-4 text-cyan-400" />
              <div className="label-caps">SecOps Authentication</div>
            </div>
            <div className="space-y-5">
              <div>
                <label className="label-caps block mb-2">Analyst Identity</label>
                <input data-testid="login-email-input" value={email} onChange={e=>setEmail(e.target.value)}
                  className="w-full bg-[#05070A] border border-cyan-500/20 focus:border-cyan-400 rounded-sm px-3 py-3 text-sm font-mono text-slate-100 placeholder:text-slate-600 outline-none transition"
                  placeholder="analyst@threatlens.io" />
              </div>
              <div>
                <label className="label-caps block mb-2">Access Token / Password</label>
                <div className="relative">
                  <input data-testid="login-password-input" type="password" value={password} onChange={e=>setPassword(e.target.value)}
                    className="w-full bg-[#05070A] border border-cyan-500/20 focus:border-cyan-400 rounded-sm px-3 py-3 pr-10 text-sm font-mono text-slate-100 placeholder:text-slate-600 outline-none transition"
                    placeholder="••••••••••••" />
                  <Lock className="w-3.5 h-3.5 text-slate-600 absolute right-3 top-1/2 -translate-y-1/2" />
                </div>
              </div>
              {err && <div className="text-[11px] font-mono text-red-400 border border-red-500/30 bg-red-950/30 rounded-sm px-3 py-2" data-testid="login-error">{err}</div>}
              <button data-testid="login-submit-button" disabled={loading} className="btn-primary w-full flex items-center justify-center gap-2">
                {loading ? "Authenticating…" : "Enter Command Center"}
                {!loading && <ArrowRight className="w-3.5 h-3.5" />}
              </button>
            </div>
            <div className="mt-8 pt-6 border-t border-cyan-500/10">
              <div className="label-caps mb-2">Default Operator Credentials</div>
              <div className="text-[11px] font-mono text-slate-500 leading-relaxed break-all">
                {email}<br/>
                <span className="text-slate-600">threatlens2026</span>
              </div>
            </div>
          </form>
        </div>
      </div>
    </div>
  );
}