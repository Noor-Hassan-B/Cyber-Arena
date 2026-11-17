import React, { useState, useEffect } from 'react';
import { 
  X, 
  AlertTriangle, 
  ShieldCheck, 
  BrainCircuit, 
  Scale, 
  HelpCircle,
  Eye,
  Lock,
  FileCheck
} from 'lucide-react';
import { api } from '../services/api';

export default function AiLimitationsModal({ onClose }) {
  const [limitations, setLimitations] = useState([]);

  useEffect(() => {
    async function load() {
      const data = await api.getAiLimitations();
      setLimitations(data);
    }
    load();
  }, []);

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4 overflow-y-auto animate-fadeIn">
      <div className="bg-[#0F172A] border border-amber-500/30 w-full max-w-3xl rounded-2xl shadow-2xl flex flex-col overflow-hidden">
        
        {/* Header */}
        <div className="p-4 sm:p-5 border-b border-slate-800 flex items-center justify-between bg-slate-900/90">
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-lg bg-amber-500/20 text-amber-400 border border-amber-500/30">
              <AlertTriangle className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-sm font-bold text-white flex items-center gap-2">
                Explanation of AI Limitations in Threat Hunting & SOC
              </h2>
              <p className="text-xs text-slate-400">
                Critical vulnerabilities of LLMs in cyber defense & defensive architectural mitigations.
              </p>
            </div>
          </div>

          <button
            onClick={onClose}
            className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 transition"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Content */}
        <div className="p-5 sm:p-6 space-y-4 max-h-[75vh] overflow-y-auto text-xs text-slate-300">
          <div className="p-3.5 rounded-xl bg-amber-950/20 border border-amber-500/30 text-amber-200 space-y-1">
            <div className="font-bold flex items-center gap-1.5 text-xs">
              <BrainCircuit className="w-4 h-4 text-amber-400" />
              Core Principle: AI as Co-Pilot, Analyst as Commander
            </div>
            <p className="text-[11px] text-amber-300/80 leading-relaxed">
              While generative AI excels at summarizing complex incidents and suggesting queries, autonomous remediation without human verification introduces catastrophic availability risks. Threat hunting requires strict adherence to cryptographic evidence chains of custody.
            </p>
          </div>

          <div className="space-y-3">
            {limitations.map((lim, idx) => (
              <div
                key={lim.id}
                className="p-4 rounded-xl bg-slate-950/80 border border-slate-800 space-y-2 hover:border-slate-700 transition"
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="w-5 h-5 rounded-full bg-slate-800 text-[10px] font-mono flex items-center justify-center font-bold text-amber-400">
                      {idx + 1}
                    </span>
                    <h3 className="text-xs font-bold text-slate-100">
                      {lim.name}
                    </h3>
                  </div>
                  <span className={`px-2 py-0.5 rounded text-[10px] font-mono uppercase font-bold border ${
                    lim.severity === 'Critical' 
                      ? 'bg-red-950/80 border-red-500/40 text-red-400' 
                      : 'bg-amber-950/80 border-amber-500/40 text-amber-400'
                  }`}>
                    {lim.severity} Risk
                  </span>
                </div>

                <p className="text-slate-400 text-xs pl-7">
                  {lim.description}
                </p>

                {/* Platform Mitigation */}
                <div className="ml-7 p-2.5 rounded-lg bg-blue-950/30 border border-blue-500/30 text-[11px] text-blue-200">
                  <strong className="text-blue-300 flex items-center gap-1 mb-0.5">
                    <ShieldCheck className="w-3.5 h-3.5 text-blue-400" /> Platform Architecture Mitigation:
                  </strong>
                  <span>{lim.mitigation}</span>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Footer */}
        <div className="p-4 border-t border-slate-800 bg-slate-900/90 flex items-center justify-between text-xs text-slate-400">
          <span>AegisHunt Formal AI Governance Framework</span>
          <button
            onClick={onClose}
            className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-white font-semibold transition"
          >
            I Understand These Constraints
          </button>
        </div>

      </div>
    </div>
  );
}
