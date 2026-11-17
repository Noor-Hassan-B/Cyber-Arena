import React, { useState } from 'react';
import { 
  Grid, 
  ShieldCheck, 
  AlertTriangle, 
  ExternalLink,
  ChevronRight,
  Info
} from 'lucide-react';
import { MITRE_TACTICS, MITRE_TECHNIQUES_CATALOG } from '../constants/mitreMatrix';

export default function MitreMatrixView({ mitreData, onSelectEvent }) {
  const [selectedTechnique, setSelectedTechnique] = useState(null);

  const observed = mitreData?.observed_techniques || {};

  return (
    <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-4 sm:p-5 shadow-xl space-y-4">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800/80 pb-3">
        <div>
          <div className="flex items-center gap-2">
            <Grid className="w-4 h-4 text-indigo-400" />
            <h2 className="text-sm font-bold text-slate-100">
              MITRE ATT&CK Enterprise Matrix & Kill-Chain Heatmap
            </h2>
            <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-indigo-950/80 border border-indigo-500/30 text-indigo-300">
              {Object.keys(observed).length} Techniques Active
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-0.5">
            Behavioral mapping across 12 tactics. Lit tiles indicate observed adversary activity in ingested logs.
          </p>
        </div>

        {/* Legend */}
        <div className="flex items-center gap-3 text-[11px] font-mono">
          <div className="flex items-center gap-1">
            <span className="w-2.5 h-2.5 rounded bg-red-500" />
            <span className="text-slate-300">Critical / High Hit</span>
          </div>
          <div className="flex items-center gap-1">
            <span className="w-2.5 h-2.5 rounded bg-amber-500" />
            <span className="text-slate-300">Medium Hit</span>
          </div>
          <div className="flex items-center gap-1">
            <span className="w-2.5 h-2.5 rounded bg-slate-800 border border-slate-700" />
            <span className="text-slate-500">Unobserved</span>
          </div>
        </div>
      </div>

      {/* 12-Tactic Grid */}
      <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-6 gap-2.5 overflow-x-auto pb-2">
        {MITRE_TACTICS.map((tactic) => {
          // Find techniques belonging to this tactic
          const matchingTechniques = Object.entries(MITRE_TECHNIQUES_CATALOG).filter(
            ([_, t]) => t.tactic.toLowerCase() === tactic.name.toLowerCase()
          );

          return (
            <div
              key={tactic.id}
              className="bg-slate-950/70 border border-slate-800 rounded-lg p-2.5 flex flex-col min-w-[140px]"
            >
              <div className="border-b border-slate-800/80 pb-1.5 mb-2">
                <span className="text-[10px] font-mono text-slate-500 uppercase">
                  {tactic.id}
                </span>
                <h3 className="text-xs font-bold text-slate-200 tracking-tight truncate">
                  {tactic.name}
                </h3>
              </div>

              {/* Techniques List for this Tactic */}
              <div className="space-y-1.5 flex-1">
                {matchingTechniques.map(([techId, tech]) => {
                  const hit = observed[techId];
                  const isHit = !!hit;

                  let tileStyle = 'bg-slate-900/60 border-slate-800/80 text-slate-500 hover:text-slate-400';
                  if (isHit) {
                    if (hit.severity === 'critical') {
                      tileStyle = 'bg-red-950/60 border-red-500/60 text-red-300 glow-red font-semibold';
                    } else if (hit.severity === 'high') {
                      tileStyle = 'bg-amber-950/60 border-amber-500/60 text-amber-300 font-semibold';
                    } else {
                      tileStyle = 'bg-blue-950/60 border-blue-500/60 text-blue-300 font-semibold';
                    }
                  }

                  return (
                    <button
                      key={techId}
                      onClick={() => {
                        setSelectedTechnique({ techId, tech, hit });
                        if (hit && hit.event_uuids && hit.event_uuids.length > 0) {
                          onSelectEvent(hit.event_uuids[0]);
                        }
                      }}
                      className={`w-full text-left p-1.5 rounded border text-[11px] transition-all flex flex-col justify-between ${tileStyle}`}
                    >
                      <div className="flex items-center justify-between w-full">
                        <span className="font-mono text-[10px]">{techId}</span>
                        {isHit && (
                          <span className="w-4 h-4 rounded-full bg-slate-950/80 text-[9px] font-mono flex items-center justify-center text-white">
                            {hit.hit_count}
                          </span>
                        )}
                      </div>
                      <span className="truncate mt-0.5 text-[10px] leading-tight">
                        {tech.name}
                      </span>
                    </button>
                  );
                })}

                {matchingTechniques.length === 0 && (
                  <div className="text-[10px] text-slate-600 italic py-2 text-center">
                    No active techniques
                  </div>
                )}
              </div>
            </div>
          );
        })}
      </div>

      {/* Selected Technique Inspector Drawer */}
      {selectedTechnique && (
        <div className="bg-slate-950 border border-slate-700/80 rounded-xl p-3.5 mt-2 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <span className="font-mono text-xs font-bold text-indigo-400">
                {selectedTechnique.techId}
              </span>
              <span className="text-xs font-semibold text-slate-200">
                {selectedTechnique.tech.name}
              </span>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-400">
                Tactic: {selectedTechnique.tech.tactic}
              </span>
            </div>
            <p className="text-xs text-slate-400">
              {selectedTechnique.hit
                ? `Active detection: ${selectedTechnique.hit.hit_count} matching event(s) in current investigation.`
                : 'Technique is defined in MITRE Enterprise Matrix but was not triggered in this scenario.'}
            </p>
          </div>

          {selectedTechnique.hit && selectedTechnique.hit.event_uuids && (
            <div className="flex items-center gap-2 self-start sm:self-auto">
              {selectedTechnique.hit.event_uuids.map((uuid) => (
                <button
                  key={uuid}
                  onClick={() => onSelectEvent(uuid)}
                  className="px-2.5 py-1 text-xs font-mono rounded bg-blue-600 hover:bg-blue-500 text-white font-semibold flex items-center gap-1 shadow"
                >
                  Inspect {uuid} <ChevronRight className="w-3 h-3" />
                </button>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
