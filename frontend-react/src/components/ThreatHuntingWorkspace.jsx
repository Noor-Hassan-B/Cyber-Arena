import React, { useState } from 'react';
import {
  Crosshair,
  ShieldAlert,
  CheckCircle2,
  AlertTriangle,
  Clock,
  User,
  Zap,
  ArrowRight,
  Filter,
  FileText,
  Bookmark,
  Share2,
  Lock,
  ChevronRight,
  Sparkles,
  ExternalLink,
  Flame,
  Check
} from 'lucide-react';

export default function ThreatHuntingWorkspace({ events, scenario, onSelectEvent }) {
  const [activeHypothesisId, setActiveHypothesisId] = useState('hypo-01');
  const [verdict, setVerdict] = useState('tp'); // 'tp' | 'bp' | 'fp'
  const [analystNotes, setAnalystNotes] = useState('Corroborated multiple lateral movement indicators across finance enclave workstations. C2 beacon interval matches Cobalt Strike default profile.');
  const [submittedStatus, setSubmittedStatus] = useState(false);

  // SOCForge structured hunt hypotheses
  const hypotheses = [
    {
      id: 'hypo-01',
      title: 'H-01: Pass-the-Hash & Lateral SMB Execution',
      tactic: 'Lateral Movement',
      technique: 'T1021.002 & T1550.002',
      confidence: 96,
      status: 'confirmed',
      summary: 'Adversary leveraged dumped NTLM hashes from WKSTN-FIN-04 to spawn remote service sessions on DC01 and FS-CONFIDENTIAL.',
      evidenceCount: 4,
      targetAssets: ['WKSTN-FIN-04', 'DC01.corp.local', 'FS-CONFIDENTIAL'],
      killChainPhase: 'Phase 4 - Lateral Spread'
    },
    {
      id: 'hypo-02',
      title: 'H-02: C2 Beaconing via Obfuscated HTTPS Channel',
      tactic: 'Command and Control',
      technique: 'T1071.001',
      confidence: 92,
      status: 'confirmed',
      summary: 'Periodic outbound sessions at 300s intervals with 10% jitter to external bulletproof node 185.220.101.47.',
      evidenceCount: 3,
      targetAssets: ['185.220.101.47', 'WKSTN-FIN-04'],
      killChainPhase: 'Phase 3 - C2 Establishment'
    },
    {
      id: 'hypo-03',
      title: 'H-03: Cloud IAM Token Minting & S3 Exfiltration',
      tactic: 'Exfiltration & Credential Access',
      technique: 'T1530 & T1552.005',
      confidence: 88,
      status: 'investigating',
      summary: 'Compromised developer access key used to query AWS STS GetCallerIdentity and enumerate confidential S3 buckets.',
      evidenceCount: 2,
      targetAssets: ['arn:aws:iam::123456789012:user/deployer', 's3://corp-financial-backups'],
      killChainPhase: 'Phase 5 - Exfiltration'
    }
  ];

  const currentHypo = hypotheses.find(h => h.id === activeHypothesisId) || hypotheses[0];

  const handleSignOffVerdict = () => {
    setSubmittedStatus(true);
    setTimeout(() => setSubmittedStatus(false), 4000);
  };

  return (
    <div className="space-y-6">
      {/* ── Top Header: Threat Hunting Mission ──────────────────────────────── */}
      <div className="bg-[#111827] border border-[#1f293d] rounded-xl p-5 shadow-xl">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <Crosshair className="w-5 h-5 text-indigo-400" />
              <h2 className="text-base font-bold text-white tracking-wide">
                Hypothesis-Driven Threat Hunting & Incident Triage
              </h2>
              <span className="px-2 py-0.5 rounded bg-indigo-500/10 border border-indigo-500/25 text-indigo-400 text-[10px] font-mono font-bold">
                SOCForge Studio
              </span>
              <span className="px-2 py-0.5 rounded bg-red-500/10 border border-red-500/25 text-red-400 text-[10px] font-mono font-bold">
                Active Campaign
              </span>
            </div>
            <p className="text-xs text-gray-400 max-w-3xl leading-relaxed">
              Formulate adversarial hypotheses, correlate corroborated telemetry chains, validate MITRE ATT&CK kill-chain progression, and record human-in-the-loop triage verdicts.
            </p>
          </div>

          <div className="flex items-center gap-3 shrink-0">
            <div className="bg-[#0b0f17] border border-[#1f293d] rounded-lg px-3 py-2 text-center">
              <div className="text-lg font-mono font-bold text-indigo-400">3</div>
              <div className="text-[10px] font-mono text-gray-500">Active Hypotheses</div>
            </div>
            <div className="bg-[#0b0f17] border border-[#1f293d] rounded-lg px-3 py-2 text-center">
              <div className="text-lg font-mono font-bold text-emerald-400">92%</div>
              <div className="text-[10px] font-mono text-gray-500">Mean Confidence</div>
            </div>
            <div className="bg-[#0b0f17] border border-[#1f293d] rounded-lg px-3 py-2 text-center">
              <div className="text-lg font-mono font-bold text-red-400">APT29</div>
              <div className="text-[10px] font-mono text-gray-500">Attributed Actor</div>
            </div>
          </div>
        </div>

        {/* Kill Chain Progression Tracker */}
        <div className="mt-5 pt-4 border-t border-[#1f293d]">
          <div className="text-[10px] font-mono font-bold text-gray-500 uppercase tracking-widest mb-3">
            Adversary Cyber Kill Chain Progression
          </div>
          <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-6 gap-2">
            {[
              { phase: '1. Recon', state: 'bypassed', color: 'border-gray-700 text-gray-500' },
              { phase: '2. Initial Access', state: 'detected', color: 'border-orange-500/40 bg-orange-950/20 text-orange-300' },
              { phase: '3. Execution & C2', state: 'confirmed', color: 'border-red-500/50 bg-red-950/40 text-red-300' },
              { phase: '4. Lateral Spread', state: 'active', color: 'border-red-500/50 bg-red-950/40 text-red-300 font-bold' },
              { phase: '5. Collection', state: 'attempted', color: 'border-amber-500/40 bg-amber-950/20 text-amber-300' },
              { phase: '6. Exfiltration', state: 'blocked', color: 'border-emerald-500/40 bg-emerald-950/20 text-emerald-300' },
            ].map(kc => (
              <div key={kc.phase} className={`border rounded-lg p-2.5 text-center ${kc.color}`}>
                <div className="text-xs font-mono">{kc.phase}</div>
                <div className="text-[9px] font-mono uppercase tracking-wider mt-1 opacity-80">{kc.state}</div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* ── Main Workspace: Hypotheses Cards + Hypothesis Deep-Dive ────────── */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">

        {/* Left: Hypotheses List (4 Cols) */}
        <div className="lg:col-span-4 space-y-3">
          <span className="text-xs font-bold text-gray-300 font-mono uppercase tracking-wider block">
            Hunt Hypotheses ({hypotheses.length})
          </span>

          {hypotheses.map(hypo => {
            const isSelected = hypo.id === activeHypothesisId;
            return (
              <button
                key={hypo.id}
                onClick={() => setActiveHypothesisId(hypo.id)}
                className={`w-full p-4 rounded-xl border text-left transition ${
                  isSelected
                    ? 'bg-indigo-600/15 border-indigo-500/50 shadow-md'
                    : 'bg-[#111827] border-[#1f293d] hover:border-gray-700'
                }`}
              >
                <div className="flex items-center justify-between gap-2 mb-1">
                  <span className="text-xs font-bold text-white truncate">{hypo.title}</span>
                  <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-indigo-500/20 text-indigo-300 border border-indigo-500/30">
                    {hypo.confidence}%
                  </span>
                </div>

                <div className="text-xs text-gray-400 line-clamp-2 mt-1 leading-relaxed">
                  {hypo.summary}
                </div>

                <div className="flex items-center gap-2 mt-3 pt-2 border-t border-[#1f293d] text-[10px] font-mono text-gray-500">
                  <span className="text-indigo-400">{hypo.tactic}</span>
                  <span>&bull;</span>
                  <span>{hypo.evidenceCount} Linked Events</span>
                </div>
              </button>
            );
          })}
        </div>

        {/* Right: Hypothesis Investigation Workbench & Verdict Form (8 Cols) */}
        <div className="lg:col-span-8 bg-[#111827] border border-[#1f293d] rounded-xl p-5 space-y-5">
          {/* Header of Active Hypothesis */}
          <div className="flex items-start justify-between pb-4 border-b border-[#1f293d]">
            <div>
              <div className="flex items-center gap-2 mb-1">
                <Bookmark className="w-4 h-4 text-indigo-400" />
                <h3 className="text-base font-bold text-white">{currentHypo.title}</h3>
              </div>
              <p className="text-xs text-gray-400 font-mono">
                MITRE Technique: <span className="text-indigo-300">{currentHypo.technique}</span> &bull; Kill Chain: <span className="text-amber-300">{currentHypo.killChainPhase}</span>
              </p>
            </div>

            <span className="px-3 py-1 rounded-full text-xs font-mono font-bold bg-emerald-500/10 border border-emerald-500/30 text-emerald-400">
              CORROBORATED BY EVIDENCE
            </span>
          </div>

          {/* Adversary Narrative Breakdown */}
          <div className="bg-[#0b0f17] border border-[#1f293d] rounded-lg p-4 space-y-2">
            <span className="text-[10px] font-mono font-bold text-gray-500 uppercase tracking-wider block">
              Investigative Hypothesis Findings
            </span>
            <p className="text-xs text-gray-300 leading-relaxed font-mono">
              {currentHypo.summary}
            </p>
            <div className="flex items-center gap-2 pt-2 flex-wrap text-xs font-mono">
              <span className="text-gray-500">Target Assets:</span>
              {(currentHypo.targetAssets || []).map(asset => (
                <span key={asset} className="px-2 py-0.5 rounded bg-gray-800 text-gray-300 border border-gray-700">
                  {asset}
                </span>
              ))}
            </div>
          </div>

          {/* Corroborated Telemetry Events List */}
          <div>
            <span className="text-[10px] font-mono font-bold text-gray-500 uppercase tracking-wider block mb-2">
              Corroborated Telemetry Evidence Samples
            </span>
            <div className="space-y-1.5 max-h-48 overflow-y-auto">
              {(events || []).slice(0, 4).map(evt => (
                <div
                  key={evt.event_uuid}
                  onClick={() => onSelectEvent(evt.event_uuid)}
                  className="bg-[#0b0f17] border border-[#1f293d] hover:border-gray-700 rounded-lg p-3 flex items-center justify-between text-xs cursor-pointer transition"
                >
                  <div className="flex items-center gap-2 truncate">
                    <span className="w-2 h-2 rounded-full bg-red-500" />
                    <span className="font-mono text-gray-200 font-bold">{evt.event_uuid}</span>
                    <span className="text-gray-400 font-mono truncate">{evt.event_type}</span>
                  </div>
                  <div className="flex items-center gap-3 shrink-0">
                    <span className="text-[10px] font-mono text-indigo-400">{evt.mitre_technique_id}</span>
                    <ChevronRight className="w-3.5 h-3.5 text-gray-600" />
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* ── Analyst Verdict & Signoff ─────────────────────────────────── */}
          <div className="pt-4 border-t border-[#1f293d] space-y-3">
            <span className="text-[10px] font-mono font-bold text-gray-500 uppercase tracking-wider block">
              Human-in-the-Loop Triage Decision & Verdict Sign-Off
            </span>

            <div className="grid grid-cols-3 gap-2">
              {[
                { id: 'tp', label: 'True Positive (Security Incident)', color: 'bg-red-500/10 border-red-500/40 text-red-300' },
                { id: 'bp', label: 'Benign Positive (Authorized IT Activity)', color: 'bg-amber-500/10 border-amber-500/40 text-amber-300' },
                { id: 'fp', label: 'False Positive (Tuning Required)', color: 'bg-blue-500/10 border-blue-500/40 text-blue-300' },
              ].map(v => (
                <button
                  key={v.id}
                  onClick={() => setVerdict(v.id)}
                  className={`py-2 px-3 rounded-lg text-xs font-mono font-bold border transition ${
                    verdict === v.id
                      ? `${v.color} shadow-sm`
                      : 'bg-[#0b0f17] border-[#1f293d] text-gray-500 hover:text-gray-300'
                  }`}
                >
                  {v.label}
                </button>
              ))}
            </div>

            <textarea
              value={analystNotes}
              onChange={e => setAnalystNotes(e.target.value)}
              rows={3}
              placeholder="Record forensic analyst findings, MITRE attributions, and justification for remediation..."
              className="w-full bg-[#0b0f17] border border-[#1f293d] rounded-lg p-3 text-xs text-gray-200 font-mono placeholder-gray-600 focus:outline-none focus:border-indigo-500/50"
            />

            <div className="flex items-center justify-between">
              {submittedStatus ? (
                <span className="text-xs font-mono text-emerald-400 flex items-center gap-1.5 animate-pulse">
                  <Check className="w-4 h-4" /> Verdict recorded to immutable audit ledger.
                </span>
              ) : (
                <span className="text-[11px] font-mono text-gray-500">
                  Analyst Sign-Off: <span className="text-gray-300">sandeep.m@socforge.sec</span>
                </span>
              )}

              <button
                onClick={handleSignOffVerdict}
                className="flex items-center gap-2 px-4 py-2 bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg text-xs font-bold transition shadow-md shadow-indigo-600/30"
              >
                <CheckCircle2 className="w-4 h-4" />
                Commit Triage Verdict
              </button>
            </div>
          </div>

        </div>

      </div>
    </div>
  );
}
