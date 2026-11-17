import { useState, useEffect } from "react";
import { X, Check, Shield, Activity, Terminal, ShieldAlert, Cpu, Server, UserCheck, Lock, CheckCircle2, Download } from "lucide-react";
import { api } from "@/lib/api";
import { toast } from "sonner";

export default function AlertDrilldown({ alert, onClose, onChange }) {
  const [note, setNote] = useState(alert.analyst_note || "");
  const [contained, setContained] = useState(alert.contained || false);
  const [status, setStatus] = useState(alert.status || "open");
  const [savingNote, setSavingNote] = useState(false);

  useEffect(() => {
    setNote(alert.analyst_note || "");
    setContained(alert.contained || false);
    setStatus(alert.status || "open");
  }, [alert.id, alert.analyst_note, alert.contained, alert.status]);

  const downloadCaseReport = () => {
    const md = `# THREATLENS INCIDENT RESPONSE CASE REPORT
**Case ID:** ALT-${String(alert.id || "").slice(-8)}
**Incident Title:** ${alert.title}
**Severity Tier:** ${(alert.severity || "").toUpperCase()}
**Risk Score:** ${alert.risk_score}/100
**Timestamp:** ${alert.triggered_at}
**Target Enclave:** Tier-1 Neo-Bank Hybrid Cloud Infrastructure (65,000 tx/s Baseline)

## 1. Incident Overview & Impact
${alert.summary}

## 2. MITRE ATT&CK Classification
- **Technique ID:** ${alert.mitre?.id || "T1078"}
- **Technique Name:** ${alert.mitre?.name || "Anomaly"}
- **Source Node:** ${alert.source_ip} (${alert.geo || "Unknown"})
- **Target Service:** ${alert.service || "svc-ledger"} on ${alert.target_vm || "10.42.0.10"}

## 3. Multi-Model Anomaly Detection Consensus
${(alert.detectors || []).map(d => `- **${d.name}:** ${d.vote ? "ANOMALOUS TRIGGER" : "NORMAL"} (${d.confidence}% confidence)`).join("\n")}

## 4. Telemetry Signatures Detected
${(alert.features || []).map(f => `- ${f}`).join("\n")}

## 5. Recommended Remediation
${alert.recommended}

## 6. Analyst Investigation Findings
${note || "No analyst notes recorded."}

## 7. Containment & Incident Status
- **Incident Status:** ${(status || "").toUpperCase()}
- **SDN Hypervisor Containment:** ${contained ? "ENGAGED / HOST ENCLAVE ISOLATED" : "NOT ENGAGED"}

---
*ThreatLens Autonomous SecOps Intelligence Engine*
`;
    const blob = new Blob([md], { type: "text/markdown;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `incident_triage_${String(alert.id || "alt").slice(-8)}.md`;
    a.click();
    URL.revokeObjectURL(url);
    toast.success("Incident Response Case Report downloaded");
  };

  const save = async () => {
    setSavingNote(true);
    try {
      await api.saveNote(alert.id, note);
      toast.success("Analyst investigation note saved");
      onChange?.();
    } catch (e) {
      toast.error("Failed to save note");
    } finally {
      setSavingNote(false);
    }
  };

  const setSt = async (s) => {
    setStatus(s);
    await api.setStatus(alert.id, s);
    toast.success(`Incident status updated to '${s.toUpperCase()}'`);
    onChange?.();
  };

  const toggle = async () => {
    const nv = !contained;
    setContained(nv);
    await api.setContainment(alert.id, nv);
    if (nv) {
      toast.error("Host containment policy engaged (Host isolated from enclave)");
    } else {
      toast.success("Host containment policy released");
    }
    onChange?.();
  };

  return (
    <>
      {/* Backdrop */}
      <div
        className="fixed inset-0 bg-black/70 backdrop-blur-sm z-40 transition-opacity"
        onClick={onClose}
        data-testid="drilldown-overlay"
      />

      {/* Investigation Drawer */}
      <aside
        className="fixed top-0 right-0 h-full w-full sm:w-[560px] bg-[#0A0E17] border-l border-slate-800 z-50 overflow-y-auto font-sans shadow-2xl flex flex-col"
        data-testid="alert-drilldown"
      >
        {/* Drawer Header */}
        <div className="sticky top-0 bg-[#0B0F19]/95 backdrop-blur-md border-b border-slate-800 px-6 py-4 flex items-center justify-between z-10">
          <div className="flex items-center gap-2.5">
            <span className={`pulse-dot ${alert.severity === "critical" ? "critical" : "amber"}`} />
            <div>
              <div className="text-xs font-bold uppercase tracking-wider text-slate-200">
                Incident Triage Workbench
              </div>
              <div className="text-[10px] font-mono text-slate-500">ID: {alert.id || "ALT-4029"}</div>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={downloadCaseReport}
              data-testid="download-case-report"
              className="px-2.5 py-1 rounded text-xs font-mono text-cyan-300 hover:text-white bg-slate-800 hover:bg-slate-700 flex items-center gap-1.5 transition border border-slate-700/60"
              title="Download Incident Triage Report (.md)"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Export Triage Report</span>
            </button>
            <button
              onClick={onClose}
              data-testid="drilldown-close"
              className="p-1 text-slate-400 hover:text-slate-200 hover:bg-slate-800 rounded transition"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Content Body */}
        <div className="p-6 space-y-6 flex-1">
          {/* Incident Headline */}
          <div>
            <div className="flex items-center gap-2 mb-2 flex-wrap">
              <span className={`badge badge-${alert.severity}`}>{alert.severity}</span>
              <span className="badge badge-medium">MITRE {alert.mitre?.id}</span>
              <span className="text-xs font-mono font-bold text-slate-300">
                Risk Score:{" "}
                <strong
                  className={
                    alert.risk_score >= 90
                      ? "text-red-400"
                      : alert.risk_score >= 70
                      ? "text-amber-400"
                      : "text-cyan-400"
                  }
                >
                  {alert.risk_score}/100
                </strong>
              </span>
            </div>
            <h2 className="text-lg font-bold text-slate-100 leading-snug mb-2">{alert.title}</h2>
            <p className="text-xs text-slate-400 leading-relaxed">{alert.summary}</p>
          </div>

          {/* Key Incident Indicators */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-xs">
            <MetaTile label="Source IP" value={alert.source_ip} mono />
            <MetaTile label="Target Service" value={alert.service || "svc-ledger"} mono />
            <MetaTile label="Origin Geo" value={alert.geo || "Frankfurt, DE"} />
            <MetaTile label="Correlated Evts" value={alert.events_count || 14} mono />
          </div>

          {/* Multi-Model ML Consensus */}
          <div className="tl-card p-4">
            <div className="flex items-center gap-2 mb-3">
              <Activity className="w-4 h-4 text-cyan-400" />
              <span className="label-caps text-slate-200">Ensemble Detection Consensus</span>
            </div>
            <div className="grid grid-cols-2 gap-2">
              {(alert.detectors || []).map((d, i) => (
                <div
                  key={i}
                  className={`p-2.5 rounded border ${
                    d.vote ? "bg-[#0E1524] border-cyan-500/40" : "bg-[#080B12] border-slate-800"
                  }`}
                  data-testid={`detector-${i}`}
                >
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-xs font-medium text-slate-200">{d.name}</span>
                    <span
                      className={`text-[10px] font-mono font-bold uppercase ${
                        d.vote ? "text-emerald-400" : "text-slate-500"
                      }`}
                    >
                      {d.vote ? "ALERT" : "NORMAL"}
                    </span>
                  </div>
                  <div className="text-[10px] font-mono text-slate-400">
                    Confidence: <strong className="text-slate-200">{d.confidence}%</strong>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Anomaly Signatures */}
          <div>
            <div className="label-caps mb-2 text-slate-400">Telemetry Signatures Triggered</div>
            <div className="space-y-1.5 font-mono">
              {(alert.features || []).map((f, i) => (
                <div
                  key={i}
                  className="flex items-center gap-2 text-[11px] text-slate-300 py-2 px-3 rounded border border-slate-800 bg-[#080C14]"
                  data-testid={`feature-${i}`}
                >
                  <span className="w-1.5 h-1.5 rounded-full bg-amber-400 flex-shrink-0" />
                  <span>{f}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Recommended SecOps Mitigation */}
          <div className="p-4 rounded-md border border-cyan-500/30 bg-[#09111D]">
            <div className="label-caps mb-1.5 flex items-center gap-2 text-cyan-300">
              <Shield className="w-3.5 h-3.5" /> Recommended Remediation
            </div>
            <div className="text-xs text-slate-200 leading-relaxed">{alert.recommended}</div>
          </div>

          {/* Analyst Note Editor */}
          <div>
            <div className="label-caps mb-2 flex items-center gap-2 text-slate-400">
              <Terminal className="w-3.5 h-3.5" /> Analyst Investigation Notes
            </div>
            <textarea
              value={note}
              onChange={e => setNote(e.target.value)}
              placeholder="Record investigation notes, IOC findings, containment timeline..."
              rows={3}
              data-testid="analyst-note-input"
              className="w-full bg-[#070A11] border border-slate-800 focus:border-cyan-500/80 rounded-md p-3 text-xs font-mono text-slate-100 outline-none placeholder:text-slate-600 transition"
            />
            <div className="flex justify-end mt-2">
              <button
                onClick={save}
                disabled={savingNote}
                data-testid="save-note-button"
                className="btn-ghost text-xs"
              >
                {savingNote ? "Saving..." : "Save Note"}
              </button>
            </div>
          </div>

          {/* Incident Response & Containment */}
          <div className="pt-2 border-t border-slate-800">
            <div className="label-caps mb-3 text-slate-400">Incident Response Actions</div>
            <div className="grid grid-cols-3 gap-2 mb-3">
              <button
                onClick={() => setSt("open")}
                data-testid="status-open-button"
                className={`py-2 px-3 rounded text-xs font-medium border transition ${
                  status === "open"
                    ? "bg-amber-950/40 text-amber-300 border-amber-500/50 font-semibold"
                    : "bg-[#0A0D15] text-slate-400 border-slate-800 hover:text-slate-200"
                }`}
              >
                Open
              </button>
              <button
                onClick={() => setSt("acknowledged")}
                data-testid="status-ack-button"
                className={`py-2 px-3 rounded text-xs font-medium border transition ${
                  status === "acknowledged"
                    ? "bg-cyan-950/40 text-cyan-300 border-cyan-500/50 font-semibold"
                    : "bg-[#0A0D15] text-slate-400 border-slate-800 hover:text-slate-200"
                }`}
              >
                Acknowledge
              </button>
              <button
                onClick={() => setSt("resolved")}
                data-testid="status-resolved-button"
                className={`py-2 px-3 rounded text-xs font-medium border transition ${
                  status === "resolved"
                    ? "bg-emerald-950/40 text-emerald-300 border-emerald-500/50 font-semibold"
                    : "bg-[#0A0D15] text-slate-400 border-slate-800 hover:text-slate-200"
                }`}
              >
                Resolve
              </button>
            </div>

            <button
              onClick={toggle}
              data-testid="containment-toggle"
              className={`w-full flex items-center justify-between px-4 py-3 rounded-md border transition ${
                contained
                  ? "border-red-500/60 bg-red-950/30 text-red-300 font-semibold"
                  : "border-slate-800 bg-[#0C101A] hover:bg-[#101624] text-slate-200"
              }`}
            >
              <span className="flex items-center gap-2 text-xs">
                <Lock className="w-4 h-4 text-red-400" />
                {contained ? "Host Enclave Isolation Active" : "Trigger Host Enclave Isolation"}
              </span>
              <span className="text-[10px] font-mono uppercase text-slate-400">
                {contained ? "SDN ISOLATED" : "POLICY READY"}
              </span>
            </button>
          </div>
        </div>
      </aside>
    </>
  );
}

function MetaTile({ label, value, mono }) {
  return (
    <div className="p-2.5 rounded border border-slate-800 bg-[#070A11]">
      <div className="text-[10px] font-medium uppercase tracking-wider text-slate-500 mb-1">{label}</div>
      <div className={`text-xs text-slate-200 truncate ${mono ? "font-mono font-medium" : "font-medium"}`}>
        {value}
      </div>
    </div>
  );
}