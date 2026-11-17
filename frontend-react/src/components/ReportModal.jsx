import React, { useState, useEffect } from 'react';
import { 
  X, 
  Printer, 
  Download, 
  FileText, 
  ShieldCheck, 
  Clock, 
  CheckCircle2,
  Copy,
  Check
} from 'lucide-react';
import { api } from '../services/api';

export default function ReportModal({ scenarioId, onClose }) {
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(true);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    async function loadReport() {
      setLoading(true);
      try {
        const data = await api.getInvestigationReport(scenarioId, 'Senior Threat Hunter (SOC L3)');
        setReport(data);
      } catch (err) {
        console.error(err);
      } finally {
        setLoading(false);
      }
    }
    loadReport();
  }, [scenarioId]);

  const handlePrint = () => {
    window.print();
  };

  const handleDownloadMarkdown = () => {
    if (!report) return;

    let md = `# INCIDENT INVESTIGATION REPORT: ${report.report_id}\n\n`;
    md += `**Classification:** ${report.classification}\n`;
    md += `**Incident Title:** ${report.title}\n`;
    md += `**Lead Analyst:** ${report.lead_analyst}\n`;
    md += `**Generated At:** ${report.generated_at}\n\n`;
    md += `## 1. Executive Summary\n${report.executive_summary}\n\n`;
    md += `## 2. Reconstructed Incident Timeline\n`;
    report.timeline.forEach(t => {
      md += `- **${t.timestamp}** [${t.domain}] \`${t.event_uuid}\`: ${t.action} (MITRE: ${t.mitre_technique})\n`;
    });
    md += `\n## 3. Evidence Chain of Custody\n`;
    report.evidence_chain.forEach(e => {
      md += `- \`${e.item_id}\` | ${e.timestamp} | ${e.actor_entity} | ${e.custody_status}\n`;
    });
    md += `\n## 4. Containment & Remediation Playbook\n`;
    Object.entries(report.containment_playbook).forEach(([phase, steps]) => {
      md += `### ${phase}\n`;
      steps.forEach(s => md += `- ${s}\n`);
    });

    const blob = new Blob([md], { type: 'text/markdown;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.setAttribute('download', `${report.report_id}.md`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  if (!report && loading) {
    return (
      <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm">
        <div className="bg-slate-900 border border-slate-800 p-6 rounded-xl flex items-center gap-3 text-slate-200">
          <div className="w-5 h-5 border-2 border-blue-500 border-t-transparent rounded-full animate-spin" />
          <span>Compiling forensic incident investigation report...</span>
        </div>
      </div>
    );
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4 overflow-y-auto animate-fadeIn">
      <div className="bg-[#0F172A] border border-slate-700 w-full max-w-4xl max-h-[90vh] rounded-2xl shadow-2xl flex flex-col overflow-hidden">
        
        {/* Modal Top Bar */}
        <div className="p-4 sm:p-5 border-b border-slate-800 flex items-center justify-between bg-slate-900/90">
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-lg bg-blue-600/20 text-blue-400 border border-blue-500/30">
              <FileText className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-mono text-xs font-bold text-slate-200">
                  {report?.report_id}
                </span>
                <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-red-950/80 border border-red-500/30 text-red-300 font-bold">
                  {report?.classification}
                </span>
              </div>
              <h2 className="text-sm font-bold text-white tracking-tight">
                {report?.title}
              </h2>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={handleDownloadMarkdown}
              className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium flex items-center gap-1.5 transition"
              title="Download as Markdown file"
            >
              <Download className="w-3.5 h-3.5 text-blue-400" />
              <span className="hidden sm:inline">Export .MD</span>
            </button>
            <button
              onClick={handlePrint}
              className="px-3 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold flex items-center gap-1.5 transition shadow"
              title="Print or Save as PDF"
            >
              <Printer className="w-3.5 h-3.5" />
              <span>Print / PDF</span>
            </button>
            <button
              onClick={onClose}
              className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 transition"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Modal Content */}
        <div className="flex-1 overflow-y-auto p-5 sm:p-8 space-y-6 text-xs text-slate-300 font-sans">
          
          {/* Header Metadata */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 bg-slate-950 p-4 rounded-xl border border-slate-800 font-mono">
            <div>
              <span className="text-[10px] text-slate-500 uppercase">Lead Investigator</span>
              <div className="text-slate-200 font-semibold mt-0.5">{report?.lead_analyst}</div>
            </div>
            <div>
              <span className="text-[10px] text-slate-500 uppercase">Analysis Confidence</span>
              <div className="text-emerald-400 font-bold mt-0.5">{Math.round((report?.confidence_score || 0.95) * 100)}% Verified</div>
            </div>
            <div>
              <span className="text-[10px] text-slate-500 uppercase">Scenario Reference</span>
              <div className="text-slate-200 mt-0.5">{report?.scenario_id}</div>
            </div>
            <div>
              <span className="text-[10px] text-slate-500 uppercase">Generated Timestamp</span>
              <div className="text-slate-400 text-[11px] mt-0.5">{report?.generated_at}</div>
            </div>
          </div>

          {/* 1. Executive Summary */}
          <div className="space-y-2">
            <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono border-b border-slate-800 pb-1 flex items-center gap-2">
              <span className="text-blue-400">01.</span> Executive Summary & Threat Scope
            </h3>
            <p className="text-slate-300 leading-relaxed text-xs sm:text-sm bg-slate-950/60 p-4 rounded-xl border border-slate-800/80">
              {report?.executive_summary}
            </p>
          </div>

          {/* 2. Reconstructed Incident Timeline */}
          <div className="space-y-2">
            <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono border-b border-slate-800 pb-1 flex items-center gap-2">
              <span className="text-blue-400">02.</span> Forensic Timeline & Kill-Chain Traversal
            </h3>
            <div className="overflow-x-auto border border-slate-800 rounded-xl">
              <table className="w-full text-left border-collapse text-[11px]">
                <thead>
                  <tr className="bg-slate-950 text-slate-400 font-mono border-b border-slate-800">
                    <th className="p-2.5">Time</th>
                    <th className="p-2.5">ID</th>
                    <th className="p-2.5">Domain</th>
                    <th className="p-2.5">Actor & Target</th>
                    <th className="p-2.5">Action & MITRE Technique</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 font-mono">
                  {report?.timeline.map((item) => (
                    <tr key={item.event_uuid} className="hover:bg-slate-900/60 transition">
                      <td className="p-2.5 text-slate-300 whitespace-nowrap">{item.timestamp}</td>
                      <td className="p-2.5 text-blue-400 font-bold">{item.event_uuid}</td>
                      <td className="p-2.5 uppercase text-slate-400">{item.domain}</td>
                      <td className="p-2.5 text-slate-300">{item.user} &bull; {item.source} ➔ {item.target}</td>
                      <td className="p-2.5 text-slate-200">
                        <div className="truncate max-w-sm">{item.action}</div>
                        <span className="text-[10px] text-indigo-400">{item.mitre_technique}</span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* 3. Chain of Custody */}
          <div className="space-y-2">
            <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono border-b border-slate-800 pb-1 flex items-center gap-2">
              <span className="text-blue-400">03.</span> Telemetry Evidence Chain of Custody
            </h3>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
              {report?.evidence_chain.slice(0, 6).map((item) => (
                <div key={item.item_id} className="p-2.5 bg-slate-950/80 border border-slate-800 rounded-lg text-[11px] font-mono">
                  <div className="flex items-center justify-between">
                    <span className="text-blue-400 font-bold">{item.item_id}</span>
                    <span className="text-emerald-400 text-[10px] flex items-center gap-1">
                      <CheckCircle2 className="w-3 h-3" /> {item.custody_status}
                    </span>
                  </div>
                  <div className="text-slate-300 mt-1 truncate">{item.evidence_type} - {item.actor_entity}</div>
                </div>
              ))}
            </div>
          </div>

          {/* 4. Containment Playbook */}
          <div className="space-y-3">
            <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono border-b border-slate-800 pb-1 flex items-center gap-2">
              <span className="text-blue-400">04.</span> Actionable Containment & Remediation Playbook
            </h3>
            <div className="space-y-3">
              {Object.entries(report?.containment_playbook || {}).map(([phase, tasks]) => (
                <div key={phase} className="p-3 bg-slate-950 border border-slate-800/90 rounded-xl space-y-2">
                  <span className="text-xs font-bold text-indigo-300 font-mono">{phase}</span>
                  <ul className="space-y-1">
                    {tasks.map((task, idx) => (
                      <li key={idx} className="flex items-start gap-2 text-xs text-slate-300">
                        <CheckCircle2 className="w-3.5 h-3.5 text-blue-400 flex-shrink-0 mt-0.5" />
                        <span>{task}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              ))}
            </div>
          </div>

        </div>

        {/* Modal Footer */}
        <div className="p-4 border-t border-slate-800 bg-slate-900/90 flex items-center justify-between text-xs text-slate-400">
          <span>AegisHunt Platform Security Incident Response</span>
          <button
            onClick={onClose}
            className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-white font-semibold transition"
          >
            Close Report
          </button>
        </div>

      </div>
    </div>
  );
}
