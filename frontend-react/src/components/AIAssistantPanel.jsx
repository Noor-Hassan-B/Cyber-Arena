import React, { useState } from 'react';
import { 
  Bot, 
  Sparkles, 
  Send, 
  Copy, 
  Check, 
  ExternalLink, 
  Search, 
  AlertCircle,
  HelpCircle,
  ShieldAlert,
  ChevronRight,
  Database,
  Cpu
} from 'lucide-react';

export default function AIAssistantPanel({ 
  aiSummary, 
  querySuggestions, 
  onAskCustomQuery, 
  onSelectEvent,
  onOpenLimitations
}) {
  const [customInput, setCustomInput] = useState('');
  const [isQuerying, setIsQuerying] = useState(false);
  const [customResponses, setCustomResponses] = useState([]);
  const [copiedIndex, setCopiedIndex] = useState(null);

  const handleSendCustomQuery = async (e) => {
    e.preventDefault();
    if (!customInput.trim() || isQuerying) return;

    const query = customInput.trim();
    setCustomInput('');
    setIsQuerying(true);

    try {
      const response = await onAskCustomQuery(query);
      setCustomResponses(prev => [response, ...prev]);
    } catch (err) {
      console.error(err);
    } finally {
      setIsQuerying(false);
    }
  };

  const handleCopyQuery = (text, idx) => {
    navigator.clipboard.writeText(text);
    setCopiedIndex(idx);
    setTimeout(() => setCopiedIndex(null), 2000);
  };

  // Render text and turn [EVT-...] into clickable evidence buttons
  const renderEvidenceLinkedText = (text) => {
    if (!text) return '';
    const parts = text.split(/(\[EVT-[A-Za-z0-9-]+\])/g);
    return parts.map((part, i) => {
      const match = part.match(/\[(EVT-[A-Za-z0-9-]+)\]/);
      if (match) {
        const uuid = match[1];
        return (
          <button
            key={i}
            onClick={() => onSelectEvent(uuid)}
            className="inline-flex items-center gap-0.5 mx-1 px-1.5 py-0.5 rounded text-[11px] font-mono font-bold bg-blue-600/30 hover:bg-blue-600/50 border border-blue-400 text-blue-300 transition-all hover:scale-105"
            title="Inspect underlying raw telemetry evidence"
          >
            <span>{uuid}</span>
            <ExternalLink className="w-2.5 h-2.5 opacity-70" />
          </button>
        );
      }
      return <span key={i}>{part}</span>;
    });
  };

  return (
    <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-4 sm:p-5 shadow-xl space-y-5">
      {/* Panel Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800/80 pb-3">
        <div>
          <div className="flex items-center gap-2">
            <div className="p-1.5 rounded-lg bg-indigo-600/20 text-indigo-400 border border-indigo-500/30">
              <Sparkles className="w-4 h-4" />
            </div>
            <h2 className="text-sm font-bold text-slate-100">
              AI Threat Hunting Copilot & Evidence-Grounded Investigation
            </h2>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-950/80 border border-emerald-500/30 text-emerald-300">
              Deterministic Evidence Links
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-0.5">
            Synthesizes hypotheses with strict forensic citations back to underlying log IDs.
          </p>
        </div>

        <button
          onClick={onOpenLimitations}
          className="flex items-center gap-1.5 text-xs text-amber-400 hover:text-amber-300 underline font-medium self-start sm:self-auto"
        >
          <HelpCircle className="w-3.5 h-3.5" /> Explain AI Limitations & Risks
        </button>
      </div>

      {/* AI Executive Summary Card */}
      {aiSummary && (
        <div className="bg-slate-950/80 border border-slate-800 rounded-xl p-4 space-y-3">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold text-indigo-300 uppercase tracking-wide font-mono flex items-center gap-1.5">
              <Bot className="w-4 h-4 text-indigo-400" />
              AI Investigation Narrative & Root Cause Analysis
            </span>
            <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-slate-900 text-slate-400 border border-slate-800">
              Confidence: {Math.round((aiSummary.confidence || 0.94) * 100)}%
            </span>
          </div>

          <p className="text-xs sm:text-sm text-slate-200 leading-relaxed">
            {renderEvidenceLinkedText(aiSummary.executive_summary)}
          </p>

          {/* Recommended Containment Actions */}
          {aiSummary.recommended_actions && (
            <div className="mt-3 pt-3 border-t border-slate-800/80 space-y-1.5">
              <span className="text-xs font-semibold text-slate-300">
                Recommended Immediate Containment Leads:
              </span>
              <ul className="space-y-1">
                {aiSummary.recommended_actions.map((act, idx) => (
                  <li key={idx} className="flex items-start gap-2 text-xs text-slate-300">
                    <span className="w-4 h-4 rounded-full bg-blue-900/60 text-blue-300 text-[10px] flex items-center justify-center font-bold flex-shrink-0 mt-0.5">
                      {idx + 1}
                    </span>
                    <span>{act}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}

      {/* Interactive Natural Language Threat Query Input */}
      <div className="space-y-2">
        <label className="text-xs font-semibold text-slate-300 flex items-center gap-1.5">
          <Search className="w-3.5 h-3.5 text-blue-400" />
          Ask Hunting Copilot (Evidence Grounded)
        </label>
        <form onSubmit={handleSendCustomQuery} className="flex gap-2">
          <input
            type="text"
            placeholder="e.g. How did the threat actor move laterally between assets? Or did they access S3?"
            value={customInput}
            onChange={(e) => setCustomInput(e.target.value)}
            disabled={isQuerying}
            className="flex-1 bg-slate-950 border border-slate-800 rounded-lg px-3.5 py-2 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-blue-500 disabled:opacity-50"
          />
          <button
            type="submit"
            disabled={isQuerying || !customInput.trim()}
            className="px-4 py-2 text-xs font-semibold rounded-lg bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white flex items-center gap-1.5 shadow transition"
          >
            {isQuerying ? (
              <span className="animate-spin">⌛</span>
            ) : (
              <>
                <span>Ask AI</span>
                <Send className="w-3.5 h-3.5" />
              </>
            )}
          </button>
        </form>

        {/* Custom Analyst Responses */}
        {customResponses.map((res, i) => (
          <div key={i} className="p-3 bg-slate-950/70 border border-slate-800 rounded-lg space-y-1.5 mt-2 animate-fadeIn">
            <div className="flex items-center justify-between text-[11px] text-slate-400 font-mono">
              <span>Q: "{res.query}"</span>
              <span>{res.timestamp}</span>
            </div>
            <p className="text-xs text-slate-200 leading-relaxed">
              {renderEvidenceLinkedText(res.ai_answer)}
            </p>
          </div>
        ))}
      </div>

      {/* Recommended SIEM / SQL Query Suggestions */}
      <div className="space-y-3 pt-2 border-t border-slate-800/80">
        <div className="flex items-center justify-between">
          <h3 className="text-xs font-bold text-slate-200 uppercase tracking-wide font-mono flex items-center gap-1.5">
            <Database className="w-3.5 h-3.5 text-cyan-400" />
            AI Query Suggestions (Hunting Rules & SIEM Logic)
          </h3>
          <span className="text-[11px] text-slate-400">
            Click to copy SPL or SQL syntax
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {querySuggestions.slice(0, 4).map((sug, idx) => (
            <div
              key={sug.id}
              className="bg-slate-950/70 border border-slate-800/90 rounded-xl p-3 flex flex-col justify-between hover:border-slate-700 transition"
            >
              <div className="space-y-1.5">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold text-slate-200 truncate max-w-[240px]">
                    {sug.title}
                  </span>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-indigo-950 text-indigo-300 border border-indigo-800">
                    {sug.mitre_technique}
                  </span>
                </div>
                <p className="text-[11px] text-slate-400">
                  {sug.description}
                </p>
                <div className="p-2 rounded bg-slate-900 border border-slate-800/80 font-mono text-[10px] text-slate-300 break-all select-all">
                  {sug.sql_query}
                </div>
              </div>

              <div className="mt-2.5 pt-2 border-t border-slate-800/60 flex items-center justify-between">
                <span className="text-[10px] text-slate-500 italic">
                  Tactic: {sug.target_tactic}
                </span>
                <button
                  onClick={() => handleCopyQuery(sug.sql_query, idx)}
                  className="flex items-center gap-1 text-[11px] text-blue-400 hover:text-blue-300 font-medium"
                >
                  {copiedIndex === idx ? (
                    <>
                      <Check className="w-3 h-3 text-emerald-400" /> Copied!
                    </>
                  ) : (
                    <>
                      <Copy className="w-3 h-3" /> Copy SQL
                    </>
                  )}
                </button>
              </div>
            </div>
          ))}
        </div>
      </div>

    </div>
  );
}
