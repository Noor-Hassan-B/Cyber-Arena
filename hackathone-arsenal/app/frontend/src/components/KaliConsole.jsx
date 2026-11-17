import { useEffect, useRef, useState, useMemo } from "react";
import {
  X,
  Minimize2,
  Maximize2,
  Play,
  Terminal,
  Sparkles,
  Trash2,
  HelpCircle,
  HardDrive,
  ShieldAlert,
  Cpu,
  Layers,
  Radio,
  Copy,
  Check,
  ChevronRight,
  CornerDownLeft,
  ArrowRight,
  ExternalLink,
  Laptop
} from "lucide-react";

const ATTACK_ARSENAL = [
  {
    category: "Reconnaissance",
    label: "Nmap SYN Stealth Scan",
    cmd: "nmap -sS -p 22,80,443,5432 -sV 10.42.0.10",
    mitre: "T1595.001",
    desc: "Low-noise TCP SYN sweep across enclave ports to fingerprint OS and daemons.",
  },
  {
    category: "Credential Access",
    label: "Hydra Low-and-Slow Spray",
    cmd: "hydra -l root -P rockyou.txt 10.42.0.10 ssh",
    mitre: "T1110.003",
    desc: "Throttled SSH password spraying with 90s inter-request jitter to evade naive thresholds.",
  },
  {
    category: "Web Exploitation",
    label: "SQLMap Blind Injection",
    cmd: "sqlmap -u \"https://10.42.0.10/api/ledger?acc=1092\" --batch --dbs",
    mitre: "T1190",
    desc: "Automated boolean blind SQL injection against API query parameters to exfiltrate schema.",
  },
  {
    category: "Credential Access",
    label: "Distributed Credential Stuffer",
    cmd: "python3 cred_stuffer.py --proxies 19",
    mitre: "T1110.004",
    desc: "Rotates 19 residential proxies to spray credential pairs against OAuth identity gateway.",
  },
  {
    category: "Defense Evasion",
    label: "Ghost Transactions Latency Spike",
    cmd: "curl -X POST https://10.42.0.10/api/v1/payments/tx --ghost-replay",
    mitre: "T1078",
    desc: "Bursts synthetic transaction replays causing p99 latency spikes without valid auth cookies.",
  },
  {
    category: "Content Discovery",
    label: "Gobuster Directory Brute",
    cmd: "gobuster dir -u https://10.42.0.10 -w /usr/share/wordlists/dirb/common.txt",
    mitre: "T1595.003",
    desc: "Enumerates hidden administrative directories and API endpoints.",
  },
  {
    category: "Command & Control",
    label: "Metasploit Handler Console",
    cmd: "msfconsole",
    mitre: "T1071",
    desc: "Initializes interactive Metasploit Framework C2 session handler.",
  },
  {
    category: "Persistence",
    label: "Netcat Reverse Shell Listener",
    cmd: "nc -lvnp 4444",
    mitre: "T1059.004",
    desc: "Opens raw TCP listener on port 4444 to catch inbound reverse shell connections.",
  },
];

const AUTOCOMPLETE_MAP = [
  "nmap -sS -p 22,80,443,5432 -sV 10.42.0.10",
  "nmap 10.42.0.10",
  "hydra -l root -P rockyou.txt 10.42.0.10 ssh",
  "sqlmap -u \"https://10.42.0.10/api/ledger?acc=1092\" --batch --dbs",
  "python3 cred_stuffer.py --proxies 19",
  "curl -X POST https://10.42.0.10/api/v1/payments/tx --ghost-replay",
  "gobuster dir -u https://10.42.0.10 -w /usr/share/wordlists/dirb/common.txt",
  "msfconsole",
  "nc -lvnp 4444",
  "cat targets.lst",
  "cat notes.md",
  "cat rockyou.txt",
  "whoami",
  "id",
  "uname -a",
  "ifconfig",
  "ip a",
  "ping 10.42.0.10",
  "netstat -tuln",
  "ps aux",
  "ls -la",
  "clear",
  "help",
  "status",
  "targets",
  "uptime",
  "date"
];

export default function KaliConsole({
  lines = [],
  progress = 0,
  labEvents = 0,
  running = false,
  onClose,
  onRun,
  onCommand,
  isDocked = false,
  onToggleDock,
  isEmbedded = false,
}) {
  const [pos, setPos] = useState({ x: Math.max(16, window.innerWidth - 680), y: 65 });
  const [size, setSize] = useState({ w: Math.min(640, window.innerWidth - 32), h: 560 });
  const [maximized, setMaximized] = useState(false);
  const [input, setInput] = useState("");
  const [history, setHistory] = useState([]);
  const [historyIndex, setHistoryIndex] = useState(-1);
  const [fontSize, setFontSize] = useState(11);
  const [activeTab, setActiveTab] = useState("bash"); // "bash" | "msf" | "listener" | "arsenal"
  const [copiedCmd, setCopiedCmd] = useState(null);

  const dragging = useRef(null);
  const bodyRef = useRef(null);
  const inputRef = useRef(null);

  // Auto-scroll on new output
  useEffect(() => {
    if (bodyRef.current) {
      bodyRef.current.scrollTop = bodyRef.current.scrollHeight;
    }
  }, [lines, activeTab]);

  // Dragging handlers
  const onMouseDown = (e) => {
    if (maximized || isDocked) return;
    dragging.current = { dx: e.clientX - pos.x, dy: e.clientY - pos.y };
    window.addEventListener("mousemove", onMove);
    window.addEventListener("mouseup", onUp);
  };

  const onMove = (e) => {
    if (!dragging.current) return;
    setPos({
      x: Math.max(8, Math.min(window.innerWidth - 360, e.clientX - dragging.current.dx)),
      y: Math.max(8, Math.min(window.innerHeight - 140, e.clientY - dragging.current.dy)),
    });
  };

  const onUp = () => {
    dragging.current = null;
    window.removeEventListener("mousemove", onMove);
    window.removeEventListener("mouseup", onUp);
  };

  // Ghost autocomplete suggestion
  const ghostSuggestion = useMemo(() => {
    const trimmed = input.trim();
    if (!trimmed || trimmed.length < 2) return "";
    const match = AUTOCOMPLETE_MAP.find(cmd => cmd.toLowerCase().startsWith(trimmed.toLowerCase()));
    if (match && match.toLowerCase() !== trimmed.toLowerCase()) {
      return match.slice(trimmed.length);
    }
    return "";
  }, [input]);

  const handleKeyDown = (e) => {
    if (e.key === "ArrowUp") {
      e.preventDefault();
      if (history.length === 0) return;
      const nextIdx = historyIndex + 1 < history.length ? historyIndex + 1 : historyIndex;
      setHistoryIndex(nextIdx);
      setInput(history[history.length - 1 - nextIdx] || "");
    } else if (e.key === "ArrowDown") {
      e.preventDefault();
      if (historyIndex > 0) {
        const nextIdx = historyIndex - 1;
        setHistoryIndex(nextIdx);
        setInput(history[history.length - 1 - nextIdx] || "");
      } else if (historyIndex === 0) {
        setHistoryIndex(-1);
        setInput("");
      }
    } else if (e.key === "Tab" || (e.key === "ArrowRight" && ghostSuggestion)) {
      e.preventDefault();
      if (ghostSuggestion) {
        setInput(input + ghostSuggestion);
      } else {
        const trimmed = input.trim().toLowerCase();
        const match = AUTOCOMPLETE_MAP.find(c => c.startsWith(trimmed));
        if (match) setInput(match);
      }
    }
  };

  const submit = (e) => {
    e.preventDefault();
    const v = input.trim();
    if (!v) return;
    setHistory(prev => [...prev, v]);
    setHistoryIndex(-1);
    onCommand(v);
    setInput("");
  };

  const executeArsenalCmd = (cmd) => {
    setHistory(prev => [...prev, cmd]);
    onCommand(cmd);
    setActiveTab("bash");
  };

  const insertToInput = (cmd) => {
    setInput(cmd);
    setActiveTab("bash");
    if (inputRef.current) inputRef.current.focus();
  };

  // Positioning
  const containerStyle = isEmbedded
    ? { width: "100%", height: "100%" }
    : isDocked
    ? {}
    : maximized
    ? { top: 12, left: 12, right: 12, bottom: 12, width: "auto", height: "auto" }
    : { top: pos.y, left: pos.x, width: size.w, height: size.h };

  return (
    <div
      className={`${
        isEmbedded
          ? "w-full h-full rounded-lg border border-slate-700/80 bg-[#070A10] flex flex-col shadow-xl overflow-hidden"
          : isDocked
          ? "w-full border-t border-slate-800 bg-[#070A10] flex flex-col h-[400px]"
          : "fixed z-50 rounded-lg border border-slate-700/80 bg-[#070A10] flex flex-col shadow-2xl overflow-hidden"
      }`}
      style={containerStyle}
      data-testid="kali-console"
    >
      {/* Authentic Kali Terminal Titlebar */}
      <div
        className="flex items-center justify-between px-3.5 py-2.5 bg-[#0B0F17] border-b border-slate-800/90 cursor-move select-none"
        onMouseDown={onMouseDown}
      >
        <div className="flex items-center gap-2.5">
          {/* OS Window Controls */}
          <div className="flex items-center gap-1.5 mr-1">
            <span
              onClick={onClose}
              className="w-3 h-3 rounded-full bg-[#EF4444] inline-block opacity-80 hover:opacity-100 cursor-pointer transition"
              title="Close Attacker Console"
            />
            <span
              onClick={() => setMaximized(false)}
              className="w-3 h-3 rounded-full bg-[#F59E0B] inline-block opacity-80 hover:opacity-100 cursor-pointer transition"
              title="Restore Default"
            />
            <span
              onClick={() => setMaximized(v => !v)}
              className="w-3 h-3 rounded-full bg-[#10B981] inline-block opacity-80 hover:opacity-100 cursor-pointer transition"
              title="Toggle Fullscreen"
            />
          </div>

          <div className="h-4 w-px bg-slate-800 mx-0.5" />

          {/* Session Tabs */}
          <div className="flex items-center gap-1">
            <button
              onClick={() => setActiveTab("bash")}
              className={`px-2.5 py-1 rounded text-xs font-mono transition flex items-center gap-1.5 ${
                activeTab === "bash"
                  ? "bg-[#141C2B] text-cyan-300 font-semibold border border-cyan-500/30 shadow-sm"
                  : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/50"
              }`}
            >
              <Terminal className="w-3 h-3 text-cyan-400" />
              <span>1: zsh</span>
            </button>

            <button
              onClick={() => {
                setActiveTab("msf");
                onCommand("msfconsole");
              }}
              className={`px-2.5 py-1 rounded text-xs font-mono transition flex items-center gap-1.5 ${
                activeTab === "msf"
                  ? "bg-[#141C2B] text-cyan-300 font-semibold border border-cyan-500/30 shadow-sm"
                  : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/50"
              }`}
            >
              <Cpu className="w-3 h-3 text-red-400" />
              <span>2: msfconsole</span>
            </button>

            <button
              onClick={() => {
                setActiveTab("listener");
                onCommand("nc -lvnp 4444");
              }}
              className={`px-2.5 py-1 rounded text-xs font-mono transition flex items-center gap-1.5 ${
                activeTab === "listener"
                  ? "bg-[#141C2B] text-cyan-300 font-semibold border border-cyan-500/30 shadow-sm"
                  : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/50"
              }`}
            >
              <Radio className="w-3 h-3 text-emerald-400" />
              <span>3: nc listener</span>
            </button>

            <button
              onClick={() => setActiveTab(activeTab === "arsenal" ? "bash" : "arsenal")}
              className={`px-2.5 py-1 rounded text-xs font-mono transition flex items-center gap-1.5 ${
                activeTab === "arsenal"
                  ? "bg-cyan-500/20 text-cyan-300 font-semibold border border-cyan-500/50"
                  : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/50"
              }`}
            >
              <Layers className="w-3 h-3 text-amber-400" />
              <span>Arsenal</span>
            </button>
          </div>
        </div>

        {/* Action Controls */}
        <div className="flex items-center gap-1 text-slate-400">
          <button
            onClick={() => onCommand("clear")}
            className="p-1.5 hover:text-slate-200 hover:bg-slate-800 rounded transition"
            title="Clear terminal buffer"
          >
            <Trash2 className="w-3.5 h-3.5" />
          </button>

          <button
            onClick={() => setFontSize(s => (s === 11 ? 12 : s === 12 ? 10 : 11))}
            className="px-1.5 py-0.5 text-[10px] hover:text-slate-200 hover:bg-slate-800 rounded font-mono transition"
            title="Toggle terminal font scale"
          >
            {fontSize}pt
          </button>

          {onToggleDock && (
            <button
              onClick={onToggleDock}
              className="p-1.5 hover:text-slate-200 hover:bg-slate-800 rounded transition"
              title={isDocked ? "Float Window" : "Dock to Bottom"}
            >
              <Laptop className="w-3.5 h-3.5" />
            </button>
          )}

          {!isDocked && (
            <button
              onClick={() => setMaximized(v => !v)}
              className="p-1.5 hover:text-slate-200 hover:bg-slate-800 rounded transition"
              data-testid="kali-resize"
            >
              {maximized ? <Minimize2 className="w-3.5 h-3.5" /> : <Maximize2 className="w-3.5 h-3.5" />}
            </button>
          )}

          <button
            onClick={onClose}
            className="p-1.5 hover:text-red-400 hover:bg-slate-800 rounded transition ml-0.5"
            data-testid="kali-close"
          >
            <X className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {/* Network Telemetry Status Bar */}
      <div className="flex items-center justify-between px-3.5 py-1.5 bg-[#090C14] border-b border-slate-800/80 text-[11px] font-mono select-none">
        <div className="flex items-center gap-3">
          <span className="flex items-center gap-1.5 text-emerald-400 font-medium">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" /> eth0: 192.168.1.105
          </span>
          <span className="text-slate-700">|</span>
          <span className="text-cyan-400">tun0: 10.42.0.5</span>
          <span className="text-slate-700">|</span>
          <span className="text-slate-400">
            Target: <strong className="text-slate-200">10.42.0.10</strong>
          </span>
          <span className="text-slate-700 hidden sm:inline">|</span>
          <span className="text-slate-500 hidden sm:inline">rtt: 0.38ms</span>
        </div>
        <div className="flex items-center gap-2">
          <span className={`badge ${running ? "badge-critical animate-pulse" : "badge-low"}`}>
            {running ? "EXPLOITING" : "ARMED"}
          </span>
          <span className="text-slate-500 tabular-nums text-[10px]">Telemetry: {labEvents}</span>
        </div>
      </div>

      {/* Main View: Terminal OR Arsenal Drawer */}
      {activeTab === "arsenal" ? (
        <div className="flex-1 overflow-y-auto p-4 bg-[#080B11] space-y-3 font-sans">
          <div className="flex items-center justify-between pb-2 border-b border-slate-800">
            <div>
              <div className="text-xs font-semibold uppercase tracking-wider text-slate-200">
                Offensive Red Team Playbooks
              </div>
              <div className="text-[11px] text-slate-400">
                Execute approved offensive commands against TARGET-VM (10.42.0.10) to feed the SIEM pipeline.
              </div>
            </div>
            <span className="badge badge-medium">8 Approved Tools</span>
          </div>

          <div className="grid grid-cols-1 gap-2.5">
            {ATTACK_ARSENAL.map((item, idx) => (
              <div
                key={idx}
                className="p-3 rounded border border-slate-800/80 hover:border-cyan-500/40 bg-[#0C101A] hover:bg-[#101624] transition group"
              >
                <div className="flex items-center justify-between mb-1.5 flex-wrap gap-2">
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-semibold text-slate-100 group-hover:text-cyan-300">
                      {item.label}
                    </span>
                    <span className="badge badge-low text-[9px]">{item.category}</span>
                  </div>
                  <span className="text-[10px] font-mono text-cyan-400 font-medium">MITRE {item.mitre}</span>
                </div>
                <div className="text-[11px] text-slate-400 mb-2 leading-relaxed">{item.desc}</div>
                <div className="flex items-center justify-between gap-2 bg-[#06080E] px-2.5 py-1.5 rounded border border-slate-800/80">
                  <span className="text-[11px] font-mono text-cyan-200/90 truncate flex-1">$ {item.cmd}</span>
                  <div className="flex items-center gap-1.5">
                    <button
                      onClick={() => insertToInput(item.cmd)}
                      className="px-2 py-0.5 rounded text-[10px] font-mono font-medium text-slate-400 hover:text-slate-100 hover:bg-slate-800 transition"
                      title="Insert command into CLI prompt to edit flags"
                    >
                      Insert to CLI
                    </button>
                    <button
                      onClick={() => executeArsenalCmd(item.cmd)}
                      className="px-2.5 py-1 rounded bg-cyan-600 hover:bg-cyan-500 text-white text-[10px] font-mono font-semibold flex items-center gap-1 transition shadow-sm"
                      title="Execute attack immediately"
                    >
                      <Play className="w-2.5 h-2.5 fill-current" /> Execute
                    </button>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      ) : (
        <div
          ref={bodyRef}
          className="flex-1 overflow-y-auto p-3.5 bg-[#05070C] font-mono leading-relaxed text-slate-300 selection:bg-cyan-900/60"
          style={{ fontSize: `${fontSize}px` }}
          data-testid="kali-terminal-body"
        >
          {lines.map((l, i) => {
            const text = l.v || l.line || "";
            const isUserCmd = l.line?.startsWith("$ ") || l.v?.startsWith("$ ") || l.t === "$";
            const isSuccess =
              text.startsWith("[+]") ||
              text.includes("open port") ||
              text.includes("is vulnerable") ||
              text.includes("reverse_tcp");
            const isCritical =
              text.startsWith("[!]") ||
              text.includes("CRITICAL") ||
              text.includes("ALERT TRIGGERED") ||
              text.includes("SIEM CORRELATION");
            const isAttempt =
              text.startsWith("[ATTEMPT]") ||
              text.startsWith("[STATUS]") ||
              text.startsWith("[*]") ||
              text.startsWith("[stuffer]") ||
              text.startsWith("[shadow]");
            const isHttpHeader = text.startsWith("> ") || text.startsWith("< ");

            return (
              <div key={i} className="whitespace-pre-wrap">
                {isUserCmd ? (
                  <div className="my-1.5 pt-1">
                    <div className="text-emerald-400 font-semibold">
                      ┌──(kali㉿attacker-vm)-[~/threatlens]
                    </div>
                    <div className="flex items-center gap-1 text-slate-100">
                      <span className="text-emerald-400 font-semibold">└─$</span>
                      <span className="text-cyan-300 font-medium">{text.replace(/^\$\s*/, "")}</span>
                    </div>
                  </div>
                ) : (
                  <div
                    className={
                      isCritical
                        ? "text-red-400 font-medium py-0.5"
                        : isSuccess
                        ? "text-emerald-400 font-medium"
                        : isAttempt
                        ? "text-amber-300/90"
                        : isHttpHeader
                        ? "text-cyan-300/80"
                        : "text-slate-300"
                    }
                  >
                    {l.t && <span className="text-slate-500 mr-1.5">{l.t}</span>}
                    {text}
                  </div>
                )}
              </div>
            );
          })}

          {/* Active Interactive ZSH Prompt Line */}
          <div className="mt-2 text-emerald-400">
            <div>┌──(kali㉿attacker-vm)-[~/threatlens]</div>
            <div className="flex items-center gap-1.5 relative">
              <span className="font-semibold">└─$</span>
              <div className="flex-1 relative flex items-center">
                <span className="text-slate-100 font-medium">{input}</span>
                {ghostSuggestion && (
                  <span className="text-slate-600 select-none pointer-events-none">
                    {ghostSuggestion}
                  </span>
                )}
                <span className="inline-block w-2 h-4 bg-cyan-400 blink align-middle ml-0.5" />
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Attack Progress Bar (Active during playbooks) */}
      {progress > 0 && progress < 100 && (
        <div className="px-3.5 py-1.5 bg-[#080B12] border-t border-slate-800/80">
          <div className="flex items-center justify-between text-[10px] font-mono text-slate-400 mb-1">
            <span className="flex items-center gap-1.5 text-cyan-300">
              <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-ping" />
              Attack Execution Active
            </span>
            <span className="text-cyan-400 font-bold">{progress}%</span>
          </div>
          <div className="h-1 rounded-full bg-slate-800 overflow-hidden">
            <div
              className="h-full bg-gradient-to-r from-cyan-500 to-emerald-400 transition-all duration-300"
              style={{ width: `${progress}%` }}
            />
          </div>
        </div>
      )}

      {/* Quick Attack Suggestions Bar */}
      <div className="flex items-center gap-1.5 px-3 py-1 bg-[#090D15] border-t border-slate-800/70 overflow-x-auto text-[10px] font-mono select-none">
        <span className="text-slate-500 uppercase tracking-widest text-[9px] mr-1 flex items-center gap-1 flex-shrink-0">
          <Sparkles className="w-3 h-3 text-cyan-400" /> Quick:
        </span>
        {[
          { label: "Nmap Recon", cmd: "nmap -sS -p 22,80,443,5432 -sV 10.42.0.10" },
          { label: "Hydra Spray", cmd: "hydra -l root -P rockyou.txt 10.42.0.10 ssh" },
          { label: "SQLMap", cmd: "sqlmap -u \"https://10.42.0.10/api/ledger?acc=1092\" --dbs" },
          { label: "Cred Stuffer", cmd: "python3 cred_stuffer.py --proxies 19" },
          { label: "Ghost TX", cmd: "curl -X POST https://10.42.0.10/api/v1/payments/tx --ghost-replay" },
          { label: "Target Scope", cmd: "cat targets.lst" },
          { label: "Help", cmd: "help" },
        ].map((p, i) => (
          <button
            key={i}
            onClick={() => executeArsenalCmd(p.cmd)}
            className="px-2 py-0.5 rounded bg-slate-800/70 hover:bg-cyan-950 hover:text-cyan-300 text-slate-300 border border-slate-700/60 transition whitespace-nowrap text-[10px] flex-shrink-0"
          >
            {p.label}
          </button>
        ))}
      </div>

      {/* Terminal Command Input Form */}
      <form
        onSubmit={submit}
        className="flex items-center gap-2 border-t border-slate-800 px-3.5 py-2 bg-[#070A10]"
        data-testid="kali-command-form"
      >
        <span className="text-emerald-400 text-xs font-mono font-bold select-none">$</span>
        <div className="flex-1 relative flex items-center">
          <input
            ref={inputRef}
            value={input}
            onChange={e => setInput(e.target.value)}
            onKeyDown={handleKeyDown}
            data-testid="kali-command-input"
            placeholder="Type offensive command (nmap, hydra, sqlmap, curl, whoami, help)..."
            className="w-full bg-transparent outline-none font-mono text-xs text-slate-100 placeholder:text-slate-600"
            autoFocus
          />
        </div>
        {ghostSuggestion && (
          <span className="text-[10px] font-mono text-slate-500 bg-slate-900/80 px-1.5 py-0.5 rounded border border-slate-800 hidden sm:inline">
            Tab to complete
          </span>
        )}
        <button
          type="submit"
          data-testid="kali-command-run"
          className="px-3 py-1 rounded bg-cyan-600 hover:bg-cyan-500 text-white font-mono font-semibold text-xs flex items-center gap-1 transition shadow-sm"
          title="Execute command (Enter)"
        >
          <Play className="w-3 h-3 fill-current" /> Run
        </button>
      </form>
    </div>
  );
}