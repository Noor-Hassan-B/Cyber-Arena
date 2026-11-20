import React, { useState, useEffect, useMemo, useRef } from 'react';
import {
  Play,
  Pause,
  RotateCcw,
  SkipForward,
  Shield,
  Server,
  Laptop,
  Cloud,
  Radio,
  ExternalLink,
  ChevronRight,
  Info,
  Zap,
  Crosshair,
  ArrowRight,
  CheckCircle2,
  AlertTriangle,
  FileText,
  Lock,
  Layers,
  Activity,
  Download,
  Printer,
  X,
  Share2,
  Terminal,
  Cpu,
  Search,
  Eye,
  Sliders
} from 'lucide-react';

// ─── Cisco Packet Tracer Network Device Definitions ─────────────────────────
export const CISCO_DEVICES = [
  {
    id: 'dev-c2',
    name: 'C2-Adversary-Cloud',
    model: 'External Adversary Node',
    ip: '185.220.101.44',
    mac: '00:50:56:A1:B2:C3',
    type: 'cloud',
    vlan: 'WAN',
    status: 'compromised',
    x: 80,
    y: 190
  },
  {
    id: 'dev-firewall',
    name: 'ASA-5506-X',
    model: 'Cisco Adaptive Security Appliance',
    ip: '10.42.0.1 (Inside) / 194.26.29.1 (Outside)',
    mac: '00:0C:85:FE:11:01',
    type: 'firewall',
    vlan: 'Edge Gateway',
    status: 'alert',
    x: 270,
    y: 190
  },
  {
    id: 'dev-router',
    name: 'Cisco-2911-ISR',
    model: 'Integrated Services Router G2',
    ip: '10.42.0.2',
    mac: '00:1E:F7:88:22:10',
    type: 'router',
    vlan: 'VLAN 1 (Mgmt)',
    status: 'normal',
    x: 460,
    y: 190
  },
  {
    id: 'dev-switch',
    name: 'Catalyst-2960-Core',
    model: 'WS-C2960-24TT-L Layer 2/3 Switch',
    ip: '10.42.0.3',
    mac: '00:2A:6A:44:99:30',
    type: 'switch',
    vlan: 'Trunk (10, 20)',
    status: 'normal',
    x: 650,
    y: 190
  },
  {
    id: 'dev-wkstn-fin',
    name: 'WKSTN-FIN-04',
    model: 'Dell OptiPlex (Windows 11)',
    ip: '10.42.0.105',
    mac: 'F0:DE:F1:77:88:99',
    type: 'pc',
    vlan: 'VLAN 10 (Finance)',
    status: 'compromised',
    user: 'sarah.connor',
    x: 850,
    y: 80
  },
  {
    id: 'dev-wkstn-hr',
    name: 'WKSTN-HR-04',
    model: 'Dell Latitude (Windows 11)',
    ip: '10.42.0.106',
    mac: 'F0:DE:F1:77:88:AA',
    type: 'pc',
    vlan: 'VLAN 10 (Finance/HR)',
    status: 'scanned',
    user: 'john.reese',
    x: 850,
    y: 200
  },
  {
    id: 'dev-dc01',
    name: 'DC01.corp.local',
    model: 'Cisco UCS C220 M5 (Windows Server 2022)',
    ip: '10.42.0.10',
    mac: '00:25:B5:11:22:33',
    type: 'server',
    vlan: 'VLAN 20 (Servers)',
    status: 'compromised',
    service: 'Active Directory / Kerberos KDC',
    x: 850,
    y: 320
  },
  {
    id: 'dev-cloud-s3',
    name: 'AWS-S3-Exfil-Enclave',
    model: 'Amazon Web Services S3 Cloud Bucket',
    ip: '52.216.144.20 (AWS us-east-1)',
    mac: 'N/A (Cloud VPC Gateway)',
    type: 'cloud_exfil',
    vlan: 'Cloud WAN',
    status: 'exfiltrated',
    x: 1040,
    y: 190
  }
];

// ─── Network Cables / Connections (Packet Tracer Cables) ────────────────────
export const CISCO_LINKS = [
  { id: 'link-1', from: 'dev-c2', to: 'dev-firewall', portFrom: 'Internet', portTo: 'GigabitEthernet1/1', type: 'copper' },
  { id: 'link-2', from: 'dev-firewall', to: 'dev-router', portFrom: 'GigabitEthernet1/2', portTo: 'GigabitEthernet0/0', type: 'copper' },
  { id: 'link-3', from: 'dev-router', to: 'dev-switch', portFrom: 'GigabitEthernet0/1', portTo: 'GigabitEthernet0/24', type: 'copper' },
  { id: 'link-4', from: 'dev-switch', to: 'dev-wkstn-fin', portFrom: 'FastEthernet0/1', portTo: 'FastEthernet0', type: 'copper' },
  { id: 'link-5', from: 'dev-switch', to: 'dev-wkstn-hr', portFrom: 'FastEthernet0/2', portTo: 'FastEthernet0', type: 'copper' },
  { id: 'link-6', from: 'dev-switch', to: 'dev-dc01', portFrom: 'FastEthernet0/10', portTo: 'GigabitEthernet0/1', type: 'copper' },
  { id: 'link-7', from: 'dev-router', to: 'dev-cloud-s3', portFrom: 'Serial0/1/0', portTo: 'Internet-WAN', type: 'fiber' },
];

// ─── Chronological Packet Simulation Steps (Packet Tracer PDUs) ─────────────
export const SIMULATION_PDUS = [
  {
    step: 1,
    time: '00:00:01.204',
    title: 'Adversary C2 Beacon & Initial Stager Delivery',
    srcDev: 'dev-c2',
    dstDev: 'dev-firewall',
    cableId: 'link-1',
    protocol: 'HTTPS / TLS 1.3',
    port: '443',
    technique: 'T1071.001',
    techniqueName: 'Web Protocols',
    summary: 'C2 beacon session initiated from bulletproof server 185.220.101.44 targeting perimeter edge.',
    packetInfo: 'TCP [SYN] Seq=0 Win=64240 Len=0 MSS=1460 SACK_PERM=1',
    layers: {
      l1: 'Physical: Media Copper, Port Gi1/1, Link Speed 1000Mbps Full-Duplex',
      l2: 'Data Link: Src MAC 00:50:56:A1:B2:C3 -> Dst MAC 00:0C:85:FE:11:01 (Ethernet II)',
      l3: 'Network: Src IP 185.220.101.44 -> Dst IP 10.42.0.1, TTL=54, TOS=0x00',
      l4: 'Transport: TCP Src Port 51240 -> Dst Port 443 (HTTPS), Seq=1049281, Flags=[SYN]',
      l7: 'Application: TLS Client Hello, SNI: c2-telemetry-sync.net, Encrypted Handshake'
    }
  },
  {
    step: 2,
    time: '00:00:02.418',
    title: 'Firewall Inbound NAT & Policy Evaluation',
    srcDev: 'dev-firewall',
    dstDev: 'dev-router',
    cableId: 'link-2',
    protocol: 'TCP / 443',
    port: '443',
    technique: 'T1190',
    techniqueName: 'Exploit Public App',
    summary: 'ASA firewall evaluates access-list OUTSIDE_IN; permitted HTTPS reverse proxy session forwarded to core router.',
    packetInfo: 'TCP [ACK, PSH] Ack=1 Win=65535 Len=412 TLS Application Data',
    layers: {
      l1: 'Physical: Media Copper, Port Gi1/2, Tx Power Normal',
      l2: 'Data Link: Src MAC 00:0C:85:FE:11:01 -> Dst MAC 00:1E:F7:88:22:10',
      l3: 'Network: Src IP 185.220.101.44 -> Dst IP 10.42.0.105 (Post-NAT), TTL=53',
      l4: 'Transport: TCP Src Port 51240 -> Dst Port 443, Flags=[ACK, PSH]',
      l7: 'Application: Obfuscated Base64 PowerShell Cradle Payload Staged'
    }
  },
  {
    step: 3,
    time: '00:00:03.112',
    title: 'Core Switch Routing to Finance VLAN 10',
    srcDev: 'dev-router',
    dstDev: 'dev-switch',
    cableId: 'link-3',
    protocol: '802.1Q Trunk',
    port: 'Trunk',
    technique: 'T1059.001',
    techniqueName: 'PowerShell Execution',
    summary: 'Cisco 2911 routes packet across GigabitEthernet0/1 trunk interface into Catalyst 2960 switch.',
    packetInfo: '802.1Q VLAN 10 Tagged Frame, Priority 0, Len=528 bytes',
    layers: {
      l1: 'Physical: Media Copper Cat6, Port Gi0/1, Autonegotiation Active',
      l2: 'Data Link: 802.1Q VLAN ID: 10 (Finance Enclave), Priority: Best Effort',
      l3: 'Network: IP 185.220.101.44 -> IP 10.42.0.105, Checksum Valid',
      l4: 'Transport: TCP Dst Port 443, Stream Index: 3',
      l7: 'Application: Invoke-Expression (New-Object Net.WebClient).DownloadString'
    }
  },
  {
    step: 4,
    time: '00:00:04.850',
    title: 'Patient-Zero Compromise on Workstation',
    srcDev: 'dev-switch',
    dstDev: 'dev-wkstn-fin',
    cableId: 'link-4',
    protocol: 'Ethernet / IP',
    port: '445 / 443',
    technique: 'T1059.001',
    techniqueName: 'Command & Scripting Interpreter',
    summary: 'FastEthernet0/1 delivers payload to WKSTN-FIN-04. Sarah Connor\'s user session spawns hidden PowerShell process.',
    packetInfo: 'HTTP/1.1 200 OK (text/plain) Content-Length: 1024 [Payload Ingested]',
    layers: {
      l1: 'Physical: FastEthernet0/1 Link Active, Rx packets=1240',
      l2: 'Data Link: Dst MAC F0:DE:F1:77:88:99 (WKSTN-FIN-04 NIC)',
      l3: 'Network: Inbound IP Packet matched host routing table',
      l4: 'Transport: TCP Connection Established (ESTABLISHED state)',
      l7: 'Application: powershell.exe -NoP -NonI -W Hidden -Enc SQBFAFgAIAA...'
    }
  },
  {
    step: 5,
    time: '00:00:06.320',
    title: 'Credential Access: LSASS Dump & Kerberoasting',
    srcDev: 'dev-wkstn-fin',
    dstDev: 'dev-switch',
    cableId: 'link-4',
    protocol: 'Kerberos v5',
    port: '88 (UDP/TCP)',
    technique: 'T1003.001',
    techniqueName: 'OS Credential Dumping: LSASS',
    summary: 'Rundll32 comsvcs.dll dumps LSASS memory. Adversary requests RC4-encrypted Kerberos TGS tickets for domain admin accounts.',
    packetInfo: 'KRB_TGS_REQ Realm: CORP.LOCAL, Sname: MSSQLSvc/dc01.corp.local',
    layers: {
      l1: 'Physical: FastEthernet0/1 Tx Queue=0, Output rate 42 kbps',
      l2: 'Data Link: Src MAC F0:DE:F1:77:88:99 -> Dst MAC 00:2A:6A:44:99:30',
      l3: 'Network: Src IP 10.42.0.105 -> Dst IP 10.42.0.10 (DC01)',
      l4: 'Transport: UDP Src Port 53120 -> Dst Port 88 (Kerberos KDC)',
      l7: 'Application: Kerberos TGS-REQ, Encryption Type: eType 23 (RC4-HMAC)'
    }
  },
  {
    step: 6,
    time: '00:00:07.940',
    title: 'Lateral Movement: Remote SMB & PsExec to Domain Controller',
    srcDev: 'dev-switch',
    dstDev: 'dev-dc01',
    cableId: 'link-6',
    protocol: 'SMB2 / RPC',
    port: '445',
    technique: 'T1021.002',
    techniqueName: 'Remote Services: SMB/Windows Admin Shares',
    summary: 'Catalyst switch forwards SMB session from WKSTN-FIN-04 to DC01.corp.local on FastEthernet0/10. Lateral persistence established.',
    packetInfo: 'SMB2 Create Request File: ADMIN$\\System32\\PSEXESVC.exe',
    layers: {
      l1: 'Physical: FastEthernet0/10 Link Status: UP, Full Duplex',
      l2: 'Data Link: VLAN 20 Server Segment Trunking',
      l3: 'Network: Src IP 10.42.0.105 -> Dst IP 10.42.0.10',
      l4: 'Transport: TCP Src Port 49210 -> Dst Port 445 (Microsoft-DS)',
      l7: 'Application: SMB2 Tree Connect: \\\\DC01\\ADMIN$, Service Manager RPC'
    }
  },
  {
    step: 7,
    time: '00:00:09.520',
    title: 'Cloud Exfiltration: AWS S3 Staged Data Outflow',
    srcDev: 'dev-router',
    dstDev: 'dev-cloud-s3',
    cableId: 'link-7',
    protocol: 'AWS S3 REST API',
    port: '443',
    technique: 'T1530',
    techniqueName: 'Data from Cloud Storage Object',
    summary: 'Exfiltration stream routed out Serial/WAN interface to AWS S3 bucket s3://corp-financial-backups using stolen IAM credentials.',
    packetInfo: 'HTTP/1.1 PUT /corp-financial-backups/q3_ledger.enc Host: s3.amazonaws.com',
    layers: {
      l1: 'Physical: Serial0/1/0 WAN Link, Bandwidth 100 Mbps',
      l2: 'Data Link: HDLC WAN Framing Protocol',
      l3: 'Network: Src IP 10.42.0.10 -> Dst IP 52.216.144.20 (AWS S3 Cloud)',
      l4: 'Transport: TCP Port 443 (HTTPS Secure Upload)',
      l7: 'Application: PUT Object, Authorization: AWS4-HMAC-SHA256, Size: 48.2 MB'
    }
  }
];

export default function PacketTracerSimulator({ onSelectEvent, activeSimulation, theme = 'dark' }) {
  const [activeStepIdx, setActiveStepIdx] = useState(0);
  const [isPlaying, setIsPlaying] = useState(false);
  const [playbackSpeed, setPlaybackSpeed] = useState(1); // 1x, 2x, 3x
  const [selectedDevice, setSelectedDevice] = useState(null);
  const [showPduInspector, setShowPduInspector] = useState(false);
  const [showReportModal, setShowReportModal] = useState(false);
  const [packetProgress, setPacketProgress] = useState(0.5);
  const [liveSimulationBanner, setLiveSimulationBanner] = useState(null);
  const animFrameRef = useRef(null);

  const activePdu = SIMULATION_PDUS[activeStepIdx] || SIMULATION_PDUS[0];
  const isDark = theme === 'dark';

  // Playback timer
  useEffect(() => {
    let timer = null;
    if (isPlaying) {
      const interval = Math.max(800, 2400 / playbackSpeed);
      timer = setInterval(() => {
        setActiveStepIdx(prev => {
          if (prev >= SIMULATION_PDUS.length - 1) {
            setIsPlaying(false);
            return prev;
          }
          return prev + 1;
        });
      }, interval);
    }
    return () => clearInterval(timer);
  }, [isPlaying, playbackSpeed]);

  // Traveling animation for PDU envelope along the wire
  useEffect(() => {
    let start = null;
    const duration = Math.max(500, 1600 / playbackSpeed);

    const animatePacket = (timestamp) => {
      if (!start) start = timestamp;
      const elapsed = timestamp - start;
      const progress = Math.min(1, elapsed / duration);
      setPacketProgress(progress);
      if (progress < 1) {
        animFrameRef.current = requestAnimationFrame(animatePacket);
      }
    };

    setPacketProgress(0.05);
    animFrameRef.current = requestAnimationFrame(animatePacket);

    return () => {
      if (animFrameRef.current) cancelAnimationFrame(animFrameRef.current);
    };
  }, [activeStepIdx, playbackSpeed]);

  // Handle incoming activeSimulation from TerminalConsole
  useEffect(() => {
    if (!activeSimulation) return;
    const targetStep = Math.min(SIMULATION_PDUS.length - 1, Math.max(0, (activeSimulation.step || 7) - 1));
    setActiveStepIdx(targetStep);
    setLiveSimulationBanner({
      title: activeSimulation.event?.mitre_technique_name || 'Adversary Command Injected',
      technique: activeSimulation.event?.mitre_technique_id || 'T1059',
      command: activeSimulation.event?.command_line || 'Custom Injected Command',
      source: activeSimulation.event?.source_host || '10.42.0.105',
      dest: activeSimulation.event?.dest_host || 'Target Enclave',
      timestamp: activeSimulation.timestamp
    });

    let start = null;
    const duration = 1600;
    const animatePacket = (timestamp) => {
      if (!start) start = timestamp;
      const elapsed = timestamp - start;
      const progress = Math.min(1, elapsed / duration);
      setPacketProgress(progress);
      if (progress < 1) {
        animFrameRef.current = requestAnimationFrame(animatePacket);
      }
    };
    setPacketProgress(0.05);
    animFrameRef.current = requestAnimationFrame(animatePacket);

    const bannerTimer = setTimeout(() => {
      setLiveSimulationBanner(null);
    }, 10000);

    return () => clearTimeout(bannerTimer);
  }, [activeSimulation]);

  // Devices mapped by ID
  const deviceMap = useMemo(() => {
    const map = {};
    CISCO_DEVICES.forEach(d => { map[d.id] = d; });
    return map;
  }, []);

  const srcDev = deviceMap[activePdu.srcDev];
  const dstDev = deviceMap[activePdu.dstDev];

  // Animated packet position (interpolated along the cable wire)
  const packetPos = useMemo(() => {
    if (!srcDev || !dstDev) return { x: 400, y: 200 };
    return {
      x: srcDev.x + (dstDev.x - srcDev.x) * packetProgress,
      y: srcDev.y + (dstDev.y - srcDev.y) * packetProgress
    };
  }, [srcDev, dstDev, packetProgress]);

  const handleStepForward = () => {
    if (activeStepIdx < SIMULATION_PDUS.length - 1) {
      setActiveStepIdx(prev => prev + 1);
    } else {
      setShowReportModal(true);
    }
  };

  const handleStepBack = () => {
    if (activeStepIdx > 0) {
      setActiveStepIdx(prev => prev - 1);
    }
  };

  const handleReset = () => {
    setIsPlaying(false);
    setActiveStepIdx(0);
  };

  const getDeviceIcon = (type) => {
    switch (type) {
      case 'router':
        return (
          <div className="w-10 h-10 rounded-full bg-blue-600/20 border-2 border-blue-500 flex items-center justify-center text-blue-400 shadow-lg">
            <Radio className="w-5 h-5 animate-pulse" />
          </div>
        );
      case 'switch':
        return (
          <div className="w-10 h-10 rounded-lg bg-indigo-600/20 border-2 border-indigo-500 flex items-center justify-center text-indigo-400 shadow-lg">
            <Share2 className="w-5 h-5" />
          </div>
        );
      case 'firewall':
        return (
          <div className="w-10 h-10 rounded-lg bg-red-600/20 border-2 border-red-500 flex items-center justify-center text-red-400 shadow-lg">
            <Shield className="w-5 h-5" />
          </div>
        );
      case 'server':
        return (
          <div className="w-10 h-10 rounded-lg bg-purple-600/20 border-2 border-purple-500 flex items-center justify-center text-purple-400 shadow-lg">
            <Server className="w-5 h-5" />
          </div>
        );
      case 'pc':
        return (
          <div className="w-10 h-10 rounded-lg bg-cyan-600/20 border-2 border-cyan-500 flex items-center justify-center text-cyan-400 shadow-lg">
            <Laptop className="w-5 h-5" />
          </div>
        );
      case 'cloud':
      case 'cloud_exfil':
      default:
        return (
          <div className="w-10 h-10 rounded-full bg-amber-600/20 border-2 border-amber-500 flex items-center justify-center text-amber-400 shadow-lg">
            <Cloud className="w-5 h-5" />
          </div>
        );
    }
  };

  return (
    <div className={`space-y-4 rounded-xl border transition-colors ${
      isDark ? 'bg-[#0B0F17] border-[#1F293D]' : 'bg-white border-slate-200 shadow-md'
    } p-5`}>

      {/* ── Header: Cisco Packet Tracer Simulation Bar ──────────────────────── */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 pb-4 border-b border-inherit">
        <div>
          <div className="flex items-center gap-2 flex-wrap">
            <div className="p-1.5 rounded-lg bg-blue-600/20 border border-blue-500/30 text-blue-400">
              <Activity className="w-4 h-4" />
            </div>
            <h2 className="text-base font-bold font-mono tracking-tight flex items-center gap-2">
              <span>Cisco Packet Tracer</span>
              <span className="text-xs px-2 py-0.5 rounded font-mono font-bold bg-blue-500/10 text-blue-400 border border-blue-500/20">
                Simulation Mode (PDU Traversal)
              </span>
            </h2>
            <span className={`text-[10px] font-mono px-2 py-0.5 rounded border ${
              isDark ? 'bg-emerald-950/40 border-emerald-500/30 text-emerald-400' : 'bg-emerald-50 border-emerald-300 text-emerald-700'
            }`}>
              {CISCO_DEVICES.length} Devices &bull; 7 Link Cables Active
            </span>
          </div>
          <p className="text-xs opacity-70 mt-1 font-sans">
            Real-time packet simulator showing in-flight PDUs, link lights, OSI layers, and attack propagation across network infrastructure.
          </p>
        </div>

        {/* Playback Controls & Detailed Report Button */}
        <div className="flex items-center gap-2 flex-wrap self-start lg:self-auto">
          {/* Speed Selector */}
          <div className={`flex items-center rounded-lg border p-0.5 text-xs font-mono ${
            isDark ? 'bg-[#070A12] border-[#1F293D]' : 'bg-slate-100 border-slate-300'
          }`}>
            {[1, 2, 3].map(sp => (
              <button
                key={sp}
                onClick={() => setPlaybackSpeed(sp)}
                className={`px-2 py-1 rounded transition ${
                  playbackSpeed === sp
                    ? 'bg-blue-600 text-white font-bold shadow'
                    : 'opacity-60 hover:opacity-100'
                }`}
              >
                {sp}x
              </button>
            ))}
          </div>

          {/* Play / Pause */}
          <button
            onClick={() => setIsPlaying(!isPlaying)}
            className={`flex items-center gap-1.5 px-3.5 py-1.5 text-xs font-bold font-mono rounded-lg transition-all ${
              isPlaying
                ? 'bg-amber-600 hover:bg-amber-500 text-white shadow-md shadow-amber-600/30'
                : 'bg-blue-600 hover:bg-blue-500 text-white shadow-md shadow-blue-600/30'
            }`}
          >
            {isPlaying ? (
              <>
                <Pause className="w-3.5 h-3.5" /> Pause Simulation
              </>
            ) : (
              <>
                <Play className="w-3.5 h-3.5 fill-current" /> Auto-Simulate (PDU)
              </>
            )}
          </button>

          {/* Step Back */}
          <button
            onClick={handleStepBack}
            disabled={activeStepIdx === 0}
            className={`p-2 rounded-lg border text-xs font-mono transition disabled:opacity-40 ${
              isDark ? 'bg-[#070A12] border-[#1F293D] hover:bg-slate-800' : 'bg-slate-100 border-slate-300 hover:bg-slate-200'
            }`}
            title="Previous Step"
          >
            &larr; Step
          </button>

          {/* Step Forward (Capture / Forward in Packet Tracer) */}
          <button
            onClick={handleStepForward}
            className={`flex items-center gap-1 px-3 py-1.5 rounded-lg border text-xs font-mono font-bold transition ${
              isDark ? 'bg-[#070A12] border-blue-500/40 text-blue-400 hover:bg-blue-950/40' : 'bg-blue-50 border-blue-300 text-blue-700 hover:bg-blue-100'
            }`}
            title="Step Forward (Capture / Forward)"
          >
            <SkipForward className="w-3.5 h-3.5" />
            <span>Capture / Forward</span>
          </button>

          {/* Reset */}
          <button
            onClick={handleReset}
            className={`p-2 rounded-lg border transition ${
              isDark ? 'bg-[#070A12] border-[#1F293D] text-gray-400 hover:text-white' : 'bg-slate-100 border-slate-300 text-slate-600 hover:text-slate-900'
            }`}
            title="Reset Simulation"
          >
            <RotateCcw className="w-3.5 h-3.5" />
          </button>

          {/* Detailed Forensic Report Modal Trigger */}
          <button
            onClick={() => setShowReportModal(true)}
            className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg text-xs font-bold font-mono bg-emerald-600 hover:bg-emerald-500 text-white shadow-md shadow-emerald-600/30 transition"
          >
            <FileText className="w-3.5 h-3.5" />
            <span>Forensic Incident Report</span>
          </button>
        </div>
      </div>

      {/* ── Packet Tracer Workspace Canvas (SVG Network Diagram) ────────────── */}
      <div className={`relative w-full h-[480px] rounded-xl border overflow-hidden select-none transition-colors ${
        isDark ? 'bg-[#070C16] border-[#1F293D]' : 'bg-[#F8FAFC] border-slate-200 shadow-inner'
      }`}>

        {/* Cisco Packet Tracer Grid Lines Background */}
        <svg className="absolute inset-0 w-full h-full opacity-20 pointer-events-none">
          <defs>
            <pattern id="cisco-grid" width="40" height="40" patternUnits="userSpaceOnUse">
              <path d="M 40 0 L 0 0 0 40" fill="none" stroke={isDark ? '#3B82F6' : '#94A3B8'} strokeWidth="0.6" />
              <circle cx="20" cy="20" r="1" fill={isDark ? '#3B82F6' : '#94A3B8'} />
            </pattern>
          </defs>
          <rect width="100%" height="100%" fill="url(#cisco-grid)" />
        </svg>

        {/* Live Simulation Trigger HUD Banner */}
        {liveSimulationBanner && (
          <div className="absolute top-3 left-4 right-4 z-40 p-3 rounded-xl bg-[#080D1A]/95 border-2 border-red-500 text-white shadow-2xl flex items-center justify-between gap-3 animate-fadeIn backdrop-blur-md">
            <div className="flex items-center gap-3 min-w-0">
              <span className="w-3.5 h-3.5 rounded-full bg-red-500 animate-ping shrink-0" />
              <div className="min-w-0">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-red-600 text-white font-bold">
                    LIVE SIMULATION ACTIVE
                  </span>
                  <span className="text-xs font-mono font-bold text-red-300 truncate">
                    [{liveSimulationBanner.technique}] {liveSimulationBanner.title}
                  </span>
                </div>
                <div className="text-[11px] font-mono text-slate-300 truncate mt-0.5">
                  Flow: <span className="text-cyan-400 font-bold">{srcDev?.name}</span> &rarr; <span className="text-red-400 font-bold">{dstDev?.name}</span> ({activePdu.protocol}) &bull; Cmd: <span className="text-slate-400 font-mono">{liveSimulationBanner.command}</span>
                </div>
              </div>
            </div>
            <div className="flex items-center gap-2 shrink-0">
              <button
                onClick={() => setShowPduInspector(true)}
                className="px-2.5 py-1 rounded bg-blue-600 hover:bg-blue-500 text-white text-[10px] font-mono font-bold transition flex items-center gap-1 shadow-xs"
              >
                Inspect OSI Layers &rarr;
              </button>
              <button
                onClick={() => setLiveSimulationBanner(null)}
                className="p-1 rounded text-slate-400 hover:text-white"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
          </div>
        )}

        {/* Cables / Physical Links */}
        <svg className="absolute inset-0 w-full h-full pointer-events-none">
          {CISCO_LINKS.map(link => {
            const devA = deviceMap[link.from];
            const devB = deviceMap[link.to];
            if (!devA || !devB) return null;

            const isLinkInActivePdu = activePdu.cableId === link.id;

            return (
              <g key={link.id}>
                {/* Main Cable Line */}
                <line
                  x1={devA.x}
                  y1={devA.y}
                  x2={devB.x}
                  y2={devB.y}
                  stroke={
                    isLinkInActivePdu
                      ? '#EF4444'
                      : isDark ? '#334155' : '#94A3B8'
                  }
                  strokeWidth={isLinkInActivePdu ? 3.5 : 2}
                  strokeDasharray={link.type === 'fiber' ? '5,4' : 'none'}
                  className="transition-all duration-300"
                />

                {/* Active Simulated Laser Beam */}
                {isLinkInActivePdu && srcDev && (
                  <line
                    x1={srcDev.x}
                    y1={srcDev.y}
                    x2={packetPos.x}
                    y2={packetPos.y}
                    stroke="#EF4444"
                    strokeWidth={4.5}
                    strokeLinecap="round"
                    className="animate-pulse"
                  />
                )}

                {/* Port Link Lights (Green/Red LED lights like Cisco hardware) */}
                <circle
                  cx={devA.x + (devB.x - devA.x) * 0.12}
                  cy={devA.y + (devB.y - devA.y) * 0.12}
                  r="3.5"
                  fill={isLinkInActivePdu ? '#EF4444' : '#10B981'}
                  className={isLinkInActivePdu ? 'animate-ping' : ''}
                />
                <circle
                  cx={devA.x + (devB.x - devA.x) * 0.88}
                  cy={devA.y + (devB.y - devA.y) * 0.88}
                  r="3.5"
                  fill={isLinkInActivePdu ? '#EF4444' : '#10B981'}
                />

                {/* Port Interface Label */}
                <text
                  x={devA.x + (devB.x - devA.x) * 0.25}
                  y={devA.y + (devB.y - devA.y) * 0.25 - 6}
                  fill={isDark ? '#64748B' : '#94A3B8'}
                  fontSize="9"
                  fontFamily="monospace"
                  textAnchor="middle"
                >
                  {link.portFrom}
                </text>
              </g>
            );
          })}
        </svg>

        {/* Animated In-Flight PDU Envelope (Cisco Packet Tracer Envelope) */}
        {srcDev && dstDev && (
          <div
            style={{
              left: `${packetPos.x}px`,
              top: `${packetPos.y}px`,
              transform: 'translate(-50%, -50%)'
            }}
            onClick={() => setShowPduInspector(true)}
            className="absolute z-30 cursor-pointer animate-bounce transition-all duration-500"
            title="Click to Inspect In-Flight PDU (OSI Layers)"
          >
            <div className="flex flex-col items-center">
              <div className="px-2.5 py-1 rounded-md bg-red-600 text-white font-mono text-[10px] font-bold shadow-lg shadow-red-500/40 flex items-center gap-1.5 border border-red-400">
                <span className="w-2 h-2 rounded-full bg-white animate-ping" />
                <span>PDU #{activePdu.step}</span>
                <span className="text-[9px] opacity-80">({activePdu.protocol})</span>
              </div>
              <div className="text-[9px] font-mono text-red-400 font-bold mt-0.5 bg-black/60 px-1 rounded">
                {activePdu.technique}
              </div>
            </div>
          </div>
        )}

        {/* Device Nodes (Cisco Hardware Icons & Labels) */}
        {CISCO_DEVICES.map(dev => {
          const isSelected = selectedDevice?.id === dev.id;
          const isDevInTransit = activePdu.srcDev === dev.id || activePdu.dstDev === dev.id;
          const isTargetReached = packetProgress > 0.75 && activePdu.dstDev === dev.id;

          return (
            <div
              key={dev.id}
              style={{
                left: `${dev.x}px`,
                top: `${dev.y}px`,
                transform: 'translate(-50%, -50%)'
              }}
              onClick={() => setSelectedDevice(dev)}
              className={`absolute z-20 cursor-pointer flex flex-col items-center p-2 rounded-xl transition-all duration-300 ${
                isSelected
                  ? 'ring-2 ring-blue-500 scale-105'
                  : isTargetReached
                  ? 'ring-4 ring-red-500 scale-110 shadow-2xl shadow-red-500/50 bg-red-950/40'
                  : isDevInTransit
                  ? 'ring-2 ring-red-500/80 scale-105'
                  : 'hover:scale-105'
              }`}
            >
              {/* Hardware Icon */}
              {getDeviceIcon(dev.type)}

              {/* Device Hostname & IP */}
              <div className="text-center mt-1.5">
                <span className={`text-[11px] font-mono font-bold block truncate max-w-[130px] ${
                  isDark ? 'text-gray-200' : 'text-slate-800'
                }`}>
                  {dev.name}
                </span>
                <span className="text-[9px] font-mono opacity-60 block truncate max-w-[130px]">
                  {dev.ip.split(' ')[0]}
                </span>
                {dev.user && (
                  <span className="text-[8px] font-mono text-amber-500 bg-amber-500/10 px-1 rounded block truncate max-w-[120px] mt-0.5">
                    User: {dev.user}
                  </span>
                )}
              </div>
            </div>
          );
        })}

        {/* Live Simulation Step Overlay Card (Bottom-Left) */}
        <div className={`absolute bottom-3 left-3 z-20 max-w-md p-3.5 rounded-lg border backdrop-blur-md shadow-xl ${
          isDark ? 'bg-[#0B0F17]/90 border-[#1F293D]' : 'bg-white/95 border-slate-200 text-slate-800'
        }`}>
          <div className="flex items-center justify-between gap-2 mb-1">
            <span className="text-[10px] font-mono font-bold uppercase text-red-500 flex items-center gap-1">
              <Zap className="w-3 h-3" /> Step {activePdu.step} of {SIMULATION_PDUS.length} &bull; {activePdu.time}
            </span>
            <button
              onClick={() => setShowPduInspector(true)}
              className="text-[10px] font-mono text-blue-500 hover:underline flex items-center gap-0.5"
            >
              <Info className="w-3 h-3" /> Inspect OSI Layers
            </button>
          </div>

          <div className="text-xs font-bold font-mono">
            {activePdu.title}
          </div>

          <div className="text-[11px] opacity-80 mt-1 leading-relaxed">
            {activePdu.summary}
          </div>

          <div className="flex items-center gap-2 mt-2 pt-1.5 border-t border-inherit text-[10px] font-mono">
            <span className="text-blue-500">{activePdu.technique}</span>
            <span>&bull;</span>
            <span className="opacity-70">{activePdu.packetInfo}</span>
          </div>
        </div>

        {/* Selected Device Context Card (Top-Right) */}
        {selectedDevice && (
          <div className={`absolute top-3 right-3 z-20 w-64 p-3 rounded-lg border shadow-xl backdrop-blur-md ${
            isDark ? 'bg-[#0B0F17]/90 border-[#1F293D]' : 'bg-white/95 border-slate-200 text-slate-800'
          }`}>
            <div className="flex items-center justify-between pb-1 border-b border-inherit mb-2">
              <span className="text-xs font-bold font-mono truncate">{selectedDevice.name}</span>
              <button onClick={() => setSelectedDevice(null)} className="opacity-60 hover:opacity-100">
                <X className="w-3.5 h-3.5" />
              </button>
            </div>
            <div className="text-[10px] font-mono space-y-1">
              <div><span className="opacity-60">Model:</span> {selectedDevice.model}</div>
              <div><span className="opacity-60">IP:</span> {selectedDevice.ip}</div>
              <div><span className="opacity-60">MAC:</span> {selectedDevice.mac}</div>
              <div><span className="opacity-60">Segment:</span> {selectedDevice.vlan}</div>
              <div>
                <span className="opacity-60">Status:</span>{' '}
                <span className={selectedDevice.status === 'compromised' ? 'text-red-500 font-bold' : 'text-emerald-500'}>
                  {selectedDevice.status.toUpperCase()}
                </span>
              </div>
            </div>
          </div>
        )}

      </div>

      {/* ── Packet Tracer PDU Event List Table (Simulation Table) ──────────── */}
      <div className={`rounded-xl border overflow-hidden ${
        isDark ? 'bg-[#070C16] border-[#1F293D]' : 'bg-slate-50 border-slate-200'
      }`}>
        <div className="flex items-center justify-between px-4 py-2.5 border-b border-inherit">
          <span className="text-xs font-bold font-mono uppercase tracking-wider flex items-center gap-1.5">
            <Layers className="w-3.5 h-3.5 text-blue-500" />
            Packet Tracer Simulation Event List (PDUs)
          </span>
          <span className="text-[10px] font-mono opacity-60">Click any step to inspect & navigate</span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left font-mono text-xs">
            <thead>
              <tr className={`border-b text-[10px] uppercase opacity-70 ${
                isDark ? 'border-[#1F293D] bg-[#0B0F17]' : 'border-slate-200 bg-white'
              }`}>
                <th className="p-2.5">Step</th>
                <th className="p-2.5">Time</th>
                <th className="p-2.5">Source Device</th>
                <th className="p-2.5">Destination</th>
                <th className="p-2.5">Protocol</th>
                <th className="p-2.5">MITRE Technique</th>
                <th className="p-2.5">Payload Info</th>
              </tr>
            </thead>
            <tbody>
              {SIMULATION_PDUS.map((pdu, idx) => {
                const isActive = activeStepIdx === idx;
                return (
                  <tr
                    key={pdu.step}
                    onClick={() => setActiveStepIdx(idx)}
                    className={`border-b cursor-pointer transition-colors ${
                      isActive
                        ? isDark ? 'bg-blue-900/30 border-blue-500/50' : 'bg-blue-100/70 border-blue-300'
                        : isDark ? 'border-[#1F293D]/50 hover:bg-[#111827]' : 'border-slate-200 hover:bg-slate-100'
                    }`}
                  >
                    <td className="p-2.5 font-bold">
                      {isActive ? (
                        <span className="px-1.5 py-0.5 rounded bg-red-600 text-white text-[10px]">
                          #{pdu.step}
                        </span>
                      ) : (
                        `#${pdu.step}`
                      )}
                    </td>
                    <td className="p-2.5 opacity-70">{pdu.time}</td>
                    <td className="p-2.5 font-bold text-blue-500">{deviceMap[pdu.srcDev]?.name || pdu.srcDev}</td>
                    <td className="p-2.5 font-bold text-purple-500">{deviceMap[pdu.dstDev]?.name || pdu.dstDev}</td>
                    <td className="p-2.5">
                      <span className="px-1.5 py-0.2 rounded text-[10px] bg-slate-800 text-slate-200">
                        {pdu.protocol}
                      </span>
                    </td>
                    <td className="p-2.5 text-amber-500 font-bold">{pdu.technique}</td>
                    <td className="p-2.5 opacity-80 truncate max-w-xs">{pdu.title}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* ── Modal 1: Cisco Packet Tracer OSI Model & PDU Inspector ─────────── */}
      {showPduInspector && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm animate-fadeIn">
          <div className={`w-full max-w-2xl rounded-2xl border shadow-2xl p-6 space-y-4 max-h-[90vh] overflow-y-auto ${
            isDark ? 'bg-[#0B0F17] border-[#1F293D] text-gray-100' : 'bg-white border-slate-200 text-slate-800'
          }`}>
            <div className="flex items-center justify-between pb-3 border-b border-inherit">
              <div className="flex items-center gap-2">
                <Shield className="w-5 h-5 text-blue-500" />
                <h3 className="text-base font-bold font-mono">
                  PDU Information at Device: {deviceMap[activePdu.dstDev]?.name}
                </h3>
              </div>
              <button onClick={() => setShowPduInspector(false)} className="opacity-60 hover:opacity-100">
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="text-xs font-mono opacity-80">
              PDU #{activePdu.step} &bull; Timestamp: {activePdu.time} &bull; Protocol: {activePdu.protocol}
            </div>

            {/* OSI 7-Layer Model Inspection */}
            <div className="space-y-2">
              <div className="text-xs font-mono font-bold uppercase tracking-wider text-blue-500">
                OSI Model Layers (Packet Analysis)
              </div>
              <div className="space-y-2 font-mono text-xs">
                <div className={`p-2.5 rounded-lg border ${isDark ? 'bg-[#070C16] border-[#1F293D]' : 'bg-slate-50 border-slate-200'}`}>
                  <strong className="text-blue-400">Layer 7 (Application):</strong> {activePdu.layers.l7}
                </div>
                <div className={`p-2.5 rounded-lg border ${isDark ? 'bg-[#070C16] border-[#1F293D]' : 'bg-slate-50 border-slate-200'}`}>
                  <strong className="text-indigo-400">Layer 4 (Transport):</strong> {activePdu.layers.l4}
                </div>
                <div className={`p-2.5 rounded-lg border ${isDark ? 'bg-[#070C16] border-[#1F293D]' : 'bg-slate-50 border-slate-200'}`}>
                  <strong className="text-cyan-400">Layer 3 (Network):</strong> {activePdu.layers.l3}
                </div>
                <div className={`p-2.5 rounded-lg border ${isDark ? 'bg-[#070C16] border-[#1F293D]' : 'bg-slate-50 border-slate-200'}`}>
                  <strong className="text-emerald-400">Layer 2 (Data Link):</strong> {activePdu.layers.l2}
                </div>
                <div className={`p-2.5 rounded-lg border ${isDark ? 'bg-[#070C16] border-[#1F293D]' : 'bg-slate-50 border-slate-200'}`}>
                  <strong className="text-amber-400">Layer 1 (Physical):</strong> {activePdu.layers.l1}
                </div>
              </div>
            </div>

            <div className="flex justify-end pt-2">
              <button
                onClick={() => setShowPduInspector(false)}
                className="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-xs font-bold font-mono transition"
              >
                Close Inspector
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ── Modal 2: Detailed Post-Simulation Forensic Incident Report ──────── */}
      {showReportModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-md animate-fadeIn">
          <div className={`w-full max-w-4xl rounded-2xl border shadow-2xl p-6 sm:p-8 space-y-6 max-h-[92vh] overflow-y-auto ${
            isDark ? 'bg-[#0B0F17] border-[#1F293D] text-gray-100' : 'bg-white border-slate-200 text-slate-800'
          }`}>
            
            {/* Report Header */}
            <div className="flex items-start justify-between pb-4 border-b border-inherit">
              <div>
                <div className="flex items-center gap-2 mb-1">
                  <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-red-600 text-white">
                    SEVERITY: CRITICAL
                  </span>
                  <span className="text-xs font-mono opacity-70">
                    REPORT REF: PKT-SIM-2026-0982
                  </span>
                </div>
                <h2 className="text-xl font-bold font-mono tracking-tight">
                  Post-Simulation Network Forensics & Attack Sequence Report
                </h2>
                <p className="text-xs opacity-70 mt-1">
                  Generated automatically following completion of the Cisco Packet Tracer attack trajectory.
                </p>
              </div>

              <div className="flex items-center gap-2">
                <button
                  onClick={() => window.print()}
                  className={`p-2 rounded-lg border text-xs font-mono transition ${
                    isDark ? 'bg-slate-800 border-slate-700 hover:bg-slate-700' : 'bg-slate-100 border-slate-300 hover:bg-slate-200'
                  }`}
                  title="Print / Save PDF"
                >
                  <Printer className="w-4 h-4" />
                </button>
                <button onClick={() => setShowReportModal(false)} className="p-2 opacity-60 hover:opacity-100">
                  <X className="w-5 h-5" />
                </button>
              </div>
            </div>

            {/* 1. Executive Summary */}
            <div className={`p-4 rounded-xl border ${isDark ? 'bg-[#070C16] border-[#1F293D]' : 'bg-slate-50 border-slate-200'}`}>
              <h4 className="text-xs font-mono font-bold uppercase tracking-wider text-blue-500 mb-2">
                1. Executive Summary
              </h4>
              <p className="text-xs leading-relaxed opacity-90">
                During the simulated campaign, external adversary infrastructure (<strong>185.220.101.44</strong>) bypassed perimeter firewall inspections via HTTPS tunneling, propagated across the internal Catalyst core switch to compromise <strong>WKSTN-FIN-04</strong>, dumped memory credentials (LSASS), and executed remote SMB lateral movement to gain full domain administrative access on <strong>DC01.corp.local</strong>, culminating in AWS S3 cloud data exfiltration.
              </p>
            </div>

            {/* 2. Compromised Assets & IOCs */}
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
              <div className={`p-3.5 rounded-xl border ${isDark ? 'bg-[#070C16] border-[#1F293D]' : 'bg-slate-50 border-slate-200'}`}>
                <div className="text-[10px] font-mono opacity-60 uppercase">Attacker Origin</div>
                <div className="text-sm font-bold font-mono text-red-500 mt-0.5">185.220.101.44</div>
                <div className="text-[10px] font-mono opacity-60 mt-1">Bulletproof C2 Node</div>
              </div>
              <div className={`p-3.5 rounded-xl border ${isDark ? 'bg-[#070C16] border-[#1F293D]' : 'bg-slate-50 border-slate-200'}`}>
                <div className="text-[10px] font-mono opacity-60 uppercase">Patient Zero</div>
                <div className="text-sm font-bold font-mono text-amber-500 mt-0.5">WKSTN-FIN-04 (10.42.0.105)</div>
                <div className="text-[10px] font-mono opacity-60 mt-1">User: sarah.connor</div>
              </div>
              <div className={`p-3.5 rounded-xl border ${isDark ? 'bg-[#070C16] border-[#1F293D]' : 'bg-slate-50 border-slate-200'}`}>
                <div className="text-[10px] font-mono opacity-60 uppercase">Crown Jewel Impact</div>
                <div className="text-sm font-bold font-mono text-purple-500 mt-0.5">DC01 & S3 Backups</div>
                <div className="text-[10px] font-mono opacity-60 mt-1">Full Domain Admin Taken</div>
              </div>
            </div>

            {/* 3. Chronological PDU Traversal Table */}
            <div>
              <h4 className="text-xs font-mono font-bold uppercase tracking-wider text-blue-500 mb-2">
                2. Chronological Packet Traversal Transcript
              </h4>
              <div className="border border-inherit rounded-lg overflow-hidden">
                <table className="w-full text-left font-mono text-xs">
                  <thead>
                    <tr className={`border-b text-[10px] uppercase opacity-70 ${
                      isDark ? 'bg-[#070C16] border-[#1F293D]' : 'bg-slate-100 border-slate-200'
                    }`}>
                      <th className="p-2">Step</th>
                      <th className="p-2">Source</th>
                      <th className="p-2">Destination</th>
                      <th className="p-2">Protocol</th>
                      <th className="p-2">Technique</th>
                      <th className="p-2">Forensic Assessment</th>
                    </tr>
                  </thead>
                  <tbody>
                    {SIMULATION_PDUS.map(pdu => (
                      <tr key={pdu.step} className="border-b border-inherit/40 text-[11px]">
                        <td className="p-2 font-bold">#{pdu.step}</td>
                        <td className="p-2 text-blue-500">{deviceMap[pdu.srcDev]?.name}</td>
                        <td className="p-2 text-purple-500">{deviceMap[pdu.dstDev]?.name}</td>
                        <td className="p-2">{pdu.protocol}</td>
                        <td className="p-2 text-amber-500 font-bold">{pdu.technique}</td>
                        <td className="p-2 opacity-80">{pdu.title}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            {/* 4. Cisco IOS & ASA Hardening Mitigation Commands */}
            <div className={`p-4 rounded-xl border space-y-2 ${isDark ? 'bg-[#070C16] border-[#1F293D]' : 'bg-slate-50 border-slate-200'}`}>
              <div className="flex items-center justify-between">
                <h4 className="text-xs font-mono font-bold uppercase tracking-wider text-emerald-500 flex items-center gap-1.5">
                  <Terminal className="w-4 h-4" /> Recommended Cisco ACL & Interface Remediation Script
                </h4>
                <span className="text-[10px] font-mono opacity-60">Ready to apply on ASA/Router</span>
              </div>
              <pre className="p-3 rounded-lg bg-black/80 text-emerald-400 font-mono text-xs overflow-x-auto select-all leading-relaxed">
{`! 1. Cisco ASA 5506-X Perimeter Firewall Block
configure terminal
access-list OUTSIDE_IN extended deny ip host 185.220.101.44 any
access-list OUTSIDE_IN extended deny tcp any host 10.42.0.105 eq 443
access-group OUTSIDE_IN in interface GigabitEthernet1/1

! 2. Catalyst 2960 Core Switch Port Quarantine (Isolate Patient-Zero)
interface FastEthernet0/1
 shutdown
 description QUARANTINED: Active Lateral Movement (Incident PKT-SIM-2026-0982)

! 3. Restrict SMB Lateral Movement Between VLANs on Cisco 2911 Router
interface GigabitEthernet0/1.10
 ip access-group BLOCK_LATERAL_SMB in
access-list 102 deny tcp 10.42.0.0 0.0.0.255 host 10.42.0.10 eq 445
access-list 102 permit ip any any`}
              </pre>
            </div>

            {/* Close Button */}
            <div className="flex justify-end pt-2">
              <button
                onClick={() => setShowReportModal(false)}
                className="px-6 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-white font-mono text-xs font-bold transition shadow-md"
              >
                Close Report
              </button>
            </div>

          </div>
        </div>
      )}

    </div>
  );
}
