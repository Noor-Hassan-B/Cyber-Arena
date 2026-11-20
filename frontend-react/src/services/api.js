// =========================================================================
// Unified API Client & Dual-Mode Engine (PHP MySQL API + Local Fallback)
// =========================================================================

import { ATTACK_SCENARIOS } from '../constants/attackScenarios';
import { MITRE_TECHNIQUES_CATALOG, MITRE_TACTICS } from '../constants/mitreMatrix';

const API_BASE = 'http://localhost:8000/api';

class ThreatHunterService {
  constructor() {
    this.useLiveBackend = false;
    this.backendChecked = false;
    this.customEvents = [];
  }

  async checkBackendHealth() {
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 1200);
      const res = await fetch(`${API_BASE}/scenarios`, { signal: controller.signal });
      clearTimeout(timeoutId);
      if (res.ok) {
        this.useLiveBackend = true;
        return { online: true, url: API_BASE };
      }
    } catch (e) {
      this.useLiveBackend = false;
    }
    return { online: false, url: API_BASE };
  }

  async getScenarios() {
    if (this.useLiveBackend) {
      try {
        const res = await fetch(`${API_BASE}/scenarios`);
        const data = await res.json();
        if (data.status === 'success' && data.scenarios) {
          return data.scenarios;
        }
      } catch (e) {
        console.warn('PHP API scenarios failed, using local scenario catalog:', e);
      }
    }
    return ATTACK_SCENARIOS.map(s => ({
      scenario_id: s.scenario_id,
      name: s.name,
      threat_actor: s.threat_actor,
      severity: s.severity,
      target_environment: s.target_environment,
      attack_vector: s.attack_vector,
      impact: s.impact,
      description: s.description,
      total_events: s.events.length
    }));
  }

  async getEvents(scenarioId = 'SCN-APT29-GHOST', filters = {}) {
    if (this.useLiveBackend) {
      try {
        let url = `${API_BASE}/events?scenario_id=${encodeURIComponent(scenarioId)}`;
        if (filters.domain && filters.domain !== 'ALL') url += `&domain=${filters.domain}`;
        if (filters.severity && filters.severity !== 'ALL') url += `&severity=${filters.severity}`;
        if (filters.search) url += `&search=${encodeURIComponent(filters.search)}`;
        const res = await fetch(url);
        const data = await res.json();
        if (data.status === 'success' && data.events) {
          return data.events.slice().sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
        }
      } catch (e) {
        console.warn('PHP API events failed, falling back to local dataset:', e);
      }
    }

    // Local fallback
    const matched = ATTACK_SCENARIOS.find(s => s.scenario_id === scenarioId);
    let events = matched ? [...matched.events] : [...ATTACK_SCENARIOS[0].events];

    // Append custom injected events matching this scenario
    const injected = this.customEvents.filter(e => e.scenario_id === scenarioId || scenarioId === 'ALL');
    events = [...injected, ...events];
    events.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());

    if (filters.domain && filters.domain !== 'ALL') {
      events = events.filter(e => e.domain === filters.domain);
    }
    if (filters.severity && filters.severity !== 'ALL') {
      events = events.filter(e => e.severity === filters.severity);
    }
    if (filters.search) {
      const q = filters.search.toLowerCase();
      events = events.filter(e =>
        e.event_uuid.toLowerCase().includes(q) ||
        (e.source_host && e.source_host.toLowerCase().includes(q)) ||
        (e.dest_host && e.dest_host.toLowerCase().includes(q)) ||
        (e.user_id && e.user_id.toLowerCase().includes(q)) ||
        (e.command_line && e.command_line.toLowerCase().includes(q)) ||
        (e.mitre_technique_id && e.mitre_technique_id.toLowerCase().includes(q))
      );
    }
    return events;
  }

  async ingestEvent(eventPayload) {
    const scenarioId = eventPayload.scenario_id || 'SCN-APT29-GHOST';
    const newUuid = eventPayload.event_uuid || ('EVT-ING-' + Math.random().toString(36).substring(2, 8).toUpperCase());
    const normalizedPayload = {
      ...eventPayload,
      event_uuid: newUuid,
      scenario_id: scenarioId,
      timestamp: eventPayload.timestamp || new Date().toISOString()
    };

    // Always maintain local custom events for instant responsive fallback
    this.customEvents.unshift(normalizedPayload);

    if (this.useLiveBackend) {
      try {
        const res = await fetch(`${API_BASE}/events`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(normalizedPayload)
        });
        const data = await res.json();
        return data;
      } catch (e) {
        console.warn('Live API event ingest failed, stored locally:', e);
      }
    }

    return {
      status: 'success_local',
      message: 'Event ingested into local correlation pipeline',
      event_uuid: newUuid,
      event: normalizedPayload
    };
  }

  async getCorrelation(scenarioId = 'SCN-APT29-GHOST') {
    if (this.useLiveBackend) {
      try {
        const res = await fetch(`${API_BASE}/correlate?scenario_id=${scenarioId}`);
        const data = await res.json();
        if (data.status === 'success') return data;
      } catch (e) {
        console.warn('Live API correlate failed, using local correlation engine:', e);
      }
    }

    const events = await this.getEvents(scenarioId);
    return this.calculateLocalCorrelation(scenarioId, events);
  }

  calculateLocalCorrelation(scenarioId, events) {
    const users = new Set();
    const hosts = new Set();
    const ips = new Set();
    const tactics = new Set();
    const domains = new Set();

    let prevEvent = null;
    const chain = events.map((evt, idx) => {
      if (evt.user_id) users.add(evt.user_id);
      if (evt.source_host) hosts.add(evt.source_host);
      if (evt.dest_host) hosts.add(evt.dest_host);
      if (evt.source_ip) ips.add(evt.source_ip);
      if (evt.dest_ip) ips.add(evt.dest_ip);
      if (evt.domain) domains.add(evt.domain);
      if (evt.mitre_tactic) tactics.add(evt.mitre_tactic);

      let linkReason = 'Initial ingress or foothold telemetry.';
      if (prevEvent) {
        const t1 = new Date(prevEvent.timestamp).getTime();
        const t2 = new Date(evt.timestamp).getTime();
        const mins = Math.max(1, Math.round((t2 - t1) / 60000));

        if (evt.user_id === prevEvent.user_id) {
          linkReason = `Direct user identity session continuity (${evt.user_id}) +${mins}m`;
        } else if (evt.source_host === prevEvent.source_host || evt.dest_host === prevEvent.dest_host) {
          linkReason = `Asset traversal / host pivot on ${evt.source_host} +${mins}m`;
        } else if (evt.source_ip === prevEvent.dest_ip || evt.dest_ip === prevEvent.dest_ip) {
          linkReason = `Network socket convergence on IP ${evt.dest_ip}`;
        } else {
          linkReason = `Cross-domain kill-chain progression: ${prevEvent.domain} ➔ ${evt.domain}`;
        }
      }
      prevEvent = evt;

      return {
        sequence: idx + 1,
        event_uuid: evt.event_uuid,
        timestamp: evt.timestamp,
        domain: evt.domain,
        event_type: evt.event_type,
        severity: evt.severity,
        source: evt.source_host || evt.source_ip,
        target: evt.dest_host || evt.dest_ip,
        user: evt.user_id,
        action_summary: evt.command_line || (evt.cloud_action ? `${evt.cloud_service}::${evt.cloud_action}` : evt.event_type),
        mitre_technique: {
          id: evt.mitre_technique_id,
          name: evt.mitre_technique_name,
          tactic: evt.mitre_tactic
        },
        correlation_link: linkReason,
        raw_payload: evt.raw_payload
      };
    });

    const confidenceScore = Math.min(0.98, Math.max(0.70, (domains.size * 0.1) + (tactics.size * 0.08) + 0.35));

    let title = `Multi-Stage Attack Chain: ${events.length} correlated events across ${domains.size} domains`;
    if (scenarioId === 'SCN-APT29-GHOST') title = 'APT29 GhostToken: Endpoint Weaponization to Cloud S3 Exfiltration';
    if (scenarioId === 'SCN-RANSOM-BLACKCAT') title = 'BlackCat Ransomware: VPN Infiltration to Shadow Copy Purge & Encryption';
    if (scenarioId === 'SCN-CLOUD-CRYPTOMINE') title = 'IAM Key Hijack: CloudTrail Tampering to GPU Cryptomining Fleet';

    return {
      status: 'success',
      scenario_id: scenarioId,
      total_events_analyzed: events.length,
      incident_title: title,
      confidence_score: Number(confidenceScore.toFixed(2)),
      kill_chain_coverage: Array.from(tactics),
      correlated_chain: chain,
      entities_involved: {
        users: Array.from(users),
        hosts: Array.from(hosts),
        ips: Array.from(ips)
      },
      hypothesis: `Adversary traversed ${tactics.size} MITRE ATT&CK tactics (${Array.from(tactics).join(', ')}). Multiple security controls bypassed across ${domains.size} telemetry layers (${Array.from(domains).join(', ')}). Telemetry strongly confirms active adversary intent rather than isolated baseline noise.`
    };
  }

  async getAttackPath(scenarioId = 'SCN-APT29-GHOST') {
    if (this.useLiveBackend) {
      try {
        const res = await fetch(`${API_BASE}/attack_path?scenario_id=${scenarioId}`);
        const data = await res.json();
        if (data.status === 'success') return data;
      } catch (e) {
        console.warn('Live API attack_path failed, using local graph generator:', e);
      }
    }

    const events = await this.getEvents(scenarioId);
    return this.generateLocalGraph(events, scenarioId);
  }

  generateLocalGraph(events, scenarioId) {
    const nodesMap = {};
    const edges = [];
    const criticalPath = [];

    events.forEach((evt, idx) => {
      const src = evt.source_host || evt.source_ip || 'External-Origin';
      const dst = evt.dest_host || evt.dest_ip || evt.cloud_service || 'Internal-Target';

      if (!nodesMap[src]) {
        nodesMap[src] = {
          id: src,
          label: src,
          type: this.classifyNodeType(src, evt.domain),
          compromised: true,
          events_count: 0,
          users: new Set()
        };
      }
      nodesMap[src].events_count++;
      if (evt.user_id) nodesMap[src].users.add(evt.user_id);

      if (!nodesMap[dst]) {
        nodesMap[dst] = {
          id: dst,
          label: dst,
          type: this.classifyNodeType(dst, evt.domain),
          compromised: true,
          events_count: 0,
          users: new Set()
        };
      }
      nodesMap[dst].events_count++;
      if (evt.user_id) nodesMap[dst].users.add(evt.user_id);

      const edgeId = `edge-${idx + 1}`;
      edges.push({
        id: edgeId,
        source: src,
        target: dst,
        label: evt.mitre_technique_name || evt.event_type,
        technique_id: evt.mitre_technique_id,
        tactic: evt.mitre_tactic,
        severity: evt.severity,
        timestamp: evt.timestamp,
        event_uuid: evt.event_uuid,
        user: evt.user_id,
        detail: evt.command_line || (evt.cloud_action ? `${evt.cloud_service}::${evt.cloud_action}` : evt.event_type)
      });

      criticalPath.push({
        step: idx + 1,
        source: src,
        target: dst,
        technique: `${evt.mitre_technique_id} (${evt.mitre_technique_name || ''})`,
        event_uuid: evt.event_uuid
      });
    });

    const nodes = Object.values(nodesMap).map(n => ({
      ...n,
      users: Array.from(n.users)
    }));

    return {
      status: 'success',
      scenario_id: scenarioId,
      nodes,
      edges,
      critical_path: criticalPath,
      blast_radius: {
        total_assets: nodes.length,
        high_risk_pivots: edges.length,
        compromised_identities: Array.from(new Set(events.map(e => e.user_id).filter(Boolean)))
      }
    };
  }

  classifyNodeType(name, domain) {
    if (name.startsWith('185.') || name.startsWith('194.') || name.includes('External') || name.includes('c2-')) {
      return 'c2_server';
    }
    if (name.includes('AWS') || name.includes('S3') || name.includes('IAM') || domain === 'cloud') {
      return 'cloud_resource';
    }
    if (name.includes('DC01') || name.includes('SRV') || name.includes('VPN')) {
      return 'server';
    }
    return 'endpoint';
  }

  async getMitreData(scenarioId = 'SCN-APT29-GHOST') {
    if (this.useLiveBackend) {
      try {
        const res = await fetch(`${API_BASE}/mitre?scenario_id=${scenarioId}`);
        const data = await res.json();
        if (data.status === 'success') return data;
      } catch (e) {
        console.warn('Live API mitre failed, using local matrix:', e);
      }
    }

    const events = await this.getEvents(scenarioId);
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

    return {
      status: 'success',
      scenario_id: scenarioId,
      tactics_order: MITRE_TACTICS.map(t => t.name),
      total_techniques_mapped: Object.keys(observed).length,
      observed_techniques: observed
    };
  }

  async getAiSummary(scenarioId = 'SCN-APT29-GHOST') {
    if (this.useLiveBackend) {
      try {
        const res = await fetch(`${API_BASE}/ai_assist?action=summary&scenario_id=${scenarioId}`);
        const data = await res.json();
        if (data.status === 'success') return data;
      } catch (e) {
        console.warn('Live API ai summary failed, using local summary:', e);
      }
    }

    if (scenarioId === 'SCN-RANSOM-BLACKCAT') {
      return {
        status: 'success',
        scenario_id: scenarioId,
        summary_title: 'Ransomware Attack Path & Staging Assessment',
        executive_summary: 'Adversary breached perimeter security via external VPN brute forcing [EVT-RSM-001], pivoted to the primary file repository via RDP [EVT-RSM-002], conducted subnet discovery [EVT-RSM-003], neutralized backup recovery points via vssadmin [EVT-RSM-004], disabled antivirus [EVT-RSM-005], exfiltrated financial data to cloud storage [EVT-RSM-006], and executed enterprise-wide ransomware encryption [EVT-RSM-007].',
        evidence_citations: [
          { citation: 'EVT-RSM-001', claim: 'Initial perimeter VPN access from Russian IP 194.26.29.112', tactic: 'Initial Access', technique: 'T1133' },
          { citation: 'EVT-RSM-002', claim: 'RDP lateral movement using compromised svc_backup account', tactic: 'Lateral Movement', technique: 'T1021.001' },
          { citation: 'EVT-RSM-004', claim: 'Deletion of 18 volume shadow copies to prevent file recovery', tactic: 'Defense Evasion', technique: 'T1490' },
          { citation: 'EVT-RSM-006', claim: 'Exfiltration of 4.2 GB of financial spreadsheets to Mega cloud', tactic: 'Exfiltration', technique: 'T1567.002' },
          { citation: 'EVT-RSM-007', claim: 'Detonation of BlackCat ransomware encrypting 42,918 files', tactic: 'Impact', technique: 'T1486' }
        ],
        confidence: 0.98,
        recommended_actions: [
          'Immediately terminate VPN session 194.26.29.112 and enforce MFA on svc_backup.',
          'Isolate SRV-FILE-01 from internal network VLAN.',
          'Block outbound egress destination 31.216.144.5 (Mega storage).',
          'Initiate offline bare-metal restore using immutable backup images.'
        ]
      };
    } else if (scenarioId === 'SCN-CLOUD-CRYPTOMINE') {
      return {
        status: 'success',
        scenario_id: scenarioId,
        summary_title: 'Cloud IAM Hijacking & Cryptomining Campaign',
        executive_summary: 'A compromised CI/CD developer credential [EVT-CLD-001] was used to attach AdministratorAccess policy [EVT-CLD-002], disable CloudTrail defensive auditing [EVT-CLD-003], provision 16 GPU-accelerated EC2 compute instances [EVT-CLD-004], and direct sustained high-hashrate traffic to Monero mining pool [EVT-CLD-005].',
        evidence_citations: [
          { citation: 'EVT-CLD-001', claim: 'Secondary access key generation for dev_ci_user from 198.51.100.77', tactic: 'Persistence', technique: 'T1098' },
          { citation: 'EVT-CLD-002', claim: 'Unauthorized escalation to AdministratorAccess IAM policy', tactic: 'Privilege Escalation', technique: 'T1078.004' },
          { citation: 'EVT-CLD-003', claim: 'Defense evasion by stopping CloudTrail production logging', tactic: 'Defense Evasion', technique: 'T1562.008' },
          { citation: 'EVT-CLD-004', claim: 'RunInstances API call launching 16 g4dn.12xlarge GPU nodes', tactic: 'Impact', technique: 'T1496' },
          { citation: 'EVT-CLD-005', claim: 'XMRig stratum TCP outbound connections at 98.4 MH/s', tactic: 'Impact', technique: 'T1496' }
        ],
        confidence: 0.93,
        recommended_actions: [
          'Revoke AWS Access Key AKIAIOSFODNN7EXAMPLE immediately.',
          'Re-enable CloudTrail logging trail "production-audit-trail".',
          'Terminate unauthorized EC2 instances across eu-west-1 region.',
          'Audit Git repositories for exposed AWS API secrets and commit histories.'
        ]
      };
    } else {
      // Default APT29
      return {
        status: 'success',
        scenario_id: scenarioId,
        summary_title: 'APT29 GhostToken Hybrid Enterprise Intrusion & S3 Theft',
        executive_summary: 'Adversary initiated intrusion via spearphishing attachment on WKSTN-FIN-04 [EVT-APT-001], initiating base64-encoded PowerShell download cradles [EVT-APT-002] and establishing C2 beaconing to 185.220.101.5 [EVT-APT-003]. Memory dumping of LSASS [EVT-APT-004] and Kerberoasting against Domain Controller [EVT-APT-005] facilitated lateral movement via remote WMI [EVT-APT-006]. Workstation file inspection uncovered plaintext AWS secrets [EVT-APT-007], allowing the attacker to assume ProductionDataOpsRole [EVT-APT-008], download customer databases from S3 [EVT-APT-009], and exfiltrate 1.49 GB to foreign drop servers [EVT-APT-010].',
        evidence_citations: [
          { citation: 'EVT-APT-001', claim: 'Malicious Word document execution by user sarah.connor', tactic: 'Initial Access', technique: 'T1566.001' },
          { citation: 'EVT-APT-002', claim: 'Hidden PowerShell execution downloading stage 1 payload', tactic: 'Execution', technique: 'T1059.001' },
          { citation: 'EVT-APT-003', claim: 'Encrypted C2 TLS beaconing with 12% jitter to c2-telemetry-sync.net', tactic: 'Command and Control', technique: 'T1071.001' },
          { citation: 'EVT-APT-004', claim: 'LSASS memory dump via comsvcs.dll into C:\\Users\\Public\\lsass.dmp', tactic: 'Credential Access', technique: 'T1003.001' },
          { citation: 'EVT-APT-005', claim: 'Kerberoasting attack targeting service account svc_sqladmin', tactic: 'Credential Access', technique: 'T1558.003' },
          { citation: 'EVT-APT-006', claim: 'Remote WMI command execution on Domain Controller DC01.corp.local', tactic: 'Lateral Movement', technique: 'T1047' },
          { citation: 'EVT-APT-007', claim: 'Local discovery and reading of .aws/credentials token file', tactic: 'Credential Access', technique: 'T1552.001' },
          { citation: 'EVT-APT-008', claim: 'External IP 185.220.101.5 assumes ProductionDataOpsRole in AWS STS', tactic: 'Privilege Escalation', technique: 'T1078.004' },
          { citation: 'EVT-APT-009', claim: 'Bulk S3 GetObject download of customer parquet database dumps', tactic: 'Collection', technique: 'T1530' },
          { citation: 'EVT-APT-010', claim: 'Network egress exfiltration of 1.49 GB to IP 91.240.118.12', tactic: 'Exfiltration', technique: 'T1048' }
        ],
        confidence: 0.94,
        recommended_actions: [
          'Immediately isolate endpoint WKSTN-FIN-04 from the corporate network.',
          'Reset Kerberos krbtgt account password twice and rotate svc_sqladmin password.',
          'Revoke all active STS assumed-role sessions for ProductionDataOpsRole.',
          'Block external IP addresses 185.220.101.5 and 91.240.118.12 at the perimeter firewall.',
          'Submit SHA256 hashes of payload.ps1 and srvmgr.exe to EDR containment blocklists.'
        ]
      };
    }
  }

  async getAiQuerySuggestions(scenarioId = 'SCN-APT29-GHOST') {
    if (this.useLiveBackend) {
      try {
        const res = await fetch(`${API_BASE}/ai_assist?action=query_suggestions&scenario_id=${scenarioId}`);
        const data = await res.json();
        if (data.status === 'success') return data.suggestions;
      } catch (e) {
        console.warn('Live API query suggestions failed, using local templates:', e);
      }
    }

    return [
      {
        id: 'sug-1',
        title: 'Anomalous Parent-Child Process Spawns',
        description: 'Hunt for office productivity software spawning shells or scripting engines (winword.exe -> powershell.exe).',
        target_tactic: 'Execution',
        mitre_technique: 'T1059.001',
        spl_query: 'index=endpoint process_name IN ("powershell.exe", "cmd.exe") parent_process="winword.exe"',
        sql_query: "SELECT * FROM events WHERE parent_process = 'winword.exe' AND process_name IN ('powershell.exe', 'cmd.exe');",
        rationale: 'Detects macro exploitation and download cradles before persistence is established.'
      },
      {
        id: 'sug-2',
        title: 'High-Frequency Kerberos Ticket Requests (Kerberoasting)',
        description: 'Identify Event ID 4769 with weak RC4 encryption (0x17) requested for multiple service principal names.',
        target_tactic: 'Credential Access',
        mitre_technique: 'T1558.003',
        spl_query: 'index=auth event_id=4769 ticket_encryption="0x17" | stats count by user_id, service_name | where count > 5',
        sql_query: "SELECT user_id, dest_host, COUNT(*) as ticket_count FROM events WHERE event_type = 'kerberos_request' GROUP BY user_id, dest_host;",
        rationale: 'Catches adversaries attempting offline password cracking of elevated service accounts.'
      },
      {
        id: 'sug-3',
        title: 'Cross-Subnet Lateral Movement via Remote WMI',
        description: 'Detect wmic.exe process calls targeting remote host IPs with embedded command strings.',
        target_tactic: 'Lateral Movement',
        mitre_technique: 'T1047',
        spl_query: 'index=endpoint process_name="wmic.exe" command_line="*/node:*process call create*"',
        sql_query: "SELECT * FROM events WHERE process_name = 'wmic.exe' AND command_line LIKE '%/node:%';",
        rationale: 'Discloses active adversary pivoting between internal assets using harvested credentials.'
      },
      {
        id: 'sug-4',
        title: 'Cloud Privilege Escalation with Non-MFA STS Sessions',
        description: 'Filter AWS CloudTrail AssumeRole calls originating from unapproved foreign IP addresses without MFA.',
        target_tactic: 'Privilege Escalation',
        mitre_technique: 'T1078.004',
        spl_query: 'index=cloud eventName="AssumeRole" sourceIPAddress!="10.0.*" NOT userIdentity.sessionContext.attributes.mfaAuthenticated="true"',
        sql_query: "SELECT * FROM events WHERE domain = 'cloud' AND cloud_action = 'AssumeRole' AND source_ip NOT LIKE '10.%';",
        rationale: 'Flags token theft and unauthorized cloud role assumption from external adversary infrastructure.'
      },
      {
        id: 'sug-5',
        title: 'Shadow Copy Purge Prior to Ransomware Detonation',
        description: 'Monitor vssadmin.exe or wbadmin.exe commands executed with quiet/delete parameters.',
        target_tactic: 'Defense Evasion',
        mitre_technique: 'T1490',
        spl_query: 'index=endpoint process_name="vssadmin.exe" command_line="*delete shadows*"',
        sql_query: "SELECT * FROM events WHERE process_name = 'vssadmin.exe' AND command_line LIKE '%delete shadows%';",
        rationale: 'Early warning signal that adversary is preparing for irreversible ransomware deployment.'
      }
    ];
  }

  async askAiCustomQuery(query, scenarioId = 'SCN-APT29-GHOST') {
    if (this.useLiveBackend) {
      try {
        const res = await fetch(`${API_BASE}/ai_assist`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ action: 'custom_query', scenario_id: scenarioId, query })
        });
        const data = await res.json();
        if (data.status === 'success') return data;
      } catch (e) {
        console.warn('Live API custom query failed, using local reasoning engine:', e);
      }
    }

    const lowerQuery = query.toLowerCase();
    let answer = '';
    let matchedEvidence = [];

    if (lowerQuery.includes('lateral') || lowerQuery.includes('pivot') || lowerQuery.includes('wmi') || lowerQuery.includes('rdp')) {
      answer = 'Lateral movement analysis indicates the adversary leveraged administrative protocols to traverse internal assets. In this incident, lateral traversal was evidenced by authenticated execution targeting high-value infrastructure [EVT-APT-006 / EVT-RSM-002].';
      matchedEvidence = ['EVT-APT-006', 'EVT-RSM-002'];
    } else if (lowerQuery.includes('cloud') || lowerQuery.includes('s3') || lowerQuery.includes('iam') || lowerQuery.includes('aws')) {
      answer = 'Cloud telemetry analysis confirms that stolen credentials enabled the adversary to interact with cloud management APIs without traversing on-premise perimeter firewalls. In AWS CloudTrail, STS AssumeRole and S3 GetObject operations were logged from unapproved public IPs [EVT-APT-008, EVT-APT-009, EVT-CLD-002].';
      matchedEvidence = ['EVT-APT-008', 'EVT-APT-009', 'EVT-CLD-002'];
    } else if (lowerQuery.includes('credential') || lowerQuery.includes('password') || lowerQuery.includes('lsass') || lowerQuery.includes('hash')) {
      answer = 'Credential theft was conducted through memory-scraping tools and ticket requests. Raw telemetry confirms LSASS memory dumping using comsvcs.dll [EVT-APT-004] and Kerberoasting against Domain Controller service principal names [EVT-APT-005].';
      matchedEvidence = ['EVT-APT-004', 'EVT-APT-005', 'EVT-APT-007'];
    } else {
      answer = `Investigation analysis against current scenario telemetry correlates suspicious activity spanning multiple kill-chain stages. Initial compromise initiated on the perimeter, escalated through credential harvesting, and completed with exfiltration/impact actions. Direct evidence linkage is maintained across all corresponding event UUIDs.`;
      matchedEvidence = ['EVT-APT-001', 'EVT-APT-004', 'EVT-APT-010'];
    }

    return {
      status: 'success',
      query,
      ai_answer: answer,
      linked_evidence: matchedEvidence,
      timestamp: new Date().toISOString()
    };
  }

  async getAiLimitations() {
    return [
      {
        id: 'lim-1',
        name: 'Hallucination & Fabricated Threat Indicators',
        severity: 'Critical',
        description: 'Large Language Models may hallucinate non-existent IP addresses, malicious domains, file hashes, or CVE vulnerabilities when prompts lack strict factual grounding.',
        mitigation: 'Deterministic Evidence Linking: Our platform forces every AI claim to map directly to an ingested event UUID and validates payloads against raw SIEM logs before rendering.'
      },
      {
        id: 'lim-2',
        name: 'Base-Rate Fallacy & False Positive Cascades',
        severity: 'High',
        description: 'In a standard enterprise generating billions of benign daily events, a 99% accurate model still generates thousands of false positive investigations, overwhelming analysts.',
        mitigation: 'Multi-Factor Correlation Pipeline: Alerts are only elevated when correlated across multiple independent entities (User + Host + Network socket + Sliding Time Window).'
      },
      {
        id: 'lim-3',
        name: 'Adversarial Evasion & Telemetry Poisoning',
        severity: 'High',
        description: 'Sophisticated threat actors (e.g., APT29) can craft benign-looking living-off-the-land commands (certutil, powershell -encoded) or flood event streams with noisy decoy telemetry to degrade AI confidence.',
        mitigation: 'Behavioral MITRE ATT&CK Matrix Alignment: Classifies fundamental tactics and techniques rather than brittle static signature strings.'
      },
      {
        id: 'lim-4',
        name: 'Context Window & Multi-Week Latency Gaps',
        severity: 'Medium',
        description: 'Advanced Persistent Threats (APTs) often maintain dwell times of 60 to 200 days with dormant intervals between stages. Feeding weeks of telemetry into LLM context windows exceeds token budgets and introduces recency bias.',
        mitigation: 'Hierarchical Graph Abstraction: Graph topology nodes reduce millions of raw logs into high-level causality vertices and edges before LLM summarization.'
      },
      {
        id: 'lim-5',
        name: 'Lack of Ground-Truth Grounding & Need for Human-in-the-Loop',
        severity: 'High',
        description: 'AI systems lack awareness of business context (e.g., an authorized red team exercise, scheduled backup script, or developer testing new credentials). Autonomous remediation without human confirmation can cause massive operational downtime.',
        mitigation: 'Human-in-the-Loop (HITL) Workflow: AI provides recommendations and hypotheses, but containment actions (host isolation, credential revocation) require senior SOC analyst approval.'
      }
    ];
  }

  async getInvestigationReport(scenarioId = 'SCN-APT29-GHOST', analystName = 'Senior SOC Threat Hunter') {
    if (this.useLiveBackend) {
      try {
        const res = await fetch(`${API_BASE}/report?scenario_id=${scenarioId}&analyst=${encodeURIComponent(analystName)}`);
        const data = await res.json();
        if (data.status === 'success' && data.report) return data.report;
      } catch (e) {
        console.warn('Live API report failed, generating local report:', e);
      }
    }

    const events = await this.getEvents(scenarioId);
    const correlation = await this.getCorrelation(scenarioId);
    const aiSummary = await this.getAiSummary(scenarioId);

    const reportId = `IR-${new Date().toISOString().slice(0, 10).replace(/-/g, '')}-${scenarioId.slice(4, 10)}`;

    const timeline = events.map(evt => ({
      timestamp: evt.timestamp,
      event_uuid: evt.event_uuid,
      domain: evt.domain.toUpperCase(),
      event_type: evt.event_type,
      severity: evt.severity,
      source: evt.source_host || evt.source_ip || 'N/A',
      target: evt.dest_host || evt.dest_ip || 'N/A',
      user: evt.user_id || 'System',
      action: evt.command_line || (evt.cloud_action || evt.event_type),
      mitre_technique: evt.mitre_technique_id ? `${evt.mitre_technique_id} - ${evt.mitre_technique_name}` : 'N/A'
    }));

    const evidenceChain = events.map(evt => ({
      item_id: evt.event_uuid,
      timestamp: evt.timestamp,
      evidence_type: `${evt.domain.toUpperCase()} Telemetry`,
      actor_entity: `${evt.user_id || 'Unknown'}@${evt.source_host || evt.source_ip || 'Internal'}`,
      raw_indicator: evt.command_line || evt.event_type,
      custody_status: 'Verified & Timestamped'
    }));

    return {
      report_id: reportId,
      title: correlation.incident_title,
      scenario_id: scenarioId,
      classification: 'RESTRICTED // SOC-OPERATIONS',
      lead_analyst: analystName,
      generated_at: new Date().toUTCString(),
      executive_summary: aiSummary.executive_summary,
      confidence_score: correlation.confidence_score,
      timeline,
      evidence_chain: evidenceChain,
      mitre_coverage: correlation.kill_chain_coverage,
      containment_playbook: {
        'Phase 1: Immediate Threat Isolation': [
          'Sever network connection on infected endpoints (isolate via EDR agent).',
          'Null-route identified external C2 IP addresses on perimeter firewalls.',
          'Terminate rogue interactive sessions (RDP/SSH/VPN).'
        ],
        'Phase 2: Identity & Credential Invalidation': [
          'Force password rotation for all affected domain and service accounts.',
          'Perform double Kerberos krbtgt ticket-granting password resets.',
          'Revoke active AWS STS tokens, IAM access keys, and active web sessions.'
        ],
        'Phase 3: Root Cause Eradication & Recovery': [
          'Re-image compromised endpoints from certified golden baselines.',
          'Restore locked or altered datastores from offline air-gapped backups.',
          'Deploy targeted Sigma and YARA correlation rules to continuously monitor for recurrence.'
        ]
      }
    };
  }
}

export const api = new ThreatHunterService();
