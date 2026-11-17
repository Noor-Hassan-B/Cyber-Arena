<?php
// =========================================================================
// API: Attack Path & Graph Topology Generator
// Reconstructs directed attack graphs with evidence-linked nodes & edges
// =========================================================================

require_once __DIR__ . '/../config/db.php';

$pdo = getDatabaseConnection();
$scenarioId = $_GET['scenario_id'] ?? 'SCN-APT29-GHOST';

$events = [];
if ($pdo) {
    $stmt = $pdo->prepare("SELECT * FROM events WHERE scenario_id = ? ORDER BY timestamp ASC");
    $stmt->execute([$scenarioId]);
    $events = $stmt->fetchAll();
}

$graphData = generateAttackPathGraph($events, $scenarioId);

sendJsonResponse([
    'status' => 'success',
    'scenario_id' => $scenarioId,
    'nodes' => $graphData['nodes'],
    'edges' => $graphData['edges'],
    'critical_path' => $graphData['critical_path'],
    'blast_radius' => $graphData['blast_radius']
]);

function generateAttackPathGraph($events, $scenarioId) {
    $nodesMap = [];
    $edges = [];
    $criticalPath = [];

    // Predefined baseline nodes if no DB events
    if (empty($events)) {
        if ($scenarioId === 'SCN-APT29-GHOST') {
            return getFallbackApt29Graph();
        } elseif ($scenarioId === 'SCN-RANSOM-BLACKCAT') {
            return getFallbackRansomwareGraph();
        } else {
            return getFallbackCloudGraph();
        }
    }

    $edgeIndex = 1;
    foreach ($events as $evt) {
        $srcName = $evt['source_host'] ?: ($evt['source_ip'] ?: 'External-Actor');
        $dstName = $evt['dest_host'] ?: ($evt['dest_ip'] ?: $evt['cloud_service'] ?: 'Target-Asset');

        // Classify source node
        if (!isset($nodesMap[$srcName])) {
            $nodesMap[$srcName] = [
                'id' => $srcName,
                'label' => $srcName,
                'type' => getNodeType($srcName, $evt['domain']),
                'compromised' => true,
                'events_count' => 0,
                'users' => []
            ];
        }
        $nodesMap[$srcName]['events_count']++;
        if (!empty($evt['user_id'])) {
            $nodesMap[$srcName]['users'][$evt['user_id']] = true;
        }

        // Classify dest node
        if (!isset($nodesMap[$dstName])) {
            $nodesMap[$dstName] = [
                'id' => $dstName,
                'label' => $dstName,
                'type' => getNodeType($dstName, $evt['domain']),
                'compromised' => true,
                'events_count' => 0,
                'users' => []
            ];
        }
        $nodesMap[$dstName]['events_count']++;
        if (!empty($evt['user_id'])) {
            $nodesMap[$dstName]['users'][$evt['user_id']] = true;
        }

        // Create directed edge
        $edgeId = 'edge-' . ($edgeIndex++);
        $edges[] = [
            'id' => $edgeId,
            'source' => $srcName,
            'target' => $dstName,
            'label' => $evt['mitre_technique_name'] ?: $evt['event_type'],
            'technique_id' => $evt['mitre_technique_id'],
            'tactic' => $evt['mitre_tactic'],
            'severity' => $evt['severity'],
            'timestamp' => $evt['timestamp'],
            'event_uuid' => $evt['event_uuid'],
            'user' => $evt['user_id'],
            'detail' => $evt['command_line'] ?: ($evt['cloud_action'] ? "{$evt['cloud_service']}::{$evt['cloud_action']}" : $evt['event_type'])
        ];

        $criticalPath[] = [
            'step' => $edgeIndex - 1,
            'source' => $srcName,
            'target' => $dstName,
            'technique' => $evt['mitre_technique_id'] . ' (' . ($evt['mitre_technique_name'] ?? '') . ')',
            'event_uuid' => $evt['event_uuid']
        ];
    }

    // Convert nodes map to clean indexed array
    $nodes = [];
    foreach ($nodesMap as $n) {
        $n['users'] = array_keys($n['users']);
        $nodes[] = $n;
    }

    return [
        'nodes' => $nodes,
        'edges' => $edges,
        'critical_path' => $criticalPath,
        'blast_radius' => [
            'total_assets' => count($nodes),
            'high_risk_pivots' => count($edges),
            'compromised_identities' => array_unique(array_filter(array_column($events, 'user_id')))
        ]
    ];
}

function getNodeType($name, $domain) {
    if (strpos($name, '185.') === 0 || strpos($name, '194.') === 0 || strpos($name, 'External') !== false || strpos($name, 'c2-') !== false) {
        return 'c2_server';
    }
    if (strpos($name, 'AWS') !== false || strpos($name, 'S3') !== false || strpos($name, 'IAM') !== false || $domain === 'cloud') {
        return 'cloud_resource';
    }
    if (strpos($name, 'DC01') !== false || strpos($name, 'SRV') !== false || strpos($name, 'VPN') !== false) {
        return 'server';
    }
    return 'endpoint';
}

function getFallbackApt29Graph() {
    return [
        'nodes' => [
            ['id' => '185.220.101.5', 'label' => 'C2 Infrastructure (185.220.101.5)', 'type' => 'c2_server', 'compromised' => true, 'events_count' => 4, 'users' => []],
            ['id' => 'WKSTN-FIN-04', 'label' => 'WKSTN-FIN-04 (Finance Workstation)', 'type' => 'endpoint', 'compromised' => true, 'events_count' => 6, 'users' => ['sarah.connor']],
            ['id' => 'DC01.corp.local', 'label' => 'DC01.corp.local (Domain Controller)', 'type' => 'server', 'compromised' => true, 'events_count' => 2, 'users' => ['svc_sqladmin']],
            ['id' => 'AWS S3 (us-east-1)', 'label' => 'AWS S3 (corp-prod-financial)', 'type' => 'cloud_resource', 'compromised' => true, 'events_count' => 2, 'users' => ['ProductionDataOpsRole']],
            ['id' => '91.240.118.12', 'label' => 'Exfiltration Drop (91.240.118.12)', 'type' => 'c2_server', 'compromised' => true, 'events_count' => 1, 'users' => []]
        ],
        'edges' => [
            ['id' => 'e1', 'source' => '185.220.101.5', 'target' => 'WKSTN-FIN-04', 'label' => 'Spearphishing Attachment & Macro Spawn', 'technique_id' => 'T1566.001', 'tactic' => 'Initial Access', 'severity' => 'high', 'event_uuid' => 'EVT-APT-001'],
            ['id' => 'e2', 'source' => 'WKSTN-FIN-04', 'target' => '185.220.101.5', 'label' => 'C2 TLS Beaconing (c2-telemetry-sync.net)', 'technique_id' => 'T1071.001', 'tactic' => 'Command and Control', 'severity' => 'high', 'event_uuid' => 'EVT-APT-003'],
            ['id' => 'e3', 'source' => 'WKSTN-FIN-04', 'target' => 'DC01.corp.local', 'label' => 'Remote WMI Execution & Kerberoasting', 'technique_id' => 'T1047', 'tactic' => 'Lateral Movement', 'severity' => 'critical', 'event_uuid' => 'EVT-APT-006'],
            ['id' => 'e4', 'source' => '185.220.101.5', 'target' => 'AWS S3 (us-east-1)', 'label' => 'AssumeRole -> Bulk S3 GetObject (1.49 GB)', 'technique_id' => 'T1530', 'tactic' => 'Collection', 'severity' => 'critical', 'event_uuid' => 'EVT-APT-009'],
            ['id' => 'e5', 'source' => 'AWS S3 (us-east-1)', 'target' => '91.240.118.12', 'label' => 'Data Exfiltration over HTTPS Alternative Port', 'technique_id' => 'T1048', 'tactic' => 'Exfiltration', 'severity' => 'critical', 'event_uuid' => 'EVT-APT-010']
        ],
        'critical_path' => [
            ['step' => 1, 'source' => '185.220.101.5', 'target' => 'WKSTN-FIN-04', 'technique' => 'T1566.001 (Spearphishing)', 'event_uuid' => 'EVT-APT-001'],
            ['step' => 2, 'source' => 'WKSTN-FIN-04', 'target' => 'DC01.corp.local', 'technique' => 'T1047 (Remote WMI)', 'event_uuid' => 'EVT-APT-006'],
            ['step' => 3, 'source' => '185.220.101.5', 'target' => 'AWS S3 (us-east-1)', 'technique' => 'T1530 (Cloud Data Access)', 'event_uuid' => 'EVT-APT-009'],
            ['step' => 4, 'source' => 'AWS S3 (us-east-1)', 'target' => '91.240.118.12', 'technique' => 'T1048 (Data Exfiltration)', 'event_uuid' => 'EVT-APT-010']
        ],
        'blast_radius' => [
            'total_assets' => 5,
            'high_risk_pivots' => 5,
            'compromised_identities' => ['sarah.connor', 'svc_sqladmin', 'ProductionDataOpsRole']
        ]
    ];
}

function getFallbackRansomwareGraph() {
    return [
        'nodes' => [
            ['id' => '194.26.29.112', 'label' => 'Attacker External IP', 'type' => 'c2_server', 'compromised' => true, 'events_count' => 1, 'users' => []],
            ['id' => 'VPN-GW-01', 'label' => 'Perimeter VPN Gateway', 'type' => 'server', 'compromised' => true, 'events_count' => 2, 'users' => ['svc_backup']],
            ['id' => 'SRV-FILE-01', 'label' => 'Enterprise File Server (SRV-FILE-01)', 'type' => 'server', 'compromised' => true, 'events_count' => 5, 'users' => ['svc_backup']],
            ['id' => 'mega.nz', 'label' => 'Mega Cloud Storage', 'type' => 'cloud_resource', 'compromised' => true, 'events_count' => 1, 'users' => []]
        ],
        'edges' => [
            ['id' => 're1', 'source' => '194.26.29.112', 'target' => 'VPN-GW-01', 'label' => 'VPN Brute Force Authentication', 'technique_id' => 'T1133', 'tactic' => 'Initial Access', 'severity' => 'high', 'event_uuid' => 'EVT-RSM-001'],
            ['id' => 're2', 'source' => 'VPN-GW-01', 'target' => 'SRV-FILE-01', 'label' => 'RDP Pivot via Compromised Admin Account', 'technique_id' => 'T1021.001', 'tactic' => 'Lateral Movement', 'severity' => 'high', 'event_uuid' => 'EVT-RSM-002'],
            ['id' => 're3', 'source' => 'SRV-FILE-01', 'target' => 'SRV-FILE-01', 'label' => 'Vssadmin Delete Shadows & Stop WinDefend', 'technique_id' => 'T1490', 'tactic' => 'Defense Evasion', 'severity' => 'critical', 'event_uuid' => 'EVT-RSM-004'],
            ['id' => 're4', 'source' => 'SRV-FILE-01', 'target' => 'mega.nz', 'label' => 'Exfiltration of Financials via mega-cmd', 'technique_id' => 'T1567.002', 'tactic' => 'Exfiltration', 'severity' => 'high', 'event_uuid' => 'EVT-RSM-006'],
            ['id' => 're5', 'source' => 'SRV-FILE-01', 'target' => 'SRV-FILE-01', 'label' => 'BlackCat Ransomware File Encryption', 'technique_id' => 'T1486', 'tactic' => 'Impact', 'severity' => 'critical', 'event_uuid' => 'EVT-RSM-007']
        ],
        'critical_path' => [
            ['step' => 1, 'source' => '194.26.29.112', 'target' => 'VPN-GW-01', 'technique' => 'T1133 (External Remote Services)', 'event_uuid' => 'EVT-RSM-001'],
            ['step' => 2, 'source' => 'VPN-GW-01', 'target' => 'SRV-FILE-01', 'technique' => 'T1021.001 (RDP Lateral)', 'event_uuid' => 'EVT-RSM-002'],
            ['step' => 3, 'source' => 'SRV-FILE-01', 'target' => 'mega.nz', 'technique' => 'T1567.002 (Cloud Exfil)', 'event_uuid' => 'EVT-RSM-006'],
            ['step' => 4, 'source' => 'SRV-FILE-01', 'target' => 'SRV-FILE-01', 'technique' => 'T1486 (Ransomware Encryption)', 'event_uuid' => 'EVT-RSM-007']
        ],
        'blast_radius' => [
            'total_assets' => 4,
            'high_risk_pivots' => 5,
            'compromised_identities' => ['svc_backup']
        ]
    ];
}

function getFallbackCloudGraph() {
    return [
        'nodes' => [
            ['id' => '198.51.100.77', 'label' => 'Attacker External IP (198.51.100.77)', 'type' => 'c2_server', 'compromised' => true, 'events_count' => 4, 'users' => ['dev_ci_user']],
            ['id' => 'AWS IAM (us-east-1)', 'label' => 'AWS IAM & Security Config', 'type' => 'cloud_resource', 'compromised' => true, 'events_count' => 2, 'users' => ['dev_ci_user']],
            ['id' => 'AWS CloudTrail (global)', 'label' => 'AWS CloudTrail Service', 'type' => 'cloud_resource', 'compromised' => true, 'events_count' => 1, 'users' => ['dev_ci_user']],
            ['id' => 'i-0a88bf2e99d12a', 'label' => 'EC2 GPU Fleet (16x g4dn.12xlarge)', 'type' => 'server', 'compromised' => true, 'events_count' => 2, 'users' => ['root']],
            ['id' => 'xmr.pool.minergate.com', 'label' => 'Monero Mining Pool (Stratum TCP)', 'type' => 'c2_server', 'compromised' => true, 'events_count' => 1, 'users' => []]
        ],
        'edges' => [
            ['id' => 'ce1', 'source' => '198.51.100.77', 'target' => 'AWS IAM (us-east-1)', 'label' => 'CreateAccessKey & Attach Admin Policy', 'technique_id' => 'T1078.004', 'tactic' => 'Privilege Escalation', 'severity' => 'critical', 'event_uuid' => 'EVT-CLD-002'],
            ['id' => 'ce2', 'source' => '198.51.100.77', 'target' => 'AWS CloudTrail (global)', 'label' => 'StopLogging Blind Defensive Auditing', 'technique_id' => 'T1562.008', 'tactic' => 'Defense Evasion', 'severity' => 'high', 'event_uuid' => 'EVT-CLD-003'],
            ['id' => 'ce3', 'source' => '198.51.100.77', 'target' => 'i-0a88bf2e99d12a', 'label' => 'RunInstances 16 GPU Instances', 'technique_id' => 'T1496', 'tactic' => 'Impact', 'severity' => 'critical', 'event_uuid' => 'EVT-CLD-004'],
            ['id' => 'ce4', 'source' => 'i-0a88bf2e99d12a', 'target' => 'xmr.pool.minergate.com', 'label' => 'High-rate Monero Miner Stratum Egress', 'technique_id' => 'T1496', 'tactic' => 'Impact', 'severity' => 'critical', 'event_uuid' => 'EVT-CLD-005']
        ],
        'critical_path' => [
            ['step' => 1, 'source' => '198.51.100.77', 'target' => 'AWS IAM (us-east-1)', 'technique' => 'T1078.004 (IAM Admin Escalation)', 'event_uuid' => 'EVT-CLD-002'],
            ['step' => 2, 'source' => '198.51.100.77', 'target' => 'AWS CloudTrail (global)', 'technique' => 'T1562.008 (StopLogging)', 'event_uuid' => 'EVT-CLD-003'],
            ['step' => 3, 'source' => '198.51.100.77', 'target' => 'i-0a88bf2e99d12a', 'technique' => 'T1496 (RunInstances)', 'event_uuid' => 'EVT-CLD-004'],
            ['step' => 4, 'source' => 'i-0a88bf2e99d12a', 'target' => 'xmr.pool.minergate.com', 'technique' => 'T1496 (Mining Traffic)', 'event_uuid' => 'EVT-CLD-005']
        ],
        'blast_radius' => [
            'total_assets' => 5,
            'high_risk_pivots' => 4,
            'compromised_identities' => ['dev_ci_user', 'root']
        ]
    ];
}
