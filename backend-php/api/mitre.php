<?php
// =========================================================================
// API: MITRE ATT&CK Mapping & Coverage Heatmap
// =========================================================================

require_once __DIR__ . '/../config/db.php';

$pdo = getDatabaseConnection();
$scenarioId = $_GET['scenario_id'] ?? null;

$tacticsOrder = [
    'Initial Access',
    'Execution',
    'Persistence',
    'Privilege Escalation',
    'Defense Evasion',
    'Credential Access',
    'Discovery',
    'Lateral Movement',
    'Collection',
    'Command and Control',
    'Exfiltration',
    'Impact'
];

$observedTechniques = [];

if ($pdo) {
    $where = "";
    $params = [];
    if ($scenarioId && $scenarioId !== 'ALL') {
        $where = "WHERE scenario_id = ?";
        $params[] = $scenarioId;
    }
    
    $stmt = $pdo->prepare("
        SELECT mitre_technique_id, mitre_technique_name, mitre_tactic, severity, COUNT(*) as hit_count,
               GROUP_CONCAT(event_uuid) as event_uuids
        FROM events
        {$where}
        AND mitre_technique_id IS NOT NULL
        GROUP BY mitre_technique_id, mitre_technique_name, mitre_tactic, severity
    ");
    $stmt->execute($params);
    $rows = $stmt->fetchAll();

    foreach ($rows as $r) {
        $observedTechniques[$r['mitre_technique_id']] = [
            'technique_id' => $r['mitre_technique_id'],
            'technique_name' => $r['mitre_technique_name'],
            'tactic' => $r['mitre_tactic'],
            'severity' => $r['severity'],
            'hit_count' => intval($r['hit_count']),
            'event_uuids' => explode(',', $r['event_uuids'])
        ];
    }
} else {
    // Built-in fallback mappings if MySQL offline
    $observedTechniques = getFallbackObservedTechniques($scenarioId);
}

sendJsonResponse([
    'status' => 'success',
    'scenario_id' => $scenarioId ?: 'ALL',
    'tactics_order' => $tacticsOrder,
    'total_techniques_mapped' => count($observedTechniques),
    'observed_techniques' => $observedTechniques
]);

function getFallbackObservedTechniques($scenarioId) {
    if ($scenarioId === 'SCN-RANSOM-BLACKCAT') {
        return [
            'T1133' => ['technique_id' => 'T1133', 'technique_name' => 'External Remote Services', 'tactic' => 'Initial Access', 'severity' => 'high', 'hit_count' => 1, 'event_uuids' => ['EVT-RSM-001']],
            'T1021.001' => ['technique_id' => 'T1021.001', 'technique_name' => 'Remote Desktop Protocol', 'tactic' => 'Lateral Movement', 'severity' => 'high', 'hit_count' => 1, 'event_uuids' => ['EVT-RSM-002']],
            'T1046' => ['technique_id' => 'T1046', 'technique_name' => 'Network Service Discovery', 'tactic' => 'Discovery', 'severity' => 'medium', 'hit_count' => 1, 'event_uuids' => ['EVT-RSM-003']],
            'T1490' => ['technique_id' => 'T1490', 'technique_name' => 'Inhibit System Recovery', 'tactic' => 'Defense Evasion', 'severity' => 'critical', 'hit_count' => 1, 'event_uuids' => ['EVT-RSM-004']],
            'T1562.001' => ['technique_id' => 'T1562.001', 'technique_name' => 'Disable or Modify Tools', 'tactic' => 'Defense Evasion', 'severity' => 'high', 'hit_count' => 1, 'event_uuids' => ['EVT-RSM-005']],
            'T1567.002' => ['technique_id' => 'T1567.002', 'technique_name' => 'Exfiltration to Cloud Storage', 'tactic' => 'Exfiltration', 'severity' => 'high', 'hit_count' => 1, 'event_uuids' => ['EVT-RSM-006']],
            'T1486' => ['technique_id' => 'T1486', 'technique_name' => 'Data Encrypted for Impact', 'tactic' => 'Impact', 'severity' => 'critical', 'hit_count' => 1, 'event_uuids' => ['EVT-RSM-007']],
        ];
    } elseif ($scenarioId === 'SCN-CLOUD-CRYPTOMINE') {
        return [
            'T1098' => ['technique_id' => 'T1098', 'technique_name' => 'Account Manipulation', 'tactic' => 'Persistence', 'severity' => 'medium', 'hit_count' => 1, 'event_uuids' => ['EVT-CLD-001']],
            'T1078.004' => ['technique_id' => 'T1078.004', 'technique_name' => 'Cloud Accounts Compromise', 'tactic' => 'Privilege Escalation', 'severity' => 'critical', 'hit_count' => 1, 'event_uuids' => ['EVT-CLD-002']],
            'T1562.008' => ['technique_id' => 'T1562.008', 'technique_name' => 'Disable Cloud Logs', 'tactic' => 'Defense Evasion', 'severity' => 'high', 'hit_count' => 1, 'event_uuids' => ['EVT-CLD-003']],
            'T1496' => ['technique_id' => 'T1496', 'technique_name' => 'Resource Hijacking', 'tactic' => 'Impact', 'severity' => 'critical', 'hit_count' => 2, 'event_uuids' => ['EVT-CLD-004', 'EVT-CLD-005']]
        ];
    } else {
        // APT29 default
        return [
            'T1566.001' => ['technique_id' => 'T1566.001', 'technique_name' => 'Spearphishing Attachment', 'tactic' => 'Initial Access', 'severity' => 'medium', 'hit_count' => 1, 'event_uuids' => ['EVT-APT-001']],
            'T1059.001' => ['technique_id' => 'T1059.001', 'technique_name' => 'PowerShell Execution', 'tactic' => 'Execution', 'severity' => 'high', 'hit_count' => 1, 'event_uuids' => ['EVT-APT-002']],
            'T1071.001' => ['technique_id' => 'T1071.001', 'technique_name' => 'Web Protocols (C2)', 'tactic' => 'Command and Control', 'severity' => 'high', 'hit_count' => 1, 'event_uuids' => ['EVT-APT-003']],
            'T1003.001' => ['technique_id' => 'T1003.001', 'technique_name' => 'LSASS Memory Dumping', 'tactic' => 'Credential Access', 'severity' => 'critical', 'hit_count' => 1, 'event_uuids' => ['EVT-APT-004']],
            'T1558.003' => ['technique_id' => 'T1558.003', 'technique_name' => 'Kerberoasting', 'tactic' => 'Credential Access', 'severity' => 'high', 'hit_count' => 1, 'event_uuids' => ['EVT-APT-005']],
            'T1047' => ['technique_id' => 'T1047', 'technique_name' => 'Windows Management Instrumentation', 'tactic' => 'Lateral Movement', 'severity' => 'critical', 'hit_count' => 1, 'event_uuids' => ['EVT-APT-006']],
            'T1552.001' => ['technique_id' => 'T1552.001', 'technique_name' => 'Credentials In Files', 'tactic' => 'Credential Access', 'severity' => 'medium', 'hit_count' => 1, 'event_uuids' => ['EVT-APT-007']],
            'T1078.004' => ['technique_id' => 'T1078.004', 'technique_name' => 'Cloud Accounts Compromise', 'tactic' => 'Privilege Escalation', 'severity' => 'high', 'hit_count' => 1, 'event_uuids' => ['EVT-APT-008']],
            'T1530' => ['technique_id' => 'T1530', 'technique_name' => 'Data from Cloud Storage', 'tactic' => 'Collection', 'severity' => 'critical', 'hit_count' => 1, 'event_uuids' => ['EVT-APT-009']],
            'T1048' => ['technique_id' => 'T1048', 'technique_name' => 'Exfiltration Over Alternative Protocol', 'tactic' => 'Exfiltration', 'severity' => 'critical', 'hit_count' => 1, 'event_uuids' => ['EVT-APT-010']],
        ];
    }
}
