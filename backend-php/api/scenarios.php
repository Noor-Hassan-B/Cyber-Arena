<?php
// =========================================================================
// API: Attack Scenarios Catalog & Loader
// =========================================================================

require_once __DIR__ . '/../config/db.php';

$pdo = getDatabaseConnection();
$scenarioId = $_GET['scenario_id'] ?? null;

if ($pdo) {
    if ($scenarioId) {
        $stmt = $pdo->prepare("SELECT * FROM attack_scenarios WHERE scenario_id = ?");
        $stmt->execute([$scenarioId]);
        $scenario = $stmt->fetch();
        sendJsonResponse(['status' => 'success', 'scenario' => $scenario]);
    } else {
        $stmt = $pdo->query("
            SELECT s.*, COUNT(e.id) as total_events
            FROM attack_scenarios s
            LEFT JOIN events e ON s.scenario_id = e.scenario_id
            GROUP BY s.id
        ");
        $scenarios = $stmt->fetchAll();
        sendJsonResponse(['status' => 'success', 'scenarios' => $scenarios]);
    }
} else {
    // Built-in fallback scenarios
    $fallbackScenarios = [
        [
            'id' => 1,
            'scenario_id' => 'SCN-APT29-GHOST',
            'name' => 'Operation GhostToken: Hybrid Enterprise Infiltration',
            'threat_actor' => 'APT29 / Cozy Bear Archetype',
            'description' => 'Multi-stage intrusion beginning with spearphishing, pivoting through active directory with Kerberoasting, lateral movement via remote WMI, and exfiltrating AWS S3 cloud data through compromised IAM tokens.',
            'target_environment' => 'Hybrid (Windows Domain + AWS Cloud)',
            'attack_vector' => 'Spearphishing Attachment -> In-Memory Execution',
            'impact' => 'Critical data exfiltration of customer PII and database snapshots from AWS S3',
            'total_events' => 10
        ],
        [
            'id' => 2,
            'scenario_id' => 'SCN-RANSOM-BLACKCAT',
            'name' => 'Double-Extortion Ransomware Campaign',
            'threat_actor' => 'ALPHV / BlackCat Archetype',
            'description' => 'External perimeter compromise via VPN credential stuffing, RDP lateral movement, shadow copy deletion, mass data staging to cloud mega storage, followed by enterprise-wide encryption.',
            'target_environment' => 'Enterprise On-Premise Network',
            'attack_vector' => 'VPN Credential Stuffing -> Admin RDP',
            'impact' => 'Operational disruption, critical shadow copies wiped, enterprise-wide file encryption',
            'total_events' => 7
        ],
        [
            'id' => 3,
            'scenario_id' => 'SCN-CLOUD-CRYPTOMINE',
            'name' => 'Cloud-Native IAM Hijack & Compute Hijacking',
            'threat_actor' => 'TeamTNT / Cloud Threat Group',
            'description' => 'Compromised developer access key leading to privilege escalation, defense evasion by tampering with CloudTrail, and spinning up high-cost GPU instances for Monero mining.',
            'target_environment' => 'AWS Cloud Infrastructure',
            'attack_vector' => 'Leaked Git Credentials -> IAM API Exploitation',
            'impact' => 'Mass cloud billing fraud ($45k/day GPU compute), potential infrastructure takeover',
            'total_events' => 5
        ]
    ];
    
    if ($scenarioId) {
        foreach ($fallbackScenarios as $s) {
            if ($s['scenario_id'] === $scenarioId) {
                sendJsonResponse(['status' => 'success_mock', 'scenario' => $s]);
            }
        }
    }
    
    sendJsonResponse(['status' => 'success_mock', 'scenarios' => $fallbackScenarios]);
}
