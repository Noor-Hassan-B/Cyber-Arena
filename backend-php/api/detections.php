<?php
// =========================================================================
// API: Detection Engineering Studio (Sigma / SPL / KQL)
// Supports Rule Listing and Hot Rule Deployment
// =========================================================================

require_once __DIR__ . '/../config/db.php';

$pdo = getDatabaseConnection();
$method = $_SERVER['REQUEST_METHOD'];

$defaultRules = [
    [
        'id' => 'RULE-SIGMA-001',
        'title' => 'Suspicious PowerShell Encoded Command Execution',
        'format' => 'sigma',
        'mitre_technique' => 'T1059.001',
        'severity' => 'high',
        'analyst' => 'hunter@soc',
        'status' => 'active',
        'created_at' => date('Y-m-d H:i:s', time() - 86400),
        'rule_content' => "title: Suspicious PowerShell Encoded Command\nid: 7f8a1290-b1c2-40a1-9876-123456789abc\nstatus: production\nlogsource:\n  category: process_creation\n  product: windows\ndetection:\n  selection:\n    Image|endswith: '\\powershell.exe'\n    CommandLine|contains:\n      - '-enc '\n      - '-EncodedCommand'\n      - 'bypass'\n  condition: selection\nlevel: high"
    ],
    [
        'id' => 'RULE-SPL-002',
        'title' => 'LSASS Memory Dumping via Comsvcs MiniDump',
        'format' => 'spl',
        'mitre_technique' => 'T1003.001',
        'severity' => 'critical',
        'analyst' => 'lead_analyst@soc',
        'status' => 'active',
        'created_at' => date('Y-m-d H:i:s', time() - 3600),
        'rule_content' => "index=sysmon EventCode=1 Image=\"*rundll32.exe*\" CommandLine=\"*comsvcs.dll*#24*\" OR CommandLine=\"*MiniDump*\"\n| eval target=\"LSASS Memory Space\"\n| stats count min(_time) as first_seen max(_time) as last_seen by host, user, CommandLine\n| where count > 0"
    ],
    [
        'id' => 'RULE-KQL-003',
        'title' => 'Lateral Movement - Remote Service Execution (PsExec / WMI)',
        'format' => 'kql',
        'mitre_technique' => 'T1021.002',
        'severity' => 'high',
        'analyst' => 'analyst@soc',
        'status' => 'active',
        'created_at' => date('Y-m-d H:i:s'),
        'rule_content' => "DeviceProcessEvents\n| where FileName in~ (\"psexec.exe\", \"psexesvc.exe\", \"wmic.exe\")\n| where ProcessCommandLine has_any (\"/node:\", \"process call create\", \"-accepteula\")\n| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName"
    ]
];

if ($method === 'POST') {
    $rawInput = file_get_contents('php://input');
    $payload = json_decode($rawInput, true);

    if (!$payload) {
        sendJsonResponse(['error' => 'Invalid JSON'], 400);
    }

    $rule = [
        'id' => 'RULE-' . strtoupper(substr(md5(uniqid(rand(), true)), 0, 8)),
        'title' => $payload['title'] ?? 'Custom Detection Rule',
        'format' => $payload['format'] ?? 'sigma',
        'mitre_technique' => $payload['mitre_technique'] ?? 'T1059.001',
        'severity' => $payload['severity'] ?? 'high',
        'analyst' => $payload['analyst'] ?? 'analyst@soc',
        'status' => 'active',
        'created_at' => date('Y-m-d H:i:s'),
        'rule_content' => $payload['rule_content'] ?? ''
    ];

    sendJsonResponse([
        'status' => 'success',
        'message' => 'Detection rule deployed successfully',
        'rule' => $rule,
        'detection' => $rule
    ], 201);
}

// GET
sendJsonResponse([
    'status' => 'success',
    'count' => count($defaultRules),
    'rules' => $defaultRules,
    'detections' => $defaultRules
]);
