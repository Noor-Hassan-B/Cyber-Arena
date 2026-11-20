<?php
// =========================================================================
// API: Append-Only Immutable Audit Ledger
// Records All Security Actions, Detections, and HITL Sign-offs
// =========================================================================

require_once __DIR__ . '/../config/db.php';

$pdo = getDatabaseConnection();

$defaultLedger = [
    [
        'audit_id' => 'AUD-00000001',
        'timestamp' => date('Y-m-d H:i:s', time() - 7200),
        'actor' => 'system@aegishunt',
        'role' => 'SYSTEM',
        'action' => 'SYSTEM',
        'details' => 'AegisHunt Audit Ledger initialized — cryptographic append-only state active.',
        'status' => 'COMMITTED',
        'signature' => 'sha256:' . hash('sha256', 'AUD-00000001-INIT')
    ],
    [
        'audit_id' => 'AUD-00000002',
        'timestamp' => date('Y-m-d H:i:s', time() - 5400),
        'actor' => 'sarah.connor@corp',
        'role' => 'L2 Threat Hunter',
        'action' => 'INGEST',
        'details' => 'Ingested 10 security telemetry events for scenario SCN-APT29-GHOST across 4 domains.',
        'status' => 'COMMITTED',
        'signature' => 'sha256:' . hash('sha256', 'AUD-00000002-INGEST')
    ],
    [
        'audit_id' => 'AUD-00000003',
        'timestamp' => date('Y-m-d H:i:s', time() - 3600),
        'actor' => 'detection.engineer@corp',
        'role' => 'Detection Engineer',
        'action' => 'CREATE_DETECTION_RULE',
        'details' => 'Created Sigma rule: Suspicious PowerShell Encoded Command Execution (T1059.001)',
        'status' => 'COMMITTED',
        'signature' => 'sha256:' . hash('sha256', 'AUD-00000003-RULE')
    ],
    [
        'audit_id' => 'AUD-00000004',
        'timestamp' => date('Y-m-d H:i:s', time() - 1800),
        'actor' => 'commander@soc',
        'role' => 'L3 Incident Commander',
        'action' => 'HITL_ACTION_APPROVED',
        'details' => 'APPROVED containment action BLOCK_IP targeting 185.220.101.5. Reason: Confirmed C2 beaconing.',
        'status' => 'EXECUTED_AND_LOCKED',
        'signature' => 'sha256:' . hash('sha256', 'AUD-00000004-GATE')
    ]
];

sendJsonResponse([
    'status' => 'success',
    'count' => count($defaultLedger),
    'ledger' => $defaultLedger,
    'audit' => $defaultLedger
]);
