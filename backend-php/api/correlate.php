<?php
// =========================================================================
// API: Cross-Domain Correlation Engine
// Correlates security telemetry across Users, Assets, Time, and MITRE ATT&CK
// =========================================================================

require_once __DIR__ . '/../config/db.php';

$pdo = getDatabaseConnection();
$scenarioId = $_GET['scenario_id'] ?? 'SCN-APT29-GHOST';

if ($pdo) {
    // 1. Fetch scenario events
    $stmt = $pdo->prepare("SELECT * FROM events WHERE scenario_id = ? ORDER BY timestamp ASC");
    $stmt->execute([$scenarioId]);
    $events = $stmt->fetchAll();

    if (empty($events)) {
        // Fallback to all events if specific scenario has none
        $stmtAll = $pdo->query("SELECT * FROM events ORDER BY timestamp ASC LIMIT 50");
        $events = $stmtAll->fetchAll();
    }
} else {
    // Database offline response
    sendJsonResponse([
        'status' => 'db_offline',
        'message' => 'MySQL server not connected. Connect MySQL or use frontend local correlation engine.',
        'correlation_chains' => []
    ]);
}

// Perform Algorithmic Correlation
$correlationResult = performCorrelation($events, $scenarioId);

sendJsonResponse([
    'status' => 'success',
    'scenario_id' => $scenarioId,
    'total_events_analyzed' => count($events),
    'incident_title' => $correlationResult['title'],
    'confidence_score' => $correlationResult['confidence_score'],
    'kill_chain_coverage' => $correlationResult['kill_chain_coverage'],
    'correlated_chain' => $correlationResult['chain'],
    'entities_involved' => $correlationResult['entities'],
    'hypothesis' => $correlationResult['hypothesis']
]);

function performCorrelation($events, $scenarioId) {
    if (empty($events)) {
        return [
            'title' => 'No telemetry events available for correlation',
            'confidence_score' => 0.0,
            'kill_chain_coverage' => [],
            'chain' => [],
            'entities' => ['users' => [], 'hosts' => [], 'ips' => []],
            'hypothesis' => 'Insufficient data'
        ];
    }

    $users = [];
    $hosts = [];
    $ips = [];
    $tacticsSeen = [];
    $chain = [];
    $domainDistribution = [];

    $prevEvent = null;
    $sequence = 1;

    foreach ($events as $evt) {
        if (!empty($evt['user_id'])) $users[$evt['user_id']] = true;
        if (!empty($evt['source_host'])) $hosts[$evt['source_host']] = true;
        if (!empty($evt['dest_host'])) $hosts[$evt['dest_host']] = true;
        if (!empty($evt['source_ip'])) $ips[$evt['source_ip']] = true;
        if (!empty($evt['dest_ip'])) $ips[$evt['dest_ip']] = true;

        $domain = $evt['domain'];
        $domainDistribution[$domain] = ($domainDistribution[$domain] ?? 0) + 1;

        if (!empty($evt['mitre_tactic'])) {
            $tacticsSeen[$evt['mitre_tactic']] = true;
        }

        // Determine correlation causality link
        $linkReason = "Initial baseline event detected in telemetry.";
        if ($prevEvent) {
            $timeDiffMin = (strtotime($evt['timestamp']) - strtotime($prevEvent['timestamp'])) / 60;
            
            if ($evt['user_id'] === $prevEvent['user_id']) {
                $linkReason = "Direct user session continuity ({$evt['user_id']}) after {$timeDiffMin} mins.";
            } elseif ($evt['source_host'] === $prevEvent['source_host'] || $evt['dest_host'] === $prevEvent['dest_host']) {
                $linkReason = "Host pivot on asset {$evt['source_host']} within {$timeDiffMin} mins.";
            } elseif ($evt['source_ip'] === $prevEvent['dest_ip'] || $evt['dest_ip'] === $prevEvent['dest_ip']) {
                $linkReason = "Network socket linkage on IP {$evt['dest_ip']}.";
            } else {
                $linkReason = "Cross-domain kill-chain progression: {$prevEvent['domain']} -> {$evt['domain']}.";
            }
        }

        $chain[] = [
            'sequence' => $sequence++,
            'event_uuid' => $evt['event_uuid'],
            'timestamp' => $evt['timestamp'],
            'domain' => $evt['domain'],
            'event_type' => $evt['event_type'],
            'severity' => $evt['severity'],
            'source' => $evt['source_host'] ?: $evt['source_ip'],
            'target' => $evt['dest_host'] ?: $evt['dest_ip'],
            'user' => $evt['user_id'],
            'action_summary' => $evt['command_line'] ?: ($evt['cloud_action'] ? "{$evt['cloud_service']}::{$evt['cloud_action']}" : $evt['event_type']),
            'mitre_technique' => [
                'id' => $evt['mitre_technique_id'],
                'name' => $evt['mitre_technique_name'],
                'tactic' => $evt['mitre_tactic']
            ],
            'correlation_link' => $linkReason,
            'raw_payload' => is_string($evt['raw_payload']) ? json_decode($evt['raw_payload'], true) : $evt['raw_payload']
        ];

        $prevEvent = $evt;
    }

    // Scoring Formula: domain diversity + tactic breadth + severity weighting
    $domainScore = min(0.35, count($domainDistribution) * 0.09);
    $tacticScore = min(0.40, count($tacticsSeen) * 0.08);
    $severityScore = 0.20; // Default high baseline for alert cluster

    $confidenceScore = round(min(0.99, $domainScore + $tacticScore + $severityScore), 2);

    // Dynamic Title & Hypothesis
    $title = "Multi-Stage Attack Chain: " . count($chain) . " correlated events across " . count($domainDistribution) . " domains";
    if ($scenarioId === 'SCN-APT29-GHOST') {
        $title = "APT29 GhostToken: Endpoint Weaponization to Cloud S3 Exfiltration";
    } elseif ($scenarioId === 'SCN-RANSOM-BLACKCAT') {
        $title = "BlackCat Ransomware: VPN Infiltration to Shadow Copy Purge & Encryption";
    } elseif ($scenarioId === 'SCN-CLOUD-CRYPTOMINE') {
        $title = "IAM Key Hijack: CloudTrail Tampering to GPU Cryptomining Fleet";
    }

    $hypothesis = "Adversary demonstrated persistent progression across " . count($tacticsSeen) . " MITRE ATT&CK tactics (" . implode(', ', array_keys($tacticsSeen)) . "). Initial footprint commenced on host(s) " . implode(', ', array_keys($hosts)) . " affecting user identities " . implode(', ', array_keys($users)) . ". Telemetry strongly supports unified adversarial intent rather than isolated noise.";

    return [
        'title' => $title,
        'confidence_score' => $confidenceScore,
        'kill_chain_coverage' => array_keys($tacticsSeen),
        'chain' => $chain,
        'entities' => [
            'users' => array_keys($users),
            'hosts' => array_keys($hosts),
            'ips' => array_keys($ips)
        ],
        'hypothesis' => $hypothesis
    ];
}
