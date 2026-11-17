<?php
// =========================================================================
// API: Events Ingestion & Telemetry Retrieval
// Supports Endpoint, Authentication, Network, and Cloud Security Events
// =========================================================================

require_once __DIR__ . '/../config/db.php';

$pdo = getDatabaseConnection();
$method = $_SERVER['REQUEST_METHOD'];

// Handle POST: Ingest new event
if ($method === 'POST') {
    $rawInput = file_get_contents('php://input');
    $payload = json_decode($rawInput, true);

    if (!$payload) {
        sendJsonResponse(['error' => 'Invalid JSON payload provided'], 400);
    }

    if (empty($payload['domain']) || empty($payload['event_type'])) {
        sendJsonResponse(['error' => 'Missing mandatory fields: domain and event_type'], 422);
    }

    $eventUuid = $payload['event_uuid'] ?? ('EVT-ING-' . strtoupper(bin2hex(random_bytes(4))));
    $scenarioId = $payload['scenario_id'] ?? 'SCN-CUSTOM-INGEST';
    $timestamp = $payload['timestamp'] ?? date('Y-m-d H:i:s');
    $domain = strtolower($payload['domain']);
    $eventType = $payload['event_type'];
    $severity = strtolower($payload['severity'] ?? 'low');
    $sourceHost = $payload['source_host'] ?? null;
    $destHost = $payload['dest_host'] ?? null;
    $sourceIp = $payload['source_ip'] ?? null;
    $destIp = $payload['dest_ip'] ?? null;
    $userId = $payload['user_id'] ?? null;
    $processName = $payload['process_name'] ?? null;
    $commandLine = $payload['command_line'] ?? null;
    $parentProcess = $payload['parent_process'] ?? null;
    $cloudService = $payload['cloud_service'] ?? null;
    $cloudAction = $payload['cloud_action'] ?? null;
    $mitreTactic = $payload['mitre_tactic'] ?? null;
    $mitreTechniqueId = $payload['mitre_technique_id'] ?? null;
    $mitreTechniqueName = $payload['mitre_technique_name'] ?? null;
    $rawPayloadJson = isset($payload['raw_payload']) ? json_encode($payload['raw_payload']) : null;

    if ($pdo) {
        $stmt = $pdo->prepare("
            INSERT INTO events (
                event_uuid, scenario_id, timestamp, domain, event_type, severity,
                source_host, dest_host, source_ip, dest_ip, user_id,
                process_name, command_line, parent_process, cloud_service, cloud_action,
                mitre_tactic, mitre_technique_id, mitre_technique_name, raw_payload
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ");
        
        $stmt->execute([
            $eventUuid, $scenarioId, $timestamp, $domain, $eventType, $severity,
            $sourceHost, $destHost, $sourceIp, $destIp, $userId,
            $processName, $commandLine, $parentProcess, $cloudService, $cloudAction,
            $mitreTactic, $mitreTechniqueId, $mitreTechniqueName, $rawPayloadJson
        ]);

        sendJsonResponse([
            'status' => 'success',
            'message' => 'Security event ingested and indexed successfully',
            'event_uuid' => $eventUuid,
            'indexed_at' => date('Y-m-d H:i:s')
        ], 201);
    } else {
        // Database not reachable, return simulated success for decoupling
        sendJsonResponse([
            'status' => 'success_mock',
            'message' => 'Simulated event ingestion (MySQL offline). Connect MySQL for persistent storage.',
            'event_uuid' => $eventUuid,
            'indexed_at' => date('Y-m-d H:i:s')
        ], 201);
    }
}

// Handle GET: Retrieve and query events
$scenarioId = $_GET['scenario_id'] ?? null;
$domain = $_GET['domain'] ?? null;
$severity = $_GET['severity'] ?? null;
$search = $_GET['search'] ?? null;
$limit = min(intval($_GET['limit'] ?? 100), 500);
$offset = intval($_GET['offset'] ?? 0);

if ($pdo) {
    $where = [];
    $params = [];

    if ($scenarioId && $scenarioId !== 'ALL') {
        $where[] = "scenario_id = ?";
        $params[] = $scenarioId;
    }
    if ($domain && $domain !== 'ALL') {
        $where[] = "domain = ?";
        $params[] = $domain;
    }
    if ($severity && $severity !== 'ALL') {
        $where[] = "severity = ?";
        $params[] = $severity;
    }
    if ($search) {
        $where[] = "(event_uuid LIKE ? OR source_host LIKE ? OR dest_host LIKE ? OR user_id LIKE ? OR command_line LIKE ? OR process_name LIKE ? OR mitre_technique_id LIKE ?)";
        $searchTerm = "%{$search}%";
        for ($i = 0; $i < 7; $i++) {
            $params[] = $searchTerm;
        }
    }

    $whereSql = count($where) > 0 ? "WHERE " . implode(" AND ", $where) : "";
    $query = "SELECT * FROM events {$whereSql} ORDER BY timestamp ASC LIMIT {$limit} OFFSET {$offset}";

    $stmt = $pdo->prepare($query);
    $stmt->execute($params);
    $events = $stmt->fetchAll();

    // Decode JSON raw payload for clean client consumption
    foreach ($events as &$evt) {
        if (!empty($evt['raw_payload'])) {
            $evt['raw_payload'] = json_decode($evt['raw_payload'], true);
        }
    }

    sendJsonResponse([
        'status' => 'success',
        'count' => count($events),
        'events' => $events
    ]);
} else {
    // Return structured notification if DB is not active
    sendJsonResponse([
        'status' => 'db_offline',
        'message' => 'MySQL server not connected. Please verify credentials in backend-php/config/db.php and run sql/schema.sql and sql/seed_data.sql.',
        'events' => []
    ], 200);
}
