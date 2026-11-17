<?php
// =========================================================================
// Built-in PHP Development Server Router
// Usage: php -S localhost:8000 router.php
// =========================================================================

$uri = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);

// Allow CORS preflights
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type, Authorization, X-Requested-With");

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

// Serve existing static files directly
if ($uri !== '/' && file_exists(__DIR__ . $uri)) {
    return false;
}

// Map /api/events -> /api/events.php
if (preg_match('#^/api/([a-zA-Z0-9_-]+)$#', $uri, $matches)) {
    $targetScript = __DIR__ . '/api/' . $matches[1] . '.php';
    if (file_exists($targetScript)) {
        require $targetScript;
        exit;
    }
}

// Map /api/events.php directly
if (strpos($uri, '/api/') === 0 && file_exists(__DIR__ . $uri)) {
    require __DIR__ . $uri;
    exit;
}

// Root route
if ($uri === '/' || $uri === '') {
    header('Content-Type: application/json');
    echo json_encode([
        'platform' => 'AI-Assisted Cyber Threat Hunting Platform Backend (PHP + MySQL)',
        'version' => '1.0.0',
        'status' => 'operational',
        'endpoints' => [
            'GET /api/scenarios' => 'List attack scenarios and catalog',
            'GET /api/events' => 'Query multi-source telemetry events',
            'POST /api/events' => 'Ingest new security event (endpoint, auth, net, cloud)',
            'GET /api/correlate' => 'Correlate events across users, assets, time and kill chain',
            'GET /api/attack_path' => 'Attack graph topology nodes, edges, blast radius',
            'GET /api/mitre' => 'MITRE ATT&CK matrix heatmap and technique distribution',
            'GET/POST /api/ai_assist' => 'AI threat query suggestions, hypotheses, evidence links & limitations',
            'GET /api/report' => 'Forensic investigation timeline & executive incident report'
        ]
    ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    exit;
}

http_response_code(404);
echo json_encode(['error' => 'API endpoint not found', 'path' => $uri]);
