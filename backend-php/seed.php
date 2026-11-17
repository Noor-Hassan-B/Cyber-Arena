<?php
// =========================================================================
// Database Seeder Script
// Executes schema.sql and seed_data.sql into MySQL
// Usage: php seed.php  (or open http://localhost:8000/seed.php in browser)
// =========================================================================

require_once __DIR__ . '/config/db.php';

echo "=== Cyber Threat Hunting Platform Database Setup ===\n";

$dbHost = getenv('DB_HOST') ?: '127.0.0.1';
$dbPort = getenv('DB_PORT') ?: '3306';
$dbName = getenv('DB_NAME') ?: 'threat_hunter';
$dbUser = getenv('DB_USER') ?: 'root';
$dbPass = getenv('DB_PASS') ?: '';

try {
    // 1. Connect without db name first to create database if not exists
    $dsnNoDb = "mysql:host={$dbHost};port={$dbPort};charset=utf8mb4";
    $pdoInit = new PDO($dsnNoDb, $dbUser, $dbPass, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
    $pdoInit->exec("CREATE DATABASE IF NOT EXISTS `{$dbName}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;");
    echo "[✓] Database '{$dbName}' verified or created.\n";

    // 2. Connect to database
    $pdo = new PDO("mysql:host={$dbHost};port={$dbPort};dbname={$dbName};charset=utf8mb4", $dbUser, $dbPass, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION
    ]);

    // 3. Run schema.sql
    $schemaFile = __DIR__ . '/sql/schema.sql';
    if (file_exists($schemaFile)) {
        $schemaSql = file_get_contents($schemaFile);
        $pdo->exec($schemaSql);
        echo "[✓] Schema tables successfully created.\n";
    } else {
        echo "[!] schema.sql not found at {$schemaFile}\n";
    }

    // 4. Run seed_data.sql
    $seedFile = __DIR__ . '/sql/seed_data.sql';
    if (file_exists($seedFile)) {
        $seedSql = file_get_contents($seedFile);
        $pdo->exec($seedSql);
        echo "[✓] Synthetic attack scenarios and multi-source telemetry seeded.\n";
    } else {
        echo "[!] seed_data.sql not found at {$seedFile}\n";
    }

    // 5. Verification count
    $stmt = $pdo->query("SELECT COUNT(*) FROM events");
    $eventCount = $stmt->fetchColumn();

    $stmt2 = $pdo->query("SELECT COUNT(*) FROM attack_scenarios");
    $scenarioCount = $stmt2->fetchColumn();

    echo "====================================================\n";
    echo "SUCCESS: Database populated with {$scenarioCount} scenarios and {$eventCount} security events.\n";
    echo "The Threat Hunting Platform is ready for action!\n";

} catch (PDOException $e) {
    echo "[-] Database Error: " . $e->getMessage() . "\n";
    echo "Please ensure MySQL is running on {$dbHost}:{$dbPort} with user '{$dbUser}'.\n";
}
