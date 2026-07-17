<?php
declare(strict_types=1);

require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/../lib/helpers.php';

corsAndSecurityHeaders();

if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
    jsonError('method_not_allowed', 405);
}

$pdo = getDbConnection();

try {
    $pdo->query('SELECT 1');
    $dbOk = true;
} catch (Throwable $e) {
    $dbOk = false;
}

jsonResponse([
    'status' => $dbOk ? 'ok' : 'degraded',
    'database' => $dbOk,
    'time' => date('c'),
]);
