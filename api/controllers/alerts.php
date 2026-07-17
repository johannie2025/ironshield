<?php
declare(strict_types=1);

require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/../lib/helpers.php';

corsAndSecurityHeaders();
$pdo = getDbConnection();

if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
    jsonError('method_not_allowed', 405);
}

$machine = authenticateMachine($pdo);
if (!$machine) {
    jsonError('unauthorized', 401);
}
if (!checkRateLimit($pdo, 'alerts', 120, 60)) {
    jsonError('rate_limited', 429);
}

$limit = isset($_GET['limit']) ? max(1, min(200, (int)$_GET['limit'])) : 50;
$onlyUnack = isset($_GET['unacknowledged']) && $_GET['unacknowledged'] === '1';

$sql = 'SELECT id, title, description, severity, acknowledged, created_at
        FROM alerts WHERE machine_id = :mid';
if ($onlyUnack) {
    $sql .= ' AND acknowledged = 0';
}
$sql .= ' ORDER BY created_at DESC LIMIT :limit';

$stmt = $pdo->prepare($sql);
$stmt->bindValue('mid', $machine['id'], PDO::PARAM_INT);
$stmt->bindValue('limit', $limit, PDO::PARAM_INT);
$stmt->execute();

jsonResponse(['alerts' => $stmt->fetchAll()]);
