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
if (!checkRateLimit($pdo, 'config', 30, 60)) {
    jsonError('rate_limited', 429);
}

$stmt = $pdo->prepare(
    'SELECT entry_type, value FROM whitelist_entries WHERE license_id = :lid'
);
$stmt->execute(['lid' => $machine['license_id']]);
$rows = $stmt->fetchAll();

$allowlist = ['paths' => [], 'process_names' => [], 'hashes' => []];
foreach ($rows as $row) {
    match ($row['entry_type']) {
        'path' => $allowlist['paths'][] = $row['value'],
        'process_name' => $allowlist['process_names'][] = $row['value'],
        'hash' => $allowlist['hashes'][] = $row['value'],
        default => null,
    };
}

// Le mode de réponse par défaut reste AlertOnly tant qu'un admin ne l'a
// pas explicitement relevé pour cette licence (voir colonne à ajouter si
// besoin d'un pilotage par client ; MVP: configurable uniquement en local
// pour l'instant, ce endpoint sert avant tout à distribuer la whitelist).
jsonResponse([
    'allowlist' => $allowlist,
    'updated_at' => date('c'),
]);
