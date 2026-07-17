<?php
declare(strict_types=1);

require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/../lib/helpers.php';

corsAndSecurityHeaders();
$pdo = getDbConnection();

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    jsonError('method_not_allowed', 405);
}

$machine = authenticateMachine($pdo);
if (!$machine) {
    jsonError('unauthorized', 401);
}
if (!checkRateLimit($pdo, 'events', 300, 60)) {
    jsonError('rate_limited', 429);
}

$body = readJsonBody(1048576); // jusqu'à 1 Mo pour un lot d'événements
$events = $body['events'] ?? null;
if (!is_array($events) || count($events) === 0) {
    jsonError('no_events', 422);
}
if (count($events) > 500) {
    jsonError('batch_too_large', 422);
}

$validTypes = ['created', 'modified', 'deleted', 'renamed'];
$validSeverities = ['info', 'warning', 'critical'];

$insertEvent = $pdo->prepare(
    'INSERT INTO file_events (machine_id, path, event_type, sha256, severity, occurred_at)
     VALUES (:mid, :path, :type, :sha, :sev, :occurred)'
);
$insertAlert = $pdo->prepare(
    'INSERT INTO alerts (machine_id, file_event_id, title, description, severity)
     VALUES (:mid, :eid, :title, :desc, :sev)'
);
$touchMachine = $pdo->prepare('UPDATE machines SET last_seen = NOW() WHERE id = :id');

$pdo->beginTransaction();
try {
    $inserted = 0;
    foreach ($events as $ev) {
        $path = mb_substr((string)($ev['path'] ?? ''), 0, 1024);
        $type = (string)($ev['event_type'] ?? '');
        $sha  = (string)($ev['sha256'] ?? '');
        $sev  = (string)($ev['severity'] ?? 'info');
        $ts   = (string)($ev['timestamp'] ?? '');

        if ($path === '' || !in_array($type, $validTypes, true)) {
            continue; // événement malformé, on ignore silencieusement
        }
        if ($sha !== '' && !preg_match('/^[a-f0-9]{64}$/i', $sha)) {
            $sha = '';
        }
        if (!in_array($sev, $validSeverities, true)) {
            $sev = 'info';
        }
        $occurredAt = ctype_digit($ts) ? date('Y-m-d H:i:s', (int)$ts) : date('Y-m-d H:i:s');

        $insertEvent->execute([
            'mid' => $machine['id'], 'path' => $path, 'type' => $type,
            'sha' => $sha ?: null, 'sev' => $sev, 'occurred' => $occurredAt,
        ]);
        $inserted++;

        if ($sev === 'critical') {
            $eventId = (int) $pdo->lastInsertId();
            $insertAlert->execute([
                'mid' => $machine['id'],
                'eid' => $eventId,
                'title' => 'Modification critique détectée',
                'desc'  => sprintf('%s sur %s', $type, $path),
                'sev'   => 'critical',
            ]);
        }
    }

    $touchMachine->execute(['id' => $machine['id']]);
    $pdo->commit();
} catch (Throwable $e) {
    $pdo->rollBack();
    error_log('[IronShield] events insert error: ' . $e->getMessage());
    jsonError('internal_error', 500);
}

jsonResponse(['received' => $inserted]);
