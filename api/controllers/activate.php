<?php
declare(strict_types=1);

require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/../lib/helpers.php';

corsAndSecurityHeaders();
$pdo = getDbConnection();

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    jsonError('method_not_allowed', 405);
}
if (!checkRateLimit($pdo, 'activate', 20, 60)) {
    jsonError('rate_limited', 429);
}

$body = readJsonBody();
$licenseKey = trim((string)($body['license_key'] ?? ''));
$hardwareId = trim((string)($body['hardware_id'] ?? ''));
$hostname   = trim((string)($body['hostname'] ?? ''));
$osVersion  = trim((string)($body['os_version'] ?? ''));
$agentVer   = trim((string)($body['agent_version'] ?? ''));

if (!preg_match('/^[A-Z0-9]{5}(-[A-Z0-9]{5}){4}$/', $licenseKey)) {
    jsonError('invalid_license_format', 422);
}
if (!preg_match('/^[a-f0-9]{64}$/i', $hardwareId)) {
    jsonError('invalid_hardware_id', 422);
}

$stmt = $pdo->prepare(
    "SELECT * FROM licenses WHERE license_key = :key LIMIT 1"
);
$stmt->execute(['key' => $licenseKey]);
$license = $stmt->fetch();

if (!$license) {
    jsonError('license_not_found', 404);
}
if ($license['status'] !== 'active') {
    jsonError('license_' . $license['status'], 403);
}
if ($license['expires_at'] !== null && strtotime($license['expires_at']) < time()) {
    $pdo->prepare("UPDATE licenses SET status = 'expired' WHERE id = :id")
        ->execute(['id' => $license['id']]);
    jsonError('license_expired', 403);
}

$pdo->beginTransaction();
try {
    // Cette machine est-elle déjà activée sur cette licence ?
    $stmt = $pdo->prepare(
        'SELECT * FROM machines WHERE license_id = :lid AND hardware_id = :hw LIMIT 1'
    );
    $stmt->execute(['lid' => $license['id'], 'hw' => $hardwareId]);
    $machine = $stmt->fetch();

    if ($machine) {
        $pdo->prepare(
            'UPDATE machines SET last_seen = NOW(), hostname = :h, os_version = :o, agent_version = :a
             WHERE id = :id'
        )->execute([
            'h' => $hostname, 'o' => $osVersion, 'a' => $agentVer, 'id' => $machine['id'],
        ]);
        $token = $machine['activation_token'];
    } else {
        // Vérifier le quota de machines actives
        $stmt = $pdo->prepare(
            "SELECT COUNT(*) FROM machines WHERE license_id = :lid AND status = 'active'"
        );
        $stmt->execute(['lid' => $license['id']]);
        $activeCount = (int) $stmt->fetchColumn();

        if ($activeCount >= $license['max_machines']) {
            $pdo->rollBack();
            jsonError('machine_quota_exceeded', 403);
        }

        $token = generateToken();
        $pdo->prepare(
            'INSERT INTO machines (license_id, hardware_id, hostname, os_version, agent_version, activation_token)
             VALUES (:lid, :hw, :h, :o, :a, :token)'
        )->execute([
            'lid' => $license['id'], 'hw' => $hardwareId, 'h' => $hostname,
            'o' => $osVersion, 'a' => $agentVer, 'token' => $token,
        ]);
    }

    $pdo->commit();
} catch (Throwable $e) {
    $pdo->rollBack();
    error_log('[IronShield] activation error: ' . $e->getMessage());
    jsonError('internal_error', 500);
}

jsonResponse([
    'valid'      => true,
    'token'      => $token,
    'tier'       => $license['tier'],
    'expires_at' => $license['expires_at'],
]);
