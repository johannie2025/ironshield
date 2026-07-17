<?php
declare(strict_types=1);

function jsonResponse(array $data, int $status = 200): void
{
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($data, JSON_UNESCAPED_UNICODE);
    exit;
}

function jsonError(string $message, int $status = 400): void
{
    jsonResponse(['error' => $message], $status);
}

/** Lit et décode le body JSON de la requête, avec limite de taille. */
function readJsonBody(int $maxBytes = 262144): array
{
    $raw = file_get_contents('php://input', false, null, 0, $maxBytes + 1);
    if ($raw === false || strlen($raw) > $maxBytes) {
        jsonError('payload_too_large', 413);
    }
    $data = json_decode($raw, true);
    if (!is_array($data)) {
        jsonError('invalid_json', 400);
    }
    return $data;
}

/** Génère un token opaque aléatoire cryptographiquement sûr. */
function generateToken(int $bytes = 32): string
{
    return bin2hex(random_bytes($bytes));
}

/** Génère une clé de licence lisible: XXXXX-XXXXX-XXXXX-XXXXX-XXXXX */
function generateLicenseKey(): string
{
    $alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // sans caractères ambigus
    $groups = [];
    for ($g = 0; $g < 5; $g++) {
        $chunk = '';
        for ($i = 0; $i < 5; $i++) {
            $chunk .= $alphabet[random_int(0, strlen($alphabet) - 1)];
        }
        $groups[] = $chunk;
    }
    return implode('-', $groups);
}

/**
 * Rate limiting par compteur agrégé (bucket par minute), pas un INSERT par
 * requête : la version précédente écrivait une ligne par appel API, ce qui
 * devient un goulot d'étranglement dès quelques centaines de machines
 * actives. Un compteur UPSERT par (ip, endpoint, minute) scale largement
 * mieux et donne une précision suffisante pour du rate limiting.
 */
function checkRateLimit(PDO $pdo, string $endpoint, int $maxRequests = 60, int $windowSeconds = 60): bool
{
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    $bucket = intdiv(time(), max(1, $windowSeconds));

    $stmt = $pdo->prepare(
        'INSERT INTO api_rate_buckets (ip_address, endpoint, bucket, request_count)
         VALUES (:ip, :endpoint, :bucket, 1)
         ON DUPLICATE KEY UPDATE request_count = request_count + 1'
    );
    $stmt->execute(['ip' => $ip, 'endpoint' => $endpoint, 'bucket' => $bucket]);

    $check = $pdo->prepare(
        'SELECT request_count FROM api_rate_buckets WHERE ip_address = :ip AND endpoint = :endpoint AND bucket = :bucket'
    );
    $check->execute(['ip' => $ip, 'endpoint' => $endpoint, 'bucket' => $bucket]);
    $count = (int) $check->fetchColumn();

    return $count <= $maxRequests;
}

/** Authentifie une machine via son token Bearer et retourne sa ligne, ou null. */
function authenticateMachine(PDO $pdo): ?array
{
    $header = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
    if (!preg_match('/^Bearer\s+([a-f0-9]{64})$/i', $header, $m)) {
        return null;
    }
    $token = $m[1];

    $stmt = $pdo->prepare(
        "SELECT m.*, l.status AS license_status, l.expires_at
         FROM machines m
         JOIN licenses l ON l.id = m.license_id
         WHERE m.activation_token = :token AND m.status = 'active'
         LIMIT 1"
    );
    $stmt->execute(['token' => $token]);
    $machine = $stmt->fetch();

    if (!$machine) {
        return null;
    }
    if ($machine['license_status'] !== 'active') {
        return null;
    }
    if ($machine['expires_at'] !== null && strtotime($machine['expires_at']) < time()) {
        return null;
    }

    return $machine;
}

function corsAndSecurityHeaders(): void
{
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: DENY');
    header('Referrer-Policy: no-referrer');
    // CORS restreint : adapter l'origine au domaine du dashboard en production
    header('Access-Control-Allow-Origin: *');
    header('Access-Control-Allow-Methods: POST, GET, OPTIONS');
    header('Access-Control-Allow-Headers: Content-Type, Authorization');

    if (($_SERVER['REQUEST_METHOD'] ?? '') === 'OPTIONS') {
        http_response_code(204);
        exit;
    }
}
