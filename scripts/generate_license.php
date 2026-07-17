#!/usr/bin/env php
<?php
declare(strict_types=1);

/**
 * CLI de génération de licences IronShield FIM.
 *
 * Usage:
 *   php scripts/generate_license.php --client="Nom Client" --email=contact@exemple.com \
 *       --tier=pro --machines=5 --days=365
 *
 * Variables d'environnement requises (mêmes que l'API): DB_HOST, DB_NAME, DB_USER, DB_PASS
 */

// Volontairement hors du webroot (api/) : ce script ne doit jamais être
// accessible via HTTP, uniquement en CLI (SSH sur alwaysdata).
if (PHP_SAPI !== 'cli') {
    fwrite(STDERR, "Ce script ne peut être exécuté qu'en CLI.\n");
    exit(1);
}

require_once __DIR__ . '/../api/config/database.php';
require_once __DIR__ . '/../api/lib/helpers.php';

function argValue(array $args, string $name, ?string $default = null): ?string
{
    foreach ($args as $arg) {
        if (str_starts_with($arg, "--{$name}=")) {
            return substr($arg, strlen("--{$name}="));
        }
    }
    return $default;
}

$args = array_slice($argv, 1);

$clientName = argValue($args, 'client');
$email      = argValue($args, 'email');
$tier       = argValue($args, 'tier', 'trial');
$machines   = (int) argValue($args, 'machines', '1');
$days       = (int) argValue($args, 'days', '30');

if (!$clientName || !$email) {
    fwrite(STDERR, "Usage: --client=\"Nom\" --email=... [--tier=trial|standard|pro|enterprise] [--machines=N] [--days=N]\n");
    exit(1);
}
if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    fwrite(STDERR, "Email invalide: {$email}\n");
    exit(1);
}
if (!in_array($tier, ['trial', 'standard', 'pro', 'enterprise'], true)) {
    fwrite(STDERR, "Tier invalide: {$tier}\n");
    exit(1);
}

$pdo = getDbConnection();

$pdo->beginTransaction();
try {
    // Réutilise le client s'il existe déjà (par email), sinon le crée.
    $stmt = $pdo->prepare('SELECT id FROM clients WHERE email = :email LIMIT 1');
    $stmt->execute(['email' => $email]);
    $clientId = $stmt->fetchColumn();

    if (!$clientId) {
        $pdo->prepare('INSERT INTO clients (nom, email) VALUES (:nom, :email)')
            ->execute(['nom' => $clientName, 'email' => $email]);
        $clientId = (int) $pdo->lastInsertId();
    }

    // Génère une clé unique (retry en cas de collision très improbable).
    do {
        $licenseKey = generateLicenseKey();
        $check = $pdo->prepare('SELECT COUNT(*) FROM licenses WHERE license_key = :key');
        $check->execute(['key' => $licenseKey]);
    } while ((int) $check->fetchColumn() > 0);

    $expiresAt = $days > 0
        ? (new DateTime())->modify("+{$days} days")->format('Y-m-d H:i:s')
        : null;

    $pdo->prepare(
        'INSERT INTO licenses (client_id, license_key, max_machines, tier, expires_at)
         VALUES (:client_id, :key, :machines, :tier, :expires_at)'
    )->execute([
        'client_id'  => $clientId,
        'key'        => $licenseKey,
        'machines'   => $machines,
        'tier'       => $tier,
        'expires_at' => $expiresAt,
    ]);

    $pdo->commit();
} catch (Throwable $e) {
    $pdo->rollBack();
    fwrite(STDERR, 'Erreur: ' . $e->getMessage() . "\n");
    exit(1);
}

echo "Licence créée avec succès\n";
echo "  Client    : {$clientName} <{$email}>\n";
echo "  Clé       : {$licenseKey}\n";
echo "  Tier      : {$tier}\n";
echo "  Machines  : {$machines}\n";
echo "  Expire le : " . ($expiresAt ?? 'jamais') . "\n";
