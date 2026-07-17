#!/usr/bin/env php
<?php
declare(strict_types=1);

if (PHP_SAPI !== 'cli') {
    fwrite(STDERR, "Ce script ne peut être exécuté qu'en CLI.\n");
    exit(1);
}

require_once __DIR__ . '/../api/config/database.php';

/**
 * Ajoute une entrée à la liste blanche d'un client, pour traiter un faux
 * positif signalé sans avoir à modifier chaque poste manuellement.
 *
 * Usage:
 *   php scripts/whitelist_add.php --license=ABCDE-FGHJK-LMNPQ-RSTUV-WXY23 \
 *       --type=path --value="C:\MonERP\app.exe" --reason="ERP maison, faux positif YARA" --by="support-wise"
 */

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
$licenseKey = argValue($args, 'license');
$type = argValue($args, 'type');
$value = argValue($args, 'value');
$reason = argValue($args, 'reason', '');
$by = argValue($args, 'by', 'cli');

if (!$licenseKey || !$type || !$value) {
    fwrite(STDERR, "Usage: --license=XXXXX-... --type=path|process_name|hash --value=... [--reason=...] [--by=...]\n");
    exit(1);
}
if (!in_array($type, ['path', 'process_name', 'hash'], true)) {
    fwrite(STDERR, "Type invalide: {$type}\n");
    exit(1);
}

$pdo = getDbConnection();

$stmt = $pdo->prepare('SELECT id FROM licenses WHERE license_key = :key LIMIT 1');
$stmt->execute(['key' => $licenseKey]);
$licenseId = $stmt->fetchColumn();

if (!$licenseId) {
    fwrite(STDERR, "Licence introuvable: {$licenseKey}\n");
    exit(1);
}

$pdo->prepare(
    'INSERT INTO whitelist_entries (license_id, entry_type, value, reason, created_by)
     VALUES (:lid, :type, :value, :reason, :by)'
)->execute([
    'lid' => $licenseId, 'type' => $type, 'value' => $value, 'reason' => $reason, 'by' => $by,
]);

echo "Entrée ajoutée à la liste blanche du client (licence {$licenseKey}).\n";
echo "  Type   : {$type}\n";
echo "  Valeur : {$value}\n";
echo "Les postes de ce client la récupéreront à leur prochaine synchronisation (GET /api/config).\n";
