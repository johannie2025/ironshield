#!/usr/bin/env php
<?php
declare(strict_types=1);

require_once __DIR__ . '/../api/lib/helpers.php';

$failures = 0;

function assertTrue(bool $cond, string $desc): void
{
    global $failures;
    if ($cond) {
        echo "  ✓ {$desc}\n";
    } else {
        echo "  ✗ {$desc}\n";
        $failures++;
    }
}

echo "== generateLicenseKey() ==\n";
$key = generateLicenseKey();
assertTrue((bool) preg_match('/^[A-Z0-9]{5}(-[A-Z0-9]{5}){4}$/', $key), "format XXXXX-XXXXX-XXXXX-XXXXX-XXXXX ({$key})");

$keys = array_map(fn() => generateLicenseKey(), range(1, 200));
assertTrue(count(array_unique($keys)) === count($keys), "200 clés générées sont toutes uniques");

echo "\n== generateToken() ==\n";
$token = generateToken();
assertTrue((bool) preg_match('/^[a-f0-9]{64}$/', $token), "token 64 caractères hex ({$token})");

echo "\n== Résultat ==\n";
if ($failures === 0) {
    echo "Tous les tests unitaires sont passés.\n";
    exit(0);
}
echo "{$failures} test(s) en échec.\n";
exit(1);
