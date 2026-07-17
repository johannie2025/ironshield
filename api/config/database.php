<?php
declare(strict_types=1);

/**
 * Connexion PDO MySQL.
 * Les identifiants viennent de variables d'environnement (jamais en dur).
 * Sur alwaysdata : configurer via le panneau "Variables d'environnement"
 * ou un fichier .env chargé en dehors du webroot.
 */

function getDbConnection(): PDO
{
    static $pdo = null;
    if ($pdo !== null) {
        return $pdo;
    }

    $host = getenv('DB_HOST') ?: 'mysql-wise.alwaysdata.net';
    $name = getenv('DB_NAME') ?: 'wise_ironshield';
    $user = getenv('DB_USER') ?: '';
    $pass = getenv('DB_PASS') ?: '';

    $dsn = "mysql:host={$host};dbname={$name};charset=utf8mb4";

    try {
        $pdo = new PDO($dsn, $user, $pass, [
            PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES   => false,
        ]);
    } catch (PDOException $e) {
        error_log('[IronShield] DB connection failed: ' . $e->getMessage());
        http_response_code(500);
        echo json_encode(['error' => 'internal_error']);
        exit;
    }

    return $pdo;
}
