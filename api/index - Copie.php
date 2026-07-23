<?php
declare(strict_types=1);

// Point d'entrée unique de l'API IronShield FIM
// Route selon PATH_INFO: /api/activate, /api/events, /api/alerts

$path = $_SERVER['PATH_INFO'] ?? parse_url($_SERVER['REQUEST_URI'] ?? '', PHP_URL_PATH);
$path = trim((string)$path, '/');
$segments = explode('/', $path);
$route = $segments[0] ?? '';

$routes = [
    'activate' => __DIR__ . '/controllers/activate.php',
    'events'   => __DIR__ . '/controllers/events.php',
    'alerts'   => __DIR__ . '/controllers/alerts.php',
    'health'   => __DIR__ . '/controllers/health.php',
    'config'   => __DIR__ . '/controllers/config.php',
];

if (isset($routes[$route])) {
    require $routes[$route];
} else {
    http_response_code(404);
    header('Content-Type: application/json');
    echo json_encode(['error' => 'not_found']);
}
