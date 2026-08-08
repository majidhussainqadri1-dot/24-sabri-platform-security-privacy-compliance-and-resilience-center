<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

use Sabri\Platform\Security\Registry\ModuleRegistry;

function c190(bool $condition, string $message): void { if (! $condition) { fwrite(STDERR, "FAIL: {$message}\n"); exit(1); } }

$registry = new ModuleRegistry();
$base = [
    'module_key' => 'cycle190',
    'name' => 'Cycle 190 manifest',
    'version' => '1.0.0',
    'owner' => 'File 24',
    'data_classes' => ['C1 Internal'],
    'public_routes' => [],
    'private_routes' => [],
];

$routes = [];
for ($i = 0; $i < 51; ++$i) $routes[] = '/cycle190/route-' . $i;
$routeOverflow = $registry->validate(array_merge($base, ['public_routes' => $routes]));
c190(is_wp_error($routeOverflow) && $routeOverflow->get_error_code() === 'spcrc_manifest_route_limit', 'A 51st route must reject the manifest rather than disappear through silent truncation.');

$classes = [];
for ($i = 0; $i < 21; ++$i) $classes[] = 'C1 domain-' . $i;
$listOverflow = $registry->validate(array_merge($base, ['data_classes' => $classes]));
c190(is_wp_error($listOverflow) && $listOverflow->get_error_code() === 'spcrc_manifest_list_limit', 'An over-limit data-class inventory must reject the manifest rather than silently omit declared security scope.');

$bounded = $registry->validate(array_merge($base, ['public_routes' => array_slice($routes, 0, 50), 'data_classes' => array_slice($classes, 0, 20)]));
c190(is_array($bounded) && count($bounded['public_routes'] ?? []) === 50 && count($bounded['data_classes'] ?? []) === 20, 'Maximum-size bounded manifest lists must remain valid without truncation.');

echo "PASS: cycle190 module-manifest silent truncation/completeness defect fixed and retested\n";
