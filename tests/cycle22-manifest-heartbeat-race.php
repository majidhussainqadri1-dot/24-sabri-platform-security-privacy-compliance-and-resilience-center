<?php

declare(strict_types=1);

require __DIR__ . '/bootstrap.php';
require_once __DIR__ . '/../plugin/sabri-security-center/src/Support/Sanitizer.php';
require_once __DIR__ . '/../plugin/sabri-security-center/src/Capabilities.php';
require_once __DIR__ . '/../plugin/sabri-security-center/src/Registry/ModuleRegistry.php';

use Sabri\Platform\Security\Registry\ModuleRegistry;

$assertions = 0;
$assert = static function (bool $condition, string $message) use (&$assertions): void {
    if (! $condition) {
        fwrite(STDERR, "FAIL: {$message}\n");
        exit(1);
    }
    ++$assertions;
};

$manifest = [
    'module_key' => 'file-22-composer',
    'name' => 'Universal Post Composer',
    'version' => '1.0.0',
    'owner' => 'File 22',
    'posture' => 'foundation',
    'data_classes' => ['content metadata'],
    'public_routes' => [],
    'private_routes' => ['/wp-admin/post-new.php'],
];

$first = new ModuleRegistry();
$assert($first->register($manifest), 'Initial manifest must persist.');
$stored = $GLOBALS['wpdb']->manifests['file-22-composer'];
$stored['last_seen_at'] = gmdate('Y-m-d H:i:s', time() - 7200);
$GLOBALS['wpdb']->manifests['file-22-composer'] = $stored;

// Simulate a concurrent writer changing the hash after the heartbeat read but
// before the conditional heartbeat update reaches storage.
$GLOBALS['wpdb']->manifestConcurrentHash = str_repeat('a', 64);
$second = new ModuleRegistry();
$assert(! $second->register($manifest), 'Concurrent heartbeat hash drift must fail closed.');
$assert($second->get('file-22-composer') === null, 'Rejected concurrent manifest must not enter runtime memory.');
$assert(
    array_reduce(
        $GLOBALS['wp_actions'],
        static fn (bool $found, array $action): bool => $found || ($action[0] === 'spcrc/module_manifest_persist_failed'),
        false
    ),
    'Concurrent heartbeat failure must emit the persistence-failure action.'
);

// A zero-row heartbeat with an unchanged canonical hash is idempotent success.
$GLOBALS['wpdb']->manifests['file-22-composer']['manifest_hash'] = hash('sha256', wp_json_encode((new ModuleRegistry())->validate($manifest), JSON_UNESCAPED_SLASHES));
$GLOBALS['wpdb']->manifests['file-22-composer']['last_seen_at'] = gmdate('Y-m-d H:i:s', time() - 7200);
$GLOBALS['wpdb']->zeroUpdate = true;
$third = new ModuleRegistry();
$assert($third->register($manifest), 'Zero-row heartbeat may succeed only after identical canonical re-read.');
$GLOBALS['wpdb']->zeroUpdate = false;
$assert($third->get('file-22-composer') !== null, 'Verified identical manifest may enter runtime memory.');

echo "PASS: {$assertions} Cycle 22 manifest-heartbeat race assertions\n";
