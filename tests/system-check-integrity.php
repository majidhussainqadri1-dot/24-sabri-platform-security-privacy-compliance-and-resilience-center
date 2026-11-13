<?php

declare(strict_types=1);
require_once __DIR__ . '/bootstrap.php';

use Sabri\Platform\Security\Registry\ModuleRegistry;
use Sabri\Platform\Security\System\SystemCheck;

function sciAssert(bool $passed, string $message): void
{
    if (! $passed) { fwrite(STDERR, "FAIL: {$message}\n"); exit(1); }
}

$checker = new SystemCheck(new ModuleRegistry());
$baseline = $checker->run();
$required = array_column($baseline, null, 'key');
sciAssert(count($required) === 13, 'Native File 24 checks retain canonical inventory.');

add_filter('spcrc/system_checks', static fn (array $checks): array => [[
    'key' => 'all_clear', 'label' => 'All clear', 'status' => 'pass', 'detail' => 'No issues',
]], 10, 1);
$suppressed = array_column($checker->run(), null, 'key');
sciAssert(isset($suppressed['schema']) && ($suppressed['schema'] === $required['schema']), 'Missing mandatory schema check must survive the filter.');
sciAssert(($suppressed['system_checks_integrity']['status'] ?? '') === 'critical', 'Suppression must surface as a critical integrity error.');

$GLOBALS['wp_filters']['spcrc/system_checks'] = [];
add_filter('spcrc/system_checks', static function (array $checks): array {
    foreach ($checks as &$check) {
        if (($check['key'] ?? '') === 'schema') { $check['status'] = 'pass'; }
    }
    unset($check);
    $checks[] = ['key' => 'module_extra', 'label' => 'Module extra', 'status' => 'warning', 'detail' => 'External'];
    return $checks;
}, 10, 1);
$changed = array_column($checker->run(), null, 'key');
sciAssert(($changed['schema']['status'] ?? '') === ($required['schema']['status'] ?? ''), 'Core result cannot be overwritten.');
sciAssert(($changed['system_checks_integrity']['status'] ?? '') === 'critical', 'Core overwrite must surface as a critical integrity error.');
sciAssert(($changed['module_extra']['status'] ?? '') === 'warning', 'Legitimate module checks must still be appended.');

$GLOBALS['wp_filters']['spcrc/system_checks'] = [];
add_filter('spcrc/system_checks', static function (array $checks): array {
    $checks[] = ['key' => 'module_extra', 'label' => 'Module extra', 'status' => 'warning', 'detail' => 'External'];
    return $checks;
}, 10, 1);
$valid = array_column($checker->run(), null, 'key');
sciAssert(! isset($valid['system_checks_integrity']), 'Unchanged core with added module checks must not produce a false warning.');
sciAssert(($valid['module_extra']['status'] ?? '') === 'warning', 'External warning retained.');

echo "PASS: system-check native evidence and extension integrity\n";
