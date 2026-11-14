<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

use Sabri\Platform\Security\Registry\ModuleRegistry;
use Sabri\Platform\Security\System\SystemCheck;

function assertV123SystemEvidence(bool $condition, string $message): void
{
    if (! $condition) {
        fwrite(STDERR, "FAIL: {$message}\n");
        exit(1);
    }
}

$checks = new SystemCheck(new ModuleRegistry());
$base = $checks->run();
assertV123SystemEvidence(count($base) === 13, 'Baseline mandatory checks are retained.');

// Malformed extension evidence cannot vanish silently during normalization.
add_filter('spcrc/system_checks', static function (array $results): array {
    $results[] = ['key' => '', 'label' => 'Unidentified external check', 'status' => 'pass'];
    $results[] = null;
    $results[] = ['key' => 'external_valid', 'label' => 'External warning', 'status' => 'warning', 'detail' => 'Needs action'];
    return $results;
}, 10, 1);
$malformed = array_column($checks->run(), null, 'key');
assertV123SystemEvidence(
    ($malformed['system_checks_integrity']['status'] ?? '') === 'critical',
    'Malformed appended checks must produce a critical integrity result.'
);
assertV123SystemEvidence(
    ($malformed['external_valid']['status'] ?? '') === 'warning',
    'Well-formed extension warnings must remain visible during an integrity failure.'
);
assertV123SystemEvidence(
    ($malformed['schema'] ?? null) === (array_column($base, null, 'key')['schema'] ?? null),
    'Malformed extension data must not replace mandatory checks.'
);

// Limit overflows cannot silently suppress pending extension checks either.
$GLOBALS['wp_filters']['spcrc/system_checks'] = [];
add_filter('spcrc/system_checks', static function (array $results): array {
    for ($i = 0; $i < 101; ++$i) {
        $results[] = ['key' => 'extra_' . $i, 'label' => 'External ' . $i, 'status' => 'unknown', 'detail' => 'Pending'];
    }
    return $results;
}, 10, 1);
$overflow = array_column($checks->run(), null, 'key');
assertV123SystemEvidence(
    ($overflow['system_checks_integrity']['status'] ?? '') === 'critical',
    'Truncated extension checks must be reported, not discarded without warning.'
);

$GLOBALS['wp_filters']['spcrc/system_checks'] = [];
add_filter('spcrc/system_checks', static function (array $results): array {
    $results[] = ['key' => 'external_pending', 'label' => 'External pending', 'status' => 'unknown', 'detail' => 'Not measured'];
    return $results;
}, 10, 1);
$wellFormed = array_column($checks->run(), null, 'key');
assertV123SystemEvidence(
    ! isset($wellFormed['system_checks_integrity']),
    'A valid extension must not trigger a false integrity alert.'
);
assertV123SystemEvidence(
    ($wellFormed['external_pending']['status'] ?? '') === 'unknown',
    'A valid unknown result must never be displayed as PASS.'
);

echo "PASS: V12.3 malformed/overflowed system-check extension evidence is fail-closed\n";
