<?php

declare(strict_types=1);
require_once __DIR__ . '/bootstrap.php';

use Sabri\Platform\Security\Registry\ModuleRegistry;
use Sabri\Platform\Security\System\SystemCheck;
use Sabri\Platform\Security\Storage\AuditGapStore;

function cgeAssert(bool $passed, string $message): void
{
    if (! $passed) { fwrite(STDERR, "FAIL: {$message}\n"); exit(1); }
}

$option = 'spcrc_detection_audit_gap';
$checker = new SystemCheck(new ModuleRegistry());
$fixtures = [
    'invalid-nested-record' => ['opaque:invalid' => ['entity_type' => 'alert']],
    'invalid-scalar-storage' => 'corrupted record',
    'invalid-empty-row' => ['opaque:blank' => []],
];
foreach ($fixtures as $label => $raw) {
    update_option($option, $raw, false);
    cgeAssert(AuditGapStore::count($option) >= 1, 'Nonempty corrupted audit gap evidence cannot be silently erased: ' . $label);
    $map = array_column($checker->run(), null, 'key');
    cgeAssert(($map['audit_gaps']['status'] ?? '') === 'critical', 'Corrupt evidence must block green security posture: ' . $label);
}
delete_option($option);
cgeAssert(AuditGapStore::count($option) === 0, 'Valid empty gap store reports zero.');
echo "PASS: corrupted operational evidence cannot clear security or release gates\n";
