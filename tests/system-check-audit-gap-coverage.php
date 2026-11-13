<?php

declare(strict_types=1);
require_once __DIR__ . '/bootstrap.php';

use Sabri\Platform\Security\Registry\ModuleRegistry;
use Sabri\Platform\Security\System\SystemCheck;
use Sabri\Platform\Security\Storage\AuditGapStore;

function gacAssert(bool $condition, string $message): void
{
    if (! $condition) { fwrite(STDERR, "FAIL: {$message}\n"); exit(1); }
}

$checker = new SystemCheck(new ModuleRegistry());
$initial = array_column($checker->run(), null, 'key');
gacAssert(($initial['audit_gaps']['status'] ?? '') === 'pass', 'Clean test setup must not fabricate gaps.');

$operationalCategories = [
    'spcrc_detection_audit_gap',
    'spcrc_remote_evidence_audit_gap',
    'spcrc_deletion_replay_audit_gap',
];
foreach ($operationalCategories as $option) {
    gacAssert(in_array($option, AuditGapStore::managedOptions(), true), 'Operational category is canonical in AuditGapStore.');
    update_option($option, ['reason' => 'evidence_write_failed', 'recorded_at' => gmdate('c')], false);
    $checks = array_column($checker->run(), null, 'key');
    gacAssert(($checks['audit_gaps']['status'] ?? '') === 'critical', 'Operational audit gap must block green security posture: ' . $option);
    gacAssert(str_contains((string) ($checks['audit_gaps']['detail'] ?? ''), 'Unresolved audit-evidence gaps'), 'Operational gap must be described in result.');
    delete_option($option);
}
$final = array_column($checker->run(), null, 'key');
gacAssert(($final['audit_gaps']['status'] ?? '') === 'pass', 'Reconciled audit evidence must return to healthy posture.');
echo "PASS: all canonical operational audit-gap categories covered in SystemCheck\n";
