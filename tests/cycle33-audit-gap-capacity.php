<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';
require_once dirname(__DIR__) . '/plugin/sabri-security-center/src/Support/Sanitizer.php';
require_once dirname(__DIR__) . '/plugin/sabri-security-center/src/Support/AtomicOptionLock.php';
require_once dirname(__DIR__) . '/plugin/sabri-security-center/src/Storage/AuditGapStore.php';

use Sabri\Platform\Security\Storage\AuditGapStore;

$assertions = 0;
function expectCycle33(bool $condition, string $message): void
{
    global $assertions;
    ++$assertions;
    if (! $condition) {
        fwrite(STDERR, "FAIL: {$message}\n");
        exit(1);
    }
}

$option = 'spcrc_admin_audit_gap';
$gaps = [];
for ($i = 1; $i <= 100; ++$i) {
    $id = sprintf('gap-%03d', $i);
    $gaps[$id] = [
        'entity_type' => 'test',
        'entity_id' => (string) $i,
        'reason' => 'unresolved',
        'recorded_at' => gmdate('c'),
        'context' => [],
    ];
}
update_option($option, $gaps, false);
$before = get_option($option, []);

expectCycle33(AuditGapStore::count($option) === 100, 'Capacity fixture must contain one hundred unresolved gaps.');
expectCycle33(! AuditGapStore::record($option, 'test', 'overflow', 'new_failure'), 'A full registry must reject a new gap instead of evicting an unresolved one.');
expectCycle33(AuditGapStore::count($option) === 100, 'Rejected overflow must preserve the release-blocking count.');
expectCycle33(get_option($option, []) === $before, 'Rejected overflow must not mutate or reorder existing gaps.');
expectCycle33(isset(get_option($option, [])['gap-001']), 'The oldest unresolved gap must not be silently evicted.');
expectCycle33(isset(get_option($option, [])['gap-100']), 'The newest existing unresolved gap must remain present.');
expectCycle33(! isset(get_option($option, [])['overflow']), 'Rejected overflow must not masquerade as a stored record.');

printf("PASS: %d Cycle 33 audit-gap capacity assertions\n", $assertions);
