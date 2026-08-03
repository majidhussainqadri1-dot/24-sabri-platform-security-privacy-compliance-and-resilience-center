<?php

declare(strict_types=1);

require __DIR__ . '/support/cycle57-96.php';


use Sabri\Platform\Security\Storage\AuditGapStore;
for ($i = 0; $i < 100; ++$i) {
    cycleReviewAssert(AuditGapStore::record('spcrc_cycle70_audit_gap', 'batch', (string) $i, 'failed'), 'Initial bounded gap must persist.');
}
cycleReviewAssert(! AuditGapStore::record('spcrc_cycle70_audit_gap', 'batch', 'overflow', 'failed'), 'Capacity overflow must fail closed.');
$marker = get_option('spcrc_audit_gap_capacity_marker', []);
cycleReviewAssert(($marker['option'] ?? '') === 'spcrc_cycle70_audit_gap', 'Capacity exhaustion must persist a durable category marker.');
cycleReviewAssert(($marker['unresolved_count'] ?? 0) === 100, 'Capacity marker must preserve unresolved count.');

cycleReviewPass(70, 'audit-gap-capacity-marker');
