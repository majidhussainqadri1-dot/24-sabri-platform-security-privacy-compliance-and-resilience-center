<?php

declare(strict_types=1);
require_once __DIR__ . '/bootstrap.php';

use Sabri\Platform\Security\Storage\AuditGapStore;
use Sabri\Platform\Security\Storage\AuditLogger;

function assertGapNoLoss(bool $ok, string $why): void
{
    if (! $ok) {
        fwrite(STDERR, "FAIL: {$why}\n");
        exit(1);
    }
}

$option = 'spcrc_risk_audit_gap';
$initial = [
    'valid-1' => ['entity_type' => 'risk', 'entity_id' => 'ref:good-id', 'reason' => 'audit_failed', 'recorded_at' => gmdate('c'), 'context' => []],
    'invalid-1' => ['entity_type' => 'risk', 'entity_id' => 'ref:corrupt', 'recorded_at' => gmdate('c'), 'context' => []],
];
update_option($option, $initial, false);
assertGapNoLoss(AuditGapStore::count($option) === 2, 'Valid and invalid raw rows must both be counted.');
$written = AuditGapStore::record($option, 'risk', 'ref:new-id', 'audit_failed');
assertGapNoLoss($written === false, 'A new write must fail closed rather than replacing malformed unresolved evidence.');
assertGapNoLoss(get_option($option, []) === $initial, 'Raw evidence must be unchanged after rejected write.');

$GLOBALS['current_user_caps'] = ['spcrc_manage_security_settings' => true];
add_filter('spcrc/verify_step_up_assurance', '__return_true', 10, 4);
$reconciled = AuditGapStore::reconcile($option, 'valid-1', 'evidence:review-one', 'assertion:step-up-one', new AuditLogger());
assertGapNoLoss(is_wp_error($reconciled), 'Corrupt evidence must block reconciliation until independently recovered.');
assertGapNoLoss($reconciled->get_error_code() === 'spcrc_audit_gap_existing_evidence_invalid', 'Corrupt evidence has a stable remediation error code.');
assertGapNoLoss(get_option($option, []) === $initial, 'Raw evidence must survive rejected reconciliation.');

// A legacy flat record is an unresolved failure; do not convert and overwrite
// it accidentally during a new write.
$legacy = ['reason' => 'legacy_failed'];
update_option($option, $legacy, false);
assertGapNoLoss(! AuditGapStore::record($option, 'risk', 'ref:new-id', 'audit_failed'), 'Legacy flat evidence cannot be silently rewritten.');
assertGapNoLoss(get_option($option, []) === $legacy, 'Legacy raw evidence remains intact.');

delete_option($option);
assertGapNoLoss(AuditGapStore::record($option, 'risk', 'ref:good-id', 'audit_failed'), 'Clean records remain writable.');
assertGapNoLoss(AuditGapStore::count($option) === 1, 'Clean records remain countable.');

echo "PASS: unresolved corrupt or legacy gap evidence survives write and reconcile attempts\n";
