<?php

declare(strict_types=1);

require __DIR__ . '/support/cycle57-96.php';


use Sabri\Platform\Security\Storage\AuditGapStore;
use Sabri\Platform\Security\Storage\AuditLogger;
AuditGapStore::record('spcrc_risk_audit_gap', 'risk_uuid', '22222222-2222-4222-8222-222222222222', 'failed');
$gapId = (string) array_key_first(get_option('spcrc_risk_audit_gap', []));
add_filter('spcrc/verify_step_up_assurance', static fn(): bool => true, 10, 5);
add_action('spcrc/security_event_recorded', static function (string $eventUuid, string $eventType): void {
    if ($eventType === 'audit_gap_reconciliation_authorized') {
        $GLOBALS['wpdb']->failAuditInsert = true;
    }
}, 10, 2);
$result = AuditGapStore::reconcile('spcrc_risk_audit_gap', $gapId, 'vault:cycle71', 'file00:cycle71', new AuditLogger());
cycleReviewAssert(is_wp_error($result) && $result->get_error_code() === 'spcrc_audit_gap_completion_audit_failed', 'Completion-audit failure must roll reconciliation back.');
cycleReviewAssert(AuditGapStore::count('spcrc_risk_audit_gap') === 1, 'Original unresolved gap must be restored.');

cycleReviewPass(71, 'audit-gap-reconciliation-rollback');
