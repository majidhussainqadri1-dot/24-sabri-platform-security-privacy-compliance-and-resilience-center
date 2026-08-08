<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

use Sabri\Platform\Security\Privacy\DeletionReplayManager;
use Sabri\Platform\Security\Registry\GovernedArtifactRegistry;
use Sabri\Platform\Security\Storage\AuditGapStore;
use Sabri\Platform\Security\Storage\AuditLogger;

function c153(bool $condition, string $message): void { if (! $condition) { fwrite(STDERR, "FAIL: {$message}\n"); exit(1); } }

$registry = new GovernedArtifactRegistry(new AuditLogger());
$key = 'held-deletion';
$created = $registry->save([
    'artifact_type' => 'deletion-ledger', 'artifact_key' => $key, 'title' => 'Deletion obligation',
    'status' => 'pending', 'classification' => 'C4', 'module_key' => 'file-00-membership',
    'payload' => [
        'legal_hold_ref' => 'hold:cycle153-active', 'attempts' => 0, 'next_retry_at' => '',
        'subject_ref' => 'subject:cycle153', 'request_ref' => 'request:cycle153',
    ],
]);
c153(! is_wp_error($created), 'Baseline deletion obligation must save.');
add_filter('spcrc/privacy_legal_hold_active', '__return_true', 10, 3);
$option = 'spcrc_artifact_' . substr(hash('sha256', 'deletion-ledger|' . $key), 0, 40);
$GLOBALS['wp_update_option_fail'][$option] = true;
$counts = (new DeletionReplayManager($registry, new AuditLogger()))->run();
c153(($counts['held'] ?? -1) === 0 && ($counts['failed'] ?? 0) === 1, 'A failed legal-hold state transition must not be falsely counted as durably held.');
c153(AuditGapStore::count('spcrc_deletion_replay_audit_gap') >= 1, 'Deletion replay persistence failure must create durable audit-gap evidence.');
c153(in_array('spcrc_deletion_replay_audit_gap', AuditGapStore::managedOptions(), true), 'Deletion replay gaps must be exposed to the reconciliation surface.');

// Fresh empty run: the completion audit itself must also fail visibly and durably.
$GLOBALS['wp_options'] = [];
$GLOBALS['wp_filters']['spcrc/privacy_legal_hold_active'] = [];
$GLOBALS['wpdb']->failAuditInsert = true;
$emptyRegistry = new GovernedArtifactRegistry(new AuditLogger());
(new DeletionReplayManager($emptyRegistry, new AuditLogger()))->run();
c153(AuditGapStore::count('spcrc_deletion_replay_audit_gap') === 1, 'Deletion replay completion-audit failure must create a durable gap instead of being ignored.');
$signals = array_values(array_filter($GLOBALS['wp_actions'], static fn (array $action): bool => ($action[0] ?? '') === 'spcrc/privacy_deletion_replay_audit_failed'));
c153(count($signals) >= 1, 'Deletion replay completion-audit failure must emit an operational signal.');

echo "PASS: cycle153 deletion-replay state/audit durability defects fixed and retested\n";
