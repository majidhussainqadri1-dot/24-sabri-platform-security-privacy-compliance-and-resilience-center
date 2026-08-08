<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

use Sabri\Platform\Security\Privacy\DeletionReplayManager;
use Sabri\Platform\Security\Registry\GovernedArtifactRegistry;
use Sabri\Platform\Security\Storage\AuditGapStore;
use Sabri\Platform\Security\Storage\AuditLogger;

function c159(bool $condition, string $message): void { if (! $condition) { fwrite(STDERR, "FAIL: {$message}\n"); exit(1); } }

$registry = new GovernedArtifactRegistry(new AuditLogger());
$created = $registry->save([
    'artifact_type' => 'deletion-ledger',
    'artifact_key' => 'cycle159-deletion',
    'title' => 'Deletion replay lease review',
    'status' => 'pending',
    'classification' => 'C4',
    'module_key' => 'file-00-membership',
    'payload' => ['attempts' => 0, 'subject_ref' => 'subject:cycle159', 'request_ref' => 'request:cycle159'],
]);
c159(! is_wp_error($created), 'Deletion obligation must save for lease-loss review.');

add_filter('spcrc/privacy_deletion_replay_module', static function (array $default, array $record): array {
    // Simulate the long-running adapter crossing the lease boundary: another
    // worker could now reclaim the expired global lease, so this worker must
    // refuse to commit a success after ownership is lost.
    unset($GLOBALS['wp_options']['spcrc_deletion_replay_lock']);
    return ['status' => 'reconciled', 'evidence_ref' => 'evidence:cycle159-reconciled', 'error_code' => ''];
}, 10, 2);

$counts = (new DeletionReplayManager($registry, new AuditLogger()))->run();
c159(($counts['processed'] ?? 0) === 1, 'Deletion replay must claim one eligible record.');
c159(($counts['reconciled'] ?? 0) === 0 && ($counts['failed'] ?? 0) === 1, 'Worker that loses its global lease during an external dispatch must not commit success.');
$record = $registry->get('deletion-ledger', 'cycle159-deletion');
c159(is_array($record) && ($record['status'] ?? '') === 'dispatching', 'Lease-loss record must remain visibly dispatching for safe later reconciliation, not falsely reconciled.');
c159((int) (($record['payload']['attempts'] ?? 0)) === 1, 'Dispatch claim must durably record the attempt before invoking the external adapter.');
c159(AuditGapStore::count('spcrc_deletion_replay_audit_gap') >= 1, 'Lease loss must create durable managed audit-gap evidence.');

echo "PASS: cycle159 deletion-replay renewable lease and dispatch-state integrity defects fixed and retested\n";
