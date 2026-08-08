<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

use Sabri\Platform\Security\Monitoring\RemoteEvidenceQueue;
use Sabri\Platform\Security\Privacy\DeletionReplayManager;
use Sabri\Platform\Security\Registry\GovernedArtifactRegistry;
use Sabri\Platform\Security\Storage\AuditLogger;

function c187(bool $condition, string $message): void { if (! $condition) { fwrite(STDERR, "FAIL: {$message}\n"); exit(1); } }

$registry = new GovernedArtifactRegistry(new AuditLogger());
$queue = new RemoteEvidenceQueue($registry);
$remote = $registry->save([
    'artifact_type' => 'remote-evidence',
    'artifact_key' => 'cycle187-remote-exception',
    'title' => 'Remote exception containment',
    'status' => 'queued',
    'classification' => 'C5',
    'payload' => ['attempts' => 0],
]);
c187(! is_wp_error($remote), 'Remote evidence fixture must seed.');
add_filter('spcrc/remote_evidence_deliver', static function () { throw new RuntimeException('provider failure with private detail'); }, 10, 2);
$remoteCounts = $queue->process(10);
c187(($remoteCounts['retry'] ?? 0) === 1, 'Throwing remote evidence adapter must be contained and converted into retry state.');
$remoteAfter = $registry->get('remote-evidence', 'cycle187-remote-exception');
c187(is_array($remoteAfter) && ($remoteAfter['status'] ?? '') === 'retry' && (($remoteAfter['payload']['last_error_code'] ?? '') === 'remote_adapter_exception'), 'Remote adapter exception must persist only a bounded public-safe error code.');

$GLOBALS['wp_filters']['spcrc/remote_evidence_deliver'] = [];
$manager = new DeletionReplayManager($registry, new AuditLogger());
$hold = $registry->save([
    'artifact_type' => 'deletion-ledger',
    'artifact_key' => 'cycle187-hold-exception',
    'title' => 'Legal hold adapter exception',
    'status' => 'pending',
    'classification' => 'C4',
    'owner_user_id' => 7,
    'payload' => ['attempts' => 0, 'legal_hold_ref' => 'hold:cycle187'],
]);
$module = $registry->save([
    'artifact_type' => 'deletion-ledger',
    'artifact_key' => 'cycle187-module-exception',
    'title' => 'Deletion module adapter exception',
    'status' => 'pending',
    'classification' => 'C4',
    'owner_user_id' => 7,
    'payload' => ['attempts' => 0, 'legal_hold_ref' => ''],
]);
c187(! is_wp_error($hold) && ! is_wp_error($module), 'Deletion replay exception fixtures must seed.');
add_filter('spcrc/privacy_legal_hold_active', static function (bool $default, string $holdRef): bool {
    if ($holdRef === 'hold:cycle187') throw new RuntimeException('hold service unavailable');
    return $default;
}, 10, 2);
add_filter('spcrc/privacy_deletion_replay_module', static function () { throw new RuntimeException('module unavailable'); }, 10, 2);
$deletionCounts = $manager->run(10);
c187(($deletionCounts['failed'] ?? 0) === 2, 'Both legal-hold and deletion-module adapter exceptions must fail closed without escaping the worker.');
$holdAfter = $registry->get('deletion-ledger', 'cycle187-hold-exception');
$moduleAfter = $registry->get('deletion-ledger', 'cycle187-module-exception');
c187(is_array($holdAfter) && ($holdAfter['status'] ?? '') === 'failed' && (($holdAfter['payload']['last_error_code'] ?? '') === 'legal_hold_adapter_exception'), 'Unknown legal-hold state must prevent destructive replay and schedule safe retry.');
c187(is_array($moduleAfter) && ($moduleAfter['status'] ?? '') === 'failed' && (($moduleAfter['payload']['last_error_code'] ?? '') === 'module_handler_exception'), 'Throwing module adapter must persist a bounded retryable failure instead of crashing the worker.');

echo "PASS: cycle187 external adapter exception-containment defects fixed and retested\n";
