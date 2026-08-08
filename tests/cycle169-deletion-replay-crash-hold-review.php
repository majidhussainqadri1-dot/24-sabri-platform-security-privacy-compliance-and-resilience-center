<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

use Sabri\Platform\Security\Privacy\DeletionReplayManager;
use Sabri\Platform\Security\Registry\GovernedArtifactRegistry;
use Sabri\Platform\Security\Storage\AuditLogger;

function c169(bool $condition, string $message): void { if (! $condition) { fwrite(STDERR, "FAIL: {$message}\n"); exit(1); } }

$registry = new GovernedArtifactRegistry(new AuditLogger());
$manager = new DeletionReplayManager($registry, new AuditLogger());

$base = [
    'artifact_type' => 'deletion-ledger',
    'title' => 'Cycle 169 deletion replay review',
    'classification' => 'C4',
    'module_key' => 'file-17-network',
    'owner_user_id' => 7,
];

$stale = $registry->save($base + [
    'artifact_key' => 'cycle169-stale',
    'status' => 'dispatching',
    'payload' => ['attempts' => 1, 'dispatch_started_at' => gmdate('c', time() - 1200), 'legal_hold_ref' => ''],
]);
$fresh = $registry->save($base + [
    'artifact_key' => 'cycle169-fresh',
    'status' => 'dispatching',
    'payload' => ['attempts' => 1, 'dispatch_started_at' => gmdate('c'), 'legal_hold_ref' => ''],
]);
$held = $registry->save($base + [
    'artifact_key' => 'cycle169-held',
    'status' => 'blocked-hold',
    'payload' => ['attempts' => 0, 'legal_hold_ref' => 'hold:cycle169'],
]);
c169(! is_wp_error($stale) && ! is_wp_error($fresh) && ! is_wp_error($held), 'Deletion replay fixtures must be stored.');

add_filter('spcrc/privacy_legal_hold_active', static function (bool $default, string $holdRef): bool {
    return $holdRef === 'hold:cycle169';
}, 10, 2);
add_filter('spcrc/privacy_deletion_replay_module', static function (array $default, array $record): array {
    return ['status' => 'reconciled', 'evidence_ref' => 'evidence:cycle169-recovered', 'error_code' => ''];
}, 10, 2);

$heldBefore = $registry->get('deletion-ledger', 'cycle169-held');
$counts = $manager->run(10);
c169(($counts['processed'] ?? 0) === 2, 'Only stale dispatch and held item should be counted; fresh dispatch must not be duplicated.');
c169(($counts['reconciled'] ?? 0) === 1, 'Stale dispatch must be safely recoverable.');
c169(($counts['held'] ?? 0) === 1, 'Active legal hold must remain held without redispatch.');
$staleAfter = $registry->get('deletion-ledger', 'cycle169-stale');
$freshAfter = $registry->get('deletion-ledger', 'cycle169-fresh');
$heldAfter = $registry->get('deletion-ledger', 'cycle169-held');
c169(is_array($staleAfter) && ($staleAfter['status'] ?? '') === 'reconciled', 'Stale dispatch must reconcile after recovery.');
c169(is_array($freshAfter) && ($freshAfter['status'] ?? '') === 'dispatching' && (int) ($freshAfter['version'] ?? 0) === 1, 'Fresh in-flight dispatch must remain untouched.');
c169(is_array($heldBefore) && is_array($heldAfter) && (int) ($heldAfter['version'] ?? 0) === (int) ($heldBefore['version'] ?? 0), 'Already blocked legal hold must not churn artifact versions every worker run.');

$source = file_get_contents(__DIR__ . '/../plugin/sabri-security-center/src/Privacy/DeletionReplayManager.php');
c169(is_string($source) && str_contains($source, 'IN_FLIGHT_STALE_SECONDS') && str_contains($source, "recordStatus === 'blocked-hold'"), 'Deletion crash/hold recovery invariants must remain in source.');

echo "PASS: cycle169 deletion-replay crash recovery and legal-hold churn defects fixed and retested\n";
