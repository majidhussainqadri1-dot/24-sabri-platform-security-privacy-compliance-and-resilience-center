<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

use Sabri\Platform\Security\Monitoring\RemoteEvidenceQueue;
use Sabri\Platform\Security\Registry\GovernedArtifactRegistry;
use Sabri\Platform\Security\Storage\AuditGapStore;
use Sabri\Platform\Security\Storage\AuditLogger;

function c160(bool $condition, string $message): void { if (! $condition) { fwrite(STDERR, "FAIL: {$message}\n"); exit(1); } }

$registry = new GovernedArtifactRegistry(new AuditLogger());
$queue = new RemoteEvidenceQueue($registry);
$queued = $queue->enqueue([
    'event_uuid' => '00000000-0000-4000-8000-000000000160',
    'event_type' => 'cycle160_event',
    'module_key' => 'file-24-security-center',
    'result' => 'blocked',
    'risk_level' => 'high',
    'correlation_id' => '00000000-0000-4000-8000-000000000161',
    'created_at' => gmdate('c'),
]);
c160(! is_wp_error($queued), 'Remote evidence item must queue for lease-loss review.');

add_filter('spcrc/remote_evidence_deliver', static function (array $default, array $payload): array {
    unset($GLOBALS['wp_options']['spcrc_remote_evidence_queue_lock']);
    return ['status' => 'delivered', 'evidence_ref' => 'evidence:cycle160-delivered', 'error_code' => ''];
}, 10, 2);

$counts = $queue->process();
c160(($counts['processed'] ?? 0) === 1, 'Remote evidence worker must claim one queue item.');
c160(($counts['delivered'] ?? 0) === 0 && ($counts['persistence_failed'] ?? 0) === 1, 'Worker that loses its lease during remote delivery must not commit a false delivered result.');
$records = $registry->recent('remote-evidence', 10);
c160(count($records) === 1 && ($records[0]['status'] ?? '') === 'delivering', 'Lease-loss item must remain visibly delivering for later reconciliation.');
c160((int) (($records[0]['payload']['attempts'] ?? 0)) === 1, 'Remote delivery claim must durably increment attempt count before external I/O.');
c160(AuditGapStore::count('spcrc_remote_evidence_audit_gap') >= 1, 'Remote evidence lease loss must be visible as a managed audit gap.');

echo "PASS: cycle160 remote-evidence renewable lease and delivery-state integrity defects fixed and retested\n";
