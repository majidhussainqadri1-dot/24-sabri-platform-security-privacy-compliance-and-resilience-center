<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

use Sabri\Platform\Security\Monitoring\RemoteEvidenceQueue;
use Sabri\Platform\Security\Registry\GovernedArtifactRegistry;
use Sabri\Platform\Security\Storage\AuditGapStore;
use Sabri\Platform\Security\Storage\AuditLogger;

function c148(bool $condition, string $message): void { if (! $condition) { fwrite(STDERR, "FAIL: {$message}\n"); exit(1); } }

$registry = new GovernedArtifactRegistry(new AuditLogger());
$queue = new RemoteEvidenceQueue($registry);
$uuid = '11111111-1111-4111-8111-111111111111';
$artifactKey = 'event-' . substr(hash('sha256', $uuid), 0, 32);
$option = 'spcrc_artifact_' . substr(hash('sha256', 'remote-evidence|' . $artifactKey), 0, 40);
$GLOBALS['wp_update_option_fail'][$option] = true;

$queue->observe([
    'event_uuid' => $uuid,
    'event_type' => 'security_state_requested',
    'module_key' => 'file-24-security-center',
    'result' => 'requested',
    'risk_level' => 'high',
    'correlation_id' => '22222222-2222-4222-8222-222222222222',
    'created_at' => gmdate('c'),
]);

c148(AuditGapStore::count('spcrc_remote_evidence_audit_gap') === 1, 'A failed remote-evidence enqueue must create durable release-blocking gap evidence.');
$signals = array_values(array_filter($GLOBALS['wp_actions'], static fn (array $action): bool => ($action[0] ?? '') === 'spcrc/remote_evidence_enqueue_failed'));
c148(count($signals) === 1, 'A failed enqueue must emit an operational failure signal.');
c148(in_array('spcrc_remote_evidence_audit_gap', AuditGapStore::managedOptions(), true), 'Remote evidence gaps must be visible to the managed reconciliation surface.');
c148(in_array('spcrc_detection_audit_gap', AuditGapStore::managedOptions(), true), 'Previously introduced detection gaps must also be visible to managed reconciliation.');

echo "PASS: cycle148 remote-evidence durability and reconciliation-visibility defects fixed and retested\n";
