<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

use Sabri\Platform\Security\Incident\IncidentCoordinator;
use Sabri\Platform\Security\Monitoring\RemoteEvidenceQueue;
use Sabri\Platform\Security\Registry\GovernedArtifactRegistry;
use Sabri\Platform\Security\Storage\AuditGapStore;
use Sabri\Platform\Security\Storage\AuditLogger;
use Sabri\Platform\Security\Storage\IncidentRepository;

$count = 0;
function c101(bool $condition, string $message): void { global $count; ++$count; if (! $condition) { fwrite(STDERR, "FAIL: $message\n"); exit(1); } }

$audit = new AuditLogger();
$artifacts = new GovernedArtifactRegistry($audit);
$queue = new RemoteEvidenceQueue($artifacts);
$eventUuid = '123e4567-e89b-42d3-a456-426614174101';
$queued = $queue->enqueue([
    'event_uuid' => $eventUuid,
    'event_type' => 'audit_write_failed',
    'module_key' => 'file-24-security-center',
    'result' => 'failed',
    'risk_level' => 'high',
    'created_at' => gmdate('c'),
]);
c101(is_string($queued), 'Remote evidence must enter the bounded queue.');
add_filter('spcrc/remote_evidence_deliver', static fn (): array => ['status' => 'delivered', 'evidence_ref' => 'remote:evidence-101']);
$key = 'event-' . substr(hash('sha256', $eventUuid), 0, 32);
$recordOption = 'spcrc_artifact_' . substr(hash('sha256', 'remote-evidence|' . $key), 0, 40);
$GLOBALS['wp_update_option_fail'][$recordOption] = true;
$failedPersistence = $queue->process();
c101(($failedPersistence['processed'] ?? 0) === 1, 'Remote evidence attempt must be counted as processed.');
c101(($failedPersistence['delivered'] ?? 0) === 0, 'Delivery must not be reported when delivered-state persistence fails.');
c101(($failedPersistence['persistence_failed'] ?? 0) === 1, 'Remote evidence persistence failure must be reported separately.');
unset($GLOBALS['wp_update_option_fail'][$recordOption]);
$recovered = $queue->process();
c101(($recovered['delivered'] ?? 0) === 1 && ($recovered['persistence_failed'] ?? 0) === 0, 'Queued evidence may be delivered after persistence recovers.');

$incidents = new IncidentRepository($audit);
$coordinator = new IncidentCoordinator($incidents, $artifacts);
$GLOBALS['wp_update_option_fail']['spcrc_governed_artifact_index_v1'] = true;
$partial = $coordinator->declare([
    'title' => 'Partial declaration exercise',
    'severity' => 'sev2',
    'summary' => 'Exercise validates partial transaction evidence.',
    'playbook' => 'vendor-breach',
    'evidence_ref' => 'incident:partial-101',
]);
c101(is_wp_error($partial) && $partial->get_error_code() === 'spcrc_incident_declaration_partial', 'Incident declaration must expose post-create partial failure.');
c101(AuditGapStore::count('spcrc_incident_audit_gap') === 1, 'Partial incident declaration must create a durable audit gap.');
unset($GLOBALS['wp_update_option_fail']['spcrc_governed_artifact_index_v1']);

$incidentData = $partial instanceof WP_Error ? $partial->get_error_data() : [];
c101(is_array($incidentData) && ! empty($incidentData['incident_uuid']), 'Partial declaration error must expose the canonical incident reference for controlled recovery.');

echo "PASS: $count Cycle 101 transactional-evidence hardening assertions\n";
