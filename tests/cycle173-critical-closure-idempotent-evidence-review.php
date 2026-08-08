<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

use Sabri\Platform\Security\Incident\IncidentCoordinator;
use Sabri\Platform\Security\Registry\GovernedArtifactRegistry;
use Sabri\Platform\Security\Storage\AuditLogger;
use Sabri\Platform\Security\Storage\IncidentRepository;

function c173(bool $condition, string $message): void { if (! $condition) { fwrite(STDERR, "FAIL: {$message}\n"); exit(1); } }

$GLOBALS['current_user_caps'] = [
    'spcrc_manage_incidents' => true,
    'spcrc_close_critical_incidents' => true,
];
$registry = new GovernedArtifactRegistry(new AuditLogger());
$incidents = new IncidentRepository(new AuditLogger());
$coordinator = new IncidentCoordinator($incidents, $registry);
$incident = $coordinator->declare([
    'title' => 'Cycle 173 critical incident',
    'severity' => 'sev0',
    'summary' => 'Retry-safe closure review.',
    'playbook' => 'administrator-takeover',
    'evidence_ref' => 'incident:cycle173-open',
]);
c173(is_string($incident), 'Critical incident must be declared.');
foreach (['contained', 'eradicated', 'recovering', 'resolved'] as $state) {
    c173($coordinator->advance($incident, $state, 'advance-' . $state, 'incident:cycle173-' . $state) === true, 'Incident must reach ' . $state . '.');
}

add_filter('spcrc/verify_step_up_assurance', '__return_true', 10, 4);
$armed = true;
add_action('spcrc/governed_artifact_saved', static function (array $record) use (&$armed): void {
    if ($armed && ($record['artifact_type'] ?? '') === 'incident-action' && str_starts_with((string) ($record['artifact_key'] ?? ''), 'dual-close-')) {
        $GLOBALS['wpdb']->zeroAuditInsert = true;
        $armed = false;
    }
}, 10, 1);

$args = [$incident, 'closed', 'closure', 'incident:cycle173-close', ['approval:cycle173-one', 'approval:cycle173-two'], 'assertion:cycle173-stepup'];
$first = $coordinator->advance(...$args);
c173(is_wp_error($first) && $first->get_error_code() === 'spcrc_incident_audit_failed', 'First close must simulate a post-approval incident-transition audit failure.');
c173($registry->count('incident-action') >= 2, 'Critical approval evidence must remain persisted after the incident transition rolls back.');

$second = $coordinator->advance(...$args);
c173($second === true, 'Retry with the same freshly reverified closure ceremony must reuse matching persisted approval evidence instead of deadlocking on duplicate artifact creation.');
$closed = $incidents->get($incident);
c173(is_array($closed) && ($closed['status'] ?? '') === 'closed', 'Retry-safe closure must complete the incident.');

$source = file_get_contents(__DIR__ . '/../plugin/sabri-security-center/src/Incident/IncidentCoordinator.php');
c173(is_string($source) && str_contains($source, 'persistCriticalClosureApproval') && str_contains($source, 'spcrc_critical_incident_approval_evidence_conflict'), 'Idempotent approval-evidence reuse and conflict detection must remain encoded.');

echo "PASS: cycle173 critical-incident closure retry/idempotency defect fixed and retested\n";
