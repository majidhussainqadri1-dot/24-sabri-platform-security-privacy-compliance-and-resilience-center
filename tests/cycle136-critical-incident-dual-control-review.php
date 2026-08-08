<?php
declare(strict_types=1);
require_once __DIR__ . '/bootstrap.php';

use Sabri\Platform\Security\Incident\IncidentCoordinator;
use Sabri\Platform\Security\Registry\GovernedArtifactRegistry;
use Sabri\Platform\Security\Storage\AuditLogger;
use Sabri\Platform\Security\Storage\IncidentRepository;

function c136(bool $condition, string $message): void { if (! $condition) { fwrite(STDERR, "FAIL: {$message}\n"); exit(1); } }

$GLOBALS['current_user_caps']['spcrc_close_critical_incidents'] = true;
$audit = new AuditLogger();
$artifacts = new GovernedArtifactRegistry($audit);
$repository = new IncidentRepository($audit);
$coordinator = new IncidentCoordinator($repository, $artifacts);

$incident = $coordinator->declare([
    'title' => 'Critical identity-control incident',
    'severity' => 'sev0',
    'summary' => 'Privileged identity controls require containment.',
    'playbook' => 'administrator-takeover',
    'evidence_ref' => 'incident:cycle136',
    'commander_user_id' => 7,
    'alternate_commander_user_id' => 8,
    'out_of_band_channel_ref' => 'channel:cycle136',
]);
c136(is_string($incident), 'SEV0 incident must be declared.');

c136($coordinator->advance($incident, 'contained', 'Privileged writes contained.', 'incident:c136-contain') === true, 'SEV0 containment must succeed.');
c136($coordinator->advance($incident, 'eradicated', 'Compromised access removed.', 'incident:c136-eradicate') === true, 'SEV0 eradication must succeed.');
c136($coordinator->advance($incident, 'recovering', 'Controlled recovery started.', 'incident:c136-recover') === true, 'SEV0 recovery must start.');
c136($coordinator->advance($incident, 'resolved', 'Recovery validation completed.', 'incident:c136-resolve') === true, 'SEV0 resolution must succeed.');

$oneApproval = $coordinator->advance($incident, 'closed', 'Closure requested.', 'incident:c136-close', ['approval:human-a']);
c136(is_wp_error($oneApproval) && $oneApproval->get_error_code() === 'spcrc_critical_incident_dual_approval_required', 'One approval reference must never close a critical incident.');

$duplicateApproval = $coordinator->advance($incident, 'closed', 'Closure requested.', 'incident:c136-close', ['approval:human-a', 'approval:human-a']);
c136(is_wp_error($duplicateApproval) && $duplicateApproval->get_error_code() === 'spcrc_critical_incident_dual_approval_required', 'Duplicate approval references do not satisfy dual control.');

add_filter('spcrc/verify_step_up_assurance', '__return_true', 10, 4);
$closed = $coordinator->advance($incident, 'closed', 'Two-person closure approved.', 'incident:c136-close', ['approval:human-a', 'approval:human-b'], 'assertion:cycle136-fresh-stepup');
c136($closed === true, 'Two distinct opaque human approvals must permit authorized critical closure.');
$record = $repository->get($incident);
c136(is_array($record) && ($record['status'] ?? '') === 'closed', 'Critical incident must end in closed state only after dual control.');

echo "PASS: cycle136 critical-incident dual-control closure defect fixed and retested\n";
