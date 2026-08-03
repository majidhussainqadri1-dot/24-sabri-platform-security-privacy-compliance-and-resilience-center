<?php

declare(strict_types=1);

require __DIR__ . '/bootstrap.php';

$base = dirname(__DIR__) . '/plugin/sabri-security-center/src/';
foreach ([
    'Support/Sanitizer.php',
    'Capabilities.php',
    'Storage/Schema.php',
    'Storage/AuditLogger.php',
    'Storage/GovernanceRepository.php',
    'Storage/RiskRepository.php',
    'Storage/IncidentRepository.php',
    'Storage/ControlRepository.php',
    'Storage/FindingRepository.php',
    'Registry/ModuleRegistry.php',
    'Registry/SecurityStateRegistry.php',
] as $file) {
    require_once $base . $file;
}

use Sabri\Platform\Security\Registry\ModuleRegistry;
use Sabri\Platform\Security\Registry\SecurityStateRegistry;
use Sabri\Platform\Security\Storage\AuditLogger;
use Sabri\Platform\Security\Storage\GovernanceRepository;
use Sabri\Platform\Security\Storage\RiskRepository;
use Sabri\Platform\Security\Storage\IncidentRepository;
use Sabri\Platform\Security\Storage\ControlRepository;
use Sabri\Platform\Security\Storage\FindingRepository;
use Sabri\Platform\Security\Storage\Schema;

$assertions = 0;
function expectCycle13(bool $condition, string $message): void
{
    global $assertions;
    ++$assertions;
    if (! $condition) {
        fwrite(STDERR, "FAIL: {$message}\n");
        exit(1);
    }
}

// Real-column verification must fail closed; this catches a production-only path
// that the earlier fake database did not exercise.
expectCycle13(Schema::verify() === true, 'Complete schema column set must verify.');
$GLOBALS['wpdb']->missingColumns['spcrc_risks'] = ['acceptance_expires_at'];
$missingColumn = Schema::verify();
expectCycle13(is_wp_error($missingColumn) && $missingColumn->get_error_code() === 'spcrc_schema_integrity_failed', 'Missing governed-risk column must fail schema verification.');
$GLOBALS['wpdb']->missingColumns = [];

$registry = new ModuleRegistry();
expectCycle13($registry->register([
    'module_key' => 'state-test-module',
    'name' => 'State Test Module',
    'version' => '1.0.0',
    'owner' => 'File Test',
    'data_classes' => ['C1 Internal'],
    'public_routes' => [],
    'private_routes' => ['/private-test'],
]), 'State test module must be registered durably.');
$audit = new AuditLogger();
$states = new SecurityStateRegistry($registry, $audit);

expectCycle13(! $states->request('state-test-module', 'elevated-monitoring', ['reason' => 'password=secret']), 'Sensitive state reason must be rejected.');
expectCycle13(! $states->request('state-test-module', 'elevated-monitoring', [
    'reason' => 'Bounded monitoring request.',
    'expires_at' => gmdate('c', time() + (DAY_IN_SECONDS * 2)),
]), 'Security-state expiry beyond 24 hours must be rejected.');
expectCycle13($states->request('state-test-module', 'elevated-monitoring', ['reason' => 'Bounded monitoring request.']), 'Authorized bounded state request must succeed.');
expectCycle13(! $states->request('state-test-module', 'elevated-monitoring', ['reason' => 'Duplicate request.']), 'Duplicate open module/state request must be suppressed.');
$open = $states->all();
expectCycle13(count($open) === 1, 'Exactly one canonical state request must remain.');
$requestId = (string) array_key_first($open);

$GLOBALS['wpdb']->failInsert = true;
expectCycle13(! $states->resolve($requestId), 'State resolution must fail when its audit event cannot be stored.');
$GLOBALS['wpdb']->failInsert = false;
expectCycle13(isset($states->all()[$requestId]), 'Failed resolution audit must roll back the state removal.');
expectCycle13($states->resolve($requestId), 'State resolution must succeed after audit storage recovers.');
expectCycle13($states->all() === [], 'Resolved state must be removed from active requests.');

$GLOBALS['wpdb']->failInsert = true;
expectCycle13(! $states->request('state-test-module', 'restricted-writes', ['reason' => 'Audit rollback test.']), 'State request must fail closed when request audit storage fails.');
$GLOBALS['wpdb']->failInsert = false;
expectCycle13($states->all() === [], 'Audit-failed state request must be rolled back from durable state.');

$GLOBALS['wp_options']['spcrc_security_state_lock'] = ['token' => 'other', 'expires_at' => time() + 30];
expectCycle13(! $states->request('state-test-module', 'upload-lockdown', ['reason' => 'Concurrent lock test.']), 'Concurrent state mutation lock must fail closed.');
unset($GLOBALS['wp_options']['spcrc_security_state_lock']);

unset($GLOBALS['current_user_caps']['spcrc_manage_security_settings']);
expectCycle13(! $states->request('state-test-module', 'upload-lockdown', ['reason' => 'Unauthorized request.']), 'Unauthorized programmatic state request must be denied by default.');
add_filter('spcrc/authorize_security_state_request', static fn (bool $allowed): bool => true, 10, 1);
expectCycle13($states->request('state-test-module', 'upload-lockdown', ['reason' => 'Explicit module authorization.']), 'Explicit versioned authorization bridge may permit a module request.');
$authorizedId = (string) array_key_first($states->all());
expectCycle13(! $states->resolve($authorizedId), 'Resolution requires a separate human capability or explicit resolution authorization.');
add_filter('spcrc/authorize_security_state_resolution', static fn (bool $allowed): bool => true, 10, 1);
expectCycle13($states->resolve($authorizedId, 'superseded'), 'Explicit resolution authorization may close the state request.');

// Canonical security records must not survive without their required audit evidence.
$GLOBALS['wpdb']->failAuditInsert = true;
$incidentRollback = (new IncidentRepository($audit))->create([
    'title' => 'Audit rollback incident',
    'severity' => 'sev1',
    'summary' => 'Sanitized incident summary.',
    'evidence_ref' => 'vault:incident-cycle13',
]);
expectCycle13(is_wp_error($incidentRollback) && $incidentRollback->get_error_code() === 'spcrc_incident_audit_failed', 'Incident creation must fail when audit evidence cannot be stored.');
expectCycle13($GLOBALS['wpdb']->incidents === [], 'Audit-failed incident must be deleted.');

$controlRollback = (new ControlRepository($audit))->upsert([
    'control_key' => 'cycle13-control',
    'title' => 'Cycle 13 control',
    'status' => 'implemented',
]);
expectCycle13(is_wp_error($controlRollback) && $controlRollback->get_error_code() === 'spcrc_control_audit_failed', 'Control creation must fail when audit evidence cannot be stored.');
expectCycle13(! isset($GLOBALS['wpdb']->controls['cycle13-control']), 'Audit-failed control must be deleted.');

$riskRollback = (new RiskRepository($audit))->create([
    'title' => 'Cycle 13 risk',
    'module_key' => 'state-test-module',
    'likelihood' => 2,
    'impact' => 4,
]);
expectCycle13(is_wp_error($riskRollback) && $riskRollback->get_error_code() === 'spcrc_risk_audit_failed', 'Risk creation must fail when audit evidence cannot be stored.');
expectCycle13($GLOBALS['wpdb']->risks === [], 'Audit-failed risk must be deleted.');

$findingRollback = (new FindingRepository($audit))->create([
    'title' => 'Cycle 13 finding',
    'module_key' => 'state-test-module',
    'severity' => 'high',
]);
expectCycle13(is_wp_error($findingRollback) && $findingRollback->get_error_code() === 'spcrc_finding_audit_failed', 'Finding creation must fail when audit evidence cannot be stored.');
expectCycle13($GLOBALS['wpdb']->findings === [], 'Audit-failed finding must be deleted.');
$GLOBALS['wpdb']->failAuditInsert = false;

// Multiple audit gaps must not overwrite each other and each must fail closed.
$governance = new GovernanceRepository($audit);
$first = '55555555-5555-4555-8555-555555555555';
$second = '66666666-6666-4666-8666-666666666666';
foreach ([$first, $second] as $uuid) {
    $GLOBALS['wpdb']->governance[$uuid] = [
        'decision_uuid' => $uuid,
        'decision_type' => 'policy-exception',
        'subject_key' => $uuid === $first ? 'first-gap' : 'second-gap',
        'module_key' => 'file-24-security-center',
        'status' => 'approved',
        'requester_user_id' => 7,
        'approver_user_id' => 8,
        'evidence_ref' => 'vault:' . substr($uuid, 0, 8),
        'rationale_hash' => hash('sha256', $uuid),
        'requested_at' => gmdate('Y-m-d H:i:s', time() - 3600),
        'expires_at' => gmdate('Y-m-d H:i:s', time() + 3600),
        'decided_at' => gmdate('Y-m-d H:i:s'),
        'revoked_at' => null,
        'lock_version' => 1,
    ];
}
$GLOBALS['wp_options']['spcrc_governance_audit_gap'] = [
    $first => ['reason' => 'decision_audit_failed', 'recorded_at' => gmdate('c')],
    $second => ['reason' => 'decision_audit_failed', 'recorded_at' => gmdate('c')],
];
expectCycle13($governance->hasAuditGap($first) && $governance->hasAuditGap($second), 'Multiple governance audit gaps must be retained independently.');
expectCycle13(! $governance->isApprovedFor($first, 'policy-exception', 'first-gap'), 'First audit-gapped decision must fail closed.');
expectCycle13(! $governance->isApprovedFor($second, 'policy-exception', 'second-gap'), 'Second audit-gapped decision must fail closed.');

$GLOBALS['current_user_id'] = 8;
$GLOBALS['current_user_caps']['spcrc_approve_governance_decision'] = true;
add_filter('spcrc/verify_step_up_assurance', static fn (bool $ok, int $userId, string $purpose, string $reference): bool => $userId === 8 && $reference === 'assertion:cycle13', 10, 4);
$reconciled = $governance->reconcileAuditGap($first, [
    'step_up_reference' => 'assertion:cycle13',
    'evidence_ref' => 'vault:cycle13-reconciliation',
    'note' => 'Independent audit storage has been restored and verified.',
]);
expectCycle13($reconciled === true, 'Authorized independent reconciliation with fresh step-up must succeed.');
expectCycle13(! $governance->hasAuditGap($first) && $governance->hasAuditGap($second), 'Reconciliation must clear only its exact audit gap.');
expectCycle13($governance->isApprovedFor($first, 'policy-exception', 'first-gap'), 'Reconciled exact decision may become usable again.');
expectCycle13(! $governance->isApprovedFor($second, 'policy-exception', 'second-gap'), 'Unreconciled decision must remain unusable.');

// High-risk state transitions must roll back if their audit write fails.
$GLOBALS['current_user_caps']['spcrc_accept_critical_risk'] = true;
$riskRepository = new RiskRepository($audit, $governance);
$riskUuid = $riskRepository->create([
    'title' => 'Risk acceptance rollback',
    'module_key' => 'state-test-module',
    'likelihood' => 3,
    'impact' => 5,
]);
expectCycle13(is_string($riskUuid), 'Risk used for acceptance rollback must be created.');
$riskDecision = '77777777-7777-4777-8777-777777777777';
$GLOBALS['wpdb']->governance[$riskDecision] = [
    'decision_uuid' => $riskDecision,
    'decision_type' => 'critical-risk-acceptance',
    'subject_key' => $riskUuid,
    'module_key' => 'state-test-module',
    'status' => 'approved',
    'requester_user_id' => 7,
    'approver_user_id' => 8,
    'evidence_ref' => 'vault:risk-acceptance-cycle13',
    'rationale_hash' => hash('sha256', 'risk'),
    'requested_at' => gmdate('Y-m-d H:i:s', time() - 300),
    'expires_at' => gmdate('Y-m-d H:i:s', time() + 3600),
    'decided_at' => gmdate('Y-m-d H:i:s'),
    'revoked_at' => null,
    'lock_version' => 1,
];
$GLOBALS['wpdb']->failAuditInsert = true;
$riskAcceptance = $riskRepository->acceptRisk($riskUuid, $riskDecision, 'open');
expectCycle13(is_wp_error($riskAcceptance) && $riskAcceptance->get_error_code() === 'spcrc_risk_acceptance_audit_failed', 'Risk acceptance must fail if its critical audit event fails.');
expectCycle13(($GLOBALS['wpdb']->risks[$riskUuid]['status'] ?? '') === 'open', 'Audit-failed risk acceptance must restore the previous risk status.');
$GLOBALS['wpdb']->failAuditInsert = false;

$findingRepository = new FindingRepository($audit, $governance);
$findingUuid = $findingRepository->create([
    'title' => 'Finding transition rollback',
    'module_key' => 'state-test-module',
    'severity' => 'high',
]);
expectCycle13(is_string($findingUuid), 'Finding used for transition rollback must be created.');
$GLOBALS['wpdb']->failAuditInsert = true;
$findingTransition = $findingRepository->setStatus($findingUuid, 'triaged', [
    'expected_status' => 'open',
    'note' => 'Accountability note without sensitive material.',
]);
expectCycle13(is_wp_error($findingTransition) && $findingTransition->get_error_code() === 'spcrc_finding_status_audit_failed', 'Finding transition must fail if its audit event fails.');
expectCycle13(($GLOBALS['wpdb']->findings[$findingUuid]['status'] ?? '') === 'open', 'Audit-failed finding transition must restore the previous status.');
$GLOBALS['wpdb']->failAuditInsert = false;

// Release and uninstall evidence checks.
$root = dirname(__DIR__);
$schemaSource = (string) file_get_contents($root . '/plugin/sabri-security-center/src/Storage/Schema.php');
expectCycle13(str_contains($schemaSource, '$tables = self::tables();'), 'Production schema verifier must initialize its table map.');
$uninstallSource = (string) file_get_contents($root . '/plugin/sabri-security-center/uninstall.php');
foreach ([
    'spcrc_manage_findings',
    'spcrc_manage_assurance',
    'spcrc_request_governance_decision',
    'spcrc_approve_governance_decision',
    'spcrc_accept_critical_risk',
] as $capability) {
    expectCycle13(str_contains($uninstallSource, "'{$capability}'"), 'Uninstall must remove capability: ' . $capability);
}
expectCycle13(! str_contains($uninstallSource, 'DROP TABLE'), 'Default uninstall must remain non-destructive for assurance evidence.');

$stateSource = (string) file_get_contents($root . '/plugin/sabri-security-center/src/Registry/SecurityStateRegistry.php');
expectCycle13(str_contains($stateSource, 'spcrc/authorize_security_state_request'), 'State transitions must expose an explicit authorization contract.');
expectCycle13(str_contains($stateSource, 'containsSensitiveMaterial'), 'State reasons must be sensitive-material aware.');
expectCycle13(str_contains($stateSource, 'request_rollback_failed'), 'State request audit failure must have a rollback-gap path.');

echo "PASS: {$assertions} Cycle 13 exhaustive/adversarial assertions\n";
