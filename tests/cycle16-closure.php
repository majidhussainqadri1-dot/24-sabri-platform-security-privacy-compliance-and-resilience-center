<?php

declare(strict_types=1);

require __DIR__ . '/bootstrap.php';

$base = dirname(__DIR__) . '/plugin/sabri-security-center/src/';
foreach ([
    'Support/Sanitizer.php',
    'Storage/AuditGapStore.php',
    'Storage/Schema.php',
    'Storage/AuditLogger.php',
    'Registry/ModuleRegistry.php',
    'Privacy/RequestDispatcher.php',
    'Retention/RetentionManager.php',
    'System/SystemCheck.php',
] as $file) {
    require_once $base . $file;
}

use Sabri\Platform\Security\Privacy\RequestDispatcher;
use Sabri\Platform\Security\Registry\ModuleRegistry;
use Sabri\Platform\Security\Retention\RetentionManager;
use Sabri\Platform\Security\Storage\AuditGapStore;
use Sabri\Platform\Security\Storage\AuditLogger;
use Sabri\Platform\Security\System\SystemCheck;

$assertions = 0;
function expectCycle16(bool $condition, string $message): void
{
    global $assertions;
    ++$assertions;
    if (! $condition) {
        fwrite(STDERR, "FAIL: {$message}\n");
        exit(1);
    }
}

expectCycle16(! AuditGapStore::record('other_option', 'test', 'one', 'invalid_option'), 'Audit gaps must be restricted to File 24 audit-gap options.');
expectCycle16(AuditGapStore::record('spcrc_cycle16_audit_gap', 'risk', 'one', 'rollback_failed'), 'First audit gap must persist.');
expectCycle16(AuditGapStore::record('spcrc_cycle16_audit_gap', 'risk', 'two', 'rollback_failed'), 'Second audit gap must persist independently.');
expectCycle16(AuditGapStore::count('spcrc_cycle16_audit_gap') === 2, 'Independent audit gaps must not overwrite one another.');

// Generic reconciliation is capability-, step-up-, evidence- and audit-gated.
$managedGapId = (string) array_key_first(get_option('spcrc_cycle16_audit_gap', []));
$notManaged = AuditGapStore::reconcile('spcrc_cycle16_audit_gap', $managedGapId, 'vault:cycle16-proof', 'file00:stepup', new AuditLogger());
expectCycle16(is_wp_error($notManaged) && $notManaged->get_error_code() === 'spcrc_audit_gap_invalid', 'Only explicit managed categories may be reconciled.');
AuditGapStore::record('spcrc_risk_audit_gap', 'risk_uuid', '22222222-2222-4222-8222-222222222222', 'rollback_failed');
$riskGapId = (string) array_key_first(get_option('spcrc_risk_audit_gap', []));
$missingStepUp = AuditGapStore::reconcile('spcrc_risk_audit_gap', $riskGapId, 'vault:cycle16-risk-proof', 'file00:missing', new AuditLogger());
expectCycle16(is_wp_error($missingStepUp) && $missingStepUp->get_error_code() === 'spcrc_audit_gap_step_up_required', 'Audit-gap reconciliation must fail closed without fresh File 00 step-up.');
add_filter('spcrc/verify_step_up_assurance', static fn (mixed $current): bool => true, 10, 5);
$badEvidence = AuditGapStore::reconcile('spcrc_risk_audit_gap', $riskGapId, 'https://private.example/proof', 'file00:cycle16-stepup', new AuditLogger());
expectCycle16(is_wp_error($badEvidence) && $badEvidence->get_error_code() === 'spcrc_audit_gap_evidence_required', 'Reconciliation must reject arbitrary URLs instead of opaque evidence references.');
$reconciled = AuditGapStore::reconcile('spcrc_risk_audit_gap', $riskGapId, 'vault:cycle16-risk-proof', 'file00:cycle16-stepup', new AuditLogger());
expectCycle16($reconciled === true, 'Managed audit gap must reconcile after capability, step-up, private evidence and audit authorization.');
expectCycle16(AuditGapStore::count('spcrc_risk_audit_gap') === 0, 'Reconciled gap must be durably removed.');
expectCycle16(count(array_filter($GLOBALS['wpdb']->events, static fn (array $event): bool => ($event['event_type'] ?? '') === 'audit_gap_reconciliation_authorized')) >= 1, 'Reconciliation authorization must be durably audited before removal.');
expectCycle16(($GLOBALS['wpdb']->events[array_key_last($GLOBALS['wpdb']->events)]['event_type'] ?? '') === 'audit_gap_reconciled', 'Reconciliation completion must be durably audited after removal.');

AuditGapStore::record('spcrc_cycle16_sensitive_audit_gap', 'evidence', 's3://secret-bucket/private.tar', 'audit_write_failed');
$sensitive = get_option('spcrc_cycle16_sensitive_audit_gap', []);
$lastSensitive = is_array($sensitive) ? end($sensitive) : [];
expectCycle16(is_array($lastSensitive) && ($lastSensitive['entity_id'] ?? '') === '[REDACTED]', 'Sensitive entity identifiers must be redacted in gap metadata.');

for ($i = 0; $i < 110; ++$i) {
    AuditGapStore::record('spcrc_cycle16_bounded_audit_gap', 'batch', (string) $i, 'audit_write_failed');
}
expectCycle16(AuditGapStore::count('spcrc_cycle16_bounded_audit_gap') === 100, 'Audit-gap storage must be bounded to 100 entries.');

// Failed privacy audit storage must create a release-blocking operational gap.
$GLOBALS['wpdb']->failAuditInsert = true;
$dispatcher = (new ReflectionClass(RequestDispatcher::class))->newInstanceWithoutConstructor();
$auditProperty = new ReflectionProperty(RequestDispatcher::class, 'audit');
$auditProperty->setAccessible(true);
$auditProperty->setValue($dispatcher, new AuditLogger());
$recordAudit = new ReflectionMethod(RequestDispatcher::class, 'recordAudit');
$recordAudit->setAccessible(true);
$recorded = $recordAudit->invoke(
    $dispatcher,
    'privacy_request_dispatched',
    'file-24-security-center',
    'completed',
    'informational',
    ['request_uuid' => '11111111-1111-4111-8111-111111111111']
);
expectCycle16(is_wp_error($recorded), 'Forced privacy audit failure must remain visible to the caller.');
expectCycle16(AuditGapStore::count('spcrc_privacy_audit_gap') === 1, 'Privacy audit failure must create an independent release blocker.');

// Retention deletion without a durable audit event must also block release.
$retention = new RetentionManager(new AuditLogger());
$finish = new ReflectionMethod(RetentionManager::class, 'finish');
$finish->setAccessible(true);
$retentionResult = $finish->invoke($retention, 'completed', 4, 0, '');
expectCycle16(($retentionResult['status'] ?? '') === 'completed', 'Retention result semantics must remain unchanged.');
expectCycle16(AuditGapStore::count('spcrc_retention_audit_gap') === 1, 'Retention audit failure must create a release blocker.');
$GLOBALS['wpdb']->failAuditInsert = false;

$checks = (new SystemCheck(new ModuleRegistry()))->run();
$map = [];
foreach ($checks as $check) {
    $map[$check['key'] ?? ''] = $check;
}
expectCycle16(($map['audit_gaps']['status'] ?? '') === 'critical', 'System Check must fail closed for new privacy/retention/admin audit-gap categories.');
expectCycle16(str_contains((string) ($map['audit_gaps']['detail'] ?? ''), 'privacy=1'), 'System Check must report the privacy gap count.');
expectCycle16(str_contains((string) ($map['audit_gaps']['detail'] ?? ''), 'retention=1'), 'System Check must report the retention gap count.');

$sourceRoot = dirname(__DIR__) . '/plugin/sabri-security-center/src/';
$systemCheckSource = (string) file_get_contents($sourceRoot . 'System/SystemCheck.php');
$dispatcherSource = (string) file_get_contents($sourceRoot . 'Privacy/RequestDispatcher.php');
$retentionSource = (string) file_get_contents($sourceRoot . 'Retention/RetentionManager.php');
$dashboardSource = (string) file_get_contents($sourceRoot . 'Admin/Dashboard.php');
$riskSource = (string) file_get_contents($sourceRoot . 'Storage/RiskRepository.php');
$findingSource = (string) file_get_contents($sourceRoot . 'Storage/FindingRepository.php');
$incidentSource = (string) file_get_contents($sourceRoot . 'Storage/IncidentRepository.php');
$controlSource = (string) file_get_contents($sourceRoot . 'Storage/ControlRepository.php');

foreach ([
    'spcrc_privacy_audit_gap',
    'spcrc_privacy_recovery_audit_gap',
    'spcrc_retention_audit_gap',
    'spcrc_admin_audit_gap',
    'spcrc_risk_reopen_audit_gap',
    'spcrc_finding_reopen_audit_gap',
    'spcrc_governance_batch_audit_gap',
] as $option) {
    expectCycle16(str_contains($systemCheckSource, $option), "System Check must include {$option}.");
}
expectCycle16(str_contains($dispatcherSource, 'AuditGapStore::record'), 'Privacy dispatch must preserve failed audit evidence as a gap.');
expectCycle16(str_contains($retentionSource, 'AuditGapStore::record'), 'Retention must preserve failed audit evidence as a gap.');
expectCycle16(str_contains($dashboardSource, 'AuditGapStore::record'), 'Admin operations must preserve failed audit evidence as a gap.');
expectCycle16(str_contains($dashboardSource, 'spcrc_reconcile_audit_gap'), 'Private admin UI must expose a nonce-protected generic audit-gap reconciliation path.');
$gapStoreSource = (string) file_get_contents($sourceRoot . 'Storage/AuditGapStore.php');
expectCycle16(str_contains($gapStoreSource, 'spcrc/verify_step_up_assurance'), 'Generic reconciliation must require File 00 step-up verification.');
expectCycle16(str_contains($gapStoreSource, 'audit_gap_reconciliation_authorized'), 'Reconciliation authorization must be audited before gap removal.');
foreach ([$riskSource, $findingSource, $incidentSource, $controlSource] as $source) {
    expectCycle16(str_contains($source, 'AuditGapStore::record'), 'Canonical repositories must use bounded multi-gap storage.');
}
expectCycle16(! str_contains($riskSource, "update_option('spcrc_risk_audit_gap'"), 'Risk gaps must no longer use a single overwriting option shape.');
expectCycle16(! str_contains($findingSource, "update_option('spcrc_finding_audit_gap'"), 'Finding gaps must no longer use a single overwriting option shape.');
expectCycle16(! str_contains($incidentSource, "update_option('spcrc_incident_audit_gap'"), 'Incident gaps must no longer use a single overwriting option shape.');
expectCycle16(! str_contains($controlSource, "update_option('spcrc_control_audit_gap'"), 'Control gaps must no longer use a single overwriting option shape.');

echo "PASS: {$assertions} Cycle 16 closure/adversarial assertions\n";
