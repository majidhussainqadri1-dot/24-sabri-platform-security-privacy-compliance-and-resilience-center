<?php

declare(strict_types=1);

require __DIR__ . '/bootstrap.php';

$base = dirname(__DIR__) . '/plugin/sabri-security-center/src/';
foreach ([
    'Support/Sanitizer.php',
    'Storage/Schema.php',
    'Storage/AuditLogger.php',
    'Storage/AssuranceRepository.php',
    'Storage/GovernanceRepository.php',
    'Registry/ModuleRegistry.php',
    'Registry/SecurityStateRegistry.php',
    'Storage/PrivacyRequestRepository.php',
    'Privacy/PrivacyVerificationStore.php',
    'Privacy/PrivacyRequestPolicy.php',
    'Privacy/RequestDispatcher.php',
    'System/SystemCheck.php',
] as $file) {
    require_once $base . $file;
}

use Sabri\Platform\Security\Privacy\RequestDispatcher;
use Sabri\Platform\Security\Registry\ModuleRegistry;
use Sabri\Platform\Security\Registry\SecurityStateRegistry;
use Sabri\Platform\Security\Storage\AssuranceRepository;
use Sabri\Platform\Security\Storage\AuditLogger;
use Sabri\Platform\Security\Storage\GovernanceRepository;
use Sabri\Platform\Security\Storage\Schema;
use Sabri\Platform\Security\Support\Sanitizer;
use Sabri\Platform\Security\System\SystemCheck;

$assertions = 0;
function expectCycle15(bool $condition, string $message): void
{
    global $assertions;
    ++$assertions;
    if (! $condition) {
        fwrite(STDERR, "FAIL: {$message}\n");
        exit(1);
    }
}

// The broad sensitive-material gate must recognize non-HTTP storage schemes,
// Windows paths and common Unix operational paths without rejecting ordinary text.
expectCycle15(Sanitizer::containsSensitiveMaterial('s3://private-bucket/restore.tar'), 'Cloud storage URLs must be treated as sensitive material.');
expectCycle15(Sanitizer::containsSensitiveMaterial('C:\\Backups\\restore.zip'), 'Windows filesystem paths must be treated as sensitive material.');
expectCycle15(Sanitizer::containsSensitiveMaterial('/etc/secret.conf'), 'Unix operational paths must be treated as sensitive material.');
expectCycle15(! Sanitizer::containsSensitiveMaterial('Quarterly restore rehearsal completed.'), 'Ordinary bounded operational text must remain usable.');

$audit = new AuditLogger();
$assurance = new AssuranceRepository($audit);

// The backup adapter is a final allowlist boundary. Incomplete or contradictory
// upstream input must never be upgraded to verified and unknown fields must die.
$incomplete = $assurance->backupEvidence([
    'status' => 'verified',
    'last_success_at' => gmdate('c', time() - 7200),
    'restore_tested_at' => gmdate('c', time() - 3600),
    'backup_location' => '/private/backup',
    'credential' => 'secret',
]);
expectCycle15(array_keys($incomplete) === ['status', 'last_success_at', 'restore_tested_at', 'evidence_ref'], 'Backup adapter must return only the four approved fields.');
expectCycle15(($incomplete['status'] ?? '') === 'unknown', 'Missing opaque evidence must downgrade a claimed verified backup.');
expectCycle15(! array_key_exists('backup_location', $incomplete) && ! array_key_exists('credential', $incomplete), 'Unknown and secret-like upstream fields must not survive.');

$failedWithProof = $assurance->backupEvidence([
    'status' => 'failed',
    'last_success_at' => gmdate('c', time() - 7200),
    'restore_tested_at' => gmdate('c', time() - 3600),
    'evidence_ref' => 'vault:cycle15-failed-proof',
]);
expectCycle15(($failedWithProof['status'] ?? '') === 'failed', 'A failed upstream status must not be inferred as verified from timestamps alone.');

$badChronology = $assurance->backupEvidence([
    'status' => 'verified',
    'last_success_at' => gmdate('c', time() - 3600),
    'restore_tested_at' => gmdate('c', time() - 7200),
    'evidence_ref' => 'vault:cycle15-bad-order',
]);
expectCycle15(($badChronology['status'] ?? '') === 'unknown', 'Restore evidence that predates the backup must fail closed.');

$futureProof = $assurance->backupEvidence([
    'status' => 'verified',
    'last_success_at' => gmdate('c', time() + 3600),
    'restore_tested_at' => gmdate('c', time() + 7200),
    'evidence_ref' => 'vault:cycle15-future-proof',
]);
expectCycle15(($futureProof['status'] ?? '') === 'unknown', 'Future backup/restore claims must fail closed.');

$validProof = $assurance->backupEvidence([
    'status' => 'verified',
    'last_success_at' => gmdate('c', time() - 7200),
    'restore_tested_at' => gmdate('c', time() - 3600),
    'evidence_ref' => 'vault:cycle15-valid-proof',
]);
expectCycle15(($validProof['status'] ?? '') === 'verified', 'Explicit complete chronological backup evidence may be verified.');
expectCycle15(($validProof['evidence_ref'] ?? '') === 'vault:cycle15-valid-proof', 'Only the opaque evidence reference may be exposed.');

// Assurance records are now audit-atomic: failed audit storage rolls back both
// creates and updates rather than leaving an unaudited canonical claim.
$GLOBALS['wpdb']->failAuditInsert = true;
$failedCreate = $assurance->upsert([
    'record_type' => 'backup',
    'record_key' => 'cycle15-create',
    'title' => 'Cycle 15 create',
    'status' => 'successful',
    'owner_user_id' => 7,
    'backup_completed_at' => gmdate('c', time() - 7200),
]);
expectCycle15(is_wp_error($failedCreate) && $failedCreate->get_error_code() === 'spcrc_assurance_audit_failed', 'Assurance create must fail when canonical audit evidence fails.');
expectCycle15($assurance->count() === 0, 'Failed assurance create audit must delete the canonical record.');
expectCycle15(get_option('spcrc_assurance_audit_gap', []) === [], 'Successful create rollback must not create a false audit-gap marker.');
$GLOBALS['wpdb']->failAuditInsert = false;

$created = $assurance->upsert([
    'record_type' => 'backup',
    'record_key' => 'cycle15-update',
    'title' => 'Original backup claim',
    'status' => 'scheduled',
    'owner_user_id' => 7,
]);
expectCycle15(is_string($created), 'Baseline assurance record must persist with audit evidence.');
$before = $assurance->get('backup', 'cycle15-update');
$GLOBALS['wpdb']->failAuditInsert = true;
$failedUpdate = $assurance->upsert([
    'record_type' => 'backup',
    'record_key' => 'cycle15-update',
    'title' => 'Changed backup claim',
    'status' => 'successful',
    'owner_user_id' => 7,
    'backup_completed_at' => gmdate('c', time() - 3600),
]);
expectCycle15(is_wp_error($failedUpdate) && $failedUpdate->get_error_code() === 'spcrc_assurance_audit_failed', 'Assurance update must fail when audit evidence fails.');
$after = $assurance->get('backup', 'cycle15-update');
expectCycle15(($after['title'] ?? '') === ($before['title'] ?? ''), 'Failed assurance audit must restore the prior title.');
expectCycle15(($after['status'] ?? '') === ($before['status'] ?? ''), 'Failed assurance audit must restore the prior status.');
expectCycle15(($after['backup_completed_at'] ?? '') === ($before['backup_completed_at'] ?? ''), 'Failed assurance audit must restore the prior backup timestamp.');
$GLOBALS['wpdb']->failAuditInsert = false;

// Tampered stored rows cannot create a verified public adapter claim.
$GLOBALS['wpdb']->assurance['backup:tampered'] = [
    'record_uuid' => '99999999-9999-4999-8999-999999999999',
    'record_type' => 'backup',
    'record_key' => 'tampered',
    'title' => 'Tampered row',
    'status' => 'verified',
    'owner_user_id' => 7,
    'jurisdiction' => '',
    'data_classes_json' => '[]',
    'evidence_ref' => 'https://private.example/restore',
    'notes' => 'password=must-not-render',
    'reviewed_at' => null,
    'next_review_at' => null,
    'backup_completed_at' => gmdate('Y-m-d H:i:s', time() - 7200),
    'restore_tested_at' => gmdate('Y-m-d H:i:s', time() - 3600),
    'created_at' => gmdate('Y-m-d H:i:s', time() - 7200),
    'updated_at' => gmdate('Y-m-d H:i:s', time() - 3600),
];
$tampered = $assurance->get('backup', 'tampered');
expectCycle15(($tampered['evidence_ref'] ?? 'x') === '', 'Tampered non-opaque stored evidence must be suppressed on read.');
expectCycle15(($tampered['notes'] ?? '') === '[REDACTED]', 'Tampered sensitive stored notes must be redacted on read.');
$tamperedAdapter = $assurance->backupEvidence([]);
expectCycle15(($tamperedAdapter['status'] ?? '') !== 'verified', 'Tampered stored backup evidence must not become verified adapter output.');

// System Check now requires all four facts: explicit verified status, opaque
// evidence, chronological timestamps and non-future completion.
$modules = new ModuleRegistry();
expectCycle15($modules->register([
    'module_key' => 'cycle15-module',
    'name' => 'Cycle 15 Module',
    'version' => '1.0.0',
    'owner' => 'Test',
    'data_classes' => ['C1 Internal'],
    'public_routes' => [],
    'private_routes' => ['/cycle15'],
]), 'Cycle 15 module manifest must register.');
$GLOBALS['wp_options']['spcrc_schema_version'] = Schema::VERSION;
$GLOBALS['wp_filters']['spcrc/backup_evidence'] = [];
add_filter('spcrc/backup_evidence', static fn (mixed $current): array => [
    'status' => 'verified',
    'last_success_at' => gmdate('c', time() - 7200),
    'restore_tested_at' => gmdate('c', time() - 3600),
    'evidence_ref' => '',
], 10, 1);
$map = [];
foreach ((new SystemCheck($modules))->run() as $check) $map[$check['key']] = $check;
expectCycle15(($map['backup_evidence']['status'] ?? '') === 'warning', 'System Check must reject verified backup claims without opaque evidence.');

$GLOBALS['wp_filters']['spcrc/backup_evidence'] = [];
add_filter('spcrc/backup_evidence', static fn (mixed $current): array => [
    'status' => 'verified',
    'last_success_at' => gmdate('c', time() - 7200),
    'restore_tested_at' => gmdate('c', time() - 3600),
    'evidence_ref' => 'vault:cycle15-system-check',
], 10, 1);
$map = [];
foreach ((new SystemCheck($modules))->run() as $check) $map[$check['key']] = $check;
expectCycle15(($map['backup_evidence']['status'] ?? '') === 'pass', 'System Check may pass complete chronological opaque backup evidence.');

$GLOBALS['wp_options']['spcrc_assurance_audit_gap'] = [
    '99999999-9999-4999-8999-999999999999' => ['reason' => 'rollback_failed', 'recorded_at' => gmdate('c')],
];
$map = [];
foreach ((new SystemCheck($modules))->run() as $check) $map[$check['key']] = $check;
expectCycle15(($map['audit_gaps']['status'] ?? '') === 'critical', 'Any unresolved audit-evidence gap must be a critical System Check result.');
expectCycle15(str_contains((string) ($map['audit_gaps']['detail'] ?? ''), 'assurance=1'), 'Audit-gap detail must be bounded to category and count.');
unset($GLOBALS['wp_options']['spcrc_assurance_audit_gap']);

// Boolean filter results must be parsed, not PHP-cast. The string "false"
// must never become an authorization or step-up bypass.
$GLOBALS['current_user_caps']['spcrc_approve_governance_decision'] = true;
$governance = new GovernanceRepository($audit);
$GLOBALS['wpdb']->governance['77777777-7777-4777-8777-777777777777'] = [
    'decision_uuid' => '77777777-7777-4777-8777-777777777777',
    'decision_type' => 'policy-exception',
    'subject_key' => 'cycle15-filter',
    'module_key' => 'file-24-security-center',
    'status' => 'pending',
    'requester_user_id' => 7,
    'approver_user_id' => null,
    'evidence_ref' => 'vault:cycle15-filter',
    'rationale_hash' => hash('sha256', 'cycle15'),
    'requested_at' => gmdate('Y-m-d H:i:s', time() - 600),
    'expires_at' => gmdate('Y-m-d H:i:s', time() + 3600),
    'decided_at' => null,
    'revoked_at' => null,
    'lock_version' => 0,
];
$GLOBALS['current_user_id'] = 8;
add_filter('spcrc/verify_step_up_assurance', static fn (mixed $current): string => 'false', 10, 1);
$falseStepUp = $governance->decide('77777777-7777-4777-8777-777777777777', 'approved', [
    'expected_lock_version' => 0,
    'step_up_reference' => 'assertion:cycle15-false',
    'note' => 'Bounded independent review note.',
]);
expectCycle15(is_wp_error($falseStepUp) && $falseStepUp->get_error_code() === 'spcrc_governance_step_up_required', 'String false must not satisfy governance step-up.');

unset($GLOBALS['current_user_caps']['spcrc_manage_security_settings']);
add_filter('spcrc/authorize_security_state_request', static fn (mixed $current): string => 'false', 10, 1);
$states = new SecurityStateRegistry($modules, $audit);
expectCycle15(! $states->request('cycle15-module', 'restricted-writes', ['reason' => 'Controlled Cycle 15 authorization test.']), 'String false must not authorize a security-state request.');

$GLOBALS['current_user_caps']['spcrc_manage_security_settings'] = true;
add_filter('spcrc/allow_security_state_request', static fn (mixed $current): string => 'false', 10, 1);
expectCycle15(! $states->request('cycle15-module', 'restricted-writes', ['reason' => 'Controlled Cycle 15 policy test.']), 'String false must block a security-state request even for a capable actor.');

// Expiry cleanup must not perform an unlocked durable write while another
// mutation owns the security-state lock.
$GLOBALS['wp_options']['spcrc_security_state_requests'] = [
    '66666666-6666-4666-8666-666666666666' => [
        'request_id' => '66666666-6666-4666-8666-666666666666',
        'module_key' => 'cycle15-module',
        'state' => 'restricted-writes',
        'reason' => 'Expired test state.',
        'requested_by' => 7,
        'requested_at' => gmdate('c', time() - 7200),
        'expires_at' => gmdate('c', time() - 3600),
        'status' => 'open',
    ],
];
$GLOBALS['wp_options']['spcrc_security_state_lock'] = ['token' => 'active-other-owner', 'expires_at' => time() + 30];
$lockedStates = new SecurityStateRegistry($modules, $audit);
expectCycle15($lockedStates->all() === [], 'Expired state must be hidden from reads while another mutation owns the lock.');
expectCycle15(isset($GLOBALS['wp_options']['spcrc_security_state_requests']['66666666-6666-4666-8666-666666666666']), 'Locked expiry read must not overwrite durable state without the lock.');
unset($GLOBALS['wp_options']['spcrc_security_state_lock']);
expectCycle15($lockedStates->all() === [], 'Expired state remains hidden after lock release.');
expectCycle15(get_option('spcrc_security_state_requests', []) === [], 'Lock-owning cleanup must persist expired-state removal.');

// Multiple audit gaps must be preserved rather than overwritten.
$reflection = new ReflectionClass(SecurityStateRegistry::class);
$recordGap = $reflection->getMethod('recordAuditGap');
$recordGap->setAccessible(true);
$recordGap->invoke($states, '', 'first_gap');
$recordGap->invoke($states, '', 'second_gap');
$gaps = get_option('spcrc_security_state_audit_gap', []);
expectCycle15(is_array($gaps) && count($gaps) === 2, 'Security-state audit gaps must be independently preserved.');

// Native privacy references are opaque locators, never arbitrary URLs/paths.
$dispatcherReflection = new ReflectionClass(RequestDispatcher::class);
$normalizeResult = $dispatcherReflection->getMethod('normalizeResult');
$normalizeResult->setAccessible(true);
$dispatcher = $dispatcherReflection->newInstanceWithoutConstructor();
$urlResult = $normalizeResult->invoke($dispatcher, ['ok' => true, 'status' => 'completed', 'reference' => 'https://private.example/job/1']);
expectCycle15(($urlResult['reference'] ?? 'x') === '', 'Native privacy URL references must be discarded.');
$opaqueResult = $normalizeResult->invoke($dispatcher, ['ok' => true, 'status' => 'completed', 'reference' => 'job:cycle15-001']);
expectCycle15(($opaqueResult['reference'] ?? '') === 'job:cycle15-001', 'Valid opaque native privacy references must remain available.');

// Static regression evidence for every correction in this cycle.
$assuranceSource = (string) file_get_contents($base . 'Storage/AssuranceRepository.php');
$stateSource = (string) file_get_contents($base . 'Registry/SecurityStateRegistry.php');
$governanceSource = (string) file_get_contents($base . 'Storage/GovernanceRepository.php');
$systemCheckSource = (string) file_get_contents($base . 'System/SystemCheck.php');
expectCycle15(str_contains($assuranceSource, 'spcrc_assurance_audit_failed'), 'Assurance audit-atomic failure code must remain in source.');
expectCycle15(str_contains($assuranceSource, 'normalizeBackupEvidence'), 'Backup evidence must pass through the final minimization validator.');
expectCycle15(str_contains($stateSource, 'pruneInMemory'), 'Security-state expiry cleanup must retain lock-aware separation.');
expectCycle15(str_contains($stateSource, 'Sanitizer::boolean(apply_filters'), 'Security-state filter authorization must use semantic boolean parsing.');
expectCycle15(str_contains($governanceSource, 'Sanitizer::boolean(apply_filters'), 'Governance step-up must use semantic boolean parsing.');
expectCycle15(str_contains($systemCheckSource, "'audit_gaps'"), 'System Check must retain the audit-gap release blocker.');

echo "PASS: {$assertions} Cycle 15 illuminative/adversarial assertions\n";
