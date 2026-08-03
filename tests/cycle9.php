<?php

declare(strict_types=1);

require __DIR__ . '/bootstrap.php';

$base = dirname(__DIR__) . '/plugin/sabri-security-center/src/';
foreach ([
    'Support/Sanitizer.php',
    'Capabilities.php',
    'Storage/Schema.php',
    'Storage/AuditLogger.php',
    'Storage/AssuranceRepository.php',
    'Registry/ModuleRegistry.php',
    'Retention/RetentionManager.php',
    'Privacy/RecoveryManager.php',
    'Storage/PrivacyRequestRepository.php',
    'Privacy/PrivacyVerificationStore.php',
    'Privacy/PrivacyRequestPolicy.php',
    'System/SystemCheck.php',
    'System/Repair.php',
] as $file) {
    require_once $base . $file;
}

use Sabri\Platform\Security\Capabilities;
use Sabri\Platform\Security\Privacy\PrivacyRequestPolicy;
use Sabri\Platform\Security\Registry\ModuleRegistry;
use Sabri\Platform\Security\Storage\AssuranceRepository;
use Sabri\Platform\Security\Storage\PrivacyRequestRepository;
use Sabri\Platform\Security\Storage\Schema;
use Sabri\Platform\Security\System\Repair;
use Sabri\Platform\Security\System\SystemCheck;

$assertions = 0;
function expectCycle9(bool $condition, string $message): void
{
    global $assertions;
    ++$assertions;
    if (! $condition) {
        fwrite(STDERR, "FAIL: {$message}\n");
        exit(1);
    }
}

expectCycle9(Schema::VERSION === '0.25.5' && count(Schema::tables()) === 9, 'Schema must expose nine File 24 tables.');
Capabilities::install();
expectCycle9(! empty($GLOBALS['administrator_role']->caps['spcrc_manage_assurance']), 'Assurance capability must be granted to administrators.');
expectCycle9(empty($GLOBALS['administrator_role']->caps['spcrc_accept_critical_risk']), 'Critical-risk acceptance must remain explicitly delegated.');

$registry = new ModuleRegistry();
$manifest = [
    'module_key' => 'test-module',
    'name' => 'Test Module',
    'version' => '1.0.0',
    'owner' => 'File Test',
    'posture' => 'foundation',
    'data_classes' => ['C1'],
    'public_routes' => [],
    'private_routes' => ['/private'],
    'privacy_operations' => ['access'],
];
expectCycle9($registry->register($manifest), 'Initial manifest must persist.');
expectCycle9($GLOBALS['wpdb']->manifestInsertCount === 1, 'Manifest must use insert, not destructive replace.');
expectCycle9($registry->register($manifest), 'Identical manifest must remain valid.');
expectCycle9($GLOBALS['wpdb']->manifestInsertCount === 1, 'Identical manifest must not insert again.');
$updated = $manifest;
$updated['version'] = '1.1.0';
expectCycle9($registry->register($updated), 'Canonical module identity may update versioned metadata.');
expectCycle9($GLOBALS['wpdb']->manifestUpdateCount === 1, 'Manifest update must be guarded.');
$collision = $updated;
$collision['owner'] = 'Other Owner';
expectCycle9(! $registry->register($collision), 'Module key must not be rebound to another owner.');
expectCycle9(($registry->get('test-module')['owner'] ?? '') === 'File Test', 'Rejected collision must not mutate runtime identity.');

$assurance = new AssuranceRepository();
$assurance->registerHooks();
$compliance = $assurance->upsert([
    'record_type' => 'compliance',
    'record_key' => 'gdpr-applicability',
    'title' => 'GDPR applicability',
    'status' => 'not-assessed',
    'owner_user_id' => 99,
    'jurisdiction' => 'European Union',
    'data_classes' => ['C2 Personal'],
    'evidence_ref' => 'vault:assessment-2026-08',
    'notes' => 'Qualified review is pending.',
    'reviewed_at' => gmdate('c', time() - 3600),
    'next_review_at' => gmdate('c', time() + 86400),
]);
expectCycle9(is_string($compliance), 'Compliance applicability metadata must persist.');
expectCycle9($assurance->count('compliance') === 1, 'Compliance count must be type-scoped.');

$sensitive = $assurance->upsert([
    'record_type' => 'vendor',
    'record_key' => 'mail-provider',
    'title' => 'Mail provider',
    'status' => 'under-review',
    'owner_user_id' => 99,
    'notes' => 'api_key=super-secret-value',
]);
expectCycle9(is_wp_error($sensitive) && $sensitive->get_error_code() === 'spcrc_assurance_notes_sensitive', 'Secret-like notes must be rejected.');

$badReview = $assurance->upsert([
    'record_type' => 'vendor',
    'record_key' => 'ai-provider',
    'title' => 'AI provider',
    'status' => 'under-review',
    'owner_user_id' => 99,
    'reviewed_at' => gmdate('c', time() - 3600),
    'next_review_at' => gmdate('c', time() - 7200),
]);
expectCycle9(is_wp_error($badReview) && $badReview->get_error_code() === 'spcrc_assurance_review_window_invalid', 'Next review must follow completed review.');

$missingReference = $assurance->upsert([
    'record_type' => 'backup',
    'record_key' => 'missing-reference',
    'title' => 'Missing reference backup',
    'status' => 'verified',
    'owner_user_id' => 99,
    'backup_completed_at' => gmdate('c', time() - 7200),
    'restore_tested_at' => gmdate('c', time() - 3600),
]);
expectCycle9(is_wp_error($missingReference) && $missingReference->get_error_code() === 'spcrc_backup_evidence_reference_missing', 'Verified backup must require an opaque evidence reference.');

$backup = $assurance->upsert([
    'record_type' => 'backup',
    'record_key' => 'site-primary',
    'title' => 'Primary backup',
    'status' => 'verified',
    'owner_user_id' => 99,
    'evidence_ref' => 'vault:restore-drill-2026-08',
    'backup_completed_at' => gmdate('c', time() - 7200),
    'restore_tested_at' => gmdate('c', time() - 3600),
]);
expectCycle9(is_string($backup), 'Verified backup must accept chronological evidence.');
$evidence = apply_filters('spcrc/backup_evidence', []);
expectCycle9(($evidence['status'] ?? '') === 'verified', 'Assurance registry must expose verified backup evidence.');
$minimized = $assurance->backupEvidence([
    'last_success_at' => gmdate('c', time() - 7200),
    'restore_tested_at' => gmdate('c', time() - 3600),
    'backup_location' => '/private/backup',
]);
expectCycle9(! array_key_exists('backup_location', $minimized), 'Backup adapter must discard unapproved fields.');
expectCycle9(empty($GLOBALS['wp_filters']['spcrc/upsert_assurance']), 'No generic write-through assurance hook may exist.');

$privacy = new PrivacyRequestPolicy(new PrivacyRequestRepository());
$before = count($GLOBALS['wpdb']->privacy);
$invalidEvidence = $privacy->begin([
    'request_uuid' => '80000000-0000-4000-8000-000000000001',
    'request_type' => 'access',
    'requester_user_id' => 7,
    'assigned_user_id' => 99,
    'verification_method' => 'manual-document-review',
    'authority_basis' => 'self',
    'verification_reference' => 'John Smith 12345',
    'verified_by_user_id' => 99,
    'verified_at' => gmdate('c'),
    'verification_attested' => true,
    'module_keys' => ['test-module'],
]);
expectCycle9(is_wp_error($invalidEvidence) && $invalidEvidence->get_error_code() === 'spcrc_privacy_verification_evidence_invalid', 'Malformed verification evidence must fail before persistence.');
expectCycle9(count($GLOBALS['wpdb']->privacy) === $before, 'Rejected verification evidence must not create a canonical row.');

$GLOBALS['wp_options']['spcrc_last_upgrade_error'] = [
    'at' => '2026-08-01T00:00:00Z',
    'error_code' => 'spcrc_test_failure',
    'from_schema' => '0.25.3',
    'target_schema' => '0.25.5',
];
$checkMap = [];
foreach ((new SystemCheck($registry))->run() as $check) {
    $checkMap[$check['key']] = $check;
}
expectCycle9(($checkMap['upgrade_error']['status'] ?? '') === 'critical', 'Structured upgrade failure must remain critical.');
expectCycle9(str_contains((string) ($checkMap['upgrade_error']['detail'] ?? ''), 'spcrc_test_failure'), 'Structured upgrade code must be rendered.');

$repaired = (new Repair())->run();
expectCycle9(is_array($repaired), 'Non-destructive repair must complete when schedules are verified.');
expectCycle9(($repaired['retention_schedule_verified'] ?? false) === true, 'Repair must verify retention schedule.');
expectCycle9(($repaired['privacy_recovery_schedule_verified'] ?? false) === true, 'Repair must verify privacy recovery schedule.');
expectCycle9(get_option('spcrc_schema_version') === '0.25.5' && get_option('spcrc_version') === '0.26.0', 'Repair must verify version truth.');

$pluginSource = file_get_contents(dirname(__DIR__) . '/plugin/sabri-security-center/src/Plugin.php');
$registrySource = file_get_contents(dirname(__DIR__) . '/plugin/sabri-security-center/src/Registry/ModuleRegistry.php');
$assuranceSource = file_get_contents(dirname(__DIR__) . '/plugin/sabri-security-center/src/Storage/AssuranceRepository.php');
expectCycle9(is_string($pluginSource) && ! str_contains($pluginSource, '$repair->registerHooks()'), 'Boot must not call nonexistent Repair hook method.');
expectCycle9(is_string($registrySource) && ! str_contains($registrySource, '$wpdb->replace'), 'Manifest persistence must not use replace semantics.');
expectCycle9(is_string($assuranceSource) && ! str_contains($assuranceSource, "add_action('spcrc/"), 'Assurance registry must not expose generic mutation action.');

echo "PASS: {$assertions} Cycle 9 corrective and adversarial assertions\n";
