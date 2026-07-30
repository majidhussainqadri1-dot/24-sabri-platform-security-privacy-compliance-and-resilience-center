<?php

declare(strict_types=1);

$root = dirname(__DIR__);

function fail_contract(string $message): never
{
    fwrite(STDERR, "FAIL: {$message}\n");
    exit(1);
}

function assert_contract(bool $condition, string $message): void
{
    if (! $condition) {
        fail_contract($message);
    }
}

function source(string $relative): string
{
    global $root;
    $path = $root . '/' . $relative;
    $contents = file_get_contents($path);
    if (! is_string($contents)) {
        fail_contract("Cannot read {$relative}");
    }
    return $contents;
}

$plugin = source('plugin/sabri-security-center/sabri-security-center.php');
$readme = source('plugin/sabri-security-center/readme.txt');
$capabilities = source('plugin/sabri-security-center/src/Capabilities.php');
$privacy = source('plugin/sabri-security-center/src/Privacy/RequestDispatcher.php');
$modules = source('plugin/sabri-security-center/src/Registry/ModuleRegistry.php');
$states = source('plugin/sabri-security-center/src/Registry/SecurityStateRegistry.php');
$status = source('plugin/sabri-security-center/src/Rest/StatusController.php');
$audit = source('plugin/sabri-security-center/src/Storage/AuditLogger.php');
$retention = source('plugin/sabri-security-center/src/Storage/Retention.php');
$schema = source('plugin/sabri-security-center/src/Storage/Schema.php');
$system = source('plugin/sabri-security-center/src/System/SystemCheck.php');
$upgrade = source('plugin/sabri-security-center/src/UpgradeManager.php');
$uninstall = source('plugin/sabri-security-center/uninstall.php');

assert_contract(str_contains($plugin, 'Version:     0.25.1'), 'Plugin header version mismatch.');
assert_contract(str_contains($plugin, "define('SPCRC_VERSION', '0.25.1')"), 'Runtime version mismatch.');
assert_contract(str_contains($readme, 'Stable tag: 0.25.1'), 'Readme stable tag mismatch.');
assert_contract(str_contains($schema, "public const VERSION = '0.25.1'"), 'Schema version mismatch.');

assert_contract(! str_contains($capabilities, 'map_meta_cap'), 'Blanket meta-capability bypass must not return.');
assert_contract(! str_contains($capabilities, 'FOUNDER_EMAIL'), 'Founder identity must not grant implicit privileges.');
assert_contract(str_contains($capabilities, 'removeFromAllRoles'), 'Capability cleanup contract is missing.');

assert_contract(str_contains($privacy, 'request_uuid_conflict'), 'Privacy UUID collision protection is missing.');
assert_contract(str_contains($privacy, 'request_already_exists'), 'Privacy idempotence protection is missing.');
assert_contract(str_contains($privacy, 'No module handler responded.'), 'Unhandled privacy requests must fail explicitly.');
assert_contract(str_contains($privacy, '$dispatchMetadata'), 'Privacy dispatch must use bounded metadata.');
assert_contract(! str_contains($privacy, 'secret_payload'), 'Test secret marker leaked into production source.');

assert_contract(str_contains($modules, 'authorize_module_manifest_identity_change'), 'Persisted manifest identity protection is missing.');
assert_contract(str_contains($modules, 'canonical allowlist'), 'Manifest field allowlist marker is missing.');
assert_contract(! str_contains($modules, '->replace('), 'Manifest persistence must not use blind database replace.');

assert_contract(str_contains($states, 'security_state_request_duplicate'), 'Duplicate state suppression is missing.');
assert_contract(str_contains($states, 'expires_at'), 'Persisted state expiry is missing.');
assert_contract(str_contains($states, 'resolve('), 'State resolution is missing.');

assert_contract(str_contains($status, 'private, no-store, max-age=0'), 'Private REST cache control is missing.');
assert_contract(str_contains($status, 'availabilityVerified'), 'Evidence-gated public availability is missing.');
assert_contract(str_contains($status, "'security_program' => \$payload['security_program']"), 'Canonical program status must survive extension filters.');
assert_contract(str_contains($status, "'privacy_request_available' => \$privacyAvailable"), 'Verified privacy availability must be immutable.');
assert_contract(str_contains($status, "'responsible_disclosure_available' => \$disclosureAvailable"), 'Verified disclosure availability must be immutable.');

assert_contract(str_contains($audit, 'MAX_CONTEXT_BYTES'), 'Audit context byte bound is missing.');
assert_contract(str_contains($audit, 'security_event_failed'), 'Audit persistence failure hook is missing.');
assert_contract(str_contains($audit, "'email'"), 'Sensitive identifier redaction is missing.');
assert_contract(str_contains($audit, 'Bearer [REDACTED]'), 'Bearer-token value redaction is missing.');

assert_contract(str_contains($retention, 'MAX_BATCHES'), 'Bounded retention batches are missing.');
assert_contract(str_contains($retention, 'retention_failed'), 'Retention failure evidence is missing.');
assert_contract(str_contains($schema, 'missingColumns'), 'Required-column verification is missing.');
assert_contract(str_contains($schema, 'spcrc_security_state_requests'), 'State-request persistence table is missing.');

assert_contract(str_contains($system, 'max_backup_age_seconds'), 'Backup freshness gate is missing.');
assert_contract(str_contains($system, 'max_restore_test_age_seconds'), 'Restore-test freshness gate is missing.');
assert_contract(str_contains($system, 'Boolean availability reported without structured test evidence'), 'Boolean-only assurance warning is missing.');

assert_contract(str_contains($upgrade, 'spcrc_downgrade_blocked'), 'Downgrade protection is missing.');
assert_contract(str_contains($upgrade, 'acquireLock'), 'Upgrade locking is missing.');
assert_contract(str_contains($upgrade, 'Capabilities::install'), 'Capability repair is missing.');
assert_contract(str_contains($uninstall, 'remove_cap'), 'Uninstall capability cleanup is missing.');
assert_contract(str_contains($uninstall, 'Evidence tables'), 'Non-destructive uninstall policy is missing.');

$phpFiles = [];
$iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root . '/plugin'));
foreach ($iterator as $file) {
    if ($file->isFile() && $file->getExtension() === 'php') {
        $phpFiles[] = $file->getPathname();
    }
}
assert_contract(count($phpFiles) === 16, 'Unexpected plugin PHP file count.');

foreach ($phpFiles as $path) {
    $contents = file_get_contents($path);
    assert_contract(is_string($contents) && ! preg_match('/BEGIN (RSA|EC|OPENSSH|DSA) PRIVATE KEY/', $contents), 'Private key material detected.');
}

fwrite(STDOUT, "PASS: foundation contracts\n");
