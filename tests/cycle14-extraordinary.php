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
    'System/SystemCheck.php',
] as $file) {
    require_once $base . $file;
}

use Sabri\Platform\Security\Capabilities;
use Sabri\Platform\Security\Registry\ModuleRegistry;
use Sabri\Platform\Security\Registry\SecurityStateRegistry;
use Sabri\Platform\Security\Storage\AuditLogger;
use Sabri\Platform\Security\Storage\ControlRepository;
use Sabri\Platform\Security\Storage\GovernanceRepository;
use Sabri\Platform\Security\Storage\Schema;
use Sabri\Platform\Security\System\SystemCheck;

$assertions = 0;
function expectCycle14(bool $condition, string $message): void
{
    global $assertions;
    ++$assertions;
    if (! $condition) {
        fwrite(STDERR, "FAIL: {$message}\n");
        exit(1);
    }
}

$root = dirname(__DIR__);
$audit = new AuditLogger();

// Update rollback is a distinct path from create rollback and must preserve the
// exact earlier control truth if the second audit insert fails.
$controls = new ControlRepository($audit);
$firstWrite = $controls->upsert([
    'control_key' => 'cycle14-control',
    'title' => 'Original control title',
    'framework' => 'NIST CSF 2.0',
    'status' => 'implemented',
]);
expectCycle14($firstWrite === 'cycle14-control', 'Initial control must be stored with audit evidence.');
$before = $GLOBALS['wpdb']->controls['cycle14-control'];
$GLOBALS['wpdb']->failAuditInsert = true;
$failedUpdate = $controls->upsert([
    'control_key' => 'cycle14-control',
    'title' => 'Changed title',
    'framework' => 'OWASP ASVS 5.0',
    'status' => 'failed',
]);
expectCycle14(is_wp_error($failedUpdate) && $failedUpdate->get_error_code() === 'spcrc_control_audit_failed', 'Control update must fail when its audit evidence fails.');
$after = $GLOBALS['wpdb']->controls['cycle14-control'];
expectCycle14(($after['title'] ?? '') === ($before['title'] ?? ''), 'Failed control audit must restore original title.');
expectCycle14(($after['framework'] ?? '') === ($before['framework'] ?? ''), 'Failed control audit must restore original framework.');
expectCycle14(($after['status'] ?? '') === ($before['status'] ?? ''), 'Failed control audit must restore original status.');
$GLOBALS['wpdb']->failAuditInsert = false;

// Governance reconciliation itself must fail closed and leave the gap intact if
// its reconciliation audit cannot be stored.
$governance = new GovernanceRepository($audit);
$decision = '88888888-8888-4888-8888-888888888888';
$GLOBALS['wpdb']->governance[$decision] = [
    'decision_uuid' => $decision,
    'decision_type' => 'policy-exception',
    'subject_key' => 'cycle14-exception',
    'module_key' => 'file-24-security-center',
    'status' => 'approved',
    'requester_user_id' => 7,
    'approver_user_id' => 8,
    'evidence_ref' => 'vault:cycle14-decision',
    'rationale_hash' => hash('sha256', 'cycle14'),
    'requested_at' => gmdate('Y-m-d H:i:s', time() - 600),
    'expires_at' => gmdate('Y-m-d H:i:s', time() + 3600),
    'decided_at' => gmdate('Y-m-d H:i:s', time() - 300),
    'revoked_at' => null,
    'lock_version' => 1,
];
$GLOBALS['wp_options']['spcrc_governance_audit_gap'] = [
    $decision => ['reason' => 'decision_audit_failed', 'recorded_at' => gmdate('c')],
];
$GLOBALS['current_user_caps']['spcrc_approve_governance_decision'] = true;
add_filter('spcrc/verify_step_up_assurance', static fn (bool $ok, int $userId, string $purpose, string $reference): bool => $reference === 'assertion:cycle14', 10, 4);
$sameRequester = $governance->reconcileAuditGap($decision, [
    'step_up_reference' => 'assertion:cycle14',
    'evidence_ref' => 'vault:cycle14-reconciliation',
    'note' => 'Reconciliation attempt.',
]);
expectCycle14(is_wp_error($sameRequester) && $sameRequester->get_error_code() === 'spcrc_governance_reconciliation_separation_failed', 'Original requester must not reconcile an audit gap.');
$GLOBALS['current_user_id'] = 8;
$GLOBALS['wpdb']->failAuditInsert = true;
$failedReconciliation = $governance->reconcileAuditGap($decision, [
    'step_up_reference' => 'assertion:cycle14',
    'evidence_ref' => 'vault:cycle14-reconciliation',
    'note' => 'Independent reconciliation attempt.',
]);
expectCycle14(is_wp_error($failedReconciliation) && $failedReconciliation->get_error_code() === 'spcrc_governance_reconciliation_audit_failed', 'Audit-gap reconciliation must fail if its own audit write fails.');
expectCycle14($governance->hasAuditGap($decision), 'Failed reconciliation must not clear the audit gap.');
$GLOBALS['wpdb']->failAuditInsert = false;
expectCycle14($governance->reconcileAuditGap($decision, [
    'step_up_reference' => 'assertion:cycle14',
    'evidence_ref' => 'vault:cycle14-reconciliation',
    'note' => 'Independent reconciliation completed after audit recovery.',
]) === true, 'Recovered reconciliation must succeed.');
expectCycle14(! $governance->hasAuditGap($decision), 'Successful reconciliation must clear the exact gap.');

// System Check must consume the same deep column verifier as activation/upgrade.
$GLOBALS['wp_options']['spcrc_schema_version'] = Schema::VERSION;
$modules = new ModuleRegistry();
expectCycle14($modules->register([
    'module_key' => 'cycle14-module',
    'name' => 'Cycle 14 Module',
    'version' => '1.0.0',
    'owner' => 'Test',
    'data_classes' => ['C1 Internal'],
    'public_routes' => [],
    'private_routes' => ['/cycle14'],
]), 'System-check module must register.');
$GLOBALS['wpdb']->missingColumns['spcrc_governance_decisions'] = ['approver_user_id'];
$checks = (new SystemCheck($modules))->run();
$schemaCheck = array_values(array_filter($checks, static fn (array $check): bool => ($check['key'] ?? '') === 'schema'))[0] ?? [];
expectCycle14(($schemaCheck['status'] ?? '') === 'critical', 'System Check must report missing governed columns as critical.');
expectCycle14(str_contains((string) ($schemaCheck['detail'] ?? ''), 'spcrc_schema_integrity_failed'), 'System Check must expose a bounded schema integrity code.');
$GLOBALS['wpdb']->missingColumns = [];

// Sensitive capabilities must remain explicit, not silently added to administrators.
Capabilities::install();
expectCycle14(empty($GLOBALS['administrator_role']->caps['spcrc_approve_governance_decision']), 'Approver capability must not be auto-granted.');
expectCycle14(empty($GLOBALS['administrator_role']->caps['spcrc_accept_critical_risk']), 'Risk-acceptance capability must not be auto-granted.');
expectCycle14(in_array('spcrc_approve_governance_decision', Capabilities::all(), true), 'Approver capability must still be a registered, assignable capability.');

// Static release-surface audit: no dynamic code execution, no unsafe source
// materializer, every admin mutation has capability and nonce checks, and public
// trust remains allowlisted.
$sourceFiles = [];
$iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root . '/plugin/sabri-security-center', FilesystemIterator::SKIP_DOTS));
foreach ($iterator as $file) {
    if ($file->isFile() && $file->getExtension() === 'php') {
        $sourceFiles[] = $file->getPathname();
    }
}
expectCycle14(count($sourceFiles) >= 30, 'Complete plugin PHP surface must be included in extraordinary review.');
$combined = implode("\n", array_map(static fn (string $file): string => (string) file_get_contents($file), $sourceFiles));
$testFiles = glob($root . '/tests/*.php') ?: [];
$php80Surface = $combined . "\n" . implode("\n", array_map(static fn (string $file): string => (string) file_get_contents($file), $testFiles));
expectCycle14(preg_match('/:\s*never\b/', $php80Surface) !== 1, 'Declared PHP 8.0 support must not use the PHP 8.1-only never return type.');
expectCycle14(preg_match('/(?:^|[^A-Za-z0-9_])true\s*\|/m', $php80Surface) !== 1, 'Declared PHP 8.0 support must not use the PHP 8.2-only standalone true union type.');
expectCycle14(! str_contains($php80Surface, 'array_is_' . 'list('), 'Declared PHP 8.0 support must not depend on the PHP 8.1-only array_is_list function.');
foreach (['eval(', 'base64_decode(', 'shell_exec(', 'passthru(', 'unserialize('] as $dangerous) {
    expectCycle14(! str_contains($combined, $dangerous), 'Dynamic or shell execution primitive must be absent: ' . $dangerous);
}
expectCycle14(! is_dir($root . '/handoff'), 'No staged handoff source bundle may remain.');
expectCycle14(! file_exists($root . '/.github/workflows/materialize-file24-cycle12.yml'), 'No self-mutating materialization workflow may remain.');

$adminFiles = glob($root . '/plugin/sabri-security-center/src/Admin/*.php') ?: [];
foreach ($adminFiles as $file) {
    $source = (string) file_get_contents($file);
    if (! str_contains($source, 'admin_post_')) {
        continue;
    }
    expectCycle14(str_contains($source, 'current_user_can') || str_contains($source, 'assertCapability'), basename($file) . ' mutations must have capability checks.');
    expectCycle14(str_contains($source, 'check_admin_referer'), basename($file) . ' mutations must have nonce checks.');
}

$statusSource = (string) file_get_contents($root . '/plugin/sabri-security-center/src/Rest/StatusController.php');
expectCycle14(str_contains($statusSource, 'Foundation candidate; production assurance pending'), 'Public trust must retain truthful candidate status.');
expectCycle14(str_contains($statusSource, 'unsupported_claims'), 'Public Trust Center must expose unsupported-claim boundaries.');
$governanceAdminSource = (string) file_get_contents($root . '/plugin/sabri-security-center/src/Admin/GovernanceAdmin.php');
expectCycle14(str_contains($governanceAdminSource, "'spcrc_view_overview'"), 'Governance menu must be visible to authorized approvers who are not requesters.');
expectCycle14(str_contains($governanceAdminSource, "current_user_can('spcrc_request_governance_decision')"), 'Governance request form must be capability-gated independently.');

$dashboardSource = (string) file_get_contents($root . '/plugin/sabri-security-center/src/Admin/Dashboard.php');
expectCycle14(! str_contains($dashboardSource, "'risk_created'"), 'Dashboard must not duplicate canonical repository success audit for risks.');
expectCycle14(! str_contains($dashboardSource, "'incident_created'"), 'Dashboard must not duplicate canonical repository success audit for incidents.');
expectCycle14(! str_contains($dashboardSource, "'control_saved'"), 'Dashboard must not duplicate canonical repository success audit for controls.');

$upgradeSource = (string) file_get_contents($root . '/plugin/sabri-security-center/src/UpgradeManager.php');
expectCycle14(str_contains($upgradeSource, 'spcrc_upgrade_lock'), 'Upgrade manager must own an atomic migration lock.');
expectCycle14(str_contains($upgradeSource, 'spcrc_downgrade_blocked'), 'Upgrade manager must block unsafe downgrade.');
expectCycle14(str_contains($upgradeSource, 'finally'), 'Upgrade lock must release on all throwable paths.');

$schemaSource = (string) file_get_contents($root . '/plugin/sabri-security-center/src/Storage/Schema.php');
expectCycle14(str_contains($schemaSource, '$tables = self::tables();'), 'Schema verifier must initialize its production table map.');
expectCycle14(substr_count($schemaSource, 'CREATE TABLE') === 9, 'Exactly nine File 24 owned tables must be declared in schema 0.25.5.');

echo "PASS: {$assertions} Cycle 14 extraordinary fresh-review assertions\n";
