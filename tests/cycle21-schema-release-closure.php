<?php

declare(strict_types=1);

require __DIR__ . '/bootstrap.php';
require_once dirname(__DIR__) . '/plugin/sabri-security-center/src/Storage/Schema.php';

use Sabri\Platform\Security\Storage\Schema;

$assertions = 0;
function expectCycle21(bool $condition, string $message): void
{
    global $assertions;
    ++$assertions;
    if (! $condition) {
        fwrite(STDERR, "FAIL: {$message}\n");
        exit(1);
    }
}

expectCycle21(Schema::verify() === true, 'The complete nine-table schema must verify.');

$criticalColumns = [
    'spcrc_security_events' => 'event_uuid',
    'spcrc_controls' => 'evidence_ref',
    'spcrc_privacy_requests' => 'lock_version',
    'spcrc_module_manifests' => 'manifest_hash',
    'spcrc_assurance_records' => 'restore_tested_at',
];
foreach ($criticalColumns as $table => $column) {
    $GLOBALS['wpdb']->missingColumns = [$table => [$column]];
    $result = Schema::verify();
    expectCycle21(is_wp_error($result), "Missing {$table}.{$column} must block schema integrity.");
    expectCycle21($result->get_error_code() === 'spcrc_schema_integrity_failed', "Missing {$table}.{$column} must use the canonical integrity error.");
    expectCycle21(str_contains($result->get_error_message(), $column), "Schema failure must identify the missing {$column} column.");
}
$GLOBALS['wpdb']->missingColumns = [];
expectCycle21(Schema::verify() === true, 'Schema verification must recover after all required columns are restored.');

$administrator = $GLOBALS['administrator_role'];
foreach (['spcrc_view_overview', 'spcrc_manage_security_settings', 'spcrc_accept_critical_risk'] as $capability) {
    $administrator->add_cap($capability);
}
foreach ([
    'spcrc_security_state_requests',
    'spcrc_last_upgrade_error',
    'spcrc_upgrade_lock',
    'spcrc_security_state_lock',
    'spcrc_retention_lock',
    'spcrc_audit_gap_store_lock',
] as $option) {
    update_option($option, ['token' => 'ephemeral', 'expires_at' => time() + 30], false);
}
update_option('spcrc_risk_audit_gap', ['gap-one' => ['reason' => 'audit_write_failed']], false);
update_option('spcrc_schema_version', Schema::VERSION, false);
set_transient('spcrc_upgrade_lock', 'legacy', 60);
set_transient('spcrc_retention_lock', 'legacy', 60);

define('WP_UNINSTALL_PLUGIN', true);
require dirname(__DIR__) . '/plugin/sabri-security-center/uninstall.php';

foreach ([
    'spcrc_security_state_requests',
    'spcrc_last_upgrade_error',
    'spcrc_upgrade_lock',
    'spcrc_security_state_lock',
    'spcrc_retention_lock',
    'spcrc_audit_gap_store_lock',
] as $option) {
    expectCycle21(get_option($option, false) === false, "Uninstall must remove ephemeral option {$option}.");
}
expectCycle21(get_transient('spcrc_upgrade_lock') === false, 'Uninstall must remove the legacy upgrade transient.');
expectCycle21(get_transient('spcrc_retention_lock') === false, 'Uninstall must remove the legacy retention transient.');
expectCycle21(get_option('spcrc_risk_audit_gap', false) !== false, 'Uninstall must preserve durable audit-gap evidence.');
expectCycle21(get_option('spcrc_schema_version', '') === Schema::VERSION, 'Uninstall must preserve schema/version evidence by policy.');
expectCycle21(! isset($administrator->caps['spcrc_manage_security_settings']), 'Uninstall must remove delegated File 24 capabilities.');

$root = dirname(__DIR__);
$plugin = (string) file_get_contents($root . '/plugin/sabri-security-center/sabri-security-center.php');
$readme = (string) file_get_contents($root . '/plugin/sabri-security-center/readme.txt');
$sbom = json_decode((string) file_get_contents($root . '/plugin/sabri-security-center/SBOM.spdx.json'), true);
$ci = (string) file_get_contents($root . '/.github/workflows/ci.yml');
$manifest = (string) file_get_contents($root . '/MANIFEST.md');
$receipt = (string) file_get_contents($root . '/docs/RELEASE-RECEIPT-0.25.8.md');

expectCycle21(str_contains($plugin, 'Version:     0.99.0') && str_contains($plugin, "define('SPCRC_VERSION', '0.99.0')"), 'Plugin header and runtime constant must agree on the current 0.99.0 release.');
expectCycle21(str_contains($readme, 'Stable tag: 0.99.0'), 'WordPress readme must expose the 0.99.0 stable tag.');
expectCycle21(($sbom['packages'][0]['versionInfo'] ?? '') === '0.99.0', 'SPDX package version must agree on the current 0.99.0 release.');
expectCycle21((str_contains($ci, 'php tests/cycle18-retention-concurrency.php') || str_contains($ci, 'find tests -maxdepth 1')), 'Permanent CI must run Cycle 18.');
expectCycle21((str_contains($ci, 'php tests/cycle19-privacy-retry-safety.php') || str_contains($ci, 'find tests -maxdepth 1')), 'Permanent CI must run Cycle 19.');
expectCycle21((str_contains($ci, 'php tests/cycle20-audit-gap-concurrency.php') || str_contains($ci, 'find tests -maxdepth 1')), 'Permanent CI must run Cycle 20.');
expectCycle21((str_contains($ci, 'php tests/cycle21-schema-release-closure.php') || str_contains($ci, 'find tests -maxdepth 1')), 'Permanent CI must run Cycle 21.');
expectCycle21(str_contains($manifest, 'Historical Cycle 18–21 evidence'), 'Source manifest must preserve the historical Cycle 18–21 evidence lineage.');
expectCycle21(str_contains($receipt, '**Review closure:** Cycle 21'), 'Historical 0.25.8 receipt must preserve Cycle 21 as its closure.');
expectCycle21(str_contains($receipt, '**Schema version:** 0.25.5'), 'Corrective runtime release must truthfully retain schema version 0.25.5.');

echo "PASS: {$assertions} Cycle 21 schema/release closure assertions\n";
