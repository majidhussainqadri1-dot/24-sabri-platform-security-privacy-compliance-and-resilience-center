<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

use Sabri\Platform\Security\Privacy\DataGovernanceRegistry;
use Sabri\Platform\Security\Registry\GovernedArtifactRegistry;
use Sabri\Platform\Security\Storage\AuditLogger;
use Sabri\Platform\Security\Trust\TrustCenterService;

function c163(bool $condition, string $message): void { if (! $condition) { fwrite(STDERR, "FAIL: {$message}\n"); exit(1); } }

$registry = new GovernedArtifactRegistry(new AuditLogger());
$data = new DataGovernanceRegistry($registry);
$created = $data->registerDataAsset([
    'asset_key' => 'cycle163-asset', 'title' => 'Cycle 163 data asset v1', 'classification' => 'C2',
    'native_owner' => 'file-00-membership', 'retention_rule' => 'account-life', 'status' => 'draft',
]);
c163(! is_wp_error($created), 'Data-governance record must create at version one.');
$negative = $data->registerDataAsset([
    'asset_key' => 'cycle163-asset', 'title' => 'Unsafe coerced update', 'classification' => 'C2',
    'native_owner' => 'file-00-membership', 'retention_rule' => 'account-life', 'status' => 'draft', 'expected_version' => -1,
]);
c163(is_wp_error($negative) && $negative->get_error_code() === 'spcrc_data_governance_expected_version_invalid', 'Negative data-governance expected_version must be rejected instead of absint-coerced to a valid current version.');
$record = $registry->get('data-inventory', 'cycle163-asset');
c163(is_array($record) && (int) ($record['version'] ?? 0) === 1 && ($record['title'] ?? '') === 'Cycle 163 data asset v1', 'Rejected coerced version must leave the existing record unchanged.');

$GLOBALS['current_user_caps']['spcrc_manage_trust_center'] = true;
$trust = new TrustCenterService($registry);
$trustCreated = $trust->saveClaim([
    'claim_type' => 'security-overview', 'claim_key' => 'cycle163-trust', 'title' => 'Cycle 163 trust draft',
    'summary' => 'Public-safe draft.', 'status' => 'draft',
]);
c163(! is_wp_error($trustCreated), 'Trust draft must create at version one.');
$trustNegative = $trust->saveClaim([
    'claim_type' => 'security-overview', 'claim_key' => 'cycle163-trust', 'title' => 'Unsafe trust update',
    'summary' => 'Must not overwrite.', 'status' => 'draft', 'expected_version' => '-1',
]);
c163(is_wp_error($trustNegative) && $trustNegative->get_error_code() === 'spcrc_trust_claim_expected_version_invalid', 'Trust Center must reject negative/coercive expected_version input.');
$trustRecord = $registry->get('trust-claim', 'cycle163-trust');
c163(is_array($trustRecord) && (int) ($trustRecord['version'] ?? 0) === 1 && ($trustRecord['title'] ?? '') === 'Cycle 163 trust draft', 'Rejected Trust Center version must not mutate the draft.');

$dataSource = (string) file_get_contents(__DIR__ . '/../plugin/sabri-security-center/src/Privacy/DataGovernanceRegistry.php');
$trustSource = (string) file_get_contents(__DIR__ . '/../plugin/sabri-security-center/src/Trust/TrustCenterService.php');
$adminSource = (string) file_get_contents(__DIR__ . '/../plugin/sabri-security-center/src/Admin/RegistryAdmin.php');
c163(! str_contains($dataSource, "absint(" . '$data' . "['expected_version']"), 'All data-governance optimistic versions must use strict non-coercive parsing.');
c163(! str_contains($trustSource, "absint(" . '$data' . "['expected_version']"), 'Trust Center optimistic version must use strict non-coercive parsing.');
c163(! str_contains($adminSource, "absint(" . '$_POST' . "['expected_version']"), 'Admin fallback optimistic version must use strict non-coercive parsing.');
c163(str_contains($adminSource, "Sanitizer::strictInteger(" . '$_POST' . "['expected_version']"), 'Admin fallback must reject malformed/negative version input before mutation.');

echo "PASS: cycle163 optimistic-version coercion boundaries fixed across data governance, Trust Center and admin fallback\n";
