<?php

declare(strict_types=1);

require __DIR__ . '/bootstrap.php';

use Sabri\Platform\Security\Integration\AssuranceCenterContract;
use Sabri\Platform\Security\Policy\ContinuousValueAssurance;
use Sabri\Platform\Security\Registry\ContinuousValueRequirementCatalog;

$assertions = 0;
$assert = static function (bool $condition, string $message) use (&$assertions): void {
    ++$assertions;
    if (! $condition) {
        throw new RuntimeException($message);
    }
};

$unknown = ContinuousValueAssurance::evaluate('CV-999', [
    'controls' => ['anything'],
    'evidence_ref' => 'ev:unknown:1',
    'reviewed_at' => '2026-08-08T04:00:00Z',
]);
$assert(($unknown['state'] ?? '') === 'unknown', 'Unknown CV identifiers must not be treated as compatible.');
$assert(($unknown['write_allowed'] ?? true) === false, 'Unknown CV identifiers must fail closed.');

$cookieMissingWithdrawal = ContinuousValueAssurance::evaluate('CV-268', [
    'controls' => ['necessary_category','preference_category','optional_analytics_category','no_dark_pattern'],
    'evidence_ref' => 'ev:cv268:negative',
    'reviewed_at' => '2026-08-08T04:00:00Z',
]);
$assert(($cookieMissingWithdrawal['state'] ?? '') === 'blocked', 'Cookie/tracker assurance must block without withdrawal.');
$assert(in_array('consent_withdrawal', $cookieMissingWithdrawal['missing_controls'] ?? [], true), 'Cookie/tracker assurance must report missing withdrawal.');

$pathLikeEvidence = ContinuousValueAssurance::evaluate('CV-274', [
    'controls' => ['availability_slo','latency_slo','freshness_slo','delivery_slo','recovery_slo','error_budget','public_status_evidence'],
    'evidence_ref' => '../private/slo.json',
    'reviewed_at' => '2026-08-08T04:00:00Z',
]);
$assert(($pathLikeEvidence['state'] ?? '') === 'blocked', 'Path-like evidence references must be rejected.');
$assert(($pathLikeEvidence['evidence_ref'] ?? 'x') === '', 'Rejected evidence references must not be echoed as valid references.');

$invalidDate = ContinuousValueAssurance::evaluate('CV-275', [
    'controls' => ['lcp_budget','inp_budget','cls_budget','api_p95_budget','payload_budget','db_query_budget','low_end_device_network_test'],
    'evidence_ref' => 'ev:cv275:1',
    'reviewed_at' => 'not-a-date',
]);
$assert(($invalidDate['state'] ?? '') === 'blocked', 'Unverifiable review timestamps must block performance evidence.');

$failOpen = ContinuousValueAssurance::evaluate('CV-277', [
    'controls' => ['core_read_fallback','auth_safe_fallback','downstream_degraded_state'],
    'evidence_ref' => 'ev:cv277:1',
    'reviewed_at' => '2026-08-08T04:00:00Z',
]);
$assert(($failOpen['state'] ?? '') === 'blocked', 'Graceful degradation must block any missing no-security-fail-open guarantee.');
$assert(in_array('no_security_fail_open', $failOpen['missing_controls'] ?? [], true), 'Graceful degradation must name the fail-open defect.');

$releaseWithoutCanary = ContinuousValueAssurance::evaluate('CV-279', [
    'controls' => ['local_ring','ci_ring','staging_ring','staff_ring','gradual_ring','full_ring','feature_flags','rollback_rehearsed'],
    'evidence_ref' => 'ev:cv279:1',
    'reviewed_at' => '2026-08-08T04:00:00Z',
]);
$assert(($releaseWithoutCanary['state'] ?? '') === 'blocked', 'Release-ring assurance must require the canary ring.');
$assert(in_array('canary_ring', $releaseWithoutCanary['missing_controls'] ?? [], true), 'Release-ring assurance must report a missing canary.');

$vendorNoExit = ContinuousValueAssurance::evaluate('CV-284', [
    'controls' => ['export','region','sla','security_review','subprocessors','critical_single_dependency_review'],
    'evidence_ref' => 'ev:cv284:1',
    'reviewed_at' => '2026-08-08T04:00:00Z',
]);
$assert(($vendorNoExit['state'] ?? '') === 'blocked', 'Vendor resilience must block without an exit plan.');
$assert(in_array('exit_plan', $vendorNoExit['missing_controls'] ?? [], true), 'Vendor resilience must report the missing exit plan.');

$takeover = AssuranceCenterContract::evaluate([
    'dashboards' => ['controls','evidence','exceptions','incidents','disaster_recovery'],
    'native_controls_preserved' => ['authorization','encryption','rate_limiting','validation'],
    'file24_native_control_takeover' => true,
]);
$assert(($takeover['state'] ?? '') === 'blocked', 'File 24 must never become a native-control takeover plane.');
$assert(($takeover['activation_allowed'] ?? true) === false, 'Native-control takeover must fail closed.');

$singlePoint = AssuranceCenterContract::evaluate([
    'dashboards' => ['controls','evidence','exceptions','incidents','disaster_recovery'],
    'native_controls_preserved' => ['authorization','encryption','rate_limiting','validation'],
    'security_single_point_of_failure' => true,
]);
$assert(($singlePoint['state'] ?? '') === 'blocked', 'File 24 must not be a security single point of failure.');

$publicPrivateOps = AssuranceCenterContract::evaluate([
    'dashboards' => ['controls','evidence','exceptions','incidents','disaster_recovery'],
    'native_controls_preserved' => ['authorization','encryption','rate_limiting','validation'],
    'private_operations_public' => true,
]);
$assert(($publicPrivateOps['state'] ?? '') === 'blocked', 'Private operations material must never be made public by the assurance center.');

$missingValidation = AssuranceCenterContract::evaluate([
    'dashboards' => ['controls','evidence','exceptions','incidents','disaster_recovery'],
    'native_controls_preserved' => ['authorization','encryption','rate_limiting'],
]);
$assert(($missingValidation['state'] ?? '') === 'blocked', 'Native validation must remain preserved.');
$assert(in_array('validation', $missingValidation['missing_native_controls'] ?? [], true), 'F24-CEN-01 must report missing native validation.');

foreach (ContinuousValueRequirementCatalog::all() as $id => $record) {
    $assert(($record['repository_status'] ?? '') === 'implemented', $id . ' must not carry an unresolved repository status.');
    if ($id !== 'F24-CEN-01') {
        $assert(($record['canonical_owner'] ?? '') !== 'file-24-assurance-plane', $id . ' must not silently transfer native ownership to File 24.');
    }
}

$assert(ContinuousValueRequirementCatalog::repositoryCodingComplete(), 'Adversarial review must finish with repository coding complete.');

echo "Cycle 113 Continuous Value adversarial closure passed: {$assertions} assertions.\n";
