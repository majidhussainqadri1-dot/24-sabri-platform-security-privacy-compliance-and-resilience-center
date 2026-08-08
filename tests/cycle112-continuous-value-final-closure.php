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

$assert(ContinuousValueRequirementCatalog::count() === 25, 'Continuous Value catalogue must contain CV-262..CV-285 plus F24-CEN-01.');
$assert(ContinuousValueRequirementCatalog::repositoryCodingComplete(), 'Continuous Value repository coding closure must be complete.');

$ids = ContinuousValueRequirementCatalog::ids();
for ($id = 262; $id <= 285; ++$id) {
    $key = 'CV-' . $id;
    $assert(in_array($key, $ids, true), $key . ' must be represented.');
    $record = ContinuousValueRequirementCatalog::get($key);
    $assert(is_array($record), $key . ' must resolve to a record.');
    $assert(($record['canonical_owner'] ?? '') !== '', $key . ' must preserve canonical ownership.');
    $assert(($record['file24_role'] ?? '') !== '', $key . ' must define the bounded File 24 assurance role.');
}
$assert(ContinuousValueRequirementCatalog::get('F24-CEN-01') !== null, 'F24-CEN-01 must be represented.');

$verifiedFixtures = [
    'CV-268' => ['necessary_category','preference_category','optional_analytics_category','consent_withdrawal','no_dark_pattern'],
    'CV-274' => ['availability_slo','latency_slo','freshness_slo','delivery_slo','recovery_slo','error_budget','public_status_evidence'],
    'CV-275' => ['lcp_budget','inp_budget','cls_budget','api_p95_budget','payload_budget','db_query_budget','low_end_device_network_test'],
    'CV-276' => ['metrics','structured_logs','traces','synthetic_journeys','anomaly_detection','privacy_redaction','no_pii_in_logs'],
    'CV-277' => ['core_read_fallback','auth_safe_fallback','downstream_degraded_state','no_security_fail_open'],
    'CV-278' => ['rpo_by_data_class','rto_by_data_class','immutable_copy','quarterly_restore_evidence','snapshot_not_domain_backup'],
    'CV-279' => ['local_ring','ci_ring','staging_ring','staff_ring','canary_ring','gradual_ring','full_ring','feature_flags','rollback_rehearsed'],
    'CV-280' => ['review_round_1','review_round_2','fix_after_each_review','retest_after_fix','zero_known_defect_or_founder_risk_acceptance'],
    'CV-281' => ['help_articles','ticket','status','escalation','multilingual_sla','not_medical_emergency_channel'],
    'CV-282' => ['storage_forecast','transcode_forecast','ai_forecast','search_forecast','realtime_forecast','bandwidth_forecast','caps_without_quality_safety_cut'],
    'CV-283' => ['versioned_schema','dry_run','backup','verification','rollback','no_duplicate_live_owner'],
    'CV-284' => ['exit_plan','export','region','sla','security_review','subprocessors','critical_single_dependency_review'],
    'CV-285' => ['incident_severity','contact_path','diagnosis_steps','recovery_steps','communication_plan','postmortem','blameless_and_accountable'],
];

foreach ($verifiedFixtures as $id => $controls) {
    $result = ContinuousValueAssurance::evaluate($id, [
        'controls' => $controls,
        'evidence_ref' => 'ev:' . strtolower(str_replace('-', '', $id)) . ':1',
        'reviewed_at' => '2026-08-08T04:00:00Z',
    ]);
    $assert(($result['state'] ?? '') === 'verified', $id . ' complete evidence must verify.');
    $assert(($result['write_allowed'] ?? false) === true, $id . ' verified evidence must permit the governed action.');
}

$center = AssuranceCenterContract::evaluate([
    'dashboards' => ['controls','evidence','exceptions','incidents','disaster_recovery'],
    'native_controls_preserved' => ['authorization','encryption','rate_limiting','validation'],
    'file24_native_control_takeover' => false,
    'security_single_point_of_failure' => false,
    'private_operations_public' => false,
]);
$assert(($center['state'] ?? '') === 'compatible', 'F24-CEN-01 complete manifest must be compatible.');
$assert(($center['activation_allowed'] ?? false) === true, 'F24-CEN-01 complete manifest must be activatable.');

$summary = ContinuousValueRequirementCatalog::summary();
$assert(($summary['cv_262_285'] ?? 0) === 24, 'Exactly 24 CV requirements must be mapped.');
$assert(($summary['file_specific'] ?? 0) === 1, 'Exactly one File-specific requirement must be mapped.');
$assert(($summary['external_acceptance_required'] ?? false) === true, 'External acceptance must remain a separate evidence gate.');

echo "Cycle 112 Continuous Value final closure passed: {$assertions} assertions.\n";
