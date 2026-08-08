<?php

declare(strict_types=1);

namespace Sabri\Platform\Security\Policy;

/**
 * Evidence-shape validator for File 24 Continuous Value requirements CV-262..CV-285.
 *
 * A repository contract being implemented is not the same as external evidence being
 * verified. Callers submit current evidence; missing controls fail closed.
 */
final class ContinuousValueAssurance
{
    /** @var array<string,list<string>> */
    private const REQUIRED = [
        'CV-262' => ['identity_check','role_check','object_check','purpose_check','state_check','server_side_enforcement'],
        'CV-263' => ['tls_in_transit','sensitive_at_rest','backup_encryption','object_key_protection','rotation_test','recovery_test'],
        'CV-264' => ['no_secret_in_code','no_secret_in_logs','scoped_secret_store','rotation','access_audit','no_shared_admin_password'],
        'CV-265' => ['privileged_read_audit','privileged_write_audit','role_change_audit','moderation_audit','publication_audit','export_audit','key_event_audit','retention_policy'],
        'CV-266' => ['field_purpose','lawful_basis_or_consent','retention','recipient','deletion','no_blanket_future_use'],
        'CV-267' => ['no_data_sale','no_covert_tracking','no_behavioral_surveillance','no_hidden_profiling','aggregate_minimized_analytics'],
        'CV-268' => ['necessary_category','preference_category','optional_analytics_category','consent_withdrawal','no_dark_pattern'],
        'CV-269' => ['threat_model','code_review','sast','dast','dependency_scan','sbom','secret_scan','critical_finding_gate'],
        'CV-270' => ['responsible_disclosure','triage_sla','remediation','verification','advisory_process','no_researcher_retaliation'],
        'CV-271' => ['jurisdiction','rule','owner','evidence','review_date','change_alert','qualified_local_review_gate'],
        'CV-272' => ['encrypted_backup','restore_test','deletion_propagation','restricted_restore_access','bounded_backup_retention'],
        'CV-273' => ['detect','contain','preserve','notify','recover','lessons_learned','role_timeline','tabletop_exercise'],
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

    /** @return list<string> */
    public static function supportedIds(): array { return array_keys(self::REQUIRED); }

    /** @param array<string,mixed> $evidence @return array<string,mixed> */
    public static function evaluate(string $id, array $evidence): array
    {
        if (! isset(self::REQUIRED[$id])) {
            return ['state'=>'unknown','write_allowed'=>false,'missing_controls'=>[],'evidence_ref'=>''];
        }

        $controls = self::normalizeList($evidence['controls'] ?? []);
        $missing = array_values(array_diff(self::REQUIRED[$id], $controls));
        $evidenceRef = self::opaqueReference((string) ($evidence['evidence_ref'] ?? ''));
        $reviewedAt = self::isoTime((string) ($evidence['reviewed_at'] ?? ''));
        $state = $missing === [] && $evidenceRef !== '' && $reviewedAt !== '' ? 'verified' : 'blocked';

        return [
            'state' => $state,
            'write_allowed' => $state === 'verified',
            'missing_controls' => $missing,
            'evidence_ref' => $evidenceRef,
            'reviewed_at' => $reviewedAt,
            'external_evidence_required' => true,
        ];
    }

    /** @param mixed $value @return list<string> */
    private static function normalizeList(mixed $value): array
    {
        if (! is_array($value)) { return []; }
        $out = [];
        foreach ($value as $item) {
            if (! is_string($item)) { continue; }
            $item = strtolower(trim($item));
            if ($item === '' || preg_match('/^[a-z0-9][a-z0-9_-]{0,79}$/', $item) !== 1) { continue; }
            $out[$item] = true;
        }
        return array_keys($out);
    }

    private static function opaqueReference(string $value): string
    {
        $value = trim($value);
        if ($value === '' || strlen($value) > 160) { return ''; }
        if (str_contains($value, '/') || str_contains($value, '\\') || str_contains($value, '..')) { return ''; }
        return preg_match('/^[A-Za-z0-9][A-Za-z0-9._:-]{2,159}$/', $value) === 1 ? $value : '';
    }

    private static function isoTime(string $value): string
    {
        $value = trim($value);
        if ($value === '') { return ''; }
        $timestamp = strtotime($value);
        if ($timestamp === false) { return ''; }
        return gmdate('c', $timestamp);
    }
}
