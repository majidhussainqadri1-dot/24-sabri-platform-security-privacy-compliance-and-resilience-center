<?php

declare(strict_types=1);

namespace Sabri\Platform\Security\Future;

use Sabri\Platform\Security\Support\Sanitizer;

final class FutureSecurityAssurance
{
    /** @var array<string,string[]> */
    private const REQUIRED = [
        'F24-FUT-001' => ['crypto_inventory', 'pqc_risk_classification', 'migration_plan', 'provider_readiness'],
        'F24-FUT-002' => ['algorithm_registry', 'dependency_mapping', 'rotation_contract', 'rollback_plan'],
        'F24-FUT-003' => ['algorithm_inventory', 'key_purpose_metadata', 'retention_horizon', 'custodian_mapping'],
        'F24-FUT-004' => ['typed_nodes', 'bounded_edges', 'owner_mapping', 'privacy_minimization'],
        'F24-FUT-005' => ['graph_snapshot', 'source_assets', 'target_assets', 'risk_dimensions', 'mitigation_links'],
        'F24-FUT-006' => ['domain_inventory', 'endpoint_inventory', 'certificate_inventory', 'orphan_detection', 'ownership'],
        'F24-FUT-007' => ['control_id', 'coverage', 'evidence_freshness', 'owner', 'failure_state'],
        'F24-FUT-008' => ['policy_version', 'declarative_rule', 'native_owner', 'test_fixture', 'default_deny'],
        'F24-FUT-009' => ['data_inventory', 'data_classification', 'location_mapping', 'retention_state', 'access_posture'],
        'F24-FUT-010' => ['data_classes', 'detector_results', 'destination_class', 'purpose', 'native_decision'],
        'F24-FUT-011' => ['epsilon_budget', 'minimum_cohort', 'clipping', 'no_raw_rows', 'privacy_review'],
        'F24-FUT-012' => ['clean_room_boundary', 'approved_queries', 'no_raw_export', 'output_review', 'audit'],
        'F24-FUT-013' => ['workload_identity', 'purpose', 'least_privilege', 'credential_lifetime', 'rotation'],
        'F24-FUT-014' => ['requested_scope', 'time_limit', 'step_up', 'approval', 'automatic_revoke'],
        'F24-FUT-015' => ['isolated_copy', 'immutability', 'integrity_check', 'clean_restore', 'recovery_test'],
        'F24-FUT-016' => ['failure_scenario', 'blast_radius_limit', 'abort_condition', 'observability', 'recovery_evidence'],
        'F24-FUT-017' => ['authorized_scope', 'safe_environment', 'attack_scenario', 'finding_capture', 'remediation_retest'],
        'F24-FUT-018' => ['decoy_inventory', 'non_user_surveillance', 'high_confidence_signal', 'rotation', 'incident_route'],
        'F24-FUT-019' => ['severity', 'known_exploitation', 'reachability', 'asset_criticality', 'data_sensitivity', 'attack_path'],
        'F24-FUT-020' => ['sbom_component', 'vex_status', 'justification', 'source_advisory', 'review_time'],
        'F24-FUT-021' => ['source_commit', 'builder_identity', 'artifact_digest', 'signed_attestation', 'provenance_level'],
        'F24-FUT-022' => ['agent_identity', 'tool_allowlist', 'data_scope', 'action_budget', 'network_policy', 'human_approval'],
        'F24-FUT-023' => ['model_version', 'provider', 'prompt_version', 'tool_registry', 'knowledge_sources', 'retention_region'],
        'F24-FUT-024' => ['claim', 'argument', 'evidence_refs', 'owner', 'reviewed_at', 'freshness'],
        'F24-FUT-025' => ['action_type', 'risk_level', 'reversible', 'preview', 'rollback_reference', 'approval_policy'],
    ];

    /** @return string[] */
    public static function supportedIds(): array
    {
        return array_keys(self::REQUIRED);
    }

    /** @param array<string,mixed> $evidence
     *  @return array<string,mixed>
     */
    public static function evaluate(string $id, array $evidence): array
    {
        $id = strtoupper(trim($id));
        $catalog = FutureSecurityCapabilityCatalog::get($id);
        if ($catalog === null || ! isset(self::REQUIRED[$id])) {
            return self::result($id, 'unknown', false, [], '', '', false, ['unknown_capability']);
        }

        $missing = [];
        foreach (self::REQUIRED[$id] as $control) {
            if (! self::meaningful($evidence[$control] ?? null)) {
                $missing[] = $control;
            }
        }

        $evidenceRef = Sanitizer::opaqueReference($evidence['evidence_ref'] ?? '');
        $reviewedAt = Sanitizer::isoTime($evidence['reviewed_at'] ?? '');
        if ($evidenceRef === '') {
            $missing[] = 'evidence_ref';
        }
        if ($reviewedAt === '' || ! self::fresh($reviewedAt, $evidence['max_age_days'] ?? 90)) {
            $missing[] = 'reviewed_at';
        }

        $missing = array_values(array_unique($missing));
        $verified = $missing === [];
        return self::result(
            $id,
            $verified ? 'verified' : 'incomplete',
            $verified,
            $missing,
            $evidenceRef,
            $reviewedAt,
            ! empty($catalog['external_evidence']),
            []
        );
    }

    private static function meaningful(mixed $value): bool
    {
        if (is_bool($value)) {
            return $value;
        }
        if (is_int($value) || is_float($value)) {
            return $value >= 0;
        }
        if (is_string($value)) {
            return trim($value) !== '' && ! Sanitizer::containsSensitiveMaterial($value);
        }
        if (is_array($value)) {
            return $value !== [];
        }
        return false;
    }

    private static function fresh(string $reviewedAt, mixed $maxAgeDays): bool
    {
        $timestamp = strtotime($reviewedAt);
        if ($timestamp === false || $timestamp > time() + 300) {
            return false;
        }
        $days = max(1, min(365, (int) $maxAgeDays));
        return $timestamp >= time() - ($days * 86400);
    }

    /** @param string[] $missing
     *  @param string[] $errors
     *  @return array<string,mixed>
     */
    private static function result(string $id, string $state, bool $writeAllowed, array $missing, string $evidenceRef, string $reviewedAt, bool $external, array $errors): array
    {
        return [
            'capability_id' => $id,
            'state' => $state,
            'write_allowed' => $writeAllowed,
            'missing_controls' => $missing,
            'evidence_ref' => $evidenceRef,
            'reviewed_at' => $reviewedAt,
            'external_evidence_required' => $external,
            'errors' => $errors,
            'native_enforcement_preserved' => true,
        ];
    }
}
