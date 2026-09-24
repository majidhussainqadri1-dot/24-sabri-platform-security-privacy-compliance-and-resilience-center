<?php

declare(strict_types=1);

namespace Sabri\Platform\Security\Integration;

use Sabri\Platform\Security\Support\Sanitizer;

/**
 * Conditional cross-file assurance contracts.
 *
 * These records do not activate CF-04, Traffic Analytics or Disease Intelligence
 * and do not transfer native ownership. They define the File 24 evidence contract
 * that must be satisfied before those planned capabilities may be activated.
 */
final class ConditionalIntegrationCatalog
{
    /** @var array<string,array<string,mixed>> */
    private const CONTRACTS = [
        'cf-04-media' => [
            'name' => 'CF-04 Central Media Processing and Secure Delivery',
            'canonical_owner' => 'cf-04-when-activated',
            'file24_role' => 'upload, provider, key, deletion and secure-delivery assurance',
            'required_controls' => [
                'native_scan_preserved', 'native_authorization_preserved', 'native_encryption_preserved',
                'upload_quarantine', 'provider_region_review', 'provider_security_review', 'provider_exit_plan',
                'credential_plan', 'rights_aware_delivery', 'short_lived_delivery', 'revocation',
                'deletion_propagation', 'audit',
            ],
            'activation_default' => 'off',
        ],
        'traffic-analytics' => [
            'name' => 'Traffic Analytics',
            'canonical_owner' => 'analytics-native-owner-when-approved',
            'file24_role' => 'privacy, security, compliance, retention, risk and incident assurance',
            'required_controls' => [
                'declared_measurement_purpose', 'data_minimization', 'optional_analytics_consent',
                'consent_withdrawal', 'no_covert_tracking', 'no_data_sale', 'no_commercial_profiling',
                'url_query_sanitization', 'no_auth_tokens_in_logs', 'minor_health_interest_profiling_forbidden',
                'export_authorization', 'sensitive_admin_step_up', 'retention_rule', 'incident_route',
            ],
            'activation_default' => 'off',
        ],
        'disease-intelligence' => [
            'name' => 'Disease Intelligence',
            'canonical_owner' => 'file-06-15-26-native-split',
            'file24_role' => 'medical-safety, privacy, incident and compliance assurance',
            'required_controls' => [
                'native_disease_truth_preserved', 'source_provenance', 'medical_review',
                'no_autonomous_diagnosis', 'no_autonomous_prescription', 'privacy_minimization',
                'ranking_policy_versioned', 'ranking_explainable', 'ranking_rollback',
                'correction_retraction_propagation', 'bot_interest_anomaly_monitor',
                'cache_index_reconciliation', 'backup_restore_rebuild_evidence', 'incident_route',
            ],
            'activation_default' => 'off',
        ],
    ];

    /** @return array<string,array<string,mixed>> */
    public static function all(): array
    {
        return self::CONTRACTS;
    }

    public static function count(): int
    {
        return count(self::CONTRACTS);
    }

    public static function repositoryCodingComplete(): bool
    {
        if (array_keys(self::CONTRACTS) !== ['cf-04-media', 'traffic-analytics', 'disease-intelligence']) {
            return false;
        }
        foreach (self::CONTRACTS as $key => $record) {
            if (
                $key === ''
                || trim((string) ($record['canonical_owner'] ?? '')) === ''
                || trim((string) ($record['file24_role'] ?? '')) === ''
                || ($record['activation_default'] ?? '') !== 'off'
                || empty($record['required_controls'])
            ) {
                return false;
            }
        }
        return true;
    }

    /** @param array<string,mixed> $evidence @return array<string,mixed> */
    public static function evaluate(string $key, array $evidence, ?int $now = null): array
    {
        $key = Sanitizer::key($key, 80);
        $contract = self::CONTRACTS[$key] ?? null;
        if (! is_array($contract)) {
            return ['key' => '', 'state' => 'unknown', 'write_allowed' => false, 'activation_allowed' => false];
        }

        $controls = Sanitizer::textList($evidence['controls'] ?? [], 100, 120);
        $missing = array_values(array_diff($contract['required_controls'], $controls));
        $contractVersion = Sanitizer::text($evidence['contract_version'] ?? '', 40);
        $evidenceRef = Sanitizer::opaqueReference($evidence['evidence_ref'] ?? '');
        $testedAt = Sanitizer::isoTime($evidence['tested_at'] ?? '');
        $nativeOwnershipPreserved = Sanitizer::boolean($evidence['native_ownership_preserved'] ?? false);
        $featureFlagOffByDefault = Sanitizer::boolean($evidence['feature_flag_off_by_default'] ?? false);

        $now ??= time();
        $tested = $testedAt === '' ? false : strtotime($testedAt);
        $fresh = $tested !== false && $tested <= $now + 300 && $tested >= $now - (90 * DAY_IN_SECONDS);
        $versionValid = preg_match('/^\d+\.\d+(?:\.\d+)?$/', $contractVersion) === 1;

        $verified = $missing === []
            && $versionValid
            && $evidenceRef !== ''
            && $fresh
            && $nativeOwnershipPreserved
            && $featureFlagOffByDefault;

        return [
            'key' => $key,
            'state' => $verified ? 'verified' : 'blocked',
            'canonical_owner' => $contract['canonical_owner'],
            'file24_role' => $contract['file24_role'],
            'missing_controls' => $missing,
            'contract_version_valid' => $versionValid,
            'evidence_ref' => $evidenceRef,
            'evidence_fresh' => $fresh,
            'native_ownership_preserved' => $nativeOwnershipPreserved,
            'feature_flag_off_by_default' => $featureFlagOffByDefault,
            'write_allowed' => $verified,
            'activation_allowed' => $verified,
        ];
    }
}
