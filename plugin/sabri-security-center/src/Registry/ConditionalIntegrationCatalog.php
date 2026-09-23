<?php

declare(strict_types=1);

namespace Sabri\Platform\Security\Registry;

use Sabri\Platform\Security\Support\Sanitizer;

/**
 * Machine-readable File-24 assurance contracts for approved conditional plans.
 *
 * These records never activate a conditional module and never transfer native
 * domain ownership to File 24. They define the evidence File 24 must require
 * before an activation request can be treated as compatible.
 */
final class ConditionalIntegrationCatalog
{
    /** @var array<string,array<string,mixed>> */
    private const INTEGRATIONS = [
        'traffic-analytics' => [
            'plan_id' => 'SSH-XPLAN-TA-2026-v1.0',
            'native_owner' => 'traffic analytics conditional owner when separately activated',
            'file24_role' => 'privacy, security, compliance, retention, risk and incident assurance',
            'contract_version' => '1.0.0',
            'required_controls' => [
                'privacy_by_purpose',
                'retention_policy',
                'consent_withdrawal',
                'anti_surveillance',
                'url_token_sanitization',
                'transient_ip_or_justified',
                'minors_health_interest_restriction',
                'export_authorization',
                'admin_step_up',
                'data_poisoning_detection',
                'incident_risk_governance',
            ],
        ],
        'disease-intelligence' => [
            'plan_id' => 'SSH-XPLAN-DI-2026-v1.0',
            'native_owner' => 'File 06 disease truth with File 15 trends and File 26 derived ranking projections',
            'file24_role' => 'medical-safety, privacy, incident, compliance and assurance governance',
            'contract_version' => '1.0.0',
            'required_controls' => [
                'medical_safety',
                'privacy_boundary',
                'incident_governance',
                'compliance_assurance',
                'source_provenance',
                'ranking_explainability',
                'anti_manipulation',
                'correction_retraction_propagation',
                'no_autonomous_treatment',
                'native_owner_preserved',
            ],
        ],
        'cf-04-central-media' => [
            'plan_id' => 'CF-04-2026-v1.1',
            'native_owner' => 'CF-04 central media processing and secure delivery when separately activated',
            'file24_role' => 'upload, provider, key, deletion, rights and secure-delivery assurance',
            'contract_version' => '1.1.0',
            'required_controls' => [
                'upload_assurance',
                'provider_assurance',
                'key_assurance',
                'deletion_assurance',
                'native_scan_preserved',
                'native_auth_preserved',
                'native_encryption_preserved',
                'region_contract',
                'exit_plan',
                'credential_plan',
                'rights_aware_delivery',
                'revocation',
            ],
        ],
    ];

    /** @return array<string,array<string,mixed>> */
    public static function all(): array
    {
        return self::INTEGRATIONS;
    }

    /** @return array<string,mixed>|null */
    public static function get(string $key): ?array
    {
        $key = Sanitizer::key($key, 80);
        return self::INTEGRATIONS[$key] ?? null;
    }

    public static function repositoryCodingComplete(): bool
    {
        if (count(self::INTEGRATIONS) !== 3) {
            return false;
        }

        foreach (self::INTEGRATIONS as $key => $record) {
            if ($key === '' || empty($record['plan_id']) || empty($record['native_owner']) || empty($record['file24_role'])) {
                return false;
            }
            if (preg_match('/^\d+\.\d+(?:\.\d+)?$/', (string) ($record['contract_version'] ?? '')) !== 1) {
                return false;
            }
            $controls = $record['required_controls'] ?? [];
            if (! is_array($controls) || $controls === [] || count($controls) !== count(array_unique($controls))) {
                return false;
            }
        }

        return true;
    }

    /**
     * @param array<string,mixed> $evidence
     * @return array<string,mixed>
     */
    public static function evaluate(string $key, array $evidence, ?int $now = null): array
    {
        $record = self::get($key);
        if (! is_array($record)) {
            return [
                'integration' => '',
                'state' => 'unknown',
                'activation_allowed' => false,
                'write_allowed' => false,
                'missing_controls' => ['unknown_integration'],
            ];
        }

        $controls = self::strictList($evidence['controls'] ?? [], 100, 100);
        if (is_wp_error($controls)) {
            return [
                'integration' => $key,
                'state' => 'blocked',
                'activation_allowed' => false,
                'write_allowed' => false,
                'missing_controls' => ['invalid_control_evidence'],
                'error' => $controls->get_error_code(),
            ];
        }

        $required = (array) $record['required_controls'];
        $missing = array_values(array_diff($required, $controls));
        $contractVersion = Sanitizer::text($evidence['contract_version'] ?? '', 40);
        $contractCompatible = preg_match('/^\d+\.\d+(?:\.\d+)?$/', $contractVersion) === 1
            && version_compare($contractVersion, (string) $record['contract_version'], '>=');
        $evidenceRef = Sanitizer::opaqueReference($evidence['evidence_ref'] ?? '');
        $reviewedAt = Sanitizer::isoTime($evidence['reviewed_at'] ?? '');
        $now ??= time();
        $reviewed = $reviewedAt === '' ? false : strtotime($reviewedAt);
        $fresh = $reviewed !== false
            && $reviewed <= $now + 300
            && $reviewed >= $now - (90 * DAY_IN_SECONDS);
        $nativeOwnerPreserved = Sanitizer::boolean($evidence['native_owner_preserved'] ?? false);
        $activationRequested = Sanitizer::boolean($evidence['activation_requested'] ?? false);

        $verified = $missing === []
            && $contractCompatible
            && $evidenceRef !== ''
            && $fresh
            && $nativeOwnerPreserved;

        return [
            'integration' => $key,
            'plan_id' => $record['plan_id'],
            'state' => $verified ? ($activationRequested ? 'verified' : 'ready-for-activation-review') : 'blocked',
            'activation_requested' => $activationRequested,
            'activation_allowed' => $activationRequested && $verified,
            'write_allowed' => $activationRequested && $verified,
            'native_owner' => $record['native_owner'],
            'file24_role' => $record['file24_role'],
            'missing_controls' => $missing,
            'contract_compatible' => $contractCompatible,
            'evidence_ref' => $evidenceRef,
            'evidence_fresh' => $fresh,
            'native_owner_preserved' => $nativeOwnerPreserved,
        ];
    }

    /** @return list<string>|\WP_Error */
    private static function strictList(mixed $value, int $maxItems, int $maxLength): array|\WP_Error
    {
        if (! is_array($value) || ($value !== [] && array_keys($value) !== range(0, count($value) - 1))) {
            return new \WP_Error('spcrc_conditional_controls_invalid', 'Conditional integration controls must be a sequential list.');
        }
        if (count($value) > $maxItems) {
            return new \WP_Error('spcrc_conditional_controls_limit', 'Conditional integration control evidence exceeds its bounded maximum.');
        }

        $out = [];
        foreach ($value as $item) {
            if (! is_string($item)) {
                return new \WP_Error('spcrc_conditional_control_invalid', 'Conditional integration control identifiers must be strings.');
            }
            $item = Sanitizer::key($item, $maxLength);
            if ($item === '' || isset($out[$item])) {
                return new \WP_Error('spcrc_conditional_control_invalid', 'Conditional integration controls must be non-empty and unique.');
            }
            $out[$item] = true;
        }
        return array_keys($out);
    }
}
