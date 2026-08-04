<?php

declare(strict_types=1);

namespace Sabri\Platform\Security\Policy;

use Sabri\Platform\Security\Support\Sanitizer;

/**
 * Machine-readable cross-domain safety boundaries required by F24-R051–R060.
 * Native owners remain authoritative; File 24 only evaluates assurance evidence.
 */
final class BoundaryPolicyCatalog
{
    /** @var array<string,array<string,mixed>> */
    private const DOMAINS = [
        'clinical' => [
            'native_owners' => ['file-08', 'cf-01-when-activated'],
            'forbidden_in_general_context' => ['patient_identity', 'clinical_note', 'prescription', 'consent_evidence'],
            'required_controls' => ['treating_relationship', 'minimum_necessary', 'no_store', 'noindex', 'access_history', 'de_identification'],
            'high_risk_actions' => ['break_glass', 'export', 'correction', 'publication'],
        ],
        'messaging' => [
            'native_owners' => ['file-17'],
            'forbidden_in_general_context' => ['message_body', 'private_attachment_path', 'turn_secret'],
            'required_controls' => ['file00_02_binding', 'idor_check', 'private_storage', 'scanner', 'deletion_replay', 'ephemeral_turn'],
            'high_risk_actions' => ['private_attachment_delivery', 'call_credential_issue', 'bulk_export'],
        ],
        'ai' => [
            'native_owners' => ['file-15', 'file-16'],
            'forbidden_in_general_context' => ['identity_document', 'patient_record', 'private_message', 'payment_data', 'credential_material'],
            'required_controls' => ['corpus_allowlist', 'retrieval_acl', 'source_citation', 'prompt_injection_defense', 'provider_retention_policy', 'deletion_propagation'],
            'high_risk_actions' => ['provider_transfer', 'tool_execution', 'public_publish'],
        ],
        'marketplace' => [
            'native_owners' => ['file-18'],
            'forbidden_in_general_context' => ['pan', 'cvv', 'payment_secret', 'hidden_commission'],
            'required_controls' => ['seller_verification', 'prohibited_goods', 'safe_contact', 'fraud_report', 'appeal', 'zero_commission'],
            'high_risk_actions' => ['seller_contact_release', 'listing_restore', 'future_payment_adapter'],
        ],
        'publishing' => [
            'native_owners' => ['file-21', 'file-22', 'file-23'],
            'forbidden_in_general_context' => ['fake_founder_badge', 'patient_identity', 'unreviewed_medical_claim'],
            'required_controls' => ['step_up_for_founder', 'source_integrity', 'correction_ledger', 'retraction_ledger', 'malicious_link_scan', 'privacy_scan'],
            'high_risk_actions' => ['direct_publish', 'correction', 'retraction', 'badge_change'],
        ],
        'abuse' => [
            'native_owners' => ['file-00', 'file-17', 'file-18', 'file-21'],
            'forbidden_in_general_context' => ['permanent_unappealable_block', 'secret_rate_limit_bypass'],
            'required_controls' => ['bounded_rate_limit', 'progressive_challenge', 'quota', 'anomaly_detection', 'appeal', 'resource_budget'],
            'high_risk_actions' => ['mass_block', 'mass_report_resolution', 'waf_rule_change'],
        ],
    ];

    /** @return array<string,array<string,mixed>> */
    public static function all(): array
    {
        return self::DOMAINS;
    }

    /** @return array<string,mixed>|null */
    public static function get(string $domain): ?array
    {
        $domain = Sanitizer::key($domain, 60);
        return self::DOMAINS[$domain] ?? null;
    }

    /**
     * @param array<string,mixed> $evidence
     * @return array<string,mixed>
     */
    public static function evaluate(string $domain, array $evidence): array
    {
        $policy = self::get($domain);
        if (! is_array($policy)) {
            return ['domain' => '', 'state' => 'blocked', 'missing_controls' => ['unknown_domain']];
        }

        $implemented = Sanitizer::textList($evidence['controls'] ?? [], 100, 100);
        $missing = [];
        foreach ((array) $policy['required_controls'] as $control) {
            if (! in_array($control, $implemented, true)) {
                $missing[] = $control;
            }
        }

        $evidenceRef = Sanitizer::opaqueReference($evidence['evidence_ref'] ?? '');
        $testedAt = Sanitizer::isoTime($evidence['tested_at'] ?? '');
        $state = $missing === [] && $evidenceRef !== '' && $testedAt !== '' && strtotime($testedAt) <= time() + 300
            ? 'verified'
            : ($implemented === [] ? 'unassessed' : 'incomplete');

        return [
            'domain' => Sanitizer::key($domain, 60),
            'state' => $state,
            'missing_controls' => $missing,
            'evidence_ref' => $evidenceRef,
            'tested_at' => $testedAt,
            'native_owners' => $policy['native_owners'],
            'write_allowed' => $state === 'verified',
        ];
    }
}
