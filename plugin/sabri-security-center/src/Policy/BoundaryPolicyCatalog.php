<?php

declare(strict_types=1);

namespace Sabri\Platform\Security\Policy;

use Sabri\Platform\Security\Support\Sanitizer;

/**
 * Machine-readable cross-domain safety boundaries.
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
        'privacy-anti-surveillance' => [
            'native_owners' => ['native-data-owners', 'file-24-assurance'],
            'forbidden_in_general_context' => ['sale_of_personal_data', 'covert_tracking', 'behavioral_surveillance', 'hidden_profiling', 'security_log_monetization'],
            'required_controls' => ['declared_purpose', 'data_minimization', 'bounded_retention', 'user_notice', 'user_choice_or_valid_basis', 'deletion_reconciliation', 'annual_policy_review'],
            'high_risk_actions' => ['new_tracking_purpose', 'provider_data_transfer', 'model_training', 'security_log_secondary_use'],
        ],
        'ranking' => [
            'native_owners' => ['file-26', 'file-07-profile-source', 'file-09-verification-source'],
            'forbidden_in_general_context' => ['donation_boost', 'payment_boost', 'paid_promotion_boost', 'founder_favoritism', 'purchased_engagement'],
            'required_controls' => ['file26_owner_contract', 'versioned_policy', 'explainability', 'audit_log', 'appeal_path', 'monthly_recomputation', 'manipulation_resistance'],
            'high_risk_actions' => ['policy_activate', 'manual_override', 'bulk_recompute', 'experiment_rollout'],
        ],
        'ai-teacher' => [
            'native_owners' => ['file-16', 'file-21-22-23-publishing-contracts', 'file-26-classification'],
            'forbidden_in_general_context' => ['human_impersonation', 'verified_doctor_claim', 'undisclosed_ai_post', 'autonomous_diagnosis', 'autonomous_prescription'],
            'required_controls' => ['institutional_ai_identity', 'visible_ai_disclosure', 'human_review_first_30_days', 'corpus_allowlist', 'source_citations', 'medical_review', 'shariah_review', 'budget_cap', 'provider_failure_fallback'],
            'high_risk_actions' => ['public_publish', 'provider_change', 'corpus_expand', 'daily_cap_increase'],
        ],
        'file-transfer' => [
            'native_owners' => ['file-17', 'cf-04-when-activated'],
            'forbidden_in_general_context' => ['unverified_sender', 'unbound_recipient', 'public_original_path', 'permanent_delivery_token', 'unscanned_archive'],
            'required_controls' => ['one_gib_per_file_limit', 'verified_sender', 'authorized_recipient', 'purpose_binding', 'multipart_or_chunked', 'pause_resume', 'interruption_recovery', 'checksum', 'malware_polyglot_archive_scan', 'short_lived_grant', 'expiry', 'revocation', 'audit'],
            'high_risk_actions' => ['transfer_issue', 'recipient_change', 'grant_issue', 'quarantine_release'],
        ],
        'download' => [
            'native_owners' => ['native-content-owner', 'cf-04-when-activated'],
            'forbidden_in_general_context' => ['ineligible_content_download', 'stale_authorization', 'permanent_private_url', 'revoked_object_delivery'],
            'required_controls' => ['native_owner_eligibility', 'queue', 'progress', 'pause_resume', 'retry', 'checksum', 'range_requests', 'weak_connection_recovery', 'click_time_authorization', 'history', 'audit', 'expiry', 'revocation'],
            'high_risk_actions' => ['private_download_grant', 'bulk_export', 'offline_package', 'revocation_override'],
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

    /** @param array<string,mixed> $evidence @return array<string,mixed> */
    public static function evaluate(string $domain, array $evidence, ?int $now = null): array
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
        $now ??= time();
        $maxAgeDays = max(1, min(365, (int) apply_filters('spcrc/boundary_evidence_max_age_days', 90, Sanitizer::key($domain, 60))));
        $tested = $testedAt === '' ? false : strtotime($testedAt);
        $evidenceFresh = $tested !== false
            && $tested <= $now + 300
            && $tested >= $now - ($maxAgeDays * DAY_IN_SECONDS);
        $state = $missing === [] && $evidenceRef !== '' && $evidenceFresh
            ? 'verified'
            : ($implemented === [] ? 'unassessed' : 'incomplete');

        return [
            'domain' => Sanitizer::key($domain, 60),
            'state' => $state,
            'missing_controls' => $missing,
            'evidence_ref' => $evidenceRef,
            'tested_at' => $testedAt,
            'evidence_fresh' => $evidenceFresh,
            'max_evidence_age_days' => $maxAgeDays,
            'native_owners' => $policy['native_owners'],
            'write_allowed' => $state === 'verified',
        ];
    }
}
