<?php

declare(strict_types=1);

namespace Sabri\Platform\Security\Policy;

use Sabri\Platform\Security\Support\Sanitizer;

/** Purpose-limitation and anti-surveillance assurance policy. */
final class AntiSurveillancePolicy
{
    /** @var list<string> */
    private const PROHIBITED_USES = [
        'sale_of_personal_data',
        'covert_tracking',
        'behavioral_surveillance',
        'hidden_profiling',
        'security_log_monetization',
        'undisclosed_model_training',
        'donation_or_payment_privilege_profile',
    ];

    /** @var list<string> */
    private const REQUIRED_CONTROLS = [
        'declared_purpose',
        'data_minimization',
        'bounded_retention',
        'access_control',
        'user_notice',
        'user_choice_or_valid_basis',
        'deletion_reconciliation',
        'vendor_purpose_binding',
    ];

    /** @return list<string> */
    public static function prohibitedUses(): array
    {
        return self::PROHIBITED_USES;
    }

    /** @param array<string,mixed> $processing @return array<string,mixed> */
    public static function evaluate(array $processing): array
    {
        $uses = Sanitizer::textList($processing['uses'] ?? [], 50, 100);
        $controls = Sanitizer::textList($processing['controls'] ?? [], 80, 100);
        $violations = array_values(array_intersect(self::PROHIBITED_USES, $uses));
        $missing = array_values(array_diff(self::REQUIRED_CONTROLS, $controls));
        $evidenceRef = Sanitizer::opaqueReference($processing['evidence_ref'] ?? '');
        $reviewedAt = Sanitizer::isoTime($processing['reviewed_at'] ?? '');
        $nextReviewAt = Sanitizer::isoTime($processing['next_review_at'] ?? '');
        $annualReviewValid = IslamicGovernanceCharter::annualReviewValid($reviewedAt, $nextReviewAt);
        $state = $violations === [] && $missing === [] && $evidenceRef !== '' && $annualReviewValid
            ? 'verified'
            : (($uses === [] && $controls === []) ? 'unassessed' : 'blocked');

        return [
            'state' => $state,
            'prohibited_uses_detected' => $violations,
            'missing_controls' => $missing,
            'annual_review_valid' => $annualReviewValid,
            'evidence_ref' => $evidenceRef,
            'processing_allowed' => $state === 'verified',
        ];
    }
}
