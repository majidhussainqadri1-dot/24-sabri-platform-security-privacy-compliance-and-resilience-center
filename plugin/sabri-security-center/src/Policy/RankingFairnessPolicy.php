<?php

declare(strict_types=1);

namespace Sabri\Platform\Security\Policy;

use Sabri\Platform\Security\Support\Sanitizer;

/** File 24 assurance gate for File 26 doctor-ranking policy and evidence. */
final class RankingFairnessPolicy
{
    public const MAX_RECOMPUTE_AGE_DAYS = 31;

    /** @var list<string> */
    private const FORBIDDEN_INFLUENCES = [
        'donation',
        'payment',
        'paid_promotion',
        'founder_favoritism',
        'purchased_engagement',
        'undisclosed_manual_boost',
    ];

    /** @var list<string> */
    private const REQUIRED_CONTROLS = [
        'file26_owner_contract',
        'versioned_policy',
        'explainability',
        'audit_log',
        'appeal_path',
        'manipulation_resistance',
        'verified_review_weighting',
        'monthly_recomputation',
        'donation_independence',
        'payment_independence',
        'founder_non_favoritism',
    ];

    /** @param array<string,mixed> $evidence @return array<string,mixed> */
    public static function evaluate(array $evidence, ?int $now = null): array
    {
        $now ??= time();
        $controls = Sanitizer::textList($evidence['controls'] ?? [], 80, 100);
        $influences = Sanitizer::textList($evidence['influences'] ?? [], 40, 100);
        $missing = array_values(array_diff(self::REQUIRED_CONTROLS, $controls));
        $forbidden = array_values(array_intersect(self::FORBIDDEN_INFLUENCES, $influences));
        $policyVersion = Sanitizer::text($evidence['policy_version'] ?? '', 40);
        $evidenceRef = Sanitizer::opaqueReference($evidence['evidence_ref'] ?? '');
        $testedAt = Sanitizer::isoTime($evidence['tested_at'] ?? '');
        $recomputedAt = Sanitizer::isoTime($evidence['recomputed_at'] ?? '');
        $recomputed = $recomputedAt === '' ? false : strtotime($recomputedAt);
        $fresh = $recomputed !== false && $recomputed <= $now + 300 && ($now - $recomputed) <= self::MAX_RECOMPUTE_AGE_DAYS * DAY_IN_SECONDS;
        $versionValid = preg_match('/^[0-9]+(?:\.[0-9]+){0,3}(?:-[a-z0-9.-]+)?$/i', $policyVersion) === 1;
        $state = $missing === [] && $forbidden === [] && $versionValid && $evidenceRef !== '' && $testedAt !== '' && $fresh
            ? 'verified'
            : (($controls === [] && $influences === []) ? 'unassessed' : 'blocked');

        return [
            'state' => $state,
            'missing_controls' => $missing,
            'forbidden_influences' => $forbidden,
            'policy_version_valid' => $versionValid,
            'recomputation_fresh' => $fresh,
            'evidence_ref' => $evidenceRef,
            'write_allowed' => $state === 'verified',
        ];
    }
}
