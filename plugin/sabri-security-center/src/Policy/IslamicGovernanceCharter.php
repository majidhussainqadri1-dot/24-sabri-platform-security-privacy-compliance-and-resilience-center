<?php

declare(strict_types=1);

namespace Sabri\Platform\Security\Policy;

use Sabri\Platform\Security\Support\Sanitizer;

/** File 24 assurance contract for the Founder-approved Islamic governance charter. */
final class IslamicGovernanceCharter
{
    /** @var list<string> */
    private const REQUIRED_CONTROLS = [
        'islamic_supremacy',
        'justice_and_proportionality',
        'privacy_and_human_dignity',
        'notice',
        'evidence_summary',
        'right_to_respond',
        'conflict_free_reviewer',
        'reasoned_decision',
        'appeal',
    ];

    /** @return list<string> */
    public static function requiredControls(): array
    {
        return self::REQUIRED_CONTROLS;
    }

    /** @param array<string,mixed> $evidence @return array<string,mixed> */
    public static function evaluate(array $evidence): array
    {
        $implemented = Sanitizer::textList($evidence['controls'] ?? [], 50, 100);
        $missing = array_values(array_diff(self::REQUIRED_CONTROLS, $implemented));
        $evidenceRef = Sanitizer::opaqueReference($evidence['evidence_ref'] ?? '');
        $reviewedAt = Sanitizer::isoTime($evidence['reviewed_at'] ?? '');
        $nextReviewAt = Sanitizer::isoTime($evidence['next_review_at'] ?? '');
        $annualReviewValid = self::annualReviewValid($reviewedAt, $nextReviewAt);
        $state = $missing === [] && $evidenceRef !== '' && $annualReviewValid ? 'verified' : ($implemented === [] ? 'unassessed' : 'incomplete');

        return [
            'state' => $state,
            'missing_controls' => $missing,
            'annual_review_valid' => $annualReviewValid,
            'evidence_ref' => $evidenceRef,
            'write_allowed' => $state === 'verified',
        ];
    }

    public static function annualReviewValid(string $reviewedAt, string $nextReviewAt, ?int $now = null): bool
    {
        if ($reviewedAt === '' || $nextReviewAt === '') {
            return false;
        }
        $reviewed = strtotime($reviewedAt);
        $next = strtotime($nextReviewAt);
        $now ??= time();
        if ($reviewed === false || $next === false || $next <= $reviewed) {
            return false;
        }
        if ($reviewed > $now + 300 || $next <= $now) {
            return false;
        }
        return ($next - $reviewed) <= 366 * DAY_IN_SECONDS;
    }
}
