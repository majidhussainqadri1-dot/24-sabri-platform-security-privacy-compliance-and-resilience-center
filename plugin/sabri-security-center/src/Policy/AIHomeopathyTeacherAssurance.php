<?php

declare(strict_types=1);

namespace Sabri\Platform\Security\Policy;

use Sabri\Platform\Security\Support\Sanitizer;

/** Launch and continuing assurance for the institutional AI Homeopathy Teacher. */
final class AIHomeopathyTeacherAssurance
{
    public const HUMAN_REVIEW_DAYS = 30;
    public const DEFAULT_MAX_DAILY_POSTS = 4;

    /** @var list<string> */
    private const REQUIRED_CONTROLS = [
        'institutional_ai_identity',
        'visible_ai_disclosure',
        'corpus_allowlist',
        'retrieval_acl',
        'source_citations',
        'prompt_injection_defense',
        'medical_review',
        'shariah_review',
        'budget_cap',
        'provider_failure_fallback',
        'deletion_propagation',
        'file26_classification_contract',
    ];

    /** @param array<string,mixed> $evidence @return array<string,mixed> */
    public static function evaluate(array $evidence, ?int $now = null): array
    {
        $now ??= time();
        $controls = Sanitizer::textList($evidence['controls'] ?? [], 80, 100);
        $missing = array_values(array_diff(self::REQUIRED_CONTROLS, $controls));
        $identity = Sanitizer::key($evidence['identity_type'] ?? '', 60);
        $launchAt = Sanitizer::isoTime($evidence['launch_at'] ?? '');
        $launch = $launchAt === '' ? false : strtotime($launchAt);
        $withinReviewWindow = $launch !== false && $launch <= $now && ($now - $launch) < self::HUMAN_REVIEW_DAYS * DAY_IN_SECONDS;
        $humanReviewEnabled = ! empty($evidence['human_review_enabled']);
        $dailyPostCap = absint($evidence['daily_post_cap'] ?? 0);
        $evidenceRef = Sanitizer::opaqueReference($evidence['evidence_ref'] ?? '');
        $testedAt = Sanitizer::isoTime($evidence['tested_at'] ?? '');
        $identityValid = $identity === 'institutional-ai';
        $cadenceValid = $dailyPostCap >= 1 && $dailyPostCap <= self::DEFAULT_MAX_DAILY_POSTS;
        $reviewValid = ! $withinReviewWindow || $humanReviewEnabled;
        $state = $missing === [] && $identityValid && $cadenceValid && $reviewValid && $evidenceRef !== '' && $testedAt !== ''
            ? 'verified'
            : (($controls === [] && $identity === '') ? 'unassessed' : 'blocked');

        return [
            'state' => $state,
            'missing_controls' => $missing,
            'identity_valid' => $identityValid,
            'daily_post_cap_valid' => $cadenceValid,
            'within_initial_review_window' => $withinReviewWindow,
            'human_review_valid' => $reviewValid,
            'evidence_ref' => $evidenceRef,
            'publication_allowed' => $state === 'verified',
        ];
    }
}
