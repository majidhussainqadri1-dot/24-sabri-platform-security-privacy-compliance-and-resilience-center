<?php

declare(strict_types=1);

namespace Sabri\Platform\Security\Future;

use Sabri\Platform\Security\Support\Sanitizer;

final class PrivacyAnalyticsGuard
{
    /** @param array<string,mixed> $request
     *  @return array<string,mixed>
     */
    public function evaluate(array $request): array
    {
        $epsilon = (float) ($request['epsilon'] ?? 0);
        $budget = (float) ($request['remaining_budget'] ?? 0);
        $cohort = max(0, (int) ($request['cohort_size'] ?? 0));
        $minCohort = max(10, min(10000, (int) ($request['minimum_cohort'] ?? 30)));
        $noRaw = Sanitizer::boolean($request['no_raw_rows'] ?? false);
        $clipped = Sanitizer::boolean($request['clipping_applied'] ?? false);
        $cleanRoom = Sanitizer::boolean($request['clean_room'] ?? false);
        $reasons = [];
        if ($epsilon <= 0 || $epsilon > 10) $reasons[] = 'epsilon_out_of_bounds';
        if ($epsilon > $budget) $reasons[] = 'privacy_budget_exceeded';
        if ($cohort < $minCohort) $reasons[] = 'cohort_too_small';
        if (! $noRaw) $reasons[] = 'raw_rows_forbidden';
        if (! $clipped) $reasons[] = 'clipping_required';
        if (! $cleanRoom) $reasons[] = 'clean_room_required';
        return [
            'decision' => $reasons === [] ? 'allow_aggregate' : 'block',
            'reasons' => $reasons,
            'remaining_budget_after' => $reasons === [] ? max(0.0, round($budget - $epsilon, 6)) : $budget,
        ];
    }
}
