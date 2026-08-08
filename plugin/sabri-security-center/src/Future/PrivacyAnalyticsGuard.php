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
        $epsilon = $this->finiteFloat($request['epsilon'] ?? null);
        $budget = $this->finiteFloat($request['remaining_budget'] ?? null);
        $cohort = max(0, (int) ($request['cohort_size'] ?? 0));
        $minCohort = max(10, min(10000, (int) ($request['minimum_cohort'] ?? 30)));
        $noRaw = Sanitizer::boolean($request['no_raw_rows'] ?? false);
        $clipped = Sanitizer::boolean($request['clipping_applied'] ?? false);
        $cleanRoom = Sanitizer::boolean($request['clean_room'] ?? false);
        $reasons = [];

        if ($epsilon === null || $epsilon <= 0 || $epsilon > 10) $reasons[] = 'epsilon_out_of_bounds';
        if ($budget === null || $budget < 0) $reasons[] = 'privacy_budget_invalid';
        if ($epsilon !== null && $budget !== null && $epsilon > $budget) $reasons[] = 'privacy_budget_exceeded';
        if ($cohort < $minCohort) $reasons[] = 'cohort_too_small';
        if (! $noRaw) $reasons[] = 'raw_rows_forbidden';
        if (! $clipped) $reasons[] = 'clipping_required';
        if (! $cleanRoom) $reasons[] = 'clean_room_required';

        $reasons = array_values(array_unique($reasons));
        $allow = $reasons === [] && $epsilon !== null && $budget !== null;
        return [
            'decision' => $allow ? 'allow_aggregate' : 'block',
            'reasons' => $reasons,
            'remaining_budget_after' => $allow ? max(0.0, round($budget - $epsilon, 6)) : ($budget ?? 0.0),
        ];
    }

    private function finiteFloat(mixed $value): ?float
    {
        if ((! is_int($value) && ! is_float($value) && ! is_string($value)) || ! is_numeric($value)) {
            return null;
        }
        $number = (float) $value;
        return is_finite($number) ? $number : null;
    }
}
