<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

use Sabri\Platform\Security\Future\PrivacyAnalyticsGuard;

function expectCycle122(bool $condition, string $message): void { if (! $condition) { fwrite(STDERR, "FAIL: {$message}\n"); exit(1); } }

$guard = new PrivacyAnalyticsGuard();
$base = ['cohort_size' => 100, 'minimum_cohort' => 30, 'no_raw_rows' => true, 'clipping_applied' => true, 'clean_room' => true];

$nan = $guard->evaluate($base + ['epsilon' => NAN, 'remaining_budget' => 2.0]);
expectCycle122($nan['decision'] === 'block' && in_array('epsilon_out_of_bounds', $nan['reasons'], true), 'NaN epsilon must fail closed.');

$infEpsilon = $guard->evaluate($base + ['epsilon' => INF, 'remaining_budget' => 2.0]);
expectCycle122($infEpsilon['decision'] === 'block', 'Infinite epsilon must fail closed.');

$infBudget = $guard->evaluate($base + ['epsilon' => 0.5, 'remaining_budget' => INF]);
expectCycle122($infBudget['decision'] === 'block' && in_array('privacy_budget_invalid', $infBudget['reasons'], true), 'Infinite privacy budget must not create unlimited authorization.');

$valid = $guard->evaluate($base + ['epsilon' => 0.5, 'remaining_budget' => 2.0]);
expectCycle122($valid['decision'] === 'allow_aggregate' && abs($valid['remaining_budget_after'] - 1.5) < 0.000001, 'Finite bounded privacy budget must remain usable.');

echo "PASS: cycle122 differential-privacy numeric defects fixed and retested\n";
