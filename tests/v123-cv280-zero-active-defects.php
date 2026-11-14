<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

use Sabri\Platform\Security\Policy\ContinuousValueAssurance;

function assertV123TwoReviewLaw(bool $condition, string $message): void
{
    if (! $condition) {
        fwrite(STDERR, "FAIL: {$message}\n");
        exit(1);
    }
}

$base = [
    'review_round_1','review_round_2','fix_after_each_review','retest_after_fix',
];
$metadata = [
    'evidence_ref' => 'evidence:v123-current-review-law',
    'reviewed_at' => gmdate('c', time() - 30),
];

$old = ContinuousValueAssurance::evaluate('CV-280', $metadata + [
    'controls' => array_merge($base, ['zero_known_defect_or_founder_risk_acceptance']),
]);
assertV123TwoReviewLaw(
    ($old['state'] ?? '') === 'blocked' && ($old['write_allowed'] ?? true) === false,
    'Historical Founder risk-acceptance token must not substitute zero active known defects.'
);
assertV123TwoReviewLaw(
    in_array('zero_known_active_defects', $old['missing_controls'] ?? [], true),
    'CV-280 must name the unmet V12.3 release-scope invariant.'
);

$valid = ContinuousValueAssurance::evaluate('CV-280', $metadata + [
    'controls' => array_merge($base, ['zero_known_active_defects']),
]);
assertV123TwoReviewLaw(
    ($valid['state'] ?? '') === 'verified' && ($valid['write_allowed'] ?? false) === true,
    'Exactly named zero-active-defect assurance is permitted with fresh opaque evidence.'
);

$missingFirstReview = ContinuousValueAssurance::evaluate('CV-280', $metadata + [
    'controls' => ['review_round_2', 'fix_after_each_review', 'retest_after_fix','zero_known_active_defects'],
]);
assertV123TwoReviewLaw(
    ($missingFirstReview['state'] ?? '') === 'blocked',
    'Zero defects do not replace the mandatory first review.'
);

echo "PASS: V12.3 CV-280 forbids Founder waiver as an active-defect substitute\n";
