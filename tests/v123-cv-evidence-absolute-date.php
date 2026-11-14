<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

use Sabri\Platform\Security\Policy\ContinuousValueAssurance;

function v123CVEvidenceDateAssert(bool $condition, string $message): void
{
    if (! $condition) {
        fwrite(STDERR, "FAIL: {$message}\n");
        exit(1);
    }
}

// CV-280 was selected because the complete source-level check shape is
// relatively small. This test validates date syntax only, not true operational
// evidence or the external authority behind the opaque reference.
$controls = ['review_round_1', 'review_round_2', 'fix_after_each_review', 'retest_after_fix', 'zero_known_active_defects'];
$base = ['controls' => $controls, 'evidence_ref' => 'ev:v123-absolute-date-review'];

foreach (['now', 'yesterday', '-3 hours', 'next Monday', '+1 minute', 'last week', '2026-02-31T12:00:00Z'] as $invalid) {
    $result = ContinuousValueAssurance::evaluate('CV-280', $base + ['reviewed_at' => $invalid]);
    v123CVEvidenceDateAssert(
        ($result['state'] ?? '') === 'blocked' && ($result['write_allowed'] ?? true) === false,
        "Relative/impossible review date must not verify: {$invalid}"
    );
    v123CVEvidenceDateAssert(
        ($result['reviewed_at'] ?? 'INVALID') === '',
        'Invalid date must not be normalized into an apparently certified timestamp.'
    );
}

$absolute = gmdate('c', time() - 60);
$accepted = ContinuousValueAssurance::evaluate('CV-280', $base + ['reviewed_at' => $absolute]);
v123CVEvidenceDateAssert(
    ($accepted['state'] ?? '') === 'verified'
    && ($accepted['write_allowed'] ?? false) === true,
    'Explicit recent absolute RFC3339 review time must remain supported.'
);

$negative = ContinuousValueAssurance::evaluate('CV-280', $base + ['reviewed_at' => gmdate('c', time() - 100 * 86400)]);
v123CVEvidenceDateAssert(($negative['state'] ?? '') === 'blocked', 'Old absolute evidence must still expire.');

echo "PASS: V12.3 CV evidence timestamps reject relative/impossible time input\n";
