<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

function c155(bool $condition, string $message): void
{
    if (! $condition) {
        fwrite(STDERR, "FAIL: {$message}\n");
        exit(1);
    }
}

$repo = dirname(__DIR__);
$ci = file_get_contents($repo . '/.github/workflows/ci.yml');
$review = file_get_contents($repo . '/docs/REVIEW-AND-CORRECTION-FUTURE-SECURITY-CYCLES-146-155.md');
$historical = file_get_contents(__DIR__ . '/cycle145-second-clean-final-closure-review.php');

c155(is_string($ci), 'CI workflow must be readable.');
c155(is_string($review), 'Cycles 146-155 review register must be readable.');
c155(is_string($historical), 'Historical Cycle-145 closure regression must be readable.');

// Cycle 155 found that the historical Cycle-145 closure program asserted exact
// CI floors/artifact names, so a legitimate later hardening cycle broke the
// historical suite. Historical closure tests must be monotonic, not freeze
// future CI evolution at the old cycle number.
c155(str_contains($historical, '>= 237'), 'Historical Cycle-145 lint floor must be expressed as a minimum boundary.');
c155(str_contains($historical, '>= 145'), 'Historical source-snapshot cycle must accept later cycle numbers.');
c155(str_contains($historical, 'seq 116'), 'Historical Cycle-145 presence may be satisfied by the current monotonic CI cycle range.');
c155(! str_contains($historical, "str_contains(\$ci, 'file24-source-snapshot-cycle145.zip')"), 'Historical regression must not require a stale exact Cycle-145 artifact name.');
c155(! str_contains($historical, "str_contains(\$ci, 'test \"\$count\" -ge 237')"), 'Historical regression must not require a stale exact CI floor string.');

$ciMarkers = [
    'test "$count" -ge 247',
    'test "$count" -ge 160',
    'seq 116 155',
    'REVIEW-AND-CORRECTION-FUTURE-SECURITY-CYCLES-146-155.md',
    'tests/cycle155-historical-closure-regression-review.php',
    'test "$(wc -l < /tmp/file24-source-checksums.sha256)" -ge 415',
    'file24-source-snapshot-cycle155.zip',
    'file-24-sanitized-source-snapshot-cycle155',
];
foreach ($ciMarkers as $marker) {
    c155(str_contains($ci, $marker), 'CI must retain current Cycle-155 marker: ' . $marker);
}

c155(! str_contains($ci, 'file24-source-snapshot-cycle145.zip'), 'Current CI must not package a stale Cycle-145 source snapshot.');
c155(! str_contains($ci, 'file-24-sanitized-source-snapshot-cycle145'), 'Current CI must not publish a stale Cycle-145 artifact name.');

$reviewMarkers = [
    'Defect-bearing cycles | **146, 147, 148, 149, 150, 151, 152, 153, 155**',
    'Clean cycles | **154**',
    'Known unresolved repository-correctable defects after fixes/retests | **0**',
];
foreach ($reviewMarkers as $marker) {
    c155(str_contains($review, $marker), 'Review register must retain current Cycle-155 result: ' . $marker);
}

foreach (range(146, 155) as $cycle) {
    $matches = glob(__DIR__ . '/cycle' . $cycle . '-*.php');
    c155(is_array($matches) && count($matches) === 1, 'Exactly one independent top-level review program must exist for Cycle ' . $cycle . '.');
}

echo "PASS: cycle155 historical closure-test brittleness defect corrected and full review retested\n";
