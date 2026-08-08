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

c155(str_contains($historical, '>= 237'), 'Historical Cycle-145 lint floor must be a minimum boundary.');
c155(str_contains($historical, '>= 145'), 'Historical source-snapshot cycle must accept later cycle numbers.');
c155(str_contains($historical, 'seq 116'), 'Historical Cycle-145 presence may be satisfied by a later monotonic CI cycle range.');
c155(! str_contains($historical, "str_contains(\$ci, 'file24-source-snapshot-cycle145.zip')"), 'Historical regression must not require a stale exact Cycle-145 artifact name.');
c155(! str_contains($historical, "str_contains(\$ci, 'test \"\$count\" -ge 237')"), 'Historical regression must not require a stale exact CI floor string.');

c155(preg_match('/test "\\$count" -ge ([0-9]+)/', $ci, $lintMatch) === 1 && (int) $lintMatch[1] >= 247, 'CI must retain or advance beyond the Cycle-155 PHP source/test floor.');
c155(preg_match_all('/test "\\$count" -ge ([0-9]+)/', $ci, $floorMatches) >= 2 && max(array_map('intval', $floorMatches[1])) >= 160, 'CI must retain or advance beyond the Cycle-155 independent-test floor.');
c155(preg_match('/test "\\$\\(wc -l < \\/tmp\\/file24-source-checksums\\.sha256\\)" -ge ([0-9]+)/', $ci, $checksumMatch) === 1 && (int) $checksumMatch[1] >= 415, 'CI must retain or advance beyond the Cycle-155 tracked-source checksum floor.');
c155(preg_match('/seq 116 ([0-9]+)/', $ci, $rangeMatch) === 1 && (int) $rangeMatch[1] >= 155, 'CI must retain or advance beyond Cycle 155 in its permanent review range.');
c155(preg_match('/file24-source-snapshot-cycle([0-9]+)\\.zip/', $ci, $snapshotMatch) === 1 && (int) $snapshotMatch[1] >= 155, 'Sanitized source snapshot naming must remain at Cycle 155 or advance beyond it.');
c155(preg_match('/file-24-sanitized-source-snapshot-cycle([0-9]+)/', $ci, $artifactMatch) === 1 && (int) $artifactMatch[1] >= 155, 'Sanitized source artifact naming must remain at Cycle 155 or advance beyond it.');
c155(str_contains($ci, 'REVIEW-AND-CORRECTION-FUTURE-SECURITY-CYCLES-146-155.md'), 'Historical Cycle-155 review register must remain required by current CI.');
c155(str_contains($ci, 'tests/cycle155-historical-closure-regression-review.php') || (int) ($rangeMatch[1] ?? 0) >= 155, 'Current CI must continue to execute Cycle 155 explicitly or through a monotonic range.');

foreach (range(146, 155) as $cycle) {
    $matches = glob(__DIR__ . '/cycle' . $cycle . '-*.php');
    c155(is_array($matches) && count($matches) === 1, 'Exactly one independent top-level review program must exist for Cycle ' . $cycle . '.');
}

echo "PASS: cycle155 historical closure-test brittleness defect corrected and full review retested\n";
