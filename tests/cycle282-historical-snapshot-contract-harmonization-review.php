<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

function c282(bool $condition, string $message): void
{
    if (! $condition) {
        fwrite(STDERR, "FAIL: {$message}\n");
        exit(1);
    }
}

$root = dirname(__DIR__);
$ci = (string) file_get_contents($root . '/.github/workflows/ci.yml');
$c155 = (string) file_get_contents(__DIR__ . '/cycle155-historical-closure-regression-review.php');
$c167 = (string) file_get_contents(__DIR__ . '/cycle167-second-post-ci-clean-closure-review.php');
$c197 = (string) file_get_contents(__DIR__ . '/cycle197-second-clean-final-closure-review.php');

c282(str_contains($c155, 'file24-source-snapshot-exact-head.zip'), 'Cycle 155 must accept exact-head ZIP naming.');
c282(str_contains($c155, 'file-24-sanitized-source-snapshot-exact-head'), 'Cycle 155 must accept exact-head artifact naming.');
c282(str_contains($c167, 'file-24-sanitized-source-snapshot-exact-head'), 'Cycle 167 must accept exact-head artifact naming.');
c282(str_contains($c197, "preg_match('/for cycle in \\$\\(seq 116 ([0-9]+)\\); do/'"), 'Cycle 197 must use a monotonic explicit review-range assertion.');

c282(str_contains($ci, 'file24-source-snapshot-exact-head.zip'), 'Current CI must retain exact-head ZIP naming.');
c282(str_contains($ci, 'file-24-sanitized-source-snapshot-exact-head'), 'Current CI must retain exact-head artifact naming.');
c282(preg_match('/for cycle in \\$\\(seq 116 ([0-9]+)\\); do/', $ci, $range) === 1 && (int) ($range[1] ?? 0) >= 197, 'Current CI explicit historical review gate must remain through Cycle 197 or later.');
c282(str_contains($ci, 'test "$count" -ge 296'), 'CI PHP source/test floor must advance through Cycle 282.');
c282(str_contains($ci, 'test "$count" -ge 208'), 'CI independent test floor must advance through Cycle 282.');
c282(str_contains($ci, 'cycle282-historical-snapshot-contract-harmonization-review.php'), 'CI must explicitly bind Cycle 282.');

$source = json_decode((string) file_get_contents($root . '/docs/SOURCE-MANIFEST-0.99.0.json'), true, 512, JSON_THROW_ON_ERROR);
c282(($source['verification']['php_files_minimum'] ?? 0) >= 296, 'Source manifest PHP floor must advance through Cycle 282.');
c282(($source['verification']['test_programs_minimum'] ?? 0) >= 208, 'Source manifest test floor must advance through Cycle 282.');
c282(($source['verification']['latest_review_cycle'] ?? 0) === 282, 'Source manifest latest review cycle must be 282.');

echo "PASS: Cycle 282 historical snapshot/range contracts harmonized for exact-head CI\n";
