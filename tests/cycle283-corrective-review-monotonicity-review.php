<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

function c283(bool $condition, string $message): void
{
    if (! $condition) {
        fwrite(STDERR, "FAIL: {$message}\n");
        exit(1);
    }
}

$root = dirname(__DIR__);
$ci = (string) file_get_contents($root . '/.github/workflows/ci.yml');
$c280 = (string) file_get_contents(__DIR__ . '/cycle280-release-evidence-parity-review.php');
$c281 = (string) file_get_contents(__DIR__ . '/cycle281-exact-head-snapshot-compatibility-review.php');
$c282 = (string) file_get_contents(__DIR__ . '/cycle282-historical-snapshot-contract-harmonization-review.php');

foreach ([$c280, $c281, $c282] as $historical) {
    c283(! preg_match('/latest_review_cycle[^\n]*===\s*(280|281|282)/', $historical), 'Corrective review tests must not freeze latest_review_cycle at their own cycle.');
}
c283(str_contains($c280, '>= 280'), 'Cycle 280 must remain a lower-bound historical contract.');
c283(str_contains($c281, '>= 281'), 'Cycle 281 must remain a lower-bound historical contract.');
c283(str_contains($c282, '>= 282'), 'Cycle 282 must remain a lower-bound historical contract.');

c283(preg_match('/test "\$count" -ge ([0-9]+)/', $ci, $lint) === 1 && (int) ($lint[1] ?? 0) >= 297, 'CI PHP floor must advance through Cycle 283.');
c283(preg_match_all('/test "\$count" -ge ([0-9]+)/', $ci, $floors) >= 2 && min(array_map('intval', $floors[1] ?? [])) >= 209, 'CI independent-test floor must advance through Cycle 283.');
c283(str_contains($ci, 'cycle283-corrective-review-monotonicity-review.php'), 'CI must explicitly bind Cycle 283.');

$source = json_decode((string) file_get_contents($root . '/docs/SOURCE-MANIFEST-0.99.0.json'), true, 512, JSON_THROW_ON_ERROR);
c283(($source['verification']['php_files_minimum'] ?? 0) >= 297, 'Source manifest PHP floor must advance through Cycle 283.');
c283(($source['verification']['test_programs_minimum'] ?? 0) >= 209, 'Source manifest test floor must advance through Cycle 283.');
c283(($source['verification']['latest_review_cycle'] ?? 0) === 283, 'Current source manifest latest review cycle must be 283.');

echo "PASS: Cycle 283 corrective review tests made monotonic for future exact-head hardening\n";
