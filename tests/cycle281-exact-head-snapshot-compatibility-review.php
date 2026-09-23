<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

function c281(bool $condition, string $message): void
{
    if (! $condition) {
        fwrite(STDERR, "FAIL: {$message}\n");
        exit(1);
    }
}

$root = dirname(__DIR__);
$cycle145 = (string) file_get_contents(__DIR__ . '/cycle145-second-clean-final-closure-review.php');
c281(str_contains($cycle145, 'file24-source-snapshot-exact-head.zip'), 'Historical Cycle 145 must accept exact-head snapshot naming.');

$ci = (string) file_get_contents($root . '/.github/workflows/ci.yml');
c281(preg_match('/test "\\$count" -ge ([0-9]+)/', $ci, $lintFloor) === 1 && (int) ($lintFloor[1] ?? 0) >= 295, 'CI must retain or advance the Cycle-281 PHP source/test floor.');
c281(preg_match_all('/test "\\$count" -ge ([0-9]+)/', $ci, $floors) >= 2 && min(array_map('intval', $floors[1] ?? [])) >= 207, 'CI must retain or advance the Cycle-281 independent test floor.');
c281(str_contains($ci, 'cycle281-exact-head-snapshot-compatibility-review.php'), 'CI must explicitly bind Cycle 281.');
c281(str_contains($ci, 'file24-source-snapshot-exact-head.zip'), 'Exact-head snapshot naming must remain canonical.');

$source = json_decode((string) file_get_contents($root . '/docs/SOURCE-MANIFEST-0.99.0.json'), true, 512, JSON_THROW_ON_ERROR);
c281(($source['verification']['php_files_minimum'] ?? 0) >= 295, 'Source manifest PHP floor must advance through Cycle 281.');
c281(($source['verification']['test_programs_minimum'] ?? 0) >= 207, 'Source manifest test floor must advance through Cycle 281.');
c281(($source['verification']['latest_review_cycle'] ?? 0) >= 281, 'Source manifest must retain Cycle 281 or later review evidence.');

$receipt = (string) file_get_contents($root . '/docs/RELEASE-RECEIPT-0.99.0.md');
c281(preg_match('/278–([0-9]+)/', $receipt, $receiptRange) === 1 && (int) ($receiptRange[1] ?? 0) >= 281, 'Release receipt must include Cycle 281 while allowing later corrective reviews.');

echo "PASS: Cycle 281 exact-head snapshot compatibility correction passed\n";
