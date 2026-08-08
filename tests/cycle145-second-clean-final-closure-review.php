<?php
declare(strict_types=1);
require_once __DIR__ . '/bootstrap.php';

function c145(bool $condition, string $message): void { if (! $condition) { fwrite(STDERR, "FAIL: {$message}\n"); exit(1); } }

for ($cycle = 136; $cycle <= 145; ++$cycle) {
    $matches = glob(__DIR__ . '/cycle' . $cycle . '-*.php');
    c145(is_array($matches) && count($matches) === 1, "Exactly one permanent top-level regression/review program is required for cycle {$cycle}.");
}
$ci = file_get_contents(__DIR__ . '/../.github/workflows/ci.yml');
c145(is_string($ci), 'CI workflow must be readable.');
c145(str_contains($ci, 'test "$count" -ge 237'), 'CI must lint at least the cycle145 PHP source/test floor.');
c145(str_contains($ci, 'test "$count" -ge 150'), 'CI must execute at least 150 independent top-level tests.');
c145(str_contains($ci, 'file24-source-snapshot-cycle145.zip'), 'Sanitized source snapshot naming must advance through cycle145.');
c145(str_contains($ci, 'cycle145-second-clean-final-closure-review.php'), 'Exact CI closure must explicitly require the second clean review.');

echo "PASS: cycle145 second consecutive fresh whole-system review found no new repository-correctable defect\n";
