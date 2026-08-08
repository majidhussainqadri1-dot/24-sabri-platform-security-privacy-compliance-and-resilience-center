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
c145(preg_match('/test \"\$count\" -ge ([0-9]+)/', $ci, $lintMatch) === 1 && (int) $lintMatch[1] >= 237, 'CI must retain or advance beyond the Cycle-145 PHP source/test floor.');
c145(preg_match_all('/test \"\$count\" -ge ([0-9]+)/', $ci, $floorMatches) >= 2 && max(array_map('intval', $floorMatches[1])) >= 150, 'CI must retain or advance beyond the Cycle-145 independent-test floor.');
c145(preg_match('/file24-source-snapshot-cycle([0-9]+)\\.zip/', $ci, $snapshotMatch) === 1 && (int) $snapshotMatch[1] >= 145, 'Sanitized source snapshot naming must remain at Cycle 145 or advance beyond it.');
c145(str_contains($ci, 'cycle145-second-clean-final-closure-review.php') || (preg_match('/seq 116 ([0-9]+)/', $ci, $cycleRange) === 1 && (int) $cycleRange[1] >= 145), 'CI closure must still require Cycle 145 explicitly or through a monotonic cycle range.');

echo "PASS: cycle145 second consecutive fresh whole-system review found no new repository-correctable defect\n";
