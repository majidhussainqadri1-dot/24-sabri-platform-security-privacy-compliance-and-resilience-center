<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

function c195(bool $condition, string $message): void { if (! $condition) { fwrite(STDERR, "FAIL: {$message}\n"); exit(1); } }

$violations = [];
foreach (array_merge(glob(__DIR__ . '/*.php') ?: [], glob(__DIR__ . '/../plugin/sabri-security-center/src/**/*.php') ?: []) as $file) {
    $source = (string) file_get_contents($file);
    if (preg_match('/:\s*never\b/', $source) === 1) $violations[] = basename($file);
}
c195($violations === [], 'Declared PHP 8.0 compatibility must not be broken by PHP 8.1-only never return types in review regressions or source.');
$cycle187 = (string) file_get_contents(__DIR__ . '/cycle187-external-adapter-exception-containment-review.php');
c195(! str_contains($cycle187, ':' . ' never'), 'Cycle 187 exception callbacks must remain PHP 8.0-compatible after full-suite discovery.');

echo "PASS: cycle195 full-suite PHP 8.0 regression compatibility defect fixed and retested\n";
