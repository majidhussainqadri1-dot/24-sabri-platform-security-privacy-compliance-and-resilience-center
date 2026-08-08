<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

function c179(bool $condition, string $message): void { if (! $condition) { fwrite(STDERR, "FAIL: {$message}\n"); exit(1); } }

$ci = (string) file_get_contents(__DIR__ . '/../.github/workflows/ci.yml');
$c167 = (string) file_get_contents(__DIR__ . '/cycle167-second-post-ci-clean-closure-review.php');
$c178 = (string) file_get_contents(__DIR__ . '/cycle178-second-clean-post-fix-closure-review.php');

c179(! str_contains($c167, "str_contains(\$ci, 'test \"\$count\" -ge 259')"), 'Cycle 167 must not freeze an exact historical CI floor.');
c179(! str_contains($c167, "str_contains(\$ci, 'file-24-sanitized-source-snapshot-cycle167')"), 'Cycle 167 must not freeze an exact historical snapshot name.');
c179(str_contains($c167, "preg_match('/file-24-sanitized-source-snapshot-cycle([0-9]+)/'"), 'Cycle 167 must accept a monotonic later snapshot cycle.');
c179(! str_contains($c178, "str_contains(\$workflow, 'seq 116 178')"), 'Cycle 178 must not freeze the CI review range at 178.');
c179(str_contains($c178, "preg_match('/seq 116 ([0-9]+)/'"), 'Cycle 178 must accept a monotonic later review range.');
c179(preg_match('/seq 116 ([0-9]+)/', $ci, $range) === 1 && (int) ($range[1] ?? 0) >= 181, 'Current CI must retain all regressions through the final post-fix closure range.');

$cmd167 = escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg(__DIR__ . '/cycle167-second-post-ci-clean-closure-review.php');
$cmd178 = escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg(__DIR__ . '/cycle178-second-clean-post-fix-closure-review.php');
exec($cmd167, $out167, $status167);
exec($cmd178, $out178, $status178);
c179($status167 === 0, 'Corrected Cycle 167 historical closure regression must pass under the current CI.');
c179($status178 === 0, 'Corrected Cycle 178 historical closure regression must pass under the current CI.');

echo "PASS: cycle179 historical closure QA made monotonic after full-suite discovery\n";
