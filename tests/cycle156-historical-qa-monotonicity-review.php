<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

function c156(bool $condition, string $message): void
{
    if (! $condition) {
        fwrite(STDERR, "FAIL: {$message}\n");
        exit(1);
    }
}

$historical = file_get_contents(__DIR__ . '/cycle155-historical-closure-regression-review.php');
$ci = file_get_contents(dirname(__DIR__) . '/.github/workflows/ci.yml');

c156(is_string($historical) && is_string($ci), 'Historical closure test and CI workflow must be readable.');
c156(str_contains($historical, '>= 247'), 'Cycle 155 must retain its original minimum lint floor as a lower bound.');
c156(str_contains($historical, '>= 160'), 'Cycle 155 must retain its original independent-test floor as a lower bound.');
c156(str_contains($historical, '>= 415'), 'Cycle 155 must retain its original source-integrity floor as a lower bound.');
c156(str_contains($historical, '>= 155'), 'Cycle 155 must accept later legitimate review-cycle numbers.');
c156(! str_contains($historical, "str_contains(\$ci, 'test \"\$count\" -ge 247')"), 'Historical QA must not freeze an exact future lint-floor string.');
c156(! str_contains($historical, "str_contains(\$ci, 'file24-source-snapshot-cycle155.zip')"), 'Historical QA must not freeze an exact Cycle-155 source-snapshot name.');
c156(! str_contains($historical, "str_contains(\$ci, 'file-24-sanitized-source-snapshot-cycle155')"), 'Historical QA must not freeze an exact Cycle-155 artifact name.');

// The corrected Cycle-155 program must itself pass before later cycles are added.
$command = escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg(__DIR__ . '/cycle155-historical-closure-regression-review.php');
exec($command, $output, $status);
c156($status === 0, 'Corrected historical Cycle-155 closure regression must pass against the current CI baseline.');

echo "PASS: cycle156 historical closure QA made genuinely monotonic for later legitimate hardening\n";
