<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

function c165(bool $condition, string $message): void { if (! $condition) { fwrite(STDERR, "FAIL: {$message}\n"); exit(1); } }

$ci = (string) file_get_contents(__DIR__ . '/../.github/workflows/ci.yml');
$register = (string) file_get_contents(__DIR__ . '/../docs/REVIEW-AND-CORRECTION-FUTURE-SECURITY-CYCLES-156-165.md');

c165(str_contains($register, 'Defect-bearing cycles | **156, 157, 158, 159, 160, 161, 162, 163, 165**'), 'Requested ten-round register must include the exact-head CI defect in Cycle 165.');
c165(str_contains($register, 'Clean cycles | **164**'), 'Cycle 164 must remain the only clean requested round after exact-head Cycle-165 evidence.');
c165(str_contains($register, 'Consecutive clean post-fix closing cycles: 166, 167.'), 'Register must distinguish requested rounds from mandatory post-fix closure reviews.');

foreach ([
    "grep -Fq 'Defect-bearing cycles | **156, 157, 158, 159, 160, 161, 162, 163, 165**'",
    "grep -Fq 'Clean cycles | **164**'",
    "grep -Fq 'Known unresolved repository-correctable defects after fixes/retests | **0**'",
] as $literalAssertion) {
    c165(str_contains($ci, $literalAssertion), 'Markdown closure assertions must use fixed-string grep, not regex grep: ' . $literalAssertion);
}

c165(! str_contains($ci, "grep -q 'Defect-bearing cycles | **156"), 'CI must never reinterpret Markdown emphasis as a regular expression for the current register.');
c165(! str_contains($ci, "grep -q 'Clean cycles | **164"), 'CI current-register clean-cycle assertion must be fixed-string safe.');

echo "PASS: cycle165 exact-head Markdown/regex closure-QA defect corrected and permanently regression-tested\n";
