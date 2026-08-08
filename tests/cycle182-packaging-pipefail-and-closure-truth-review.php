<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

function c182(bool $condition, string $message): void { if (! $condition) { fwrite(STDERR, "FAIL: {$message}\n"); exit(1); } }

$build = (string) file_get_contents(__DIR__ . '/../tools/build-release.sh');
$ci = (string) file_get_contents(__DIR__ . '/../.github/workflows/ci.yml');
$c181 = (string) file_get_contents(__DIR__ . '/cycle181-second-clean-final-closure-review.php');
$register = (string) file_get_contents(__DIR__ . '/../docs/REVIEW-AND-CORRECTION-FUTURE-SECURITY-CYCLES-168-177.md');

c182(! str_contains($build, 'unzip -l "$ZIP" | grep -q'), 'Release builder must not use a pipefail-sensitive unzip-to-grep-q pipeline.');
c182(str_contains($build, 'unzip -Z1 "$ZIP" > "$ENTRY_LIST"'), 'Release builder must materialize the ZIP entry list before membership assertions.');
c182(! preg_match('/unzip -l "\$PACKAGE_TWO" \| grep -q/', $ci), 'CI reproducibility gate must not use pipefail-sensitive unzip-to-grep-q assertions.');
c182(str_contains($ci, 'unzip -Z1 "$PACKAGE_TWO" > /tmp/file24-package-entries.txt'), 'CI must materialize package entries before exact membership checks.');
c182(! str_contains($c181, "str_contains(\$register, '**Consecutive clean final closing cycles: 180, 181.**')"), 'Historical Cycle 181 must not freeze an interim clean pair as final closure after later evidence.');
c182(str_contains($register, 'Additional post-request defect-bearing cycles | **179, 182**'), 'Register must record the later packaging defect truthfully.');
c182(str_contains($register, '**Consecutive clean final closing cycles: 183, 184.**'), 'Register must reserve final closure for the two clean reviews after packaging correction.');

echo "PASS: cycle182 packaging pipefail and premature-closure defects fixed and regression-tested\n";
