<?php

declare(strict_types=1);

require __DIR__ . '/bootstrap.php';

$assertions = 0;
function expectCycle17(bool $condition, string $message): void
{
    global $assertions;
    ++$assertions;
    if (! $condition) {
        fwrite(STDERR, "FAIL: {$message}\n");
        exit(1);
    }
}

$root = dirname(__DIR__);
$cycle16 = (string) file_get_contents(__DIR__ . '/cycle16-closure.php');
$ci = (string) file_get_contents($root . '/.github/workflows/ci.yml');
$readme = (string) file_get_contents($root . '/README.md');
$manifest = (string) file_get_contents($root . '/MANIFEST.md');
$receipt = (string) file_get_contents($root . '/docs/RELEASE-RECEIPT-0.25.7.md');
$traceability = (string) file_get_contents($root . '/docs/REQUIREMENTS-TRACEABILITY-0.25.7.md');
$closure = (string) file_get_contents($root . '/docs/FINAL-CLOSURE-REVIEW-AND-CORRECTION-0.25.7-CYCLE-16.md');

expectCycle17(str_contains($cycle16, '$auditProperty->setAccessible(true);'), 'PHP 8.0 must explicitly permit access to the non-public audit property used by the closure test.');
expectCycle17(str_contains($cycle16, '$recordAudit->setAccessible(true);'), 'PHP 8.0 must explicitly permit access to the non-public privacy audit method used by the closure test.');
expectCycle17(str_contains($cycle16, '$finish->setAccessible(true);'), 'PHP 8.0 must explicitly permit access to the non-public retention finish method used by the closure test.');
expectCycle17(substr_count($cycle16, '->setAccessible(true);') === 3, 'Every non-public ReflectionProperty/ReflectionMethod use in Cycle 16 must be explicitly enabled exactly once.');
expectCycle17(str_contains($closure, 'Cycle 16 added 40 closure/adversarial assertions.'), 'Cycle 16 documentation must match the actual 40-assertion result.');
expectCycle17(str_contains($receipt, '**Review closure:** Cycle 17'), 'Release receipt must identify the latest post-CI compatibility review.');
expectCycle17(str_contains($receipt, '21 separate regression'), 'Release receipt must report the complete 21-program test suite.');
expectCycle17((str_contains($readme, 'php tests/cycle17-illuminative.php') || str_contains($readme, 'find tests -maxdepth 1')), 'README must expose the Cycle 17 command.');
expectCycle17(str_contains($manifest, 'Cycle 17 post-CI illuminative review'), 'Source manifest must identify the latest review record.');
expectCycle17(str_contains($traceability, 'Cycle 17 compatibility evidence'), 'Requirements traceability must include PHP 8.0 compatibility closure evidence.');
expectCycle17((str_contains($ci, 'php tests/cycle17-illuminative.php') || str_contains($ci, 'find tests -maxdepth 1')), 'Permanent CI must execute Cycle 17 on every supported PHP runtime.');
expectCycle17(str_contains($ci, 'file24-source-snapshot-cycle'), 'CI must continue producing a sanitized reviewed-source snapshot.');
expectCycle17(! file_exists($root . '/.github/workflows/materialize-file24-cycle16.yml'), 'No temporary self-mutating materialization workflow may remain in final source.');
expectCycle17(! is_dir($root . '/handoff'), 'No staged handoff bundle may remain in final source.');
expectCycle17(str_contains((string) file_get_contents($root . '/docs/ILLUMINATIVE-REVIEW-AND-CORRECTION-0.25.7-CYCLE-17.md'), 'plugin and schema versions remain 0.25.7 / 0.25.5'), 'The historical Cycle 17 record must preserve its reviewed release identity.');

echo "PASS: {$assertions} Cycle 17 post-CI illuminative assertions\n";
