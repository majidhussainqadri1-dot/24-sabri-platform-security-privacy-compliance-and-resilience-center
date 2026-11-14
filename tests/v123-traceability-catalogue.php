<?php

declare(strict_types=1);

/**
 * Checks File 24 V12.3 traceability inventory, not live functionality.
 * Source coverage is distinct from verified staging and operational status.
 */
function v123CatalogAssert(bool $condition, string $message): void
{
    if (! $condition) {
        fwrite(STDERR, "FAIL: {$message}\n");
        exit(1);
    }
}

$path = __DIR__ . '/../docs/V123-IMPLEMENTATION-RTM-AND-GATES-2026-11-14.md';
$document = file_get_contents($path);
v123CatalogAssert(is_string($document) && $document !== '', 'V12.3 source-to-acceptance RTM must exist.');

$families = [
    'outcome metrics' => ['prefix' => 'M', 'from' => 1, 'to' => 12],
    'new acceptance cases' => ['prefix' => 'QA-', 'from' => 15, 'to' => 24],
    'storage lifecycle' => ['prefix' => 'STO-', 'from' => 1, 'to' => 10],
    'V12.3 change controls' => ['prefix' => 'V12.3-', 'from' => 1, 'to' => 10],
];
foreach ($families as $name => $family) {
    $expected = [];
    for ($index = $family['from']; $index <= $family['to']; ++$index) {
        $expected[] = $family['prefix'] . str_pad((string) $index, 2, '0', STR_PAD_LEFT);
    }
    $prefix = preg_quote($family['prefix'], '/');
    preg_match_all('/^\\|\\s*(' . $prefix . '[0-9]{2})\\s*\\|/m', $document, $matches);
    $observed = $matches[1];
    sort($observed);
    sort($expected);
    v123CatalogAssert($observed === $expected, $name . ' must be mapped once with no gaps or duplicate IDs.');
}

foreach (['UNVERIFIED', 'NOT RUN', 'BLOCKED', 'V12.3-F24-001', 'V12.3-F24-002', 'V12.3-F24-003'] as $essential) {
    v123CatalogAssert(str_contains($document, $essential), 'Traceability must preserve status/finding: ' . $essential);
}
v123CatalogAssert(
    ! str_contains($document, '100% operational') && ! str_contains($document, '100% production secure'),
    'Repository traceability must not fabricate full production acceptance.'
);

echo "PASS: V12.3 File24 42/42 newly scoped evidence IDs and truthful blocked statuses\n";
