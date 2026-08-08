<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

use Sabri\Platform\Security\Future\FutureSecurityAssurance;
use Sabri\Platform\Security\Future\FutureSecurityCapabilityCatalog;

function expectCycle116(bool $condition, string $message): void { if (! $condition) { fwrite(STDERR, "FAIL: {$message}\n"); exit(1); } }

$expected = [];
for ($i = 1; $i <= 25; $i++) {
    $expected[] = sprintf('F24-FUT-%03d', $i);
}
$catalog = FutureSecurityCapabilityCatalog::all();
expectCycle116(array_keys($catalog) === $expected, 'Future catalogue IDs must be contiguous F24-FUT-001..025.');
expectCycle116(FutureSecurityAssurance::supportedIds() === $expected, 'Assurance IDs must exactly match the approved catalogue.');
expectCycle116(FutureSecurityCapabilityCatalog::repositoryCodingComplete(), 'Catalogue repository invariants must remain complete.');
foreach ($catalog as $id => $item) {
    expectCycle116(($item['owner'] ?? '') === 'File 24 assurance', "{$id} must remain assurance-owned only.");
    expectCycle116(($item['native_enforcement_preserved'] ?? false) === true, "{$id} must preserve native enforcement.");
    expectCycle116(($item['security_single_point_of_failure_forbidden'] ?? false) === true, "{$id} must forbid File-24 security SPoF.");
    expectCycle116(($item['public_safe_evidence_only'] ?? false) === true, "{$id} must keep repository evidence public-safe.");
}

echo "PASS: cycle116 clean catalogue/ownership review\n";
