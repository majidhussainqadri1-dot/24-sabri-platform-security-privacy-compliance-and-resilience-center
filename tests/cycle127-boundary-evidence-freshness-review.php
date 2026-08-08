<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

use Sabri\Platform\Security\Policy\BoundaryPolicyCatalog;

function c127(bool $condition, string $message): void { if (! $condition) { fwrite(STDERR, "FAIL: {$message}\n"); exit(1); } }

$now = strtotime('2026-08-08T10:00:00Z');
$policy = BoundaryPolicyCatalog::get('clinical') ?? [];
$base = ['controls' => $policy['required_controls'] ?? [], 'evidence_ref' => 'evidence:boundary-127'];
$stale = BoundaryPolicyCatalog::evaluate('clinical', $base + ['tested_at' => '2020-01-01T00:00:00Z'], $now);
c127(($stale['state'] ?? '') !== 'verified' && empty($stale['write_allowed']) && empty($stale['evidence_fresh']), 'Stale boundary evidence must not remain verified indefinitely.');
$future = BoundaryPolicyCatalog::evaluate('clinical', $base + ['tested_at' => '2099-01-01T00:00:00Z'], $now);
c127(empty($future['write_allowed']) && empty($future['evidence_fresh']), 'Future-dated boundary evidence must fail closed.');
$fresh = BoundaryPolicyCatalog::evaluate('clinical', $base + ['tested_at' => gmdate('c', $now - DAY_IN_SECONDS)], $now);
c127(($fresh['state'] ?? '') === 'verified' && ! empty($fresh['evidence_fresh']), 'Fresh complete boundary evidence must still verify.');

echo "PASS: cycle127 stale boundary-evidence defect fixed and retested\n";
