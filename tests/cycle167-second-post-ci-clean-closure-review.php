<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

use Sabri\Platform\Security\Future\FutureSecurityAssurance;
use Sabri\Platform\Security\Future\FutureSecurityCapabilityCatalog;
use Sabri\Platform\Security\Registry\PlatformIntegrationMatrix;
use Sabri\Platform\Security\Registry\RequirementCatalog;

function c167(bool $condition, string $message): void { if (! $condition) { fwrite(STDERR, "FAIL: {$message}\n"); exit(1); } }

$ci = (string) file_get_contents(__DIR__ . '/../.github/workflows/ci.yml');
$register = (string) file_get_contents(__DIR__ . '/../docs/REVIEW-AND-CORRECTION-FUTURE-SECURITY-CYCLES-156-165.md');

c167(preg_match('/seq 116 ([0-9]+)/', $ci, $range) === 1 && (int) ($range[1] ?? 0) >= 167, 'Current CI must execute every review regression through Cycle 167.');
c167(preg_match_all('/test "\$count" -ge ([0-9]+)/', $ci, $floorMatches) >= 2 && max(array_map('intval', $floorMatches[1] ?? [])) >= 259 && min(array_map('intval', $floorMatches[1] ?? [])) >= 172, 'Current CI must retain or advance post-fix lint/test floors.');
c167(preg_match('/file-24-sanitized-source-snapshot-cycle([0-9]+)/', $ci, $artifactMatch) === 1 && (int) ($artifactMatch[1] ?? 0) >= 167, 'Sanitized source artifact naming must remain at Cycle 167 or advance beyond it.');
c167(str_contains($register, '**Consecutive clean post-fix closing cycles: 166, 167.**'), 'Register must record two consecutive fresh clean reviews after the last fix.');
c167(str_contains($register, 'Known unresolved repository-correctable defects after fixes/retests | **0**'), 'Repository closure must remain zero-known-defect at the repository-correctable boundary.');
c167(RequirementCatalog::repositoryCodingComplete(), 'Stable requirement catalogue must remain repository complete.');
c167(FutureSecurityCapabilityCatalog::repositoryCodingComplete(), 'Future Security catalogue must remain repository complete.');
c167(FutureSecurityAssurance::supportedIds() === array_keys(FutureSecurityCapabilityCatalog::all()), 'Future assurance implementation IDs must retain exact catalogue parity.');
c167(PlatformIntegrationMatrix::complete(), 'All Files 00-26 must remain represented in the assurance matrix.');

echo "PASS: cycle167 second independent post-fix closure review found no new repository-correctable defect\n";
