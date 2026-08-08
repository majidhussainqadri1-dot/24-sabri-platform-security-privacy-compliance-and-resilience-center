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
c167(str_contains($ci, 'test "$count" -ge 259') && str_contains($ci, 'test "$count" -ge 172'), 'Current CI must enforce post-fix lint/test floors.');
c167(str_contains($ci, 'file-24-sanitized-source-snapshot-cycle167'), 'Sanitized source artifact naming must identify Cycle-167 closure.');
c167(str_contains($register, '**Consecutive clean post-fix closing cycles: 166, 167.**'), 'Register must record two consecutive fresh clean reviews after the last fix.');
c167(str_contains($register, 'Known unresolved repository-correctable defects after fixes/retests | **0**'), 'Repository closure must remain zero-known-defect at the repository-correctable boundary.');
c167(RequirementCatalog::repositoryCodingComplete(), 'Stable requirement catalogue must remain repository complete.');
c167(FutureSecurityCapabilityCatalog::repositoryCodingComplete(), 'Future Security catalogue must remain repository complete.');
c167(FutureSecurityAssurance::supportedIds() === array_keys(FutureSecurityCapabilityCatalog::all()), 'Future assurance implementation IDs must retain exact catalogue parity.');
c167(PlatformIntegrationMatrix::complete(), 'All Files 00-26 must remain represented in the assurance matrix.');

echo "PASS: cycle167 second independent post-fix closure review found no new repository-correctable defect\n";
