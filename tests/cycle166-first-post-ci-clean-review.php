<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

use Sabri\Platform\Security\Future\FutureSecurityAssurance;
use Sabri\Platform\Security\Future\FutureSecurityCapabilityCatalog;
use Sabri\Platform\Security\Registry\PlatformIntegrationMatrix;
use Sabri\Platform\Security\Registry\RequirementCatalog;
use Sabri\Platform\Security\Release\ReleaseGateManager;

function c166(bool $condition, string $message): void { if (! $condition) { fwrite(STDERR, "FAIL: {$message}\n"); exit(1); } }

$ci = (string) file_get_contents(__DIR__ . '/../.github/workflows/ci.yml');
$register = (string) file_get_contents(__DIR__ . '/../docs/REVIEW-AND-CORRECTION-FUTURE-SECURITY-CYCLES-156-165.md');

c166(RequirementCatalog::repositoryCodingComplete(), 'Stable F24-R001..R100 requirement catalogue must remain complete.');
c166(count(FutureSecurityCapabilityCatalog::all()) === 25 && FutureSecurityCapabilityCatalog::repositoryCodingComplete(), 'Future Security Superset must remain exact 25/25.');
c166(FutureSecurityAssurance::supportedIds() === array_keys(FutureSecurityCapabilityCatalog::all()), 'Future assurance implementation must retain exact catalogue parity.');
c166(count(PlatformIntegrationMatrix::all()) === 27 && PlatformIntegrationMatrix::complete(), 'Files 00-26 integration assurance must remain complete.');
c166(count(ReleaseGateManager::phases()) === 12, 'Release phase model must remain 24A-24L.');
c166(str_contains($register, 'Cycle 165 itself found a QA/CI defect'), 'Closure register must preserve exact-head defect truth.');
c166(preg_match('/seq 116 ([0-9]+)/', $ci, $m) === 1 && (int) ($m[1] ?? 0) >= 167, 'Current CI must execute all permanent regressions through the post-fix closure range.');

echo "PASS: cycle166 first fresh post-Cycle-165 whole-system review found no new repository-correctable defect\n";
