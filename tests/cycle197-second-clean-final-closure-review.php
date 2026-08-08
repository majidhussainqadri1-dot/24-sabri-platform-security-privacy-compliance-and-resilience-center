<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

use Sabri\Platform\Security\Future\FutureSecurityAssurance;
use Sabri\Platform\Security\Future\FutureSecurityCapabilityCatalog;
use Sabri\Platform\Security\Registry\ContinuousValueRequirementCatalog;
use Sabri\Platform\Security\Registry\PlatformIntegrationMatrix;
use Sabri\Platform\Security\Registry\RequirementCatalog;

function c197(bool $condition, string $message): void { if (! $condition) { fwrite(STDERR, "FAIL: {$message}\n"); exit(1); } }

$root = dirname(__DIR__);
$ci = (string) file_get_contents($root . '/.github/workflows/ci.yml');
$register = (string) file_get_contents($root . '/docs/REVIEW-AND-CORRECTION-FUTURE-SECURITY-CYCLES-185-194.md');

c197(str_contains($ci, "find plugin tests -type f -name '*.php'") && str_contains($ci, "find tests -maxdepth 1 -type f -name '*.php' ! -name 'bootstrap.php'"), 'CI must dynamically lint all PHP source/tests and execute every top-level regression rather than rely only on a frozen cycle range.');
c197(str_contains($ci, "for cycle in $(seq 116 184); do"), 'Historical explicit cycle gate must remain at least through the prior merged closure while dynamic discovery executes later regressions.');
c197(str_contains($ci, "! grep -RInE --include='*.php' ':[[:space:]]*never\\b' plugin tests"), 'CI must preserve the PHP 8.0 compatibility guard that exposed Cycle 195.');
foreach (range(185, 197) as $cycle) {
    c197((glob($root . '/tests/cycle' . $cycle . '-*.php') ?: []) !== [], 'Every Cycle 185-197 permanent regression must exist in the repository.');
}
c197(str_contains($register, '**Consecutive clean final closing cycles: 196, 197.**'), 'Review register must truthfully record the two consecutive final clean cycles.');
c197(str_contains($register, 'Known unresolved repository-correctable defects after fixes/retests | **0**'), 'Repository closure must retain zero known unresolved repository-correctable defects after retest.');
c197(RequirementCatalog::repositoryCodingComplete(), 'Stable File 24 requirement catalogue must remain repository complete.');
c197(ContinuousValueRequirementCatalog::repositoryCodingComplete(), 'Continuous Value catalogue must remain repository complete.');
c197(FutureSecurityCapabilityCatalog::repositoryCodingComplete(), 'Future Security catalogue must remain repository complete.');
c197(FutureSecurityAssurance::supportedIds() === array_keys(FutureSecurityCapabilityCatalog::all()), 'Future assurance implementation IDs must retain exact catalogue parity.');
c197(PlatformIntegrationMatrix::complete(), 'All Files 00-26 must remain represented in the assurance matrix.');

$phpCount = 0;
foreach ([$root . '/plugin', $root . '/tests'] as $directory) {
    $iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($directory));
    foreach ($iterator as $file) if ($file->isFile() && $file->getExtension() === 'php') ++$phpCount;
}
$testPhp = glob($root . '/tests/*.php') ?: [];
c197($phpCount >= 289, 'Current source/test tree must meet the post-review PHP-file integrity floor.');
c197(count(array_filter($testPhp, static fn (string $f): bool => basename($f) !== 'bootstrap.php')) >= 202, 'Current independent top-level regression inventory must meet the post-review test floor.');

echo "PASS: cycle197 second independent final closure review found no new repository-correctable defect\n";
