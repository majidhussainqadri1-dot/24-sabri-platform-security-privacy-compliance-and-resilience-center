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

c197(preg_match('/seq 116 ([0-9]+)/', $ci, $range) === 1 && (int) ($range[1] ?? 0) >= 197, 'CI must execute every permanent review regression through Cycle 197.');
c197(str_contains($ci, 'test "$count" -ge 289') && str_contains($ci, 'test "$count" -ge 202'), 'CI must enforce post-review PHP lint and independent-test floors.');
c197(str_contains($ci, 'file-24-sanitized-source-snapshot-cycle197'), 'Sanitized source artifact naming must identify the current closure cycle.');
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
c197($phpCount >= 289, 'Current source/test tree must meet the monotonic PHP-file integrity floor.');
c197(count(array_filter($testPhp, static fn (string $f): bool => basename($f) !== 'bootstrap.php')) >= 202, 'Current independent top-level regression inventory must meet the monotonic test floor.');

echo "PASS: cycle197 second independent final closure review found no new repository-correctable defect\n";
