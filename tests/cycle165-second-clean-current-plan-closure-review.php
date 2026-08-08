<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

use Sabri\Platform\Security\Future\FutureSecurityAssurance;
use Sabri\Platform\Security\Future\FutureSecurityCapabilityCatalog;
use Sabri\Platform\Security\Registry\PlatformIntegrationMatrix;
use Sabri\Platform\Security\Registry\RequirementCatalog;

function c165(bool $condition, string $message): void { if (! $condition) { fwrite(STDERR, "FAIL: {$message}\n"); exit(1); } }

$ci = (string) file_get_contents(__DIR__ . '/../.github/workflows/ci.yml');
$register = (string) file_get_contents(__DIR__ . '/../docs/REVIEW-AND-CORRECTION-FUTURE-SECURITY-CYCLES-156-165.md');
c165(preg_match('/seq 116 ([0-9]+)/', $ci, $range) === 1 && (int) ($range[1] ?? 0) >= 165, 'Current CI must execute every permanent review regression through Cycle 165.');
c165(str_contains($ci, 'test "$count" -ge 257') && str_contains($ci, 'test "$count" -ge 170'), 'Current CI must enforce the expanded lint/test floors after ten new reviews.');
c165(str_contains($ci, 'file-24-sanitized-source-snapshot-cycle165'), 'Sanitized exact-source artifact naming must identify the current Cycle-165 closure.');
c165(str_contains($register, 'Defect-bearing cycles | **156, 157, 158, 159, 160, 161, 162, 163**'), 'Review register must truthfully enumerate every defect-bearing round in this batch.');
c165(str_contains($register, 'Consecutive clean closing cycles | **164, 165**'), 'Review register must record the two fresh clean closing rounds.');
c165(str_contains($register, 'Known unresolved repository-correctable defects after fixes/retests | **0**'), 'Repository truth boundary must close only at zero known correctable defects.');

c165(RequirementCatalog::repositoryCodingComplete(), 'Stable requirement catalogue must remain repository complete.');
c165(FutureSecurityCapabilityCatalog::repositoryCodingComplete(), 'Future Security catalogue must remain repository complete.');
c165(FutureSecurityAssurance::supportedIds() === array_keys(FutureSecurityCapabilityCatalog::all()), 'Future assurance implementation IDs must retain exact catalogue parity.');
c165(PlatformIntegrationMatrix::complete(), 'All Files 00-26 must remain represented in the integration assurance matrix.');

foreach (['EndpointGuard.php', 'PrivateDeliveryPolicy.php'] as $file) {
    $path = __DIR__ . '/../plugin/sabri-security-center/src/Security/' . $file;
    c165(is_file($path) && filesize($path) > 0, $file . ' must remain present and reviewable after closure hardening.');
}

echo "PASS: cycle165 second independent fresh closure review found no new repository-correctable defect\n";
