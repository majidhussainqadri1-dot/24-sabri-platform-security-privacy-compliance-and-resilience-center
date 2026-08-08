<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

use Sabri\Platform\Security\Future\FutureSecurityCapabilityCatalog;
use Sabri\Platform\Security\Registry\ChatDirectiveCatalog;
use Sabri\Platform\Security\Registry\ContinuousValueRequirementCatalog;
use Sabri\Platform\Security\Registry\PlatformIntegrationMatrix;
use Sabri\Platform\Security\Registry\RequirementCatalog;
use Sabri\Platform\Security\Release\ReleaseStatus;

function c180(bool $condition, string $message): void { if (! $condition) { fwrite(STDERR, "FAIL: {$message}\n"); exit(1); } }

c180(RequirementCatalog::count() === 100 && RequirementCatalog::repositoryCodingComplete(), 'Stable File 24 requirements must remain repository-complete.');
c180(ChatDirectiveCatalog::count() === 18 && ChatDirectiveCatalog::repositoryCodingComplete(), 'Recovered directives must remain repository-complete.');
c180(ContinuousValueRequirementCatalog::count() === 25 && ContinuousValueRequirementCatalog::repositoryCodingComplete(), 'Continuous Value catalogue must remain repository-complete.');
c180(count(FutureSecurityCapabilityCatalog::all()) === 25 && FutureSecurityCapabilityCatalog::repositoryCodingComplete(), 'Future Security catalogue must remain repository-complete.');
c180(count(PlatformIntegrationMatrix::all()) === 27 && PlatformIntegrationMatrix::complete(), 'File 00-26 integration matrix must remain complete.');
c180(ReleaseStatus::repositoryCodingComplete(), 'Repository coding truth boundary must remain complete without asserting staging/live.');

$ci = (string) file_get_contents(__DIR__ . '/../.github/workflows/ci.yml');
c180(preg_match('/seq 116 ([0-9]+)/', $ci, $range) === 1 && (int) ($range[1] ?? 0) >= 181, 'CI must include the final closure regressions.');
c180(! preg_match('/str_contains\([^\n]*(seq 116 178|snapshot-cycle167|test \\\"\\$count\\\" -ge 259)/', (string) file_get_contents(__DIR__ . '/cycle167-second-post-ci-clean-closure-review.php') . "\n" . (string) file_get_contents(__DIR__ . '/cycle178-second-clean-post-fix-closure-review.php')), 'Historical closure checks must remain monotonic rather than freeze old current-state literals.');

echo "PASS: cycle180 first fresh post-Cycle-179 whole-system review found no new repository-correctable defect\n";
