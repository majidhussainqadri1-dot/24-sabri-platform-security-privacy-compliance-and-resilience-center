<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

use Sabri\Platform\Security\Future\FutureSecurityCapabilityCatalog;
use Sabri\Platform\Security\Registry\ContinuousValueRequirementCatalog;
use Sabri\Platform\Security\Registry\PlatformIntegrationMatrix;
use Sabri\Platform\Security\Release\ReleaseStatus;

function c183(bool $condition, string $message): void { if (! $condition) { fwrite(STDERR, "FAIL: {$message}\n"); exit(1); } }

c183(ContinuousValueRequirementCatalog::repositoryCodingComplete(), 'Continuous Value catalogue must remain repository-complete.');
c183(FutureSecurityCapabilityCatalog::repositoryCodingComplete(), 'Future Security catalogue must remain repository-complete.');
c183(PlatformIntegrationMatrix::complete(), 'Files 00-26 integration matrix must remain complete.');
c183(ReleaseStatus::repositoryCodingComplete(), 'Repository coding truth boundary must remain complete without staging/live overclaim.');
$build = (string) file_get_contents(__DIR__ . '/../tools/build-release.sh');
c183(str_contains($build, 'ENTRY_LIST="$BUILD_DIR/.package-entries.txt"') && str_contains($build, "grep -Fxq 'sabri-security-center/sabri-security-center.php' \"\$ENTRY_LIST\""), 'Deterministic builder must retain pipefail-safe package membership verification.');

echo "PASS: cycle183 first fresh post-packaging-fix review found no new repository-correctable defect\n";
