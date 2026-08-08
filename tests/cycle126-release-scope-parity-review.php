<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

use Sabri\Platform\Security\Future\FutureSecurityAssurance;
use Sabri\Platform\Security\Future\FutureSecurityCapabilityCatalog;
use Sabri\Platform\Security\Registry\ContinuousValueRequirementCatalog;
use Sabri\Platform\Security\Registry\GovernedArtifactRegistry;
use Sabri\Platform\Security\Release\ReleaseStatus;
use Sabri\Platform\Security\Storage\AuditLogger;
use Sabri\Platform\Security\System\CompletionCheck;

function c126(bool $condition, string $message): void { if (! $condition) { fwrite(STDERR, "FAIL: {$message}\n"); exit(1); } }

c126(ContinuousValueRequirementCatalog::count() === 25 && ContinuousValueRequirementCatalog::repositoryCodingComplete(), 'Current central-plan CV/CEN scope must be 25/25 repository complete.');
c126(FutureSecurityCapabilityCatalog::count() === 25 && FutureSecurityCapabilityCatalog::repositoryCodingComplete(), 'Future Security scope must be 25/25 repository complete.');
c126(FutureSecurityAssurance::supportedIds() === array_keys(FutureSecurityCapabilityCatalog::all()), 'Future assurance IDs must remain exactly in parity with the catalogue.');
c126(ReleaseStatus::repositoryCodingComplete(), 'ReleaseStatus must include all current governing catalogues, not only historical R/CHAT scope.');
$checks = (new CompletionCheck(new GovernedArtifactRegistry(new AuditLogger())))->append([]);
$keys = array_column($checks, 'key');
c126(in_array('continuous_value_traceability', $keys, true), 'System Check must expose current CV/CEN traceability.');
c126(in_array('future_security_traceability', $keys, true), 'System Check must expose Future Security traceability.');

echo "PASS: cycle126 release-scope parity defect fixed and retested\n";
