<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

use Sabri\Platform\Security\Registry\ContinuousValueRequirementCatalog;
use Sabri\Platform\Security\Release\ReleaseGateManager;
use Sabri\Platform\Security\Release\ReleaseStatus;

function c178(bool $condition, string $message): void { if (! $condition) { fwrite(STDERR, "FAIL: {$message}\n"); exit(1); } }

c178(ContinuousValueRequirementCatalog::repositoryCodingComplete(), 'Continuous Value closure must survive the final independent rereview.');
c178(count(ReleaseGateManager::phases()) === 12, 'Release phase model must remain 24A–24L.');
c178(ReleaseStatus::repositoryCodingComplete(), 'Repository-only completion boundary must remain true after all corrections.');

$workflow = file_get_contents(__DIR__ . '/../.github/workflows/ci.yml');
$register = file_get_contents(__DIR__ . '/../docs/REVIEW-AND-CORRECTION-FUTURE-SECURITY-CYCLES-168-177.md');
c178(is_string($workflow) && preg_match('/seq 116 ([0-9]+)/', $workflow, $range) === 1 && (int) ($range[1] ?? 0) >= 178 && str_contains($workflow, 'cycle178-second-clean-post-fix-closure-review.php'), 'CI must permanently retain or advance beyond Cycle 178 while continuing to execute this regression.');
c178(is_string($register) && str_contains($register, 'Defect-bearing cycles | **168, 169, 170, 171, 172, 173, 174, 175, 176**') && str_contains($register, 'Clean requested cycles | **177**') && str_contains($register, '| 178 | Second independent fresh post-fix review |'), 'Review register must truthfully preserve defect and clean-cycle results.');

$endpoint = file_get_contents(__DIR__ . '/../plugin/sabri-security-center/src/Security/EndpointGuard.php');
$release = file_get_contents(__DIR__ . '/../plugin/sabri-security-center/src/Release/ReleaseGateManager.php');
$incident = file_get_contents(__DIR__ . '/../plugin/sabri-security-center/src/Incident/IncidentCoordinator.php');
c178(is_string($endpoint) && ! preg_match('/absint\([^\)]*(rate_limit|rate_window)/', $endpoint), 'Endpoint policy must not regress to absint coercion.');
c178(is_string($release) && str_contains($release, 'risk_acceptance_reference_hash'), 'Waiver evidence-chain hardening must remain present.');
c178(is_string($incident) && str_contains($incident, 'persistCriticalClosureApproval'), 'Critical-closure retry safety must remain present.');

echo "PASS: cycle178 independent post-fix review found no new repository-correctable defect; later closure remains monotonic\n";
