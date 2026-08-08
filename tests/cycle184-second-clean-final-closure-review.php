<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

use Sabri\Platform\Security\Registry\RequirementCatalog;
use Sabri\Platform\Security\Release\ReleaseGateManager;
use Sabri\Platform\Security\Release\ReleaseStatus;

function c184(bool $condition, string $message): void { if (! $condition) { fwrite(STDERR, "FAIL: {$message}\n"); exit(1); } }

c184(RequirementCatalog::repositoryCodingComplete(), 'File 24 stable requirement catalogue must remain repository complete.');
c184(count(ReleaseGateManager::phases()) === 12, 'Release phase model must remain 24A through 24L.');
c184(ReleaseStatus::repositoryCodingComplete(), 'Repository-only completion boundary must remain true.');
$ci = (string) file_get_contents(__DIR__ . '/../.github/workflows/ci.yml');
$register = (string) file_get_contents(__DIR__ . '/../docs/REVIEW-AND-CORRECTION-FUTURE-SECURITY-CYCLES-168-177.md');
c184(preg_match('/seq 116 ([0-9]+)/', $ci, $range) === 1 && (int) ($range[1] ?? 0) >= 184, 'CI must permanently execute regressions through Cycle 184 or later.');
c184(str_contains($register, 'Defect-bearing cycles | **168, 169, 170, 171, 172, 173, 174, 175, 176**'), 'Requested ten-round defect register must remain exact.');
c184(str_contains($register, 'Additional post-request defect-bearing cycles | **179, 182**'), 'All post-request defects discovered during closure must remain recorded.');
c184(str_contains($register, '**Consecutive clean final closing cycles: 183, 184.**'), 'Final closure requires two fresh clean reviews after the last correction.');
c184(str_contains($register, 'Known unresolved repository-correctable defects after fixes/retests | **0**'), 'Final known repository-correctable defect count must be zero.');

echo "PASS: cycle184 second consecutive fresh final closure review found no new repository-correctable defect\n";
