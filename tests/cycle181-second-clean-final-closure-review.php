<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

use Sabri\Platform\Security\Registry\ContinuousValueRequirementCatalog;
use Sabri\Platform\Security\Release\ReleaseGateManager;
use Sabri\Platform\Security\Release\ReleaseStatus;

function c181(bool $condition, string $message): void { if (! $condition) { fwrite(STDERR, "FAIL: {$message}\n"); exit(1); } }

c181(ContinuousValueRequirementCatalog::repositoryCodingComplete(), 'Current-plan Continuous Value closure must remain green.');
c181(count(ReleaseGateManager::phases()) === 12, 'Release phase model must remain 24A through 24L.');
c181(ReleaseStatus::repositoryCodingComplete(), 'Repository-only completion boundary must remain true.');

$ci = (string) file_get_contents(__DIR__ . '/../.github/workflows/ci.yml');
$register = (string) file_get_contents(__DIR__ . '/../docs/REVIEW-AND-CORRECTION-FUTURE-SECURITY-CYCLES-168-177.md');
c181(preg_match('/seq 116 ([0-9]+)/', $ci, $range) === 1 && (int) ($range[1] ?? 0) >= 181, 'CI must permanently execute all regressions through Cycle 181 or later.');
c181(str_contains($register, 'Defect-bearing cycles | **168, 169, 170, 171, 172, 173, 174, 175, 176**'), 'Requested-round defect register must remain exact.');
c181(preg_match('/Additional post-request defect-bearing cycles \| \*\*([^*]+)\*\*/', $register, $extra) === 1 && str_contains((string) ($extra[1] ?? ''), '179'), 'Post-request Cycle 179 defect must remain truthfully recorded even if later closure defects are added.');
c181(str_contains($register, '| 181 | Second independent post-Cycle-179 review |'), 'Cycle 181 clean-review result must remain historically recorded without freezing it as final closure.');
c181(str_contains($register, 'Known unresolved repository-correctable defects after fixes/retests | **0**'), 'Final repository-correctable defect count must remain zero.');

echo "PASS: cycle181 second consecutive post-Cycle-179 clean review found no new repository-correctable defect; later closure may advance\n";
