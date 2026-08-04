<?php

declare(strict_types=1);

namespace Sabri\Platform\Security\System;

use Sabri\Platform\Security\Capabilities;
use Sabri\Platform\Security\Incident\IncidentCoordinator;
use Sabri\Platform\Security\Policy\BoundaryPolicyCatalog;
use Sabri\Platform\Security\Registry\GovernedArtifactRegistry;
use Sabri\Platform\Security\Registry\PlatformIntegrationMatrix;
use Sabri\Platform\Security\Registry\RequirementCatalog;
use Sabri\Platform\Security\Release\ReleaseGateManager;
use Sabri\Platform\Security\Release\ReleaseStatus;
use Sabri\Platform\Security\Support\Sanitizer;

/** Adds repository-completeness and external-boundary checks to SystemCheck. */
final class CompletionCheck
{
    public function __construct(private GovernedArtifactRegistry $artifacts)
    {
    }

    public function registerHooks(): void
    {
        add_filter('spcrc/system_checks', [$this, 'append'], 30, 1);
    }

    /** @param mixed $checks @return array<int,array<string,mixed>> */
    public function append(mixed $checks): array
    {
        $checks = is_array($checks) ? $checks : [];
        $summary = RequirementCatalog::summary();
        $checks[] = $this->check(
            'requirements_traceability',
            'F24-R001–F24-R100 repository traceability complete',
            ($summary['repository_coding_complete'] ?? false) === true,
            (int) ($summary['repository_implemented'] ?? 0) . '/100 requirements mapped'
        );
        $checks[] = $this->check(
            'integration_matrix',
            'Files 00–25 integration matrix complete',
            PlatformIntegrationMatrix::complete(),
            count(PlatformIntegrationMatrix::all()) . '/26 file definitions'
        );
        $checks[] = $this->check(
            'governed_domains',
            'Required governance and assurance domains implemented',
            count(GovernedArtifactRegistry::types()) >= 28,
            count(GovernedArtifactRegistry::types()) . ' logical domains'
        );
        $checks[] = $this->check(
            'boundary_policies',
            'Clinical, messaging, AI, marketplace, publishing and abuse policies implemented',
            count(BoundaryPolicyCatalog::all()) === 6,
            count(BoundaryPolicyCatalog::all()) . '/6 boundary policies'
        );
        $checks[] = $this->check(
            'release_phases',
            'File 24 implementation phases encoded',
            count(ReleaseGateManager::phases()) === 12,
            count(ReleaseGateManager::phases()) . '/12 phases'
        );
        $checks[] = $this->check(
            'capability_model',
            'File 24 least-privilege capability catalogue complete',
            count(Capabilities::all()) >= 24,
            count(Capabilities::all()) . ' capabilities'
        );
        $checks[] = $this->check(
            'incident_oob_readiness',
            'Out-of-band incident operations evidence supplied',
            (bool) (IncidentCoordinator::readiness()['ready'] ?? false),
            (IncidentCoordinator::readiness()['ready'] ?? false) ? 'Ready' : 'External evidence pending',
            'warning'
        );
        $checks[] = $this->check(
            'repository_coding_status',
            'Repository coding status is code-complete candidate',
            ReleaseStatus::repositoryCodingComplete(),
            ReleaseStatus::repositoryCodingComplete() ? 'Code-complete candidate ' . (defined('SPCRC_VERSION') ? SPCRC_VERSION : '') : 'Incomplete'
        );
        $checks[] = $this->check(
            'production_truth_boundary',
            'Production is not asserted without all external gates',
            ! ReleaseStatus::productionReady(),
            ReleaseStatus::productionReady() ? 'Production evidence asserted' : 'Staging/live/operational gates remain explicit',
            'warning'
        );
        return $checks;
    }

    /** @return array<string,mixed> */
    private function check(string $key, string $label, bool $passed, string $detail, string $failure = 'critical'): array
    {
        return [
            'key' => Sanitizer::key($key, 80),
            'label' => Sanitizer::text($label, 160),
            'status' => $passed ? 'pass' : $failure,
            'detail' => Sanitizer::text($detail, 500),
        ];
    }
}
