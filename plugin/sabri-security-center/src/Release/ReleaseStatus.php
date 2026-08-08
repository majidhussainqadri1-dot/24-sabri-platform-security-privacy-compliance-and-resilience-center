<?php

declare(strict_types=1);

namespace Sabri\Platform\Security\Release;

use Sabri\Platform\Security\Future\FutureSecurityAssurance;
use Sabri\Platform\Security\Future\FutureSecurityCapabilityCatalog;
use Sabri\Platform\Security\Policy\BoundaryPolicyCatalog;
use Sabri\Platform\Security\Registry\ChatDirectiveCatalog;
use Sabri\Platform\Security\Registry\ContinuousValueRequirementCatalog;
use Sabri\Platform\Security\Registry\PlatformIntegrationMatrix;
use Sabri\Platform\Security\Registry\RequirementCatalog;
use Sabri\Platform\Security\Support\Sanitizer;

/** Truthful seven-status release model. */
final class ReleaseStatus
{
    public const CODE_COMPLETE_VERSION = '0.99.0';
    public const PRODUCTION_TARGET = '1.0.0';

    /** @return array<string,array<string,mixed>> */
    public static function all(): array
    {
        $futureParity = FutureSecurityAssurance::supportedIds() === array_keys(FutureSecurityCapabilityCatalog::all());
        $specified = RequirementCatalog::count() === 100
            && ChatDirectiveCatalog::count() === 18
            && ContinuousValueRequirementCatalog::count() === 25
            && FutureSecurityCapabilityCatalog::count() === 25
            && $futureParity
            && PlatformIntegrationMatrix::complete();
        $coded = RequirementCatalog::repositoryCodingComplete()
            && ChatDirectiveCatalog::repositoryCodingComplete()
            && ContinuousValueRequirementCatalog::repositoryCodingComplete()
            && FutureSecurityCapabilityCatalog::repositoryCodingComplete()
            && $futureParity
            && PlatformIntegrationMatrix::complete()
            && count(BoundaryPolicyCatalog::all()) === 11
            && defined('SPCRC_VERSION')
            && version_compare((string) SPCRC_VERSION, self::CODE_COMPLETE_VERSION, '>=');

        $version = defined('SPCRC_VERSION') ? (string) SPCRC_VERSION : '';
        $packaged = Sanitizer::boolean(apply_filters('spcrc/release_evidence_packaged', false, $version));
        $automatedQa = Sanitizer::boolean(apply_filters('spcrc/release_evidence_automated_qa', false, $version));
        $staging = Sanitizer::boolean(apply_filters('spcrc/release_evidence_staging_accepted', false, $version));
        $live = $staging && Sanitizer::boolean(apply_filters('spcrc/release_evidence_live_deployed', false, $version));
        $operational = $live && Sanitizer::boolean(apply_filters('spcrc/release_evidence_operational', false, $version));

        return [
            'specified' => ['complete' => $specified, 'evidence' => $specified ? 'F24-R001–R100 + 18 CHAT + 25 CV/CEN + 25 Future requirements catalogued with File 00–26 integration' : 'Current governing requirement catalogue incomplete'],
            'coded' => ['complete' => $coded, 'evidence' => $coded ? 'Current governing repository scope code-complete candidate ' . $version : 'Repository coding incomplete'],
            'packaged' => ['complete' => $packaged, 'evidence' => $packaged ? 'Exact package evidence supplied' : 'Runtime package evidence not asserted'],
            'automated_qa_green' => ['complete' => $automatedQa, 'evidence' => $automatedQa ? 'Exact-head automated QA evidence supplied' : 'Runtime CI evidence not asserted'],
            'staging_accepted' => ['complete' => $staging, 'evidence' => $staging ? 'Founder-approved staging evidence supplied' : 'Hostinger staging acceptance pending'],
            'live_deployed' => ['complete' => $live, 'evidence' => $live ? 'Controlled live deployment evidence supplied' : 'Live deployment pending'],
            'operational' => ['complete' => $operational, 'evidence' => $operational ? 'Operational SLO and incident evidence supplied' : 'Operational acceptance pending'],
        ];
    }

    public static function repositoryCodingComplete(): bool
    {
        return (bool) (self::all()['coded']['complete'] ?? false);
    }

    public static function productionReady(): bool
    {
        $statuses = self::all();
        foreach (['specified', 'coded', 'packaged', 'automated_qa_green', 'staging_accepted', 'live_deployed', 'operational'] as $key) {
            if (empty($statuses[$key]['complete'])) {
                return false;
            }
        }
        return true;
    }

    /** @return string[] */
    public static function pendingExternalGates(): array
    {
        $pending = [];
        foreach (self::all() as $key => $status) {
            if (in_array($key, ['specified', 'coded'], true)) {
                continue;
            }
            if (empty($status['complete'])) {
                $pending[] = $key;
            }
        }
        return $pending;
    }

    /** @return array<string,mixed> */
    public static function summary(): array
    {
        return [
            'version' => defined('SPCRC_VERSION') ? SPCRC_VERSION : '',
            'code_complete_version' => self::CODE_COMPLETE_VERSION,
            'production_target' => self::PRODUCTION_TARGET,
            'repository_coding_complete' => self::repositoryCodingComplete(),
            'production_ready' => self::productionReady(),
            'pending_external_gates' => self::pendingExternalGates(),
            'statuses' => self::all(),
        ];
    }
}
