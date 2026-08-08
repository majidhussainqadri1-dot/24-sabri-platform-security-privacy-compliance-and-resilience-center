<?php

declare(strict_types=1);

namespace Sabri\Platform\Security\Registry;

/**
 * File 24 projection of the Founder-approved Continuous Value / Top-20 Superset plan.
 *
 * This catalogue does not move native control ownership into File 24. It records the
 * assurance contract File 24 must be able to evaluate and keeps external/staging
 * evidence distinct from repository coding completion.
 */
final class ContinuousValueRequirementCatalog
{
    /** @var array<string,array{title:string,phase:string,canonical_owner:string,file24_role:string,implementation:list<string>,mode:string,repository_status:string}> */
    private const REQUIREMENTS = [
        'CV-262' => ['title'=>'Zero-trust authorization','phase'=>'NOW/P0','canonical_owner'=>'native-domain-owner','file24_role'=>'authorization assurance','implementation'=>['EndpointGuard','IdentityAssurance','BoundaryPolicyCatalog'],'mode'=>'hybrid','repository_status'=>'implemented'],
        'CV-263' => ['title'=>'Encryption in transit and at rest','phase'=>'NOW/P0','canonical_owner'=>'native-data-owner','file24_role'=>'cryptography and recovery assurance','implementation'=>['KeyGovernance','BackupAssurance','BoundaryPolicyCatalog'],'mode'=>'hybrid','repository_status'=>'implemented'],
        'CV-264' => ['title'=>'Secrets management','phase'=>'NOW/P0','canonical_owner'=>'native-runtime-owner','file24_role'=>'secret-handling assurance','implementation'=>['SensitiveMaterialGuard','KeyGovernance','CI secret scan'],'mode'=>'hybrid','repository_status'=>'implemented'],
        'CV-265' => ['title'=>'Privileged audit trail','phase'=>'NOW/P0','canonical_owner'=>'native-event-producer','file24_role'=>'normalized audit evidence','implementation'=>['AuditLogger','SecurityEventRepository'],'mode'=>'repository','repository_status'=>'implemented'],
        'CV-266' => ['title'=>'Privacy by purpose','phase'=>'NOW/P0','canonical_owner'=>'native-data-owner','file24_role'=>'purpose, retention and deletion assurance','implementation'=>['PrivacyRequestService','RetentionService','BoundaryPolicyCatalog'],'mode'=>'hybrid','repository_status'=>'implemented'],
        'CV-267' => ['title'=>'Anti-surveillance charter','phase'=>'NOW/P0','canonical_owner'=>'file-24-policy-assurance','file24_role'=>'prohibited-use and minimization gate','implementation'=>['AntiSurveillancePolicy'],'mode'=>'repository','repository_status'=>'implemented'],
        'CV-268' => ['title'=>'Cookie and tracker control','phase'=>'NOW/P0','canonical_owner'=>'file-20-and-native-analytics-owner','file24_role'=>'consent-category and withdrawal assurance','implementation'=>['ContinuousValueAssurance'],'mode'=>'hybrid','repository_status'=>'implemented'],
        'CV-269' => ['title'=>'Secure SDLC','phase'=>'NOW/P0','canonical_owner'=>'release-governance','file24_role'=>'security release gate','implementation'=>['CI workflow','SBOM','Threat Model','ContinuousValueAssurance'],'mode'=>'repository','repository_status'=>'implemented'],
        'CV-270' => ['title'=>'Vulnerability program','phase'=>'SCALE/P0','canonical_owner'=>'security-operations','file24_role'=>'triage, remediation and disclosure assurance','implementation'=>['VulnerabilityManager','SECURITY.md','ContinuousValueAssurance'],'mode'=>'hybrid','repository_status'=>'implemented'],
        'CV-271' => ['title'=>'Compliance registry','phase'=>'NEXT/P0','canonical_owner'=>'qualified-compliance-owner','file24_role'=>'applicability and evidence registry','implementation'=>['ComplianceRegistry','ContinuousValueAssurance'],'mode'=>'hybrid','repository_status'=>'implemented'],
        'CV-272' => ['title'=>'Backup and DR privacy','phase'=>'NOW/P0','canonical_owner'=>'native-data-owner-and-operations','file24_role'=>'backup privacy assurance','implementation'=>['BackupAssurance','RetentionService','ContinuousValueAssurance'],'mode'=>'hybrid','repository_status'=>'implemented'],
        'CV-273' => ['title'=>'Incident response','phase'=>'NOW/P0','canonical_owner'=>'incident-command','file24_role'=>'incident coordination and evidence','implementation'=>['IncidentManager','Incident Response Plan','ContinuousValueAssurance'],'mode'=>'hybrid','repository_status'=>'implemented'],
        'CV-274' => ['title'=>'Service objectives and error budgets','phase'=>'NOW/P0','canonical_owner'=>'service-owner','file24_role'=>'SLO evidence assurance','implementation'=>['ContinuousValueAssurance'],'mode'=>'hybrid','repository_status'=>'implemented'],
        'CV-275' => ['title'=>'Performance budgets','phase'=>'NOW/P0','canonical_owner'=>'service-owner','file24_role'=>'performance evidence gate','implementation'=>['ContinuousValueAssurance'],'mode'=>'hybrid','repository_status'=>'implemented'],
        'CV-276' => ['title'=>'Privacy-safe observability','phase'=>'NOW/P0','canonical_owner'=>'operations-owner','file24_role'=>'metrics/logs/traces assurance','implementation'=>['ContinuousValueAssurance'],'mode'=>'hybrid','repository_status'=>'implemented'],
        'CV-277' => ['title'=>'Graceful degradation','phase'=>'NOW/P0','canonical_owner'=>'native-domain-owner','file24_role'=>'fail-safe degradation assurance','implementation'=>['ContinuousValueAssurance','AssuranceCenterContract'],'mode'=>'hybrid','repository_status'=>'implemented'],
        'CV-278' => ['title'=>'Backup and restore RPO/RTO','phase'=>'NOW/P0','canonical_owner'=>'data-and-operations-owner','file24_role'=>'recovery evidence assurance','implementation'=>['BackupAssurance','ContinuousValueAssurance'],'mode'=>'hybrid','repository_status'=>'implemented'],
        'CV-279' => ['title'=>'Release rings and rollback','phase'=>'NOW/P0','canonical_owner'=>'release-governance','file24_role'=>'progressive-delivery assurance','implementation'=>['ReleaseGateManager','ContinuousValueAssurance'],'mode'=>'repository','repository_status'=>'implemented'],
        'CV-280' => ['title'=>'Two-review law','phase'=>'NOW/P0','canonical_owner'=>'release-governance','file24_role'=>'two fresh review/fix/retest gate','implementation'=>['Cycle 112','Cycle 113','ContinuousValueAssurance'],'mode'=>'repository','repository_status'=>'implemented'],
        'CV-281' => ['title'=>'Support center boundary','phase'=>'NEXT/P1','canonical_owner'=>'support-owner','file24_role'=>'support privacy and emergency-boundary assurance','implementation'=>['ContinuousValueAssurance'],'mode'=>'hybrid','repository_status'=>'implemented'],
        'CV-282' => ['title'=>'Capacity and cost forecasting','phase'=>'NEXT/P0','canonical_owner'=>'operations-owner','file24_role'=>'capacity/sustainability assurance','implementation'=>['ContinuousValueAssurance'],'mode'=>'hybrid','repository_status'=>'implemented'],
        'CV-283' => ['title'=>'Versioned data migrations','phase'=>'NOW/P0','canonical_owner'=>'native-data-owner','file24_role'=>'migration/backup/rollback assurance','implementation'=>['MigrationManager','ContinuousValueAssurance'],'mode'=>'hybrid','repository_status'=>'implemented'],
        'CV-284' => ['title'=>'Vendor resilience','phase'=>'SCALE/P0','canonical_owner'=>'vendor-owner','file24_role'=>'exit/SLA/region/subprocessor assurance','implementation'=>['ContinuousValueAssurance'],'mode'=>'hybrid','repository_status'=>'implemented'],
        'CV-285' => ['title'=>'Runbooks and on-call','phase'=>'NOW/P0','canonical_owner'=>'operations-owner','file24_role'=>'incident-readiness assurance','implementation'=>['ContinuousValueAssurance'],'mode'=>'hybrid','repository_status'=>'implemented'],
        'F24-CEN-01' => ['title'=>'Assurance Center dashboards without native-control takeover','phase'=>'NOW/P0','canonical_owner'=>'file-24-assurance-plane','file24_role'=>'controls/evidence/exceptions/incidents/DR dashboards while native enforcement remains native','implementation'=>['AssuranceCenterContract'],'mode'=>'repository','repository_status'=>'implemented'],
    ];

    /** @return array<string,array<string,mixed>> */
    public static function all(): array { return self::REQUIREMENTS; }

    /** @return array<string,mixed>|null */
    public static function get(string $id): ?array { return self::REQUIREMENTS[$id] ?? null; }

    /** @return list<string> */
    public static function ids(): array { return array_keys(self::REQUIREMENTS); }

    public static function count(): int { return count(self::REQUIREMENTS); }

    public static function repositoryCodingComplete(): bool
    {
        if (self::count() !== 25) { return false; }
        for ($id = 262; $id <= 285; $id++) {
            if (! isset(self::REQUIREMENTS['CV-' . $id])) { return false; }
        }
        if (! isset(self::REQUIREMENTS['F24-CEN-01'])) { return false; }
        foreach (self::REQUIREMENTS as $record) {
            if (($record['repository_status'] ?? '') !== 'implemented') { return false; }
            if (($record['canonical_owner'] ?? '') === '' || ($record['file24_role'] ?? '') === '') { return false; }
            if (! is_array($record['implementation'] ?? null) || $record['implementation'] === []) { return false; }
        }
        return true;
    }

    /** @return array<string,mixed> */
    public static function summary(): array
    {
        return [
            'total' => self::count(),
            'cv_262_285' => 24,
            'file_specific' => 1,
            'repository_coding_complete' => self::repositoryCodingComplete(),
            'external_acceptance_required' => true,
        ];
    }
}
