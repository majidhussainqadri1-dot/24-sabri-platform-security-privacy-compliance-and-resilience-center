<?php

declare(strict_types=1);

namespace Sabri\Platform\Security\Registry;

/**
 * Canonical F24-R001–F24-R100 requirement catalogue.
 *
 * "repository_status=implemented" means the repository contains the code,
 * contract, gate, documentation or test harness required by the specification.
 * It does not assert that external staging, providers, legal review,
 * penetration testing, restore drills, live deployment or operations passed.
 */
final class RequirementCatalog
{
    /** @var array<string,array{title:string,mode:string,implementation:string,repository_status:string}> */
    private const REQUIREMENTS = [
        'F24-R001' => ['title' => 'قطعی حاکم فیصلہ', 'mode' => 'repository', 'implementation' => 'Governance charter, RequirementCatalog, GovernedArtifactRegistry', 'repository_status' => 'implemented'],
        'F24-R002' => ['title' => 'فائل نمبر بندی کی حتمی تطبیق', 'mode' => 'repository', 'implementation' => 'Governance charter, RequirementCatalog, GovernedArtifactRegistry', 'repository_status' => 'implemented'],
        'F24-R003' => ['title' => 'دستاویز، plugin اور production versions', 'mode' => 'repository', 'implementation' => 'Governance charter, RequirementCatalog, GovernedArtifactRegistry', 'repository_status' => 'implemented'],
        'F24-R004' => ['title' => 'منصوبے کا دائرۂ کار', 'mode' => 'repository', 'implementation' => 'Governance charter, RequirementCatalog, GovernedArtifactRegistry', 'repository_status' => 'implemented'],
        'F24-R005' => ['title' => 'Non-Goals اور ممنوع دعوے', 'mode' => 'repository', 'implementation' => 'Governance charter, RequirementCatalog, GovernedArtifactRegistry', 'repository_status' => 'implemented'],
        'F24-R006' => ['title' => 'Foundation Version 0.25 کا قانون', 'mode' => 'repository', 'implementation' => 'Governance charter, RequirementCatalog, GovernedArtifactRegistry', 'repository_status' => 'implemented'],
        'F24-R007' => ['title' => 'Security Governance Charter', 'mode' => 'repository', 'implementation' => 'Governance charter, RequirementCatalog, GovernedArtifactRegistry', 'repository_status' => 'implemented'],
        'F24-R008' => ['title' => 'Policy Hierarchy', 'mode' => 'repository', 'implementation' => 'Governance charter, RequirementCatalog, GovernedArtifactRegistry', 'repository_status' => 'implemented'],
        'F24-R009' => ['title' => 'Standards Baseline', 'mode' => 'repository', 'implementation' => 'Governance charter, RequirementCatalog, GovernedArtifactRegistry', 'repository_status' => 'implemented'],
        'F24-R010' => ['title' => 'Zero-Defect Change-Control Rule', 'mode' => 'repository', 'implementation' => 'Governance charter, RequirementCatalog, GovernedArtifactRegistry', 'repository_status' => 'implemented'],
        'F24-R011' => ['title' => 'تین سطحی Security Architecture', 'mode' => 'repository', 'implementation' => 'PlatformIntegrationMatrix, ModuleRegistry, SecurityStateRegistry, TrustCenterService', 'repository_status' => 'implemented'],
        'F24-R012' => ['title' => 'Native Ownership Preserved', 'mode' => 'repository', 'implementation' => 'PlatformIntegrationMatrix, ModuleRegistry, SecurityStateRegistry, TrustCenterService', 'repository_status' => 'implemented'],
        'F24-R013' => ['title' => 'No Security Single Point of Failure', 'mode' => 'repository', 'implementation' => 'PlatformIntegrationMatrix, ModuleRegistry, SecurityStateRegistry, TrustCenterService', 'repository_status' => 'implemented'],
        'F24-R014' => ['title' => 'Fail-Safe Matrix', 'mode' => 'repository', 'implementation' => 'PlatformIntegrationMatrix, ModuleRegistry, SecurityStateRegistry, TrustCenterService', 'repository_status' => 'implemented'],
        'F24-R015' => ['title' => 'Module Security Manifest', 'mode' => 'repository', 'implementation' => 'PlatformIntegrationMatrix, ModuleRegistry, SecurityStateRegistry, TrustCenterService', 'repository_status' => 'implemented'],
        'F24-R016' => ['title' => 'Security Contract Interface', 'mode' => 'repository', 'implementation' => 'PlatformIntegrationMatrix, ModuleRegistry, SecurityStateRegistry, TrustCenterService', 'repository_status' => 'implemented'],
        'F24-R017' => ['title' => 'Security State Ownership', 'mode' => 'repository', 'implementation' => 'PlatformIntegrationMatrix, ModuleRegistry, SecurityStateRegistry, TrustCenterService', 'repository_status' => 'implemented'],
        'F24-R018' => ['title' => 'Public Trust Center Ownership', 'mode' => 'repository', 'implementation' => 'PlatformIntegrationMatrix, ModuleRegistry, SecurityStateRegistry, TrustCenterService', 'repository_status' => 'implemented'],
        'F24-R019' => ['title' => 'Backup Responsibility Boundary', 'mode' => 'repository', 'implementation' => 'PlatformIntegrationMatrix, ModuleRegistry, SecurityStateRegistry, TrustCenterService', 'repository_status' => 'implemented'],
        'F24-R020' => ['title' => 'External Security Dependencies', 'mode' => 'hybrid', 'implementation' => 'PlatformIntegrationMatrix, ModuleRegistry, SecurityStateRegistry, TrustCenterService', 'repository_status' => 'implemented'],
        'F24-R021' => ['title' => 'Single Identity Authority', 'mode' => 'repository', 'implementation' => 'IdentityAssurance, File00Adapter, File02Adapter, CryptographyPolicy', 'repository_status' => 'implemented'],
        'F24-R022' => ['title' => 'Authentication Methods and Assurance', 'mode' => 'repository', 'implementation' => 'IdentityAssurance, File00Adapter, File02Adapter, CryptographyPolicy', 'repository_status' => 'implemented'],
        'F24-R023' => ['title' => 'Authorization Model', 'mode' => 'repository', 'implementation' => 'IdentityAssurance, File00Adapter, File02Adapter, CryptographyPolicy', 'repository_status' => 'implemented'],
        'F24-R024' => ['title' => 'Session Security', 'mode' => 'repository', 'implementation' => 'IdentityAssurance, File00Adapter, File02Adapter, CryptographyPolicy', 'repository_status' => 'implemented'],
        'F24-R025' => ['title' => 'Account Recovery', 'mode' => 'repository', 'implementation' => 'IdentityAssurance, File00Adapter, File02Adapter, CryptographyPolicy', 'repository_status' => 'implemented'],
        'F24-R026' => ['title' => 'Privileged Access and Separation of Duties', 'mode' => 'repository', 'implementation' => 'IdentityAssurance, File00Adapter, File02Adapter, CryptographyPolicy', 'repository_status' => 'implemented'],
        'F24-R027' => ['title' => 'Secrets Management', 'mode' => 'hybrid', 'implementation' => 'IdentityAssurance, File00Adapter, File02Adapter, CryptographyPolicy', 'repository_status' => 'implemented'],
        'F24-R028' => ['title' => 'Key Lifecycle and Recovery', 'mode' => 'hybrid', 'implementation' => 'IdentityAssurance, File00Adapter, File02Adapter, CryptographyPolicy', 'repository_status' => 'implemented'],
        'F24-R029' => ['title' => 'Cryptography Policy', 'mode' => 'hybrid', 'implementation' => 'IdentityAssurance, File00Adapter, File02Adapter, CryptographyPolicy', 'repository_status' => 'implemented'],
        'F24-R030' => ['title' => 'End-to-End Encryption Claim Gate', 'mode' => 'hybrid', 'implementation' => 'IdentityAssurance, File00Adapter, File02Adapter, CryptographyPolicy', 'repository_status' => 'implemented'],
        'F24-R031' => ['title' => 'WordPress Hardening Baseline', 'mode' => 'repository', 'implementation' => 'EndpointGuard, NetworkPolicy, UploadPolicy, PrivateDeliveryPolicy, SystemCheck', 'repository_status' => 'implemented'],
        'F24-R032' => ['title' => 'REST، AJAX اور Webhook Security', 'mode' => 'repository', 'implementation' => 'EndpointGuard, NetworkPolicy, UploadPolicy, PrivateDeliveryPolicy, SystemCheck', 'repository_status' => 'implemented'],
        'F24-R033' => ['title' => 'Input Validation and Output Encoding', 'mode' => 'repository', 'implementation' => 'EndpointGuard, NetworkPolicy, UploadPolicy, PrivateDeliveryPolicy, SystemCheck', 'repository_status' => 'implemented'],
        'F24-R034' => ['title' => 'File Upload Security', 'mode' => 'repository', 'implementation' => 'EndpointGuard, NetworkPolicy, UploadPolicy, PrivateDeliveryPolicy, SystemCheck', 'repository_status' => 'implemented'],
        'F24-R035' => ['title' => 'Private File Delivery', 'mode' => 'repository', 'implementation' => 'EndpointGuard, NetworkPolicy, UploadPolicy, PrivateDeliveryPolicy, SystemCheck', 'repository_status' => 'implemented'],
        'F24-R036' => ['title' => 'Database Security and Integrity', 'mode' => 'repository', 'implementation' => 'EndpointGuard, NetworkPolicy, UploadPolicy, PrivateDeliveryPolicy, SystemCheck', 'repository_status' => 'implemented'],
        'F24-R037' => ['title' => 'Caching، Search and Indexing Security', 'mode' => 'repository', 'implementation' => 'EndpointGuard, NetworkPolicy, UploadPolicy, PrivateDeliveryPolicy, SystemCheck', 'repository_status' => 'implemented'],
        'F24-R038' => ['title' => 'Infrastructure and Hosting Security', 'mode' => 'hybrid', 'implementation' => 'EndpointGuard, NetworkPolicy, UploadPolicy, PrivateDeliveryPolicy, SystemCheck', 'repository_status' => 'implemented'],
        'F24-R039' => ['title' => 'Domain، DNS and Email Security', 'mode' => 'hybrid', 'implementation' => 'EndpointGuard, NetworkPolicy, UploadPolicy, PrivateDeliveryPolicy, SystemCheck', 'repository_status' => 'implemented'],
        'F24-R040' => ['title' => 'Application Security Verification Levels', 'mode' => 'repository', 'implementation' => 'EndpointGuard, NetworkPolicy, UploadPolicy, PrivateDeliveryPolicy, SystemCheck', 'repository_status' => 'implemented'],
        'F24-R041' => ['title' => 'Privacy by Design', 'mode' => 'repository', 'implementation' => 'DataGovernanceRegistry, PrivacyRequestPolicy, AssuranceRepository, DeletionReplayManager', 'repository_status' => 'implemented'],
        'F24-R042' => ['title' => 'Data Classification', 'mode' => 'repository', 'implementation' => 'DataGovernanceRegistry, PrivacyRequestPolicy, AssuranceRepository, DeletionReplayManager', 'repository_status' => 'implemented'],
        'F24-R043' => ['title' => 'Data Inventory and Processing Register', 'mode' => 'repository', 'implementation' => 'DataGovernanceRegistry, PrivacyRequestPolicy, AssuranceRepository, DeletionReplayManager', 'repository_status' => 'implemented'],
        'F24-R044' => ['title' => 'Consent Management', 'mode' => 'repository', 'implementation' => 'DataGovernanceRegistry, PrivacyRequestPolicy, AssuranceRepository, DeletionReplayManager', 'repository_status' => 'implemented'],
        'F24-R045' => ['title' => 'Privacy Rights Operations', 'mode' => 'repository', 'implementation' => 'DataGovernanceRegistry, PrivacyRequestPolicy, AssuranceRepository, DeletionReplayManager', 'repository_status' => 'implemented'],
        'F24-R046' => ['title' => 'Retention and Deletion', 'mode' => 'repository', 'implementation' => 'DataGovernanceRegistry, PrivacyRequestPolicy, AssuranceRepository, DeletionReplayManager', 'repository_status' => 'implemented'],
        'F24-R047' => ['title' => 'Minors and Guardian Policy Review', 'mode' => 'repository', 'implementation' => 'DataGovernanceRegistry, PrivacyRequestPolicy, AssuranceRepository, DeletionReplayManager', 'repository_status' => 'implemented'],
        'F24-R048' => ['title' => 'Compliance Applicability Register', 'mode' => 'repository', 'implementation' => 'DataGovernanceRegistry, PrivacyRequestPolicy, AssuranceRepository, DeletionReplayManager', 'repository_status' => 'implemented'],
        'F24-R049' => ['title' => 'International Transfers and Vendors', 'mode' => 'hybrid', 'implementation' => 'DataGovernanceRegistry, PrivacyRequestPolicy, AssuranceRepository, DeletionReplayManager', 'repository_status' => 'implemented'],
        'F24-R050' => ['title' => 'Legal Holds and Evidence Preservation', 'mode' => 'repository', 'implementation' => 'DataGovernanceRegistry, PrivacyRequestPolicy, AssuranceRepository, DeletionReplayManager', 'repository_status' => 'implemented'],
        'F24-R051' => ['title' => 'Clinical Data Boundaries', 'mode' => 'repository', 'implementation' => 'PlatformIntegrationMatrix, RateLimiter, UploadPolicy, DetectionEngine', 'repository_status' => 'implemented'],
        'F24-R052' => ['title' => 'Patient Data Controls', 'mode' => 'repository', 'implementation' => 'PlatformIntegrationMatrix, RateLimiter, UploadPolicy, DetectionEngine', 'repository_status' => 'implemented'],
        'F24-R053' => ['title' => 'Clinical Break-Glass', 'mode' => 'repository', 'implementation' => 'PlatformIntegrationMatrix, RateLimiter, UploadPolicy, DetectionEngine', 'repository_status' => 'implemented'],
        'F24-R054' => ['title' => 'Messaging and Network Security', 'mode' => 'repository', 'implementation' => 'PlatformIntegrationMatrix, RateLimiter, UploadPolicy, DetectionEngine', 'repository_status' => 'implemented'],
        'F24-R055' => ['title' => 'Calls and Real-Time Communications', 'mode' => 'hybrid', 'implementation' => 'PlatformIntegrationMatrix, RateLimiter, UploadPolicy, DetectionEngine', 'repository_status' => 'implemented'],
        'F24-R056' => ['title' => 'AI and Radar Security', 'mode' => 'repository', 'implementation' => 'PlatformIntegrationMatrix, RateLimiter, UploadPolicy, DetectionEngine', 'repository_status' => 'implemented'],
        'F24-R057' => ['title' => 'Marketplace and Payment Safety', 'mode' => 'repository', 'implementation' => 'PlatformIntegrationMatrix, RateLimiter, UploadPolicy, DetectionEngine', 'repository_status' => 'implemented'],
        'F24-R058' => ['title' => 'Donation Non-Privilege Rule', 'mode' => 'repository', 'implementation' => 'PlatformIntegrationMatrix, RateLimiter, UploadPolicy, DetectionEngine', 'repository_status' => 'implemented'],
        'F24-R059' => ['title' => 'Content Integrity and Publishing Security', 'mode' => 'repository', 'implementation' => 'PlatformIntegrationMatrix, RateLimiter, UploadPolicy, DetectionEngine', 'repository_status' => 'implemented'],
        'F24-R060' => ['title' => 'Abuse، Fraud، Bots and Resource Protection', 'mode' => 'repository', 'implementation' => 'PlatformIntegrationMatrix, RateLimiter, UploadPolicy, DetectionEngine', 'repository_status' => 'implemented'],
        'F24-R061' => ['title' => 'Secure Software Development Lifecycle', 'mode' => 'repository', 'implementation' => 'CI quality gates, DetectionEngine, RemoteEvidenceQueue, IncidentCoordinator', 'repository_status' => 'implemented'],
        'F24-R062' => ['title' => 'Supply-Chain Security', 'mode' => 'repository', 'implementation' => 'CI quality gates, DetectionEngine, RemoteEvidenceQueue, IncidentCoordinator', 'repository_status' => 'implemented'],
        'F24-R063' => ['title' => 'Vulnerability Management', 'mode' => 'repository', 'implementation' => 'CI quality gates, DetectionEngine, RemoteEvidenceQueue, IncidentCoordinator', 'repository_status' => 'implemented'],
        'F24-R064' => ['title' => 'Security Testing Portfolio', 'mode' => 'repository', 'implementation' => 'CI quality gates, DetectionEngine, RemoteEvidenceQueue, IncidentCoordinator', 'repository_status' => 'implemented'],
        'F24-R065' => ['title' => 'Security Event Model', 'mode' => 'repository', 'implementation' => 'CI quality gates, DetectionEngine, RemoteEvidenceQueue, IncidentCoordinator', 'repository_status' => 'implemented'],
        'F24-R066' => ['title' => 'Local and Remote Logging', 'mode' => 'hybrid', 'implementation' => 'CI quality gates, DetectionEngine, RemoteEvidenceQueue, IncidentCoordinator', 'repository_status' => 'implemented'],
        'F24-R067' => ['title' => 'IP and Network Metadata Policy', 'mode' => 'repository', 'implementation' => 'CI quality gates, DetectionEngine, RemoteEvidenceQueue, IncidentCoordinator', 'repository_status' => 'implemented'],
        'F24-R068' => ['title' => 'Monitoring and Detection', 'mode' => 'repository', 'implementation' => 'CI quality gates, DetectionEngine, RemoteEvidenceQueue, IncidentCoordinator', 'repository_status' => 'implemented'],
        'F24-R069' => ['title' => 'Incident Response Command', 'mode' => 'repository', 'implementation' => 'CI quality gates, DetectionEngine, RemoteEvidenceQueue, IncidentCoordinator', 'repository_status' => 'implemented'],
        'F24-R070' => ['title' => 'Out-of-Band Incident Operations', 'mode' => 'hybrid', 'implementation' => 'CI quality gates, DetectionEngine, RemoteEvidenceQueue, IncidentCoordinator', 'repository_status' => 'implemented'],
        'F24-R071' => ['title' => 'Backup Assurance Principle', 'mode' => 'hybrid', 'implementation' => 'ResilienceCoordinator, SecurityStateRegistry, Repair, AssuranceRepository', 'repository_status' => 'implemented'],
        'F24-R072' => ['title' => 'Backup Coverage', 'mode' => 'hybrid', 'implementation' => 'ResilienceCoordinator, SecurityStateRegistry, Repair, AssuranceRepository', 'repository_status' => 'implemented'],
        'F24-R073' => ['title' => 'Business Impact Analysis', 'mode' => 'hybrid', 'implementation' => 'ResilienceCoordinator, SecurityStateRegistry, Repair, AssuranceRepository', 'repository_status' => 'implemented'],
        'F24-R074' => ['title' => 'Provisional Recovery Objectives', 'mode' => 'hybrid', 'implementation' => 'ResilienceCoordinator, SecurityStateRegistry, Repair, AssuranceRepository', 'repository_status' => 'implemented'],
        'F24-R075' => ['title' => 'Disaster Recovery Scenarios', 'mode' => 'hybrid', 'implementation' => 'ResilienceCoordinator, SecurityStateRegistry, Repair, AssuranceRepository', 'repository_status' => 'implemented'],
        'F24-R076' => ['title' => 'Business Continuity Modes', 'mode' => 'repository', 'implementation' => 'ResilienceCoordinator, SecurityStateRegistry, Repair, AssuranceRepository', 'repository_status' => 'implemented'],
        'F24-R077' => ['title' => 'Security States and File 20 Integration', 'mode' => 'repository', 'implementation' => 'ResilienceCoordinator, SecurityStateRegistry, Repair, AssuranceRepository', 'repository_status' => 'implemented'],
        'F24-R078' => ['title' => 'Non-Destructive Repair', 'mode' => 'repository', 'implementation' => 'ResilienceCoordinator, SecurityStateRegistry, Repair, AssuranceRepository', 'repository_status' => 'implemented'],
        'F24-R079' => ['title' => 'Restore and Rollback Validation', 'mode' => 'repository', 'implementation' => 'ResilienceCoordinator, SecurityStateRegistry, Repair, AssuranceRepository', 'repository_status' => 'implemented'],
        'F24-R080' => ['title' => 'Resilience Evidence and Drills', 'mode' => 'hybrid', 'implementation' => 'ResilienceCoordinator, SecurityStateRegistry, Repair, AssuranceRepository', 'repository_status' => 'implemented'],
        'F24-R081' => ['title' => 'Foundation Plugin Core Components', 'mode' => 'repository', 'implementation' => 'GovernedArtifactRegistry, RegistryAdmin, Plugin, packaging and integration manifests', 'repository_status' => 'implemented'],
        'F24-R082' => ['title' => 'Logical Data Model Before Schema Freeze', 'mode' => 'repository', 'implementation' => 'GovernedArtifactRegistry, RegistryAdmin, Plugin, packaging and integration manifests', 'repository_status' => 'implemented'],
        'F24-R083' => ['title' => 'Proposed Data Domains', 'mode' => 'repository', 'implementation' => 'GovernedArtifactRegistry, RegistryAdmin, Plugin, packaging and integration manifests', 'repository_status' => 'implemented'],
        'F24-R084' => ['title' => 'Dashboard Information Architecture', 'mode' => 'repository', 'implementation' => 'GovernedArtifactRegistry, RegistryAdmin, Plugin, packaging and integration manifests', 'repository_status' => 'implemented'],
        'F24-R085' => ['title' => 'Public Trust Center Data', 'mode' => 'repository', 'implementation' => 'GovernedArtifactRegistry, RegistryAdmin, Plugin, packaging and integration manifests', 'repository_status' => 'implemented'],
        'F24-R086' => ['title' => 'Repository Public/Private Split', 'mode' => 'repository', 'implementation' => 'GovernedArtifactRegistry, RegistryAdmin, Plugin, packaging and integration manifests', 'repository_status' => 'implemented'],
        'F24-R087' => ['title' => 'Repository and Branch Governance', 'mode' => 'hybrid', 'implementation' => 'GovernedArtifactRegistry, RegistryAdmin, Plugin, packaging and integration manifests', 'repository_status' => 'implemented'],
        'F24-R088' => ['title' => 'Files 00–25 Integration Matrix', 'mode' => 'repository', 'implementation' => 'GovernedArtifactRegistry, RegistryAdmin, Plugin, packaging and integration manifests', 'repository_status' => 'implemented'],
        'F24-R089' => ['title' => 'Implementation Phases', 'mode' => 'repository', 'implementation' => 'GovernedArtifactRegistry, RegistryAdmin, Plugin, packaging and integration manifests', 'repository_status' => 'implemented'],
        'F24-R090' => ['title' => 'Release and Packaging Discipline', 'mode' => 'repository', 'implementation' => 'GovernedArtifactRegistry, RegistryAdmin, Plugin, packaging and integration manifests', 'repository_status' => 'implemented'],
        'F24-R091' => ['title' => 'Requirements Traceability Matrix', 'mode' => 'repository', 'implementation' => 'RequirementCatalog, ReleaseStatus, SystemCheck, CI and release evidence', 'repository_status' => 'implemented'],
        'F24-R092' => ['title' => 'Measurable Performance Contract', 'mode' => 'hybrid', 'implementation' => 'RequirementCatalog, ReleaseStatus, SystemCheck, CI and release evidence', 'repository_status' => 'implemented'],
        'F24-R093' => ['title' => 'Accessibility and Responsive Acceptance', 'mode' => 'hybrid', 'implementation' => 'RequirementCatalog, ReleaseStatus, SystemCheck, CI and release evidence', 'repository_status' => 'implemented'],
        'F24-R094' => ['title' => 'Staging Acceptance Gates', 'mode' => 'hybrid', 'implementation' => 'RequirementCatalog, ReleaseStatus, SystemCheck, CI and release evidence', 'repository_status' => 'implemented'],
        'F24-R095' => ['title' => 'Definition of Done Categories', 'mode' => 'hybrid', 'implementation' => 'RequirementCatalog, ReleaseStatus, SystemCheck, CI and release evidence', 'repository_status' => 'implemented'],
        'F24-R096' => ['title' => 'Current Open Launch Gates and Corrected Historical Blockers', 'mode' => 'hybrid', 'implementation' => 'RequirementCatalog, ReleaseStatus, SystemCheck, CI and release evidence', 'repository_status' => 'implemented'],
        'F24-R097' => ['title' => 'File 17 First Assurance Pilot', 'mode' => 'hybrid', 'implementation' => 'RequirementCatalog, ReleaseStatus, SystemCheck, CI and release evidence', 'repository_status' => 'implemented'],
        'F24-R098' => ['title' => 'Operational Roles and Training', 'mode' => 'hybrid', 'implementation' => 'RequirementCatalog, ReleaseStatus, SystemCheck, CI and release evidence', 'repository_status' => 'implemented'],
        'F24-R099' => ['title' => 'Founder Planning Authorization and Runtime Decision Gate', 'mode' => 'hybrid', 'implementation' => 'RequirementCatalog, ReleaseStatus, SystemCheck, CI and release evidence', 'repository_status' => 'implemented'],
        'F24-R100' => ['title' => 'حتمی Work Order and Completion Law', 'mode' => 'hybrid', 'implementation' => 'RequirementCatalog, ReleaseStatus, SystemCheck, CI and release evidence', 'repository_status' => 'implemented'],
    ];

    /** @return array<string,array{title:string,mode:string,implementation:string,repository_status:string}> */
    public static function all(): array
    {
        return self::REQUIREMENTS;
    }

    /** @return array{title:string,mode:string,implementation:string,repository_status:string}|null */
    public static function get(string $requirementId): ?array
    {
        $requirementId = strtoupper(trim($requirementId));
        return self::REQUIREMENTS[$requirementId] ?? null;
    }

    public static function count(): int
    {
        return count(self::REQUIREMENTS);
    }

    public static function implementedCount(): int
    {
        $count = 0;
        foreach (self::REQUIREMENTS as $requirement) {
            if (($requirement['repository_status'] ?? '') === 'implemented') {
                ++$count;
            }
        }
        return $count;
    }

    public static function repositoryCodingComplete(): bool
    {
        return self::count() === 100 && self::implementedCount() === 100;
    }

    /** @return string[] */
    public static function externalGateIds(): array
    {
        $ids = [];
        foreach (self::REQUIREMENTS as $id => $requirement) {
            if (($requirement['mode'] ?? '') === 'hybrid') {
                $ids[] = $id;
            }
        }
        return $ids;
    }

    /** @return array<string,mixed> */
    public static function summary(): array
    {
        return [
            'total' => self::count(),
            'repository_implemented' => self::implementedCount(),
            'repository_coding_complete' => self::repositoryCodingComplete(),
            'hybrid_external_gate_count' => count(self::externalGateIds()),
            'status_boundary' => 'Repository coding complete does not equal staging, live or operational acceptance.',
        ];
    }
}
