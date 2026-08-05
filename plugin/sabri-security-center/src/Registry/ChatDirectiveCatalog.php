<?php

declare(strict_types=1);

namespace Sabri\Platform\Security\Registry;

/**
 * Machine-readable File 24 subset of the Founder-approved All-Chats Directive Register v2.1.
 *
 * These records extend, and do not renumber, F24-R001–F24-R100. Repository status only
 * confirms that an assurance contract, policy or test exists; staging and operational
 * evidence remain separate release gates.
 */
final class ChatDirectiveCatalog
{
    /** @var array<string,array{title:string,source:string,canonical_owner:string,file24_role:string,implementation:list<string>,mode:string,repository_status:string}> */
    private const DIRECTIVES = [
        'CHAT-GOV-001' => [
            'title' => 'Islamic supremacy and institutional governance charter',
            'source' => 'all-chats-v2.1-section-23',
            'canonical_owner' => 'founder-governance',
            'file24_role' => 'supreme-policy assurance and conflict detection',
            'implementation' => ['IslamicGovernanceCharter', 'GovernancePolicyService'],
            'mode' => 'repository',
            'repository_status' => 'implemented',
        ],
        'CHAT-GOV-002' => [
            'title' => 'Notice, evidence, response, impartial review and appeal due process',
            'source' => 'all-chats-v2.1-section-23',
            'canonical_owner' => 'native-decision-owner',
            'file24_role' => 'due-process assurance',
            'implementation' => ['IslamicGovernanceCharter', 'BoundaryPolicyCatalog'],
            'mode' => 'repository',
            'repository_status' => 'implemented',
        ],
        'CHAT-PRIV-001' => [
            'title' => 'Islamic privacy, data minimization and human dignity',
            'source' => 'all-chats-v2.1-section-11',
            'canonical_owner' => 'native-data-owner',
            'file24_role' => 'privacy assurance',
            'implementation' => ['AntiSurveillancePolicy', 'BoundaryPolicyCatalog'],
            'mode' => 'repository',
            'repository_status' => 'implemented',
        ],
        'CHAT-PRIV-002' => [
            'title' => 'No sale of personal data, covert tracking or behavioral surveillance',
            'source' => 'all-chats-v2.1-section-11',
            'canonical_owner' => 'file-24-policy-assurance',
            'file24_role' => 'prohibited-processing gate',
            'implementation' => ['AntiSurveillancePolicy'],
            'mode' => 'repository',
            'repository_status' => 'implemented',
        ],
        'CHAT-PRIV-003' => [
            'title' => 'No hidden profiling or commercial use of security logs',
            'source' => 'all-chats-v2.1-section-11',
            'canonical_owner' => 'file-24-policy-assurance',
            'file24_role' => 'purpose-limitation gate',
            'implementation' => ['AntiSurveillancePolicy'],
            'mode' => 'repository',
            'repository_status' => 'implemented',
        ],
        'CHAT-PRIV-004' => [
            'title' => 'Annual review of privacy, tracking, AI-data, minors and provider policies',
            'source' => 'all-chats-v2.1-section-11',
            'canonical_owner' => 'policy-owner',
            'file24_role' => 'review-cadence assurance',
            'implementation' => ['GovernancePolicyService', 'AntiSurveillancePolicy'],
            'mode' => 'hybrid',
            'repository_status' => 'implemented',
        ],
        'CHAT-WELCOME-001' => [
            'title' => 'Welcome invocation/frequency owned by File 20 and presentation by File 25',
            'source' => 'all-chats-v2.1-section-1',
            'canonical_owner' => 'file-20-and-file-25',
            'file24_role' => 'duplicate-owner and privacy assurance',
            'implementation' => ['PlatformIntegrationMatrix'],
            'mode' => 'repository',
            'repository_status' => 'implemented',
        ],
        'CHAT-RANK-001' => [
            'title' => 'Doctor ranking cannot be influenced by donation, payment or favoritism',
            'source' => 'all-chats-v2.1-section-5',
            'canonical_owner' => 'file-26',
            'file24_role' => 'ranking fairness and manipulation assurance',
            'implementation' => ['RankingFairnessPolicy', 'BoundaryPolicyCatalog'],
            'mode' => 'repository',
            'repository_status' => 'implemented',
        ],
        'CHAT-RANK-002' => [
            'title' => 'Ranking is versioned, explainable, auditable, appealable and recomputed monthly',
            'source' => 'all-chats-v2.1-section-5',
            'canonical_owner' => 'file-26',
            'file24_role' => 'evidence and recency gate',
            'implementation' => ['RankingFairnessPolicy'],
            'mode' => 'hybrid',
            'repository_status' => 'implemented',
        ],
        'CHAT-AI-001' => [
            'title' => 'AI Teacher uses institutional AI identity and visible disclosure',
            'source' => 'all-chats-v2.1-section-9',
            'canonical_owner' => 'file-16',
            'file24_role' => 'identity and disclosure assurance',
            'implementation' => ['AIHomeopathyTeacherAssurance'],
            'mode' => 'repository',
            'repository_status' => 'implemented',
        ],
        'CHAT-AI-002' => [
            'title' => 'First thirty days of AI Teacher publication require human review',
            'source' => 'all-chats-v2.1-section-9',
            'canonical_owner' => 'file-16-and-publishing-owners',
            'file24_role' => 'launch-period review gate',
            'implementation' => ['AIHomeopathyTeacherAssurance'],
            'mode' => 'hybrid',
            'repository_status' => 'implemented',
        ],
        'CHAT-AI-003' => [
            'title' => 'AI Teacher cadence, budget cap, provider failure and fallback are governed',
            'source' => 'all-chats-v2.1-section-9',
            'canonical_owner' => 'file-16',
            'file24_role' => 'resource and resilience assurance',
            'implementation' => ['AIHomeopathyTeacherAssurance'],
            'mode' => 'hybrid',
            'repository_status' => 'implemented',
        ],
        'CHAT-AI-004' => [
            'title' => 'AI Teacher source, medical and Shariah review boundaries',
            'source' => 'all-chats-v2.1-section-9',
            'canonical_owner' => 'file-16',
            'file24_role' => 'corpus, citation and safety assurance',
            'implementation' => ['AIHomeopathyTeacherAssurance', 'BoundaryPolicyCatalog'],
            'mode' => 'repository',
            'repository_status' => 'implemented',
        ],
        'CHAT-DL-001' => [
            'title' => 'Universal eligible download queue, recovery, checksum, audit and revocation',
            'source' => 'all-chats-v2.1-section-14',
            'canonical_owner' => 'native-content-owner-and-cf-04-when-activated',
            'file24_role' => 'download security assurance',
            'implementation' => ['TransferDownloadAssurance', 'BoundaryPolicyCatalog'],
            'mode' => 'hybrid',
            'repository_status' => 'implemented',
        ],
        'CHAT-XFER-001' => [
            'title' => 'Verified users may transfer files up to one GiB per file',
            'source' => 'all-chats-v2.1-section-17',
            'canonical_owner' => 'file-17-and-cf-04-when-activated',
            'file24_role' => 'size, identity and relationship assurance',
            'implementation' => ['TransferDownloadAssurance', 'PlatformIntegrationMatrix'],
            'mode' => 'hybrid',
            'repository_status' => 'implemented',
        ],
        'CHAT-XFER-002' => [
            'title' => 'Transfer is resumable, recoverable, scanned, purpose-bound and revocable',
            'source' => 'all-chats-v2.1-section-17',
            'canonical_owner' => 'file-17-and-cf-04-when-activated',
            'file24_role' => 'secure-transfer control assurance',
            'implementation' => ['TransferDownloadAssurance', 'BoundaryPolicyCatalog'],
            'mode' => 'hybrid',
            'repository_status' => 'implemented',
        ],
        'CHAT-INT-026' => [
            'title' => 'File 26 is a permanent cross-platform integration owner',
            'source' => 'file-26-v1.0-and-all-chats-v2.1',
            'canonical_owner' => 'file-26',
            'file24_role' => 'search, recommendation, ranking and deletion assurance',
            'implementation' => ['PlatformIntegrationMatrix', 'BoundaryPolicyCatalog'],
            'mode' => 'repository',
            'repository_status' => 'implemented',
        ],
        'CHAT-QA-001' => [
            'title' => 'Two fresh review-fix-retest rounds after the harmonization batch',
            'source' => 'all-chats-v2.1-section-10-and-18',
            'canonical_owner' => 'file-24-release-governance',
            'file24_role' => 'release evidence gate',
            'implementation' => ['Cycle 110 tests', 'Cycle 111 adversarial tests', 'review records'],
            'mode' => 'repository',
            'repository_status' => 'implemented',
        ],
    ];

    /** @return array<string,array<string,mixed>> */
    public static function all(): array
    {
        return self::DIRECTIVES;
    }

    /** @return array<string,mixed>|null */
    public static function get(string $id): ?array
    {
        return self::DIRECTIVES[$id] ?? null;
    }

    /** @return list<string> */
    public static function ids(): array
    {
        return array_keys(self::DIRECTIVES);
    }

    public static function count(): int
    {
        return count(self::DIRECTIVES);
    }

    public static function implementedCount(): int
    {
        return count(array_filter(self::DIRECTIVES, static fn (array $directive): bool => ($directive['repository_status'] ?? '') === 'implemented'));
    }

    public static function repositoryCodingComplete(): bool
    {
        foreach (self::DIRECTIVES as $id => $directive) {
            if (preg_match('/^CHAT-[A-Z]+-[0-9]{3}$/', $id) !== 1) {
                return false;
            }
            if (($directive['repository_status'] ?? '') !== 'implemented') {
                return false;
            }
            if (($directive['source'] ?? '') === '' || ($directive['canonical_owner'] ?? '') === '' || ($directive['file24_role'] ?? '') === '') {
                return false;
            }
            if (! is_array($directive['implementation'] ?? null) || $directive['implementation'] === []) {
                return false;
            }
        }
        return self::count() === 18;
    }

    /** @return array<string,mixed> */
    public static function summary(): array
    {
        return [
            'total' => self::count(),
            'repository_implemented' => self::implementedCount(),
            'repository_coding_complete' => self::repositoryCodingComplete(),
            'external_acceptance_required' => true,
        ];
    }
}
