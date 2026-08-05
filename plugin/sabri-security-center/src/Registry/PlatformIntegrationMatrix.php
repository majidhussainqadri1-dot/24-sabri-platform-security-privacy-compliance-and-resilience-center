<?php

declare(strict_types=1);

namespace Sabri\Platform\Security\Registry;

use Sabri\Platform\Security\Support\Sanitizer;

/** Formal File 00–26 ownership and assurance matrix. */
final class PlatformIntegrationMatrix
{
    /** @var array<int,array<string,mixed>> */
    private const FILES = [
        0 => ['file' => 0, 'name' => 'Sabri Membership Core', 'native_owner' => 'membership, identity assurance, guardian, roles and suspension', 'assurance' => 'identity, guardian and retention assurance', 'contract_filter' => 'spcrc/file00_contract_state', 'criticality' => 'critical', 'degraded_behavior' => 'privileged writes fail closed'],
        1 => ['file' => 1, 'name' => 'Platform Foundation and Master Governance', 'native_owner' => 'product constitution, owner registry and runtime-safe bootstrap', 'assurance' => 'source hierarchy, contract registry and environment evidence', 'contract_filter' => 'spcrc/file01_contract_state', 'criticality' => 'critical', 'degraded_behavior' => 'changes remain blocked'],
        2 => ['file' => 2, 'name' => 'Authentication and Accounts', 'native_owner' => 'credentials, OAuth, recovery and session-entry UX', 'assurance' => 'authentication, session and recovery abuse assurance', 'contract_filter' => 'spcrc/file02_contract_state', 'criticality' => 'critical', 'degraded_behavior' => 'privileged writes fail closed'],
        3 => ['file' => 3, 'name' => 'Profiles and Doctors', 'native_owner' => 'profile master fields and visibility', 'assurance' => 'field leakage, cache and index assurance', 'contract_filter' => 'spcrc/file03_contract_state', 'criticality' => 'optional', 'degraded_behavior' => 'profile assurance unknown'],
        4 => ['file' => 4, 'name' => 'Legacy News Feed', 'native_owner' => 'legacy publishing data pending controlled cutover', 'assurance' => 'duplicate owner and migration assurance', 'contract_filter' => 'spcrc/file04_contract_state', 'criticality' => 'optional', 'degraded_behavior' => 'legacy write disabled'],
        5 => ['file' => 5, 'name' => 'Learn', 'native_owner' => 'lessons, curriculum and progress', 'assurance' => 'minor, entitlement and assessment integrity', 'contract_filter' => 'spcrc/file05_contract_state', 'criticality' => 'optional', 'degraded_behavior' => 'education assurance unavailable'],
        6 => ['file' => 6, 'name' => 'Encyclopedia', 'native_owner' => 'knowledge entries, sources and corrections', 'assurance' => 'source integrity and correction assurance', 'contract_filter' => 'spcrc/file06_contract_state', 'criticality' => 'optional', 'degraded_behavior' => 'knowledge assurance unavailable'],
        7 => ['file' => 7, 'name' => 'Doctors Directory', 'native_owner' => 'verified doctor discovery and public directory', 'assurance' => 'impersonation, scraping, contact safety and File 26 ranking-fairness evidence', 'contract_filter' => 'spcrc/file07_contract_state', 'criticality' => 'optional', 'degraded_behavior' => 'directory assurance unavailable'],
        8 => ['file' => 8, 'name' => 'Worldwide Clinic and Appointments', 'native_owner' => 'clinic and appointment truth', 'assurance' => 'clinical privacy, emergency and access assurance', 'contract_filter' => 'spcrc/file08_contract_state', 'criticality' => 'high-risk', 'degraded_behavior' => 'clinical actions gated'],
        9 => ['file' => 9, 'name' => 'Doctor Onboarding and Verification', 'native_owner' => 'professional evidence and reviewer decisions', 'assurance' => 'private evidence, reviewer separation and expiry assurance', 'contract_filter' => 'spcrc/file09_contract_state', 'criticality' => 'high-risk', 'degraded_behavior' => 'verification actions gated'],
        10 => ['file' => 10, 'name' => 'Video Wall and Live Broadcasting', 'native_owner' => 'recorded/live media, stream keys and replay', 'assurance' => 'upload, rights, live-key and provider assurance', 'contract_filter' => 'spcrc/file10_contract_state', 'criticality' => 'high-risk', 'degraded_behavior' => 'live/high-risk actions gated'],
        11 => ['file' => 11, 'name' => 'Reels', 'native_owner' => 'reel entity, discovery and watch history', 'assurance' => 'duration, abuse and patient privacy assurance', 'contract_filter' => 'spcrc/file11_contract_state', 'criticality' => 'optional', 'degraded_behavior' => 'reels assurance unavailable'],
        12 => ['file' => 12, 'name' => 'PDF Library', 'native_owner' => 'restricted PDF objects, reader access and PDF eligibility', 'assurance' => 'private delivery, entitlement, download and purge assurance', 'contract_filter' => 'spcrc/file12_contract_state', 'criticality' => 'high-risk', 'degraded_behavior' => 'restricted delivery gated'],
        13 => ['file' => 13, 'name' => 'Welcome Intro Historical Compatibility', 'native_owner' => 'legacy compatibility only; File 20 owns invocation/frequency and File 25 owns presentation', 'assurance' => 'duplicate-owner detection, safe suppression and migration assurance', 'contract_filter' => 'spcrc/file13_contract_state', 'criticality' => 'high-risk', 'degraded_behavior' => 'legacy intro remains disabled'],
        14 => ['file' => 14, 'name' => 'Global Clinic USP', 'native_owner' => 'approved clinic value proposition', 'assurance' => 'claim substantiation and privacy-safe analytics', 'contract_filter' => 'spcrc/file14_contract_state', 'criticality' => 'optional', 'degraded_behavior' => 'claim status unknown'],
        15 => ['file' => 15, 'name' => 'Radar and Trends', 'native_owner' => 'research rubric, saved studies and trends', 'assurance' => 'no-diagnosis, provenance and private study assurance', 'contract_filter' => 'spcrc/file15_contract_state', 'criticality' => 'high-risk', 'degraded_behavior' => 'private/clinical-like actions gated'],
        16 => ['file' => 16, 'name' => 'Sabri Classical Homeopathy AI', 'native_owner' => 'source-linked educational AI and institutional AI Teacher', 'assurance' => 'institutional identity, disclosure, initial human review, corpus ACL, citation, prompt-injection, budget and provider assurance', 'contract_filter' => 'spcrc/file16_contract_state', 'criticality' => 'high-risk', 'degraded_behavior' => 'AI generation/publication actions gated'],
        17 => ['file' => 17, 'name' => 'Communication Network', 'native_owner' => 'relationships, messages, media, calls and verified-user transfer orchestration', 'assurance' => 'identity, IDOR, one-GiB transfer, resumability, private storage, TURN/SFU and retention assurance', 'contract_filter' => 'spcrc/file17_contract_state', 'criticality' => 'high-risk', 'degraded_behavior' => 'private communications and transfers gated'],
        18 => ['file' => 18, 'name' => 'Marketplace', 'native_owner' => 'listings, offers/deals and disputes', 'assurance' => 'fraud, prohibited goods, zero commission and contact assurance', 'contract_filter' => 'spcrc/file18_contract_state', 'criticality' => 'high-risk', 'degraded_behavior' => 'transactions/contact gated'],
        19 => ['file' => 19, 'name' => 'Unified Notifications', 'native_owner' => 'notification center and delivery adapters', 'assurance' => 'spoofing, sensitive preview and provider retry assurance', 'contract_filter' => 'spcrc/file19_contract_state', 'criticality' => 'optional', 'degraded_behavior' => 'delivery degraded'],
        20 => ['file' => 20, 'name' => 'Unified Application Shell', 'native_owner' => 'global shell, routes, Safe Mode presentation and welcome invocation/frequency control', 'assurance' => 'security-state rendering, thirty-day welcome suppression and reversible repair', 'contract_filter' => 'spcrc/file20_contract_state', 'criticality' => 'critical', 'degraded_behavior' => 'File 24 admin falls back to wp-admin and welcome never blocks the site'],
        21 => ['file' => 21, 'name' => 'Home and News Feed', 'native_owner' => 'social/news publishing and corrections', 'assurance' => 'publishing, source/retraction and cache assurance', 'contract_filter' => 'spcrc/file21_contract_state', 'criticality' => 'high-risk', 'degraded_behavior' => 'publishing actions gated'],
        22 => ['file' => 22, 'name' => 'Universal Post Composer', 'native_owner' => 'create/draft/upload/submit orchestration', 'assurance' => 'authorization, privacy scan and idempotency assurance', 'contract_filter' => 'spcrc/file22_contract_state', 'criticality' => 'high-risk', 'degraded_behavior' => 'create/submit gated'],
        23 => ['file' => 23, 'name' => 'Publishing Dashboard', 'native_owner' => 'private publishing operations', 'assurance' => 'role, delegation, adapter and export assurance', 'contract_filter' => 'spcrc/file23_contract_state', 'criticality' => 'high-risk', 'degraded_behavior' => 'write actions gated'],
        24 => ['file' => 24, 'name' => 'Security, Privacy, Compliance and Resilience Center', 'native_owner' => 'governance and assurance', 'assurance' => 'canonical assurance owner', 'contract_filter' => 'spcrc/file24_contract_state', 'criticality' => 'critical', 'degraded_behavior' => 'native controls continue'],
        25 => ['file' => 25, 'name' => 'Public UI, Profile Timeline and Visual Experience', 'native_owner' => 'public profiles, timelines, visual presentation and welcome visual/RTL/accessibility', 'assurance' => 'public leakage, cache, trust, welcome accessibility and visual assurance', 'contract_filter' => 'spcrc/file25_contract_state', 'criticality' => 'optional', 'degraded_behavior' => 'public presentation uses safe fallback'],
        26 => ['file' => 26, 'name' => 'Search, Discovery, Recommendations, Knowledge Graph and Classification', 'native_owner' => 'federated search, derivative indexes, query understanding, ranking, recommendations, taxonomy and owner-sourced knowledge graph projections', 'assurance' => 'private-state leakage, deletion reconciliation, doctor-ranking fairness, recommendation consent, experiment rollback and policy evidence', 'contract_filter' => 'spcrc/file26_contract_state', 'criticality' => 'high-risk', 'degraded_behavior' => 'ranking/recommendation experiments and privileged discovery writes gated; safe owner results only'],
    ];

    /** @return array<int,array<string,mixed>> */
    public static function all(): array
    {
        return self::FILES;
    }

    /** @return array<string,mixed>|null */
    public static function get(int $file): ?array
    {
        return self::FILES[$file] ?? null;
    }

    /** @return array<int,array<string,mixed>> */
    public static function evaluate(): array
    {
        $results = [];
        foreach (self::FILES as $file => $definition) {
            $default = $file === 24 ? 'compatible' : 'unassessed';
            $state = Sanitizer::key(apply_filters((string) $definition['contract_filter'], $default, $definition), 30);
            if (! in_array($state, ['compatible', 'unassessed', 'degraded', 'blocked', 'missing'], true)) {
                $state = 'blocked';
            }

            $requiresCompatible = in_array((string) $definition['criticality'], ['critical', 'high-risk'], true);
            if ($file === 24) {
                $writeAllowed = $state === 'compatible';
            } elseif ($requiresCompatible) {
                $writeAllowed = $state === 'compatible';
            } else {
                $writeAllowed = ! in_array($state, ['blocked', 'missing'], true);
            }

            $results[$file] = array_merge($definition, [
                'state' => $state,
                'write_allowed' => $writeAllowed,
            ]);
        }
        return $results;
    }

    /** @return int[] */
    public static function blockingFiles(): array
    {
        $blocked = [];
        foreach (self::evaluate() as $file => $record) {
            if (empty($record['write_allowed'])) {
                $blocked[] = $file;
            }
        }
        return $blocked;
    }

    public static function complete(): bool
    {
        return count(self::FILES) === 27 && array_keys(self::FILES) === range(0, 26);
    }
}
