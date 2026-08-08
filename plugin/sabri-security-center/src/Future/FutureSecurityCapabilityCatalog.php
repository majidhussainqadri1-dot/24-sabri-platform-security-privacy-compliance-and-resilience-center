<?php

declare(strict_types=1);

namespace Sabri\Platform\Security\Future;

/**
 * Canonical File-24 future-security superset. The catalogue is assurance-only:
 * native modules keep enforcement, data and business authority.
 */
final class FutureSecurityCapabilityCatalog
{
    /** @var array<string,array<string,mixed>> */
    private const CAPABILITIES = [
        'F24-FUT-001' => ['title' => 'Post-Quantum Cryptography Readiness Center', 'priority' => 'P1', 'family' => 'cryptography', 'external_evidence' => true],
        'F24-FUT-002' => ['title' => 'Crypto-Agility Registry', 'priority' => 'P0', 'family' => 'cryptography', 'external_evidence' => false],
        'F24-FUT-003' => ['title' => 'Cryptographic Asset Inventory', 'priority' => 'P0', 'family' => 'cryptography', 'external_evidence' => true],
        'F24-FUT-004' => ['title' => 'Security Knowledge Graph', 'priority' => 'P1', 'family' => 'attack-intelligence', 'external_evidence' => false],
        'F24-FUT-005' => ['title' => 'Attack-Path Intelligence Engine', 'priority' => 'P1', 'family' => 'attack-intelligence', 'external_evidence' => true],
        'F24-FUT-006' => ['title' => 'External Attack-Surface Management', 'priority' => 'P1', 'family' => 'attack-surface', 'external_evidence' => true],
        'F24-FUT-007' => ['title' => 'Continuous Control Monitoring', 'priority' => 'P0', 'family' => 'assurance', 'external_evidence' => true],
        'F24-FUT-008' => ['title' => 'Policy-as-Code and Compliance-as-Code', 'priority' => 'P1', 'family' => 'governance', 'external_evidence' => false],
        'F24-FUT-009' => ['title' => 'Data Security Posture Management', 'priority' => 'P1', 'family' => 'data-security', 'external_evidence' => true],
        'F24-FUT-010' => ['title' => 'Universal DLP and Egress Guard', 'priority' => 'P1', 'family' => 'data-security', 'external_evidence' => true],
        'F24-FUT-011' => ['title' => 'Privacy-Preserving Analytics and Differential Privacy', 'priority' => 'P2', 'family' => 'privacy', 'external_evidence' => true],
        'F24-FUT-012' => ['title' => 'Research Data Clean Room', 'priority' => 'P2', 'family' => 'privacy', 'external_evidence' => true],
        'F24-FUT-013' => ['title' => 'Workload and Machine Identity Security', 'priority' => 'P1', 'family' => 'identity', 'external_evidence' => true],
        'F24-FUT-014' => ['title' => 'Just-in-Time Privileged Access', 'priority' => 'P1', 'family' => 'identity', 'external_evidence' => true],
        'F24-FUT-015' => ['title' => 'Cyber-Recovery Vault', 'priority' => 'P1', 'family' => 'resilience', 'external_evidence' => true],
        'F24-FUT-016' => ['title' => 'Chaos and Resilience Engineering', 'priority' => 'P1', 'family' => 'resilience', 'external_evidence' => true],
        'F24-FUT-017' => ['title' => 'Breach and Attack Simulation / Purple Team', 'priority' => 'P2', 'family' => 'validation', 'external_evidence' => true],
        'F24-FUT-018' => ['title' => 'Deception and Honeytoken Layer', 'priority' => 'P2', 'family' => 'detection', 'external_evidence' => true],
        'F24-FUT-019' => ['title' => 'Exploitability-Aware Vulnerability Prioritization', 'priority' => 'P0', 'family' => 'vulnerability', 'external_evidence' => true],
        'F24-FUT-020' => ['title' => 'VEX and Advanced SBOM Intelligence', 'priority' => 'P1', 'family' => 'supply-chain', 'external_evidence' => true],
        'F24-FUT-021' => ['title' => 'SLSA Build Provenance and Signed Attestations', 'priority' => 'P1', 'family' => 'supply-chain', 'external_evidence' => true],
        'F24-FUT-022' => ['title' => 'AI and Agentic Security Control Plane', 'priority' => 'P0', 'family' => 'ai-security', 'external_evidence' => true],
        'F24-FUT-023' => ['title' => 'AI Bill of Materials / Model and Prompt Registry', 'priority' => 'P1', 'family' => 'ai-security', 'external_evidence' => true],
        'F24-FUT-024' => ['title' => 'Automated Security Assurance Case', 'priority' => 'P1', 'family' => 'assurance', 'external_evidence' => true],
        'F24-FUT-025' => ['title' => 'Bounded Security Autopilot / Automated Remediation', 'priority' => 'P1', 'family' => 'remediation', 'external_evidence' => true],
    ];

    /** @return array<string,array<string,mixed>> */
    public static function all(): array
    {
        $result = [];
        foreach (self::CAPABILITIES as $id => $item) {
            $result[$id] = $item + [
                'id' => $id,
                'owner' => 'File 24 assurance',
                'native_enforcement_preserved' => true,
                'security_single_point_of_failure_forbidden' => true,
                'public_safe_evidence_only' => true,
            ];
        }
        return $result;
    }

    /** @return array<string,mixed>|null */
    public static function get(string $id): ?array
    {
        $id = strtoupper(trim($id));
        $all = self::all();
        return $all[$id] ?? null;
    }

    public static function count(): int
    {
        return count(self::CAPABILITIES);
    }

    public static function repositoryCodingComplete(): bool
    {
        if (self::count() !== 25) {
            return false;
        }
        foreach (self::all() as $id => $item) {
            if (
                preg_match('/^F24-FUT-0(?:0[1-9]|1[0-9]|2[0-5])$/', $id) !== 1
                || ! in_array($item['priority'] ?? '', ['P0', 'P1', 'P2'], true)
                || empty($item['title'])
                || empty($item['family'])
                || ($item['owner'] ?? '') !== 'File 24 assurance'
                || empty($item['native_enforcement_preserved'])
                || empty($item['security_single_point_of_failure_forbidden'])
            ) {
                return false;
            }
        }
        return true;
    }
}
