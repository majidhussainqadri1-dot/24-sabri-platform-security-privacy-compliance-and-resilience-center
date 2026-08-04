<?php

declare(strict_types=1);

namespace Sabri\Platform\Security\Release;

use Sabri\Platform\Security\Registry\GovernedArtifactRegistry;
use Sabri\Platform\Security\Support\Sanitizer;

/** Twelve implementation phases and evidence-bound release gates. */
final class ReleaseGateManager
{
    private const PHASES = [
        '24a-governance-source-freeze', '24b-inventory-manifests', '24c-contracts-core-kernel',
        '24d-identity-auth-assurance', '24e-app-api-file-hardening', '24f-privacy-compliance',
        '24g-monitoring', '24h-incidents', '24i-resilience', '24j-ui-trust-data',
        '24k-integrations', '24l-independent-assurance-staging',
    ];

    public function __construct(private GovernedArtifactRegistry $artifacts)
    {
    }

    public function registerHooks(): void
    {
        add_action('init', [$this, 'seed'], 25);
    }

    public function seed(): void
    {
        foreach (self::PHASES as $index => $phase) {
            if (is_array($this->artifacts->get('release-gate', $phase))) {
                continue;
            }
            $repositoryPhase = $index <= 10;
            $this->artifacts->save([
                'artifact_type' => 'release-gate',
                'artifact_key' => $phase,
                'title' => strtoupper(substr($phase, 0, 3)) . ' — ' . str_replace('-', ' ', substr($phase, 4)),
                'status' => $repositoryPhase ? 'pending' : 'pending',
                'classification' => 'C1',
                'owner_user_id' => 0,
                'payload' => [
                    'phase_order' => $index + 1,
                    'repository_phase' => $repositoryPhase,
                    'external_acceptance_required' => $phase === '24l-independent-assurance-staging',
                    'entry_criteria' => [],
                    'exit_criteria' => [],
                ],
            ]);
        }
    }

    /** @return string|\WP_Error */
    public function decide(string $phase, string $status, int $expectedVersion, string $evidenceRef, array $criteria = []): string|\WP_Error
    {
        $phase = Sanitizer::key($phase, 100);
        if (! in_array($phase, self::PHASES, true)) {
            return new \WP_Error('spcrc_release_phase_invalid', 'Release phase is invalid.');
        }
        if ($status === 'passed' && Sanitizer::opaqueReference($evidenceRef) === '') {
            return new \WP_Error('spcrc_release_gate_evidence_missing', 'Passed release gate requires opaque evidence.');
        }
        $record = $this->artifacts->get('release-gate', $phase);
        if (! is_array($record)) {
            return new \WP_Error('spcrc_release_gate_missing', 'Release gate was not initialized.');
        }
        $record['status'] = $status;
        $record['evidence_ref'] = $evidenceRef;
        $record['payload'] = array_replace_recursive(is_array($record['payload'] ?? null) ? $record['payload'] : [], [
            'criteria' => Sanitizer::textList($criteria, 100, 160),
            'decided_at' => gmdate('c'),
            'decided_by_user_id' => get_current_user_id(),
        ]);
        return $this->artifacts->save($record, $expectedVersion);
    }

    /** @return string[] */
    public static function phases(): array
    {
        return self::PHASES;
    }
}
