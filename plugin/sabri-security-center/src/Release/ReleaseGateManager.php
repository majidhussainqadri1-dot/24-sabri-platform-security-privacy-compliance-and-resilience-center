<?php

declare(strict_types=1);

namespace Sabri\Platform\Security\Release;

use Sabri\Platform\Security\Registry\GovernedArtifactRegistry;
use Sabri\Platform\Security\Storage\AuditGapStore;
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
    private const STATUSES = ['pending', 'passed', 'failed', 'waived', 'not-applicable'];

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
                'status' => 'pending',
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

    /** @param string[] $criteria @param array<string,mixed> $context @return string|\WP_Error */
    public function decide(
        string $phase,
        string $status,
        int $expectedVersion,
        string $evidenceRef,
        array $criteria = [],
        array $context = []
    ): string|\WP_Error {
        $phase = Sanitizer::key($phase, 100);
        $status = Sanitizer::key($status, 30);
        $evidenceRef = Sanitizer::opaqueReference($evidenceRef);
        if (! in_array($phase, self::PHASES, true)) {
            return new \WP_Error('spcrc_release_phase_invalid', 'Release phase is invalid.');
        }
        if (! in_array($status, self::STATUSES, true)) {
            return new \WP_Error('spcrc_release_gate_status_invalid', 'Release gate status is invalid.');
        }
        $actor = get_current_user_id();
        if ($actor < 1 || ! current_user_can('spcrc_manage_release_gates')) {
            return new \WP_Error('spcrc_release_gate_forbidden', 'Release-gate decisions require explicit delegated authority.');
        }
        if ($expectedVersion < 1) {
            return new \WP_Error('spcrc_release_gate_expected_version_invalid', 'Release-gate decisions require the exact positive current version.');
        }
        if (in_array($status, ['passed', 'failed', 'waived'], true) && $evidenceRef === '') {
            return new \WP_Error('spcrc_release_gate_evidence_missing', 'Release-gate determinations require opaque evidence.');
        }

        $record = $this->artifacts->get('release-gate', $phase);
        if (! is_array($record)) {
            return new \WP_Error('spcrc_release_gate_missing', 'Release gate was not initialized.');
        }
        if ((int) ($record['version'] ?? 0) !== $expectedVersion) {
            return new \WP_Error('spcrc_release_gate_stale_version', 'Release gate changed before this decision. Refresh and retry.');
        }

        $criteria = Sanitizer::textList($criteria, 100, 160);
        $approvalHashes = [];
        $stepUpHash = '';
        if (in_array($status, ['passed', 'waived'], true)) {
            if ($criteria === []) {
                return new \WP_Error('spcrc_release_gate_criteria_missing', 'Passing or waiving a release gate requires bounded acceptance criteria evidence.');
            }
            $stepUpReference = Sanitizer::opaqueReference($context['step_up_reference'] ?? '');
            $stepUpOk = $stepUpReference !== '' && Sanitizer::boolean(apply_filters(
                'spcrc/verify_step_up_assurance',
                false,
                $actor,
                'release-gate:' . $phase,
                $stepUpReference
            ));
            if (! $stepUpOk) {
                return new \WP_Error('spcrc_release_gate_step_up_required', 'Fresh File 00 step-up assurance is required for a positive release decision.');
            }
            $approvals = [];
            foreach (array_slice(is_array($context['approval_refs'] ?? null) ? $context['approval_refs'] : [], 0, 6) as $reference) {
                $reference = Sanitizer::opaqueReference($reference);
                if ($reference !== '' && ! in_array($reference, $approvals, true)) {
                    $approvals[] = $reference;
                }
            }
            if (count($approvals) < 2) {
                return new \WP_Error('spcrc_release_gate_dual_approval_required', 'Passing or waiving a release gate requires two distinct human approval references.');
            }
            $approvalHashes = array_map(static fn (string $reference): string => hash('sha256', $reference), $approvals);
            $stepUpHash = hash('sha256', $stepUpReference);

            $phaseIndex = array_search($phase, self::PHASES, true);
            if (is_int($phaseIndex) && $phaseIndex > 0) {
                $previous = $this->artifacts->get('release-gate', self::PHASES[$phaseIndex - 1]);
                if (! is_array($previous) || ! in_array((string) ($previous['status'] ?? ''), ['passed', 'waived', 'not-applicable'], true)) {
                    return new \WP_Error('spcrc_release_gate_sequence_blocked', 'The immediately preceding release phase has not been acceptably closed.');
                }
            }
            if ($this->hasUnresolvedAuditGaps()) {
                return new \WP_Error('spcrc_release_gate_audit_gaps_open', 'Unresolved operational audit gaps block a positive release decision.');
            }
            $p0Count = Sanitizer::strictInteger(apply_filters('spcrc/release_blocking_p0_count', 0, $phase), 0, PHP_INT_MAX);
            if ($p0Count === null || $p0Count > 0) {
                return new \WP_Error('spcrc_release_gate_p0_blocked', 'Known P0 defects block release-phase progression.');
            }
            if ($phase === '24l-independent-assurance-staging'
                && ! Sanitizer::boolean(apply_filters('spcrc/release_external_acceptance_ready', false, $phase, $evidenceRef))
            ) {
                return new \WP_Error('spcrc_release_gate_external_acceptance_missing', 'Independent assurance and staging acceptance evidence is required for Phase 24L.');
            }
        }

        $record['status'] = $status;
        $record['evidence_ref'] = $evidenceRef;
        $record['payload'] = array_replace_recursive(is_array($record['payload'] ?? null) ? $record['payload'] : [], [
            'criteria' => $criteria,
            'decided_at' => gmdate('c'),
            'decided_by_user_id' => $actor,
            'dual_approval_hashes' => $approvalHashes,
            'step_up_reference_hash' => $stepUpHash,
        ]);
        return $this->artifacts->save($record, $expectedVersion);
    }

    /** @return string[] */
    public static function phases(): array
    {
        return self::PHASES;
    }

    private function hasUnresolvedAuditGaps(): bool
    {
        foreach (AuditGapStore::managedOptions() as $option) {
            if (AuditGapStore::count($option) > 0) {
                return true;
            }
        }
        return false;
    }
}
