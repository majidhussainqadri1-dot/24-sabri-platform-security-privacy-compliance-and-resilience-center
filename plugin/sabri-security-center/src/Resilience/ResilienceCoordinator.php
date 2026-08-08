<?php

declare(strict_types=1);

namespace Sabri\Platform\Security\Resilience;

use Sabri\Platform\Security\Registry\GovernedArtifactRegistry;
use Sabri\Platform\Security\Storage\AssuranceRepository;
use Sabri\Platform\Security\Storage\AuditGapStore;
use Sabri\Platform\Security\Storage\FindingRepository;
use Sabri\Platform\Security\Support\Sanitizer;

/** Repository-level BIA, continuity, recovery-objective and drill orchestration. */
final class ResilienceCoordinator
{
    public const DRILL_EVENT = 'spcrc_resilience_drill_review';

    /** @var array<string,array{rpo:int,rto:int}> */
    private const PROVISIONAL_OBJECTIVES = [
        'tier-a' => ['rpo' => 900, 'rto' => 7200],
        'tier-b' => ['rpo' => 3600, 'rto' => 14400],
        'tier-c' => ['rpo' => 14400, 'rto' => 28800],
        'tier-d' => ['rpo' => 86400, 'rto' => 86400],
    ];

    /** @var string[] */
    private const CONTINUITY_MODES = [
        'public-read-only', 'publishing-disabled', 'upload-disabled',
        'messaging-disabled', 'appointments-read-only', 'restricted-login',
        'admin-only', 'maintenance',
    ];

    public function __construct(
        private GovernedArtifactRegistry $artifacts,
        private AssuranceRepository $assurance,
        private FindingRepository $findings
    ) {
    }

    public function registerHooks(): void
    {
        add_action('init', [self::class, 'ensureScheduled']);
        add_action(self::DRILL_EVENT, [$this, 'reviewDueDrills']);
        add_filter('spcrc/provisional_recovery_objectives', static fn (): array => self::PROVISIONAL_OBJECTIVES);
    }

    public static function ensureScheduled(): bool
    {
        if (! function_exists('wp_next_scheduled') || ! function_exists('wp_schedule_event')) {
            return false;
        }
        $next = wp_next_scheduled(self::DRILL_EVENT);
        if ($next !== false) {
            return self::scheduleValid($next, 'daily');
        }
        $scheduled = wp_schedule_event(time() + DAY_IN_SECONDS, 'daily', self::DRILL_EVENT);
        return ! is_wp_error($scheduled) && $scheduled !== false
            && self::scheduleValid(wp_next_scheduled(self::DRILL_EVENT), 'daily');
    }

    private static function scheduleValid(mixed $next, string $recurrence): bool
    {
        $now = time();
        $timestamp = Sanitizer::strictInteger($next, $now + 1, $now + (2 * DAY_IN_SECONDS));
        if ($timestamp === null) {
            return false;
        }
        if (! function_exists('wp_get_scheduled_event')) {
            return true;
        }
        $event = wp_get_scheduled_event(self::DRILL_EVENT);
        return is_object($event)
            && Sanitizer::key($event->schedule ?? '', 40) === $recurrence
            && Sanitizer::strictInteger($event->timestamp ?? null, $now + 1, $now + (2 * DAY_IN_SECONDS)) === $timestamp;
    }

    public static function unschedule(): void
    {
        if (function_exists('wp_clear_scheduled_hook')) {
            wp_clear_scheduled_hook(self::DRILL_EVENT);
        }
    }

    /** @return string|\WP_Error */
    public function saveBia(array $data): string|\WP_Error
    {
        $tier = Sanitizer::key($data['tier'] ?? '', 20);
        if (! isset(self::PROVISIONAL_OBJECTIVES[$tier])) {
            return new \WP_Error('spcrc_bia_tier_invalid', 'A supported BIA tier is required.');
        }
        return $this->artifacts->save([
            'artifact_type' => 'bia',
            'artifact_key' => $data['service_key'] ?? '',
            'title' => $data['title'] ?? '',
            'status' => $data['status'] ?? 'draft',
            'classification' => 'C1',
            'owner_user_id' => $data['owner_user_id'] ?? get_current_user_id(),
            'evidence_ref' => $data['evidence_ref'] ?? '',
            'reviewed_at' => $data['reviewed_at'] ?? '',
            'next_review_at' => $data['next_review_at'] ?? '',
            'payload' => [
                'tier' => $tier,
                'user_harm' => Sanitizer::key($data['user_harm'] ?? 'unknown', 30),
                'clinical_impact' => Sanitizer::key($data['clinical_impact'] ?? 'none', 30),
                'legal_impact' => Sanitizer::key($data['legal_impact'] ?? 'unknown', 30),
                'data_volume_class' => Sanitizer::key($data['data_volume_class'] ?? 'unknown', 30),
                'recovery_dependencies' => Sanitizer::textList($data['recovery_dependencies'] ?? [], 30, 100),
            ],
        ]);
    }

    /** @return string|\WP_Error */
    public function saveRecoveryObjective(array $data): string|\WP_Error
    {
        $tier = Sanitizer::key($data['tier'] ?? '', 20);
        if (! isset(self::PROVISIONAL_OBJECTIVES[$tier])) {
            return new \WP_Error('spcrc_recovery_tier_invalid', 'A supported recovery tier is required.');
        }
        $status = Sanitizer::key($data['status'] ?? 'provisional', 30);
        $rpo = self::secondsValue($data['rpo_seconds'] ?? self::PROVISIONAL_OBJECTIVES[$tier]['rpo'], 'rpo_seconds');
        if (is_wp_error($rpo)) {
            return $rpo;
        }
        $rto = self::secondsValue($data['rto_seconds'] ?? self::PROVISIONAL_OBJECTIVES[$tier]['rto'], 'rto_seconds');
        if (is_wp_error($rto)) {
            return $rto;
        }
        if ($status === 'approved' && Sanitizer::opaqueReference($data['evidence_ref'] ?? '') === '') {
            return new \WP_Error('spcrc_recovery_evidence_missing', 'Approved recovery objectives require measured drill evidence.');
        }
        return $this->artifacts->save([
            'artifact_type' => 'recovery-objective',
            'artifact_key' => $data['service_key'] ?? '',
            'title' => $data['title'] ?? '',
            'status' => $status,
            'classification' => 'C1',
            'owner_user_id' => $data['owner_user_id'] ?? get_current_user_id(),
            'evidence_ref' => $data['evidence_ref'] ?? '',
            'reviewed_at' => $data['reviewed_at'] ?? '',
            'next_review_at' => $data['next_review_at'] ?? '',
            'payload' => ['tier' => $tier, 'rpo_seconds' => $rpo, 'rto_seconds' => $rto, 'contractual' => $status === 'approved'],
        ]);
    }

    /** @return string|\WP_Error */
    public function saveContinuityPlan(array $data): string|\WP_Error
    {
        $mode = Sanitizer::key($data['mode'] ?? '', 60);
        if (! in_array($mode, self::CONTINUITY_MODES, true)) {
            return new \WP_Error('spcrc_continuity_mode_invalid', 'A supported continuity mode is required.');
        }
        return $this->artifacts->save([
            'artifact_type' => 'continuity-plan',
            'artifact_key' => $data['plan_key'] ?? $mode,
            'title' => $data['title'] ?? '',
            'status' => $data['status'] ?? 'draft',
            'classification' => 'C1',
            'owner_user_id' => $data['owner_user_id'] ?? get_current_user_id(),
            'evidence_ref' => $data['evidence_ref'] ?? '',
            'reviewed_at' => $data['reviewed_at'] ?? '',
            'next_review_at' => $data['next_review_at'] ?? '',
            'payload' => [
                'mode' => $mode,
                'available_services' => Sanitizer::textList($data['available_services'] ?? [], 30, 100),
                'blocked_actions' => Sanitizer::textList($data['blocked_actions'] ?? [], 30, 100),
                'user_message' => Sanitizer::text($data['user_message'] ?? '', 300),
                'exit_criteria' => Sanitizer::textList($data['exit_criteria'] ?? [], 30, 120),
            ],
        ]);
    }

    /** @return string|\WP_Error */
    public function recordDrill(array $data): string|\WP_Error
    {
        $status = Sanitizer::key($data['status'] ?? '', 30);
        $evidenceRef = Sanitizer::opaqueReference($data['evidence_ref'] ?? '');
        if (in_array($status, ['passed', 'failed'], true) && $evidenceRef === '') {
            return new \WP_Error('spcrc_drill_evidence_missing', 'Completed drills require opaque evidence.');
        }
        $measuredRpo = self::secondsValue($data['measured_rpo_seconds'] ?? 0, 'measured_rpo_seconds');
        if (is_wp_error($measuredRpo)) {
            return $measuredRpo;
        }
        $measuredRto = self::secondsValue($data['measured_rto_seconds'] ?? 0, 'measured_rto_seconds');
        if (is_wp_error($measuredRto)) {
            return $measuredRto;
        }
        $saved = $this->artifacts->save([
            'artifact_type' => 'drill',
            'artifact_key' => $data['drill_key'] ?? '',
            'title' => $data['title'] ?? '',
            'status' => $status,
            'classification' => 'C2',
            'owner_user_id' => $data['owner_user_id'] ?? get_current_user_id(),
            'evidence_ref' => $evidenceRef,
            'reviewed_at' => $data['reviewed_at'] ?? '',
            'next_review_at' => $data['next_review_at'] ?? '',
            'payload' => [
                'scenario' => Sanitizer::key($data['scenario'] ?? '', 80),
                'measured_rpo_seconds' => $measuredRpo,
                'measured_rto_seconds' => $measuredRto,
                'corrective_actions' => Sanitizer::textList($data['corrective_actions'] ?? [], 50, 140),
            ],
        ]);
        if (! is_wp_error($saved) && $status === 'failed') {
            $finding = $this->findings->create([
                'module_key' => 'file-24-security-center',
                'title' => 'Failed resilience drill requires corrective action',
                'severity' => 'high',
                'owner_user_id' => $data['owner_user_id'] ?? get_current_user_id(),
                'due_at' => gmdate('Y-m-d H:i:s', time() + 7 * DAY_IN_SECONDS),
                'evidence_ref' => $evidenceRef,
            ]);
            if (is_wp_error($finding)) {
                AuditGapStore::record('spcrc_finding_audit_gap', 'resilience-drill', $saved, 'failed_drill_finding_creation_failed', [
                    'drill_key' => Sanitizer::key($data['drill_key'] ?? '', 120),
                    'finding_error_code' => $finding->get_error_code(),
                ]);
                return new \WP_Error(
                    'spcrc_drill_finding_failed',
                    'Failed drill evidence was stored, but its mandatory corrective finding could not be created.',
                    ['drill_ref' => $saved, 'cause' => $finding->get_error_code()]
                );
            }
        }
        return $saved;
    }

    /** @return int|\WP_Error */
    private static function secondsValue(mixed $value, string $field): int|\WP_Error
    {
        if (is_int($value)) {
            $seconds = $value;
        } elseif (is_string($value) && preg_match('/^\d+$/', $value) === 1) {
            $seconds = (int) $value;
        } else {
            return new \WP_Error('spcrc_resilience_measurement_invalid', 'Resilience time measurements must be finite non-negative whole seconds.', ['field' => $field]);
        }
        if ($seconds < 0) {
            return new \WP_Error('spcrc_resilience_measurement_invalid', 'Resilience time measurements must be finite non-negative whole seconds.', ['field' => $field]);
        }
        return $seconds;
    }

    /** @return array<string,int> */
    public function reviewDueDrills(): array
    {
        $counts = ['reviewed' => 0, 'overdue' => 0];
        foreach ($this->artifacts->recent('drill', 200) as $record) {
            ++$counts['reviewed'];
            $next = Sanitizer::isoTime($record['next_review_at'] ?? '');
            if ($next !== '' && strtotime($next) < time() && ! in_array($record['status'] ?? '', ['cancelled'], true)) {
                ++$counts['overdue'];
            }
        }
        return $counts;
    }

    /** @return array<string,mixed> */
    public function posture(): array
    {
        $backup = $this->assurance->backupEvidence([]);
        return [
            'backup_verified' => ($backup['status'] ?? '') === 'verified',
            'backup_evidence' => $backup,
            'bia_count' => $this->artifacts->count('bia'),
            'recovery_objective_count' => $this->artifacts->count('recovery-objective'),
            'continuity_plan_count' => $this->artifacts->count('continuity-plan'),
            'drill_count' => $this->artifacts->count('drill'),
            'provisional_objectives' => self::PROVISIONAL_OBJECTIVES,
        ];
    }
}
