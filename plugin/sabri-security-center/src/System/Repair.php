<?php

declare(strict_types=1);

namespace Sabri\Platform\Security\System;

use Sabri\Platform\Security\Capabilities;
use Sabri\Platform\Security\Monitoring\RemoteEvidenceQueue;
use Sabri\Platform\Security\Privacy\DeletionReplayManager;
use Sabri\Platform\Security\Privacy\RecoveryManager;
use Sabri\Platform\Security\Resilience\ResilienceCoordinator;
use Sabri\Platform\Security\Retention\RetentionManager;
use Sabri\Platform\Security\Storage\Schema;
use Sabri\Platform\Security\Support\Sanitizer;

final class Repair
{
    private const CONFIRMATION = 'REPAIR FILE 24';

    /** @return array<string,mixed> */
    public function preview(): array
    {
        $schema = Schema::verify();
        $snapshot = [
            'schema_health' => is_wp_error($schema) ? $schema->get_error_code() : 'verified',
            'target_schema_version' => Schema::VERSION,
            'target_plugin_version' => defined('SPCRC_VERSION') ? SPCRC_VERSION : '',
            'potential_table_count' => count(Schema::tables()),
            'potential_capability_count' => count(Capabilities::all()),
            'owned_scope_only' => true,
            'destructive' => false,
            'schedules_present' => [
                'retention' => $this->scheduled(RetentionManager::CRON_HOOK),
                'privacy_recovery' => $this->scheduled(RecoveryManager::EVENT),
                'deletion_replay' => $this->scheduled(DeletionReplayManager::EVENT),
                'remote_evidence' => $this->scheduled(RemoteEvidenceQueue::EVENT),
                'resilience' => $this->scheduled(ResilienceCoordinator::DRILL_EVENT),
            ],
        ];
        $encoded = wp_json_encode($snapshot, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        $snapshot['preview_hash'] = is_string($encoded) ? hash('sha256', $encoded) : '';
        return $snapshot;
    }

    /** @param array<string,mixed> $context @return array<string,mixed>|\WP_Error */
    public function run(array $context = []): array|\WP_Error
    {
        $authorization = $this->authorize($context);
        if (is_wp_error($authorization)) {
            return $authorization;
        }

        $preview = $this->preview();
        $submittedPreview = strtolower(Sanitizer::text($context['preview_hash'] ?? '', 64));
        if (preg_match('/^[a-f0-9]{64}$/', $submittedPreview) !== 1
            || ! hash_equals((string) ($preview['preview_hash'] ?? ''), $submittedPreview)
        ) {
            return new \WP_Error('spcrc_repair_preview_stale', 'Repair diagnostics changed or were not previewed. Refresh the dry-run before applying repair.');
        }

        $schema = Schema::install();
        if (is_wp_error($schema)) {
            return $schema;
        }

        if (! Capabilities::install()) {
            return new \WP_Error('spcrc_repair_capability_failed', 'Non-destructive repair could not verify File 24 capabilities.');
        }
        if (! RetentionManager::ensureScheduled()) {
            return new \WP_Error('spcrc_retention_schedule_failed', 'Non-destructive repair could not verify the retention schedule.');
        }
        if (! RecoveryManager::ensureScheduled()) {
            return new \WP_Error('spcrc_privacy_recovery_schedule_failed', 'Non-destructive repair could not verify the privacy recovery schedule.');
        }
        $deletionScheduled = ! class_exists(DeletionReplayManager::class) || DeletionReplayManager::ensureScheduled();
        $remoteScheduled = ! class_exists(RemoteEvidenceQueue::class) || RemoteEvidenceQueue::ensureScheduled();
        $resilienceScheduled = ! class_exists(ResilienceCoordinator::class) || ResilienceCoordinator::ensureScheduled();
        if (! $deletionScheduled || ! $remoteScheduled || ! $resilienceScheduled) {
            return new \WP_Error('spcrc_operational_schedule_failed', 'Non-destructive repair could not verify deletion, remote evidence or resilience schedules.');
        }

        update_option('spcrc_schema_version', Schema::VERSION, false);
        update_option('spcrc_version', SPCRC_VERSION, false);
        if (
            (string) get_option('spcrc_schema_version', '') !== Schema::VERSION
            || (string) get_option('spcrc_version', '') !== SPCRC_VERSION
        ) {
            return new \WP_Error('spcrc_repair_version_state_failed', 'Non-destructive repair state could not be verified.');
        }

        delete_option('spcrc_last_upgrade_error');

        $result = [
            'schema_version' => Schema::VERSION,
            'plugin_version' => SPCRC_VERSION,
            'capabilities_reapplied' => true,
            'retention_schedule_verified' => true,
            'privacy_recovery_schedule_verified' => true,
            'deletion_replay_schedule_verified' => true,
            'remote_evidence_schedule_verified' => true,
            'resilience_schedule_verified' => true,
            'dry_run_preview_hash' => $submittedPreview,
            'backup_checkpoint_ref' => $authorization['backup_checkpoint_ref'],
            'rollback_ref' => $authorization['rollback_ref'],
            'reason' => $authorization['reason'],
            'potential_table_count' => (int) ($preview['potential_table_count'] ?? 0),
            'potential_capability_count' => (int) ($preview['potential_capability_count'] ?? 0),
            'completed_at' => gmdate('c'),
        ];
        do_action('spcrc/non_destructive_repair_completed', $result);
        return $result;
    }

    /** @param array<string,mixed> $context @return array<string,string>|\WP_Error */
    private function authorize(array $context): array|\WP_Error
    {
        $actor = get_current_user_id();
        if ($actor < 1 || ! current_user_can('spcrc_manage_security_settings')) {
            return new \WP_Error('spcrc_repair_forbidden', 'Non-destructive repair requires explicit security-settings authority.');
        }
        $confirmation = trim((string) ($context['typed_confirmation'] ?? ''));
        if (! hash_equals(self::CONFIRMATION, $confirmation)) {
            return new \WP_Error('spcrc_repair_confirmation_required', 'Type REPAIR FILE 24 exactly before applying repair.');
        }
        $reason = Sanitizer::text($context['reason'] ?? '', 500);
        if ($reason === '' || Sanitizer::containsSensitiveMaterial($reason)) {
            return new \WP_Error('spcrc_repair_reason_invalid', 'A bounded, non-sensitive repair reason is required.');
        }
        $backup = Sanitizer::opaqueReference($context['backup_checkpoint_ref'] ?? '');
        $rollback = Sanitizer::opaqueReference($context['rollback_ref'] ?? '');
        $stepUp = Sanitizer::opaqueReference($context['step_up_reference'] ?? '');
        if ($backup === '' || $rollback === '') {
            return new \WP_Error('spcrc_repair_recovery_evidence_required', 'Repair requires opaque backup-checkpoint and rollback references.');
        }
        $stepUpOk = $stepUp !== '' && Sanitizer::boolean(apply_filters(
            'spcrc/verify_step_up_assurance',
            false,
            $actor,
            'non-destructive-repair',
            $stepUp
        ));
        if (! $stepUpOk) {
            return new \WP_Error('spcrc_repair_step_up_required', 'Fresh File 00 step-up assurance is required before repair.');
        }
        return ['backup_checkpoint_ref' => $backup, 'rollback_ref' => $rollback, 'reason' => $reason];
    }

    private function scheduled(string $hook): bool
    {
        return function_exists('wp_next_scheduled') && wp_next_scheduled($hook) !== false;
    }
}
