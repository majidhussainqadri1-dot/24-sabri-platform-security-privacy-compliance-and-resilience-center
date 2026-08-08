<?php

declare(strict_types=1);

namespace Sabri\Platform\Security\Privacy;

use Sabri\Platform\Security\Registry\GovernedArtifactRegistry;
use Sabri\Platform\Security\Storage\AuditGapStore;
use Sabri\Platform\Security\Storage\AuditLogger;
use Sabri\Platform\Security\Support\AtomicOptionLock;
use Sabri\Platform\Security\Support\Sanitizer;

final class DeletionReplayManager
{
    public const EVENT = 'spcrc_privacy_deletion_replay';
    private const LOCK = 'spcrc_deletion_replay_lock';

    public function __construct(
        private GovernedArtifactRegistry $artifacts,
        private ?AuditLogger $audit = null
    ) {
        $this->audit ??= new AuditLogger();
    }

    public function registerHooks(): void
    {
        add_action('init', [self::class, 'ensureScheduled']);
        add_action(self::EVENT, [$this, 'run']);
        add_action('spcrc/after_restore', [$this, 'run']);
    }

    public static function ensureScheduled(): bool
    {
        if (! function_exists('wp_next_scheduled') || ! function_exists('wp_schedule_event')) {
            return false;
        }
        $next = wp_next_scheduled(self::EVENT);
        if ($next !== false) {
            return self::scheduleValid($next, 'hourly');
        }
        $scheduled = wp_schedule_event(time() + 300, 'hourly', self::EVENT);
        return ! is_wp_error($scheduled) && $scheduled !== false
            && self::scheduleValid(wp_next_scheduled(self::EVENT), 'hourly');
    }

    private static function scheduleValid(mixed $next, string $recurrence): bool
    {
        $now = time();
        $timestamp = Sanitizer::strictInteger($next, $now + 1, $now + (2 * HOUR_IN_SECONDS));
        if ($timestamp === null) {
            return false;
        }
        if (! function_exists('wp_get_scheduled_event')) {
            return true;
        }
        $event = wp_get_scheduled_event(self::EVENT);
        return is_object($event)
            && Sanitizer::key($event->schedule ?? '', 40) === $recurrence
            && Sanitizer::strictInteger($event->timestamp ?? null, $now + 1, $now + (2 * HOUR_IN_SECONDS)) === $timestamp;
    }

    public static function unschedule(): void
    {
        if (function_exists('wp_clear_scheduled_hook')) {
            wp_clear_scheduled_hook(self::EVENT);
        }
    }

    /** @return array<string,int> */
    public function run(int $limit = 100): array
    {
        $token = AtomicOptionLock::acquire(self::LOCK, 300);
        if (is_wp_error($token)) {
            return ['processed' => 0, 'reconciled' => 0, 'failed' => 0, 'held' => 0];
        }
        $counts = ['processed' => 0, 'reconciled' => 0, 'failed' => 0, 'held' => 0];

        try {
            foreach ($this->artifacts->recent('deletion-ledger', max(1, min(200, $limit))) as $record) {
                if (! in_array($record['status'] ?? '', ['pending', 'failed', 'dispatching', 'blocked-hold'], true)) {
                    continue;
                }
                $payload = is_array($record['payload'] ?? null) ? $record['payload'] : [];
                $nextRetryAt = Sanitizer::isoTime($payload['next_retry_at'] ?? '');
                if (($record['status'] ?? '') === 'failed' && $nextRetryAt !== '') {
                    $nextRetryTimestamp = strtotime($nextRetryAt);
                    if ($nextRetryTimestamp !== false && $nextRetryTimestamp > time()) {
                        continue;
                    }
                }
                ++$counts['processed'];
                $holdRef = Sanitizer::opaqueReference($payload['legal_hold_ref'] ?? '');
                if ($holdRef !== '' && Sanitizer::boolean(apply_filters('spcrc/privacy_legal_hold_active', false, $holdRef, $record))) {
                    $held = $this->artifacts->transition('deletion-ledger', (string) $record['artifact_key'], 'blocked-hold', (int) $record['version'], [
                        'last_error_code' => 'legal_hold_active',
                    ]);
                    if (is_wp_error($held)) {
                        ++$counts['failed'];
                        $this->recordPersistenceGap($record, 'legal_hold_state_persistence_failed', $held);
                    } else {
                        ++$counts['held'];
                    }
                    continue;
                }

                $result = apply_filters('spcrc/privacy_deletion_replay_module', [
                    'status' => 'unavailable',
                    'evidence_ref' => '',
                    'error_code' => 'module_handler_unavailable',
                ], $record);
                $result = is_array($result) ? $result : [];
                $status = Sanitizer::key($result['status'] ?? 'failed', 30);
                $evidence = Sanitizer::opaqueReference($result['evidence_ref'] ?? '');
                $attempts = absint($payload['attempts'] ?? 0) + 1;

                if ($status === 'reconciled' && $evidence !== '') {
                    $updated = $record;
                    $updated['status'] = 'reconciled';
                    $updated['evidence_ref'] = $evidence;
                    $updated['payload'] = array_merge($payload, [
                        'attempts' => $attempts,
                        'last_error_code' => '',
                        'reconciled_at' => gmdate('c'),
                    ]);
                    $saved = $this->artifacts->save($updated, (int) $record['version']);
                    if (! is_wp_error($saved)) {
                        ++$counts['reconciled'];
                    } else {
                        ++$counts['failed'];
                        $this->recordPersistenceGap($record, 'reconciled_state_persistence_failed', $saved);
                    }
                    continue;
                }

                $failed = $this->artifacts->transition('deletion-ledger', (string) $record['artifact_key'], 'failed', (int) $record['version'], [
                    'attempts' => $attempts,
                    'last_error_code' => Sanitizer::key($result['error_code'] ?? 'deletion_replay_failed', 120),
                    'next_retry_at' => gmdate('c', time() + min(86400, 300 * (2 ** min(8, $attempts)))),
                ]);
                if (is_wp_error($failed)) {
                    $this->recordPersistenceGap($record, 'failed_state_persistence_failed', $failed);
                }
                ++$counts['failed'];
            }

            $audit = $this->audit->record('privacy_deletion_replay_completed', 'file-24-security-center', 'completed', 'medium', $counts);
            if (is_wp_error($audit)) {
                AuditGapStore::record('spcrc_deletion_replay_audit_gap', 'deletion-replay-run', gmdate('YmdHis'), 'completion_audit_failed', [
                    'error_code' => $audit->get_error_code(),
                    'processed' => $counts['processed'],
                    'failed' => $counts['failed'],
                ]);
                do_action('spcrc/privacy_deletion_replay_audit_failed', $audit->get_error_code(), $counts);
            }
            return $counts;
        } finally {
            if (! AtomicOptionLock::release(self::LOCK, $token)) {
                do_action('spcrc/privacy_deletion_replay_lock_release_failed', $token);
            }
        }
    }

    /** @param array<string,mixed> $record */
    private function recordPersistenceGap(array $record, string $reason, \WP_Error $error): void
    {
        $artifactKey = Sanitizer::key($record['artifact_key'] ?? '', 120);
        AuditGapStore::record('spcrc_deletion_replay_audit_gap', 'deletion-ledger', $artifactKey, $reason, [
            'error_code' => $error->get_error_code(),
        ]);
        do_action('spcrc/privacy_deletion_replay_persistence_failed', $artifactKey, $error->get_error_code());
    }
}
