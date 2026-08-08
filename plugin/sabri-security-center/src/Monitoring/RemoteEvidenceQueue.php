<?php

declare(strict_types=1);

namespace Sabri\Platform\Security\Monitoring;

use Sabri\Platform\Security\Registry\GovernedArtifactRegistry;
use Sabri\Platform\Security\Storage\AuditGapStore;
use Sabri\Platform\Security\Support\AtomicOptionLock;
use Sabri\Platform\Security\Support\Sanitizer;
use Sabri\Platform\Security\Support\SecureIdentifier;

final class RemoteEvidenceQueue
{
    public const EVENT = 'spcrc_remote_evidence_delivery';
    private const LOCK = 'spcrc_remote_evidence_queue_lock';
    private bool $guard = false;

    public function __construct(private GovernedArtifactRegistry $artifacts)
    {
    }

    public function registerHooks(): void
    {
        add_action('spcrc/external_security_event', [$this, 'observe'], 20, 1);
        add_action('init', [self::class, 'ensureScheduled']);
        add_action(self::EVENT, [$this, 'process']);
        add_filter('spcrc/external_log_adapter_available', [$this, 'adapterAvailable'], 20, 1);
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
        $scheduled = wp_schedule_event(time() + 120, 'hourly', self::EVENT);
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

    public function adapterAvailable(bool $current): bool
    {
        return $current || has_filter('spcrc/remote_evidence_deliver');
    }

    /** @param array<string,mixed> $event */
    public function observe(array $event): void
    {
        if ($this->guard || ($event['event_type'] ?? '') === 'governed_artifact_saved') {
            return;
        }
        $queued = $this->enqueue($event);
        if (is_wp_error($queued)) {
            $eventUuid = Sanitizer::uuid($event['event_uuid'] ?? '');
            AuditGapStore::record('spcrc_remote_evidence_audit_gap', 'remote-evidence-event', $eventUuid, 'enqueue_persistence_failed', [
                'event_type' => Sanitizer::key($event['event_type'] ?? '', 120),
                'error_code' => $queued->get_error_code(),
            ]);
            do_action('spcrc/remote_evidence_enqueue_failed', $eventUuid, $queued->get_error_code());
        }
    }

    /** @param array<string,mixed> $event @return string|\WP_Error */
    public function enqueue(array $event): string|\WP_Error
    {
        $eventUuid = Sanitizer::uuid($event['event_uuid'] ?? '');
        $eventType = Sanitizer::key($event['event_type'] ?? '', 120);
        $moduleKey = Sanitizer::key($event['module_key'] ?? '', 120);
        if ($eventUuid === '' || $eventType === '' || $moduleKey === '') {
            return new \WP_Error('spcrc_remote_evidence_event_invalid', 'Normalized event identity is required.');
        }
        $queueId = SecureIdentifier::uuid4('remote-evidence');
        if (is_wp_error($queueId)) {
            return $queueId;
        }

        $this->guard = true;
        try {
            return $this->artifacts->save([
                'artifact_type' => 'remote-evidence',
                'artifact_key' => 'event-' . substr(hash('sha256', $eventUuid), 0, 32),
                'title' => 'Queued remote security evidence',
                'status' => 'queued',
                'classification' => 'C5',
                'module_key' => $moduleKey,
                'owner_user_id' => get_current_user_id(),
                'payload' => [
                    'queue_ref' => 'queue:' . substr(hash('sha256', $queueId), 0, 32),
                    'event_uuid' => $eventUuid,
                    'event_type' => $eventType,
                    'module_key' => $moduleKey,
                    'result' => Sanitizer::key($event['result'] ?? '', 40),
                    'risk_level' => Sanitizer::key($event['risk_level'] ?? 'low', 20),
                    'correlation_id' => Sanitizer::uuid($event['correlation_id'] ?? ''),
                    'created_at' => Sanitizer::isoTime($event['created_at'] ?? gmdate('c')),
                    'attempts' => 0,
                    'next_attempt_at' => gmdate('c'),
                ],
            ]);
        } finally {
            $this->guard = false;
        }
    }

    /** @return array<string,int> */
    public function process(int $limit = 100): array
    {
        $token = AtomicOptionLock::acquire(self::LOCK, 300);
        if (is_wp_error($token)) {
            return ['processed' => 0, 'delivered' => 0, 'retry' => 0, 'dead_letter' => 0, 'persistence_failed' => 0];
        }
        $counts = ['processed' => 0, 'delivered' => 0, 'retry' => 0, 'dead_letter' => 0, 'persistence_failed' => 0];
        $this->guard = true;
        try {
            foreach ($this->artifacts->recent('remote-evidence', max(1, min(200, $limit))) as $record) {
                if (! in_array($record['status'] ?? '', ['queued', 'retry'], true)) {
                    continue;
                }
                $payload = is_array($record['payload'] ?? null) ? $record['payload'] : [];
                $nextAt = Sanitizer::isoTime($payload['next_attempt_at'] ?? '');
                if ($nextAt !== '' && strtotime($nextAt) > time()) {
                    continue;
                }
                ++$counts['processed'];
                if (! AtomicOptionLock::refresh(self::LOCK, $token, 300)) {
                    ++$counts['persistence_failed'];
                    $this->recordLeaseGap($record, 'lease_lost_before_delivery');
                    break;
                }
                $attemptBase = Sanitizer::strictInteger($payload['attempts'] ?? 0, 0, 1000000);
                if ($attemptBase === null) {
                    ++$counts['persistence_failed'];
                    $this->recordLeaseGap($record, 'attempt_counter_invalid');
                    continue;
                }
                $attempts = $attemptBase + 1;
                $claimed = $this->artifacts->transition(
                    'remote-evidence',
                    (string) $record['artifact_key'],
                    'delivering',
                    (int) $record['version'],
                    [
                        'attempts' => $attempts,
                        'delivery_started_at' => gmdate('c'),
                        'last_error_code' => '',
                    ]
                );
                if (is_wp_error($claimed)) {
                    ++$counts['persistence_failed'];
                    $this->recordPersistenceGap($record, 'delivery_claim_persistence_failed', $claimed);
                    continue;
                }
                $record = $this->artifacts->get('remote-evidence', (string) $record['artifact_key']);
                if (! is_array($record)) {
                    ++$counts['persistence_failed'];
                    $this->recordLeaseGap(['artifact_key' => 'remote-evidence'], 'delivery_claim_reload_failed');
                    continue;
                }
                $payload = is_array($record['payload'] ?? null) ? $record['payload'] : [];
                if (! AtomicOptionLock::refresh(self::LOCK, $token, 300)) {
                    ++$counts['persistence_failed'];
                    $this->recordLeaseGap($record, 'lease_lost_after_delivery_claim');
                    break;
                }

                $delivery = apply_filters('spcrc/remote_evidence_deliver', [
                    'status' => 'unavailable',
                    'evidence_ref' => '',
                    'error_code' => 'remote_adapter_unavailable',
                ], $payload);
                $delivery = is_array($delivery) ? $delivery : [];
                if (! AtomicOptionLock::refresh(self::LOCK, $token, 300)) {
                    ++$counts['persistence_failed'];
                    $this->recordLeaseGap($record, 'lease_lost_during_delivery');
                    break;
                }
                if (Sanitizer::key($delivery['status'] ?? '', 30) === 'delivered'
                    && Sanitizer::opaqueReference($delivery['evidence_ref'] ?? '') !== ''
                ) {
                    $updated = $record;
                    $updated['status'] = 'delivered';
                    $updated['evidence_ref'] = Sanitizer::opaqueReference($delivery['evidence_ref']);
                    $updated['payload'] = array_merge($payload, ['attempts' => $attempts, 'delivered_at' => gmdate('c'), 'last_error_code' => '']);
                    $saved = $this->artifacts->save($updated, (int) $record['version']);
                    if (is_wp_error($saved)) {
                        ++$counts['persistence_failed'];
                        $this->recordPersistenceGap($record, 'delivery_state_persistence_failed', $saved);
                    } else {
                        ++$counts['delivered'];
                    }
                    continue;
                }

                $status = $attempts >= 8 ? 'dead-letter' : 'retry';
                $transitioned = $this->artifacts->transition('remote-evidence', (string) $record['artifact_key'], $status, (int) $record['version'], [
                    'attempts' => $attempts,
                    'last_error_code' => Sanitizer::key($delivery['error_code'] ?? 'remote_delivery_failed', 120),
                    'next_attempt_at' => gmdate('c', time() + min(86400, 60 * (2 ** min(10, $attempts)))),
                ]);
                if (is_wp_error($transitioned)) {
                    ++$counts['persistence_failed'];
                    $this->recordPersistenceGap($record, 'retry_state_persistence_failed', $transitioned);
                } else {
                    $counts[$status === 'dead-letter' ? 'dead_letter' : 'retry']++;
                }
            }
            return $counts;
        } finally {
            $this->guard = false;
            AtomicOptionLock::release(self::LOCK, $token);
        }
    }

    /** @param array<string,mixed> $record */
    private function recordLeaseGap(array $record, string $reason): void
    {
        $artifactKey = Sanitizer::key($record['artifact_key'] ?? '', 120);
        AuditGapStore::record('spcrc_remote_evidence_audit_gap', 'remote-evidence', $artifactKey, $reason, [
            'error_code' => 'spcrc_remote_evidence_lock_lost',
        ]);
        do_action('spcrc/remote_evidence_lock_lost', $artifactKey, $reason);
    }

    /** @param array<string,mixed> $record */
    private function recordPersistenceGap(array $record, string $reason, \WP_Error $error): void
    {
        $artifactKey = Sanitizer::key($record['artifact_key'] ?? '', 120);
        AuditGapStore::record('spcrc_remote_evidence_audit_gap', 'remote-evidence', $artifactKey, $reason, [
            'error_code' => $error->get_error_code(),
        ]);
        do_action('spcrc/remote_evidence_persistence_failed', $artifactKey, $error->get_error_code());
    }

    public function depth(): int
    {
        $count = 0;
        foreach ($this->artifacts->recent('remote-evidence', 200) as $record) {
            if (in_array($record['status'] ?? '', ['queued', 'retry', 'delivering'], true)) {
                ++$count;
            }
        }
        return $count;
    }
}
