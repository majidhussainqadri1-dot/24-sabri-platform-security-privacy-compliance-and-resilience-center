<?php

declare(strict_types=1);

namespace Sabri\Platform\Security\Storage;

final class Retention
{
    public const HOOK = 'spcrc_daily_retention';
    private const BATCH_SIZE = 1000;
    private const MAX_BATCHES = 10;

    public function __construct(private AuditLogger $audit)
    {
    }

    public function registerHooks(): void
    {
        add_action(self::HOOK, [$this, 'run']);
    }

    public static function schedule(): void
    {
        if (! wp_next_scheduled(self::HOOK)) {
            wp_schedule_event(time() + HOUR_IN_SECONDS, 'daily', self::HOOK);
        }
    }

    public static function unschedule(): void
    {
        $timestamp = wp_next_scheduled(self::HOOK);
        while ($timestamp) {
            if (! wp_unschedule_event($timestamp, self::HOOK)) {
                break;
            }
            $timestamp = wp_next_scheduled(self::HOOK);
        }
    }

    public function run(): void
    {
        $days = (int) apply_filters('spcrc/security_event_retention_days', 180);
        $days = max(30, min(3650, $days));
        $eventCutoff = gmdate('Y-m-d H:i:s', time() - ($days * DAY_IN_SECONDS));
        $stateCutoff = gmdate('Y-m-d H:i:s', time() - (30 * DAY_IN_SECONDS));
        $tables = Schema::tables();

        $events = $this->deleteInBatches(
            "DELETE FROM {$tables['events']} WHERE created_at < %s ORDER BY id ASC LIMIT %d",
            $eventCutoff
        );
        $states = $this->deleteInBatches(
            "DELETE FROM {$tables['state_requests']} WHERE status IN ('expired','resolved','rejected') AND resolved_at < %s ORDER BY id ASC LIMIT %d",
            $stateCutoff
        );

        $failed = $events['failed'] || $states['failed'];
        $this->audit->record(
            'retention_run',
            'file-24-security-center',
            $failed ? 'partial' : 'completed',
            $failed ? 'high' : 'informational',
            [
                'event_retention_days' => $days,
                'events_deleted' => $events['deleted'],
                'state_requests_deleted' => $states['deleted'],
                'maximum_rows_per_run' => self::BATCH_SIZE * self::MAX_BATCHES,
                'database_failure' => $failed,
            ]
        );

        if ($failed) {
            do_action('spcrc/retention_failed', [
                'events' => $events,
                'state_requests' => $states,
            ]);
        }
    }

    /** @return array{deleted:int,failed:bool} */
    private function deleteInBatches(string $sql, string $cutoff): array
    {
        global $wpdb;
        $total = 0;

        for ($batch = 0; $batch < self::MAX_BATCHES; ++$batch) {
            $deleted = $wpdb->query($wpdb->prepare($sql, $cutoff, self::BATCH_SIZE));
            if ($deleted === false) {
                return ['deleted' => $total, 'failed' => true];
            }
            if ($deleted <= 0) {
                break;
            }
            $total += $deleted;
            if ($deleted < self::BATCH_SIZE) {
                break;
            }
        }

        return ['deleted' => $total, 'failed' => false];
    }
}
