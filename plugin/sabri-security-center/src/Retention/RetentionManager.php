<?php

declare(strict_types=1);

namespace Sabri\Platform\Security\Retention;

use Sabri\Platform\Security\Storage\AuditGapStore;
use Sabri\Platform\Security\Storage\AuditLogger;

if (! class_exists(AuditGapStore::class, false)) {
    require_once dirname(__DIR__) . '/Storage/AuditGapStore.php';
}

final class RetentionManager
{
    public const CRON_HOOK = 'spcrc_daily_retention';
    private const LOCK_KEY = 'spcrc_retention_lock';
    private const LOCK_SECONDS = 900;

    public function __construct(private ?AuditLogger $audit = null)
    {
    }

    public function registerHooks(): void
    {
        add_action(self::CRON_HOOK, [$this, 'run']);
        add_action('init', [self::class, 'ensureScheduled'], 90);
    }

    public static function ensureScheduled(): bool
    {
        if (! function_exists('wp_next_scheduled') || ! function_exists('wp_schedule_event')) {
            return false;
        }
        if (wp_next_scheduled(self::CRON_HOOK)) {
            return true;
        }

        $scheduled = wp_schedule_event(time() + HOUR_IN_SECONDS, 'daily', self::CRON_HOOK);
        return ! is_wp_error($scheduled) && $scheduled !== false;
    }

    public static function unschedule(): void
    {
        if (function_exists('wp_clear_scheduled_hook')) {
            wp_clear_scheduled_hook(self::CRON_HOOK);
        }
        if (function_exists('delete_transient')) {
            delete_transient(self::LOCK_KEY);
        }
    }

    /** @return array{status:string,age_deleted:int,overflow_deleted:int,error_code:string} */
    public function run(): array
    {
        if (get_transient(self::LOCK_KEY) !== false) {
            return $this->finish('locked', 0, 0, 'retention_already_running');
        }

        $lock = wp_generate_uuid4();
        if (! set_transient(self::LOCK_KEY, $lock, self::LOCK_SECONDS)) {
            return $this->finish('failed', 0, 0, 'retention_lock_unavailable');
        }

        try {
            if ($this->boolean(apply_filters('spcrc/security_event_retention_hold', false))) {
                return $this->finish('held', 0, 0, 'retention_hold_active');
            }

            global $wpdb;
            $days = max(7, min(3650, (int) apply_filters('spcrc/security_event_retention_days', 90)));
            $maximum = max(1000, min(1000000, (int) apply_filters('spcrc/security_event_max_rows', 100000)));
            $batch = max(100, min(10000, (int) apply_filters('spcrc/security_event_retention_batch', 5000)));
            $table = $wpdb->prefix . 'spcrc_security_events';
            $found = $wpdb->get_var($wpdb->prepare('SHOW TABLES LIKE %s', $wpdb->esc_like($table)));
            if ($found !== $table) {
                return $this->finish('failed', 0, 0, 'events_table_unavailable');
            }

            $cutoff = gmdate('Y-m-d H:i:s', time() - ($days * DAY_IN_SECONDS));
            $ageDeleted = $wpdb->query($wpdb->prepare(
                "DELETE FROM {$table} WHERE created_at < %s ORDER BY id ASC LIMIT %d",
                $cutoff,
                $batch
            ));
            if ($ageDeleted === false) {
                return $this->finish('failed', 0, 0, 'age_retention_delete_failed');
            }

            $count = $wpdb->get_var("SELECT COUNT(*) FROM {$table}");
            if (! is_numeric($count)) {
                return $this->finish('failed', (int) $ageDeleted, 0, 'event_count_failed');
            }

            $overflowDeleted = 0;
            $count = (int) $count;
            if ($count > $maximum) {
                $overflowDeleted = $wpdb->query($wpdb->prepare(
                    "DELETE FROM {$table} ORDER BY id ASC LIMIT %d",
                    min($batch, $count - $maximum)
                ));
                if ($overflowDeleted === false) {
                    return $this->finish('failed', (int) $ageDeleted, 0, 'overflow_retention_delete_failed');
                }
            }

            return $this->finish('completed', (int) $ageDeleted, (int) $overflowDeleted, '');
        } finally {
            if (get_transient(self::LOCK_KEY) === $lock) {
                delete_transient(self::LOCK_KEY);
            }
        }
    }

    /** @return array{status:string,age_deleted:int,overflow_deleted:int,error_code:string} */
    private function finish(string $status, int $ageDeleted, int $overflowDeleted, string $errorCode): array
    {
        $result = [
            'status' => $status,
            'age_deleted' => max(0, $ageDeleted),
            'overflow_deleted' => max(0, $overflowDeleted),
            'error_code' => $errorCode,
        ];

        update_option('spcrc_last_retention_run', ['at' => gmdate('c')] + $result, false);

        if ($this->audit !== null) {
            $recorded = $this->audit->record(
                'security_event_retention_' . $status,
                'file-24-security-center',
                $status,
                $status === 'failed' ? 'high' : ($status === 'locked' ? 'low' : 'informational'),
                $result
            );
            if (is_wp_error($recorded)) {
                AuditGapStore::record(
                    'spcrc_retention_audit_gap',
                    'retention_run',
                    gmdate('YmdHis'),
                    'audit_write_failed',
                    ['status' => $status, 'error_code' => $errorCode]
                );
            }
        }

        do_action('spcrc/retention_result', $result);
        do_action('spcrc/retention_' . $status, $result);

        return $result;
    }

    private function boolean(mixed $value): bool
    {
        if (is_bool($value)) {
            return $value;
        }
        return filter_var($value, FILTER_VALIDATE_BOOLEAN);
    }
}
