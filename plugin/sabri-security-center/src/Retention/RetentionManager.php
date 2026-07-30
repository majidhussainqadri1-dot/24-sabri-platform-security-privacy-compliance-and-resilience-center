<?php

declare(strict_types=1);

namespace Sabri\Platform\Security\Retention;

final class RetentionManager
{
    public const CRON_HOOK = 'spcrc_daily_retention';

    public function registerHooks(): void
    {
        add_action(self::CRON_HOOK, [$this, 'run']);
        add_action('init', [self::class, 'ensureScheduled'], 90);
    }

    public static function ensureScheduled(): void
    {
        if (! function_exists('wp_next_scheduled') || ! function_exists('wp_schedule_event')) {
            return;
        }
        if (! wp_next_scheduled(self::CRON_HOOK)) {
            wp_schedule_event(time() + HOUR_IN_SECONDS, 'daily', self::CRON_HOOK);
        }
    }

    public static function unschedule(): void
    {
        if (function_exists('wp_clear_scheduled_hook')) {
            wp_clear_scheduled_hook(self::CRON_HOOK);
        }
    }

    /** @return array<string,int> */
    public function run(): array
    {
        global $wpdb;
        $days = max(7, min(3650, (int) apply_filters('spcrc/security_event_retention_days', 90)));
        $maximum = max(1000, min(1000000, (int) apply_filters('spcrc/security_event_max_rows', 100000)));
        $batch = max(100, min(10000, (int) apply_filters('spcrc/security_event_retention_batch', 5000)));
        $table = $wpdb->prefix . 'spcrc_security_events';
        $cutoff = gmdate('Y-m-d H:i:s', time() - ($days * DAY_IN_SECONDS));

        $ageDeleted = $wpdb->query($wpdb->prepare(
            "DELETE FROM {$table} WHERE created_at < %s ORDER BY id ASC LIMIT %d",
            $cutoff,
            $batch
        ));
        $count = (int) $wpdb->get_var("SELECT COUNT(*) FROM {$table}");
        $overflowDeleted = 0;
        if ($count > $maximum) {
            $overflowDeleted = $wpdb->query($wpdb->prepare(
                "DELETE FROM {$table} ORDER BY id ASC LIMIT %d",
                min($batch, $count - $maximum)
            ));
        }

        $result = [
            'age_deleted' => is_int($ageDeleted) ? $ageDeleted : 0,
            'overflow_deleted' => is_int($overflowDeleted) ? $overflowDeleted : 0,
        ];
        update_option('spcrc_last_retention_run', ['at' => gmdate('c')] + $result, false);
        do_action('spcrc/retention_completed', $result);

        return $result;
    }
}
