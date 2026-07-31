<?php

declare(strict_types=1);

namespace Sabri\Platform\Security\Privacy;

use Sabri\Platform\Security\Storage\AuditLogger;
use Sabri\Platform\Security\Storage\PrivacyRequestRepository;

final class RecoveryManager
{
    public const EVENT = 'spcrc_privacy_recovery_scan';

    public function __construct(
        private PrivacyRequestRepository $requests,
        private AuditLogger $audit
    ) {
    }

    public function registerHooks(): void
    {
        add_action('init', [self::class, 'ensureScheduled'], 20);
        add_action(self::EVENT, [$this, 'scan']);
    }

    public static function ensureScheduled(): bool
    {
        if (! function_exists('wp_next_scheduled') || ! function_exists('wp_schedule_event')) {
            return false;
        }
        if (wp_next_scheduled(self::EVENT)) {
            return true;
        }

        return wp_schedule_event(time() + 300, 'hourly', self::EVENT) !== false;
    }

    public static function unschedule(): void
    {
        if (function_exists('wp_clear_scheduled_hook')) {
            wp_clear_scheduled_hook(self::EVENT);
        }
    }

    public function scan(): void
    {
        $age = (int) apply_filters('spcrc/privacy_stale_dispatch_age', 900);
        $limit = (int) apply_filters('spcrc/privacy_stale_dispatch_limit', 100);
        $marked = $this->requests->markStaleDispatching($age, $limit);

        if (is_wp_error($marked)) {
            $this->audit->record(
                'privacy_recovery_scan_failed',
                'file-24-security-center',
                'failed',
                'high',
                ['error_code' => $marked->get_error_code()]
            );
            do_action('spcrc/privacy_recovery_scan_failed', $marked);
            return;
        }

        $this->audit->record(
            'privacy_recovery_scan_completed',
            'file-24-security-center',
            'completed',
            $marked > 0 ? 'medium' : 'informational',
            ['stale_requests_marked' => $marked]
        );
        do_action('spcrc/privacy_recovery_scan_completed', $marked);
    }
}
