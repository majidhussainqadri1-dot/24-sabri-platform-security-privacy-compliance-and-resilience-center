<?php

declare(strict_types=1);

namespace Sabri\Platform\Security\Privacy;

use Sabri\Platform\Security\Storage\AuditGapStore;
use Sabri\Platform\Security\Storage\AuditLogger;
use Sabri\Platform\Security\Storage\PrivacyRequestRepository;
use Sabri\Platform\Security\Support\AtomicOptionLock;
use Sabri\Platform\Security\Support\Sanitizer;

if (! class_exists(AuditGapStore::class, false)) {
    require_once dirname(__DIR__) . '/Storage/AuditGapStore.php';
}

final class RecoveryManager
{
    public const EVENT = 'spcrc_privacy_recovery_scan';
    private const LOCK_OPTION = 'spcrc_privacy_recovery_scan_lock';
    private const LOCK_TTL = 300;

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
        $next = wp_next_scheduled(self::EVENT);
        if ($next) {
            return self::scheduleValid($next, 'hourly');
        }

        $scheduled = wp_schedule_event(time() + 300, 'hourly', self::EVENT);
        return ! is_wp_error($scheduled) && $scheduled !== false
            && self::scheduleValid(wp_next_scheduled(self::EVENT), 'hourly');
    }


    private static function scheduleValid(mixed $next, string $recurrence): bool
    {
        if (! is_numeric($next) || (int) $next <= time() || (int) $next > time() + (2 * HOUR_IN_SECONDS)) {
            return false;
        }
        if (function_exists('wp_get_scheduled_event')) {
            $event = wp_get_scheduled_event(self::EVENT);
            return is_object($event) && (string) ($event->schedule ?? '') === $recurrence;
        }
        return true;
    }

    public static function unschedule(): void
    {
        if (function_exists('wp_clear_scheduled_hook')) {
            wp_clear_scheduled_hook(self::EVENT);
        }
    }

    public function scan(): void
    {
        $lock = AtomicOptionLock::acquire(self::LOCK_OPTION, self::LOCK_TTL);
        if (is_wp_error($lock)) {
            $this->recordAudit('privacy_recovery_scan_locked', 'file-24-security-center', 'locked', 'low', ['error_code' => $lock->get_error_code()]);
            return;
        }
        try {
        $age = (int) apply_filters('spcrc/privacy_stale_dispatch_age', 900);
        $limit = (int) apply_filters('spcrc/privacy_stale_dispatch_limit', 100);
        $marked = $this->requests->markStaleDispatching($age, $limit);

        if (is_wp_error($marked)) {
            $this->recordAudit(
                'privacy_recovery_scan_failed',
                'file-24-security-center',
                'failed',
                'high',
                ['error_code' => $marked->get_error_code()]
            );
            do_action('spcrc/privacy_recovery_scan_failed', $marked);
            return;
        }

        $this->recordAudit(
            'privacy_recovery_scan_completed',
            'file-24-security-center',
            'completed',
            $marked > 0 ? 'medium' : 'informational',
            ['stale_requests_marked' => $marked]
        );
        do_action('spcrc/privacy_recovery_scan_completed', $marked);
        } finally {
            if (! AtomicOptionLock::release(self::LOCK_OPTION, $lock)) {
                do_action('spcrc/privacy_recovery_lock_release_failed', $lock);
            }
        }
    }
    /** @param array<string,mixed> $context */
    private function recordAudit(string $event, string $module, string $result, string $risk, array $context): void
    {
        $recorded = $this->audit->record($event, $module, $result, $risk, $context);
        if (is_wp_error($recorded)) {
            AuditGapStore::record(
                'spcrc_privacy_recovery_audit_gap',
                'recovery_scan',
                Sanitizer::key($event, 120),
                'audit_write_failed',
                ['event_type' => $event]
            );
        }
    }

}
