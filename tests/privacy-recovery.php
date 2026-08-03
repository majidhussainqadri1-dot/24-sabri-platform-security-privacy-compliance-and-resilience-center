<?php

declare(strict_types=1);

namespace {
    if (! defined('HOUR_IN_SECONDS')) { define('HOUR_IN_SECONDS', 3600); }
    $GLOBALS['recovery_hooks'] = [];
    $GLOBALS['recovery_scheduled'] = false;
    $GLOBALS['recovery_recurrence'] = '';
    $GLOBALS['recovery_actions'] = [];

    final class WP_Error
    {
        public function __construct(private string $code, private string $message) {}
        public function get_error_code(): string { return $this->code; }
        public function get_error_message(): string { return $this->message; }
    }

    function add_action(string $hook, callable $callback, int $priority = 10, int $acceptedArgs = 1): void
    {
        $GLOBALS['recovery_hooks'][$hook][] = [$callback, $priority, $acceptedArgs];
    }
    function do_action(string $hook, mixed ...$args): void { $GLOBALS['recovery_actions'][] = [$hook, $args]; }
    function apply_filters(string $hook, mixed $value): mixed { return $value; }
    function wp_next_scheduled(string $hook): int|false
    {
        return $hook === 'spcrc_privacy_recovery_scan' && is_int($GLOBALS['recovery_scheduled'])
            ? $GLOBALS['recovery_scheduled']
            : false;
    }
    function wp_schedule_event(int $timestamp, string $recurrence, string $hook): bool
    {
        if ($hook !== 'spcrc_privacy_recovery_scan' || $recurrence !== 'hourly') {
            return false;
        }
        $GLOBALS['recovery_scheduled'] = $timestamp;
        $GLOBALS['recovery_recurrence'] = $recurrence;
        return true;
    }
    function wp_get_scheduled_event(string $hook): object|false
    {
        $next = wp_next_scheduled($hook);
        if ($next === false) {
            return false;
        }
        return (object) ['timestamp' => $next, 'schedule' => $GLOBALS['recovery_recurrence']];
    }
    function wp_clear_scheduled_hook(string $hook): int|false
    {
        $GLOBALS['recovery_scheduled'] = false;
        $GLOBALS['recovery_recurrence'] = '';
        return 1;
    }
    function is_wp_error(mixed $value): bool { return $value instanceof WP_Error; }
}

namespace Sabri\Platform\Security\Support {
    final class AtomicOptionLock
    {
        private static bool $owned = false;
        public static function acquire(string $optionName, int $ttl = 60): string|\WP_Error
        {
            if (self::$owned) {
                return new \WP_Error('spcrc_lock_unavailable', 'Lock unavailable.');
            }
            self::$owned = true;
            return str_repeat('a', 32);
        }
        public static function release(string $optionName, string $token): bool
        {
            self::$owned = false;
            return true;
        }
    }
}

namespace Sabri\Platform\Security\Storage {
    final class PrivacyRequestRepository
    {
        public int|\WP_Error $result = 0;
        public int $calls = 0;
        public function markStaleDispatching(int $age, int $limit): int|\WP_Error
        {
            ++$this->calls;
            return $this->result;
        }
    }

    final class AuditLogger
    {
        public array $events = [];
        public function record(string $type, string $module, string $result = 'recorded', string $risk = 'low', array $context = []): string
        {
            $this->events[] = compact('type', 'module', 'result', 'risk', 'context');
            return '00000000-0000-4000-8000-000000000001';
        }
    }
}

namespace Sabri\Platform\Security\Privacy {
    require_once dirname(__DIR__) . '/plugin/sabri-security-center/src/Privacy/RecoveryManager.php';

    use Sabri\Platform\Security\Storage\AuditLogger;
    use Sabri\Platform\Security\Storage\PrivacyRequestRepository;

    function expectRecovery(bool $condition, string $message): void
    {
        if (! $condition) { fwrite(STDERR, "FAIL: {$message}\n"); exit(1); }
    }

    $requests = new PrivacyRequestRepository();
    $audit = new AuditLogger();
    $manager = new RecoveryManager($requests, $audit);
    $manager->registerHooks();
    expectRecovery(isset($GLOBALS['recovery_hooks']['init']), 'Recovery schedule must be registered on init.');
    expectRecovery(isset($GLOBALS['recovery_hooks'][RecoveryManager::EVENT]), 'Recovery scan callback must be registered.');
    expectRecovery(RecoveryManager::ensureScheduled(), 'Hourly recovery scan must schedule successfully.');
    expectRecovery(is_int($GLOBALS['recovery_scheduled']) && $GLOBALS['recovery_scheduled'] > time(), 'Recovery schedule state must be visible.');

    $requests->result = 2;
    $manager->scan();
    expectRecovery($requests->calls === 1, 'Recovery scan must call stale-dispatch detection once.');
    expectRecovery(($audit->events[0]['context']['stale_requests_marked'] ?? 0) === 2, 'Recovery scan must audit the number of stale requests.');

    $requests->result = new \WP_Error('scan_failed', 'Scan failed.');
    $manager->scan();
    expectRecovery(($audit->events[1]['type'] ?? '') === 'privacy_recovery_scan_failed', 'Recovery scan failure must be audited.');

    RecoveryManager::unschedule();
    expectRecovery($GLOBALS['recovery_scheduled'] === false, 'Deactivation cleanup must remove recovery schedule.');

    echo "PASS: privacy recovery scheduling and failure evidence\n";
}
