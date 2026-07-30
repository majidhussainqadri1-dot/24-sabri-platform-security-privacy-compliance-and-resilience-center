<?php

declare(strict_types=1);

const HOUR_IN_SECONDS = 3600;
const DAY_IN_SECONDS = 86400;
$GLOBALS['scheduled'] = [];
$GLOBALS['options'] = [];

function add_action(string $hook, callable $callback, int $priority = 10): void {}
function apply_filters(string $hook, mixed $value): mixed { return $value; }
function wp_next_scheduled(string $hook): int|false { return $GLOBALS['scheduled'][$hook] ?? false; }
function wp_schedule_event(int $timestamp, string $recurrence, string $hook): bool { $GLOBALS['scheduled'][$hook] = $timestamp; return true; }
function wp_clear_scheduled_hook(string $hook): int { unset($GLOBALS['scheduled'][$hook]); return 1; }
function update_option(string $key, mixed $value, bool $autoload = true): bool { $GLOBALS['options'][$key] = $value; return true; }
function do_action(string $hook, mixed ...$args): void {}

final class RetentionWpdb
{
    public string $prefix = 'wp_';
    public function prepare(string $query, mixed ...$args): string { return vsprintf(str_replace(['%s', '%d'], ["'%s'", '%d'], $query), $args); }
    public function query(string $query): int { return 0; }
    public function get_var(string $query): int { return 0; }
}
$GLOBALS['wpdb'] = new RetentionWpdb();

require_once dirname(__DIR__) . '/plugin/sabri-security-center/src/Retention/RetentionManager.php';

use Sabri\Platform\Security\Retention\RetentionManager;

RetentionManager::ensureScheduled();
if (! wp_next_scheduled(RetentionManager::CRON_HOOK)) {
    fwrite(STDERR, "Retention schedule was not created.\n");
    exit(1);
}
RetentionManager::unschedule();
if (wp_next_scheduled(RetentionManager::CRON_HOOK)) {
    fwrite(STDERR, "Retention schedule was not cleared.\n");
    exit(1);
}

echo "PASS: bounded retention lifecycle\n";
