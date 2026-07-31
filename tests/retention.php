<?php

declare(strict_types=1);

const HOUR_IN_SECONDS = 3600;
const DAY_IN_SECONDS = 86400;
$GLOBALS['scheduled'] = [];
$GLOBALS['options'] = [];
$GLOBALS['transients'] = [];
$GLOBALS['retention_hold'] = false;
$GLOBALS['retention_maximum'] = 1000;
$GLOBALS['retention_batch'] = 100;

function add_action(string $hook, callable $callback, int $priority = 10): void {}
function apply_filters(string $hook, mixed $value): mixed
{
    return match ($hook) {
        'spcrc/security_event_retention_hold' => $GLOBALS['retention_hold'],
        'spcrc/security_event_max_rows' => $GLOBALS['retention_maximum'],
        'spcrc/security_event_retention_batch' => $GLOBALS['retention_batch'],
        default => $value,
    };
}
function wp_next_scheduled(string $hook): int|false { return $GLOBALS['scheduled'][$hook] ?? false; }
function wp_schedule_event(int $timestamp, string $recurrence, string $hook): bool { $GLOBALS['scheduled'][$hook] = $timestamp; return true; }
function wp_clear_scheduled_hook(string $hook): int { unset($GLOBALS['scheduled'][$hook]); return 1; }
function update_option(string $key, mixed $value, bool $autoload = true): bool { $GLOBALS['options'][$key] = $value; return true; }
function get_transient(string $key): mixed { return $GLOBALS['transients'][$key] ?? false; }
function set_transient(string $key, mixed $value, int $expiration): bool { $GLOBALS['transients'][$key] = $value; return true; }
function delete_transient(string $key): bool { unset($GLOBALS['transients'][$key]); return true; }
function wp_generate_uuid4(): string { return '00000000-0000-4000-8000-000000000001'; }
function is_wp_error(mixed $value): bool { return false; }
function do_action(string $hook, mixed ...$args): void {}

final class RetentionWpdb
{
    public string $prefix = 'wp_';
    public bool $tableExists = true;
    public int $count = 1200;
    public array $queryResults = [3, 100];
    public array $queries = [];

    public function esc_like(string $value): string { return $value; }
    public function prepare(string $query, mixed ...$args): string
    {
        return vsprintf(str_replace(['%s', '%d'], ["'%s'", '%d'], $query), $args);
    }
    public function query(string $query): int|false
    {
        $this->queries[] = $query;
        return array_shift($this->queryResults) ?? 0;
    }
    public function get_var(string $query): mixed
    {
        if (str_starts_with($query, 'SHOW TABLES LIKE')) {
            return $this->tableExists ? $this->prefix . 'spcrc_security_events' : null;
        }
        if (str_contains($query, 'COUNT(*)')) {
            return $this->count;
        }
        return null;
    }
}
$GLOBALS['wpdb'] = new RetentionWpdb();

require_once dirname(__DIR__) . '/plugin/sabri-security-center/src/Retention/RetentionManager.php';

use Sabri\Platform\Security\Retention\RetentionManager;

function expectRetention(bool $condition, string $message): void
{
    if (! $condition) {
        fwrite(STDERR, "FAIL: {$message}\n");
        exit(1);
    }
}

expectRetention(RetentionManager::ensureScheduled(), 'Retention schedule must be created.');
expectRetention((bool) wp_next_scheduled(RetentionManager::CRON_HOOK), 'Retention schedule must be discoverable.');
RetentionManager::unschedule();
expectRetention(! wp_next_scheduled(RetentionManager::CRON_HOOK), 'Retention schedule must be cleared.');

$manager = new RetentionManager();
$result = $manager->run();
expectRetention($result['status'] === 'completed', 'Successful retention must report completed.');
expectRetention($result['age_deleted'] === 3 && $result['overflow_deleted'] === 100, 'Retention must report bounded delete counts.');
expectRetention(count($GLOBALS['wpdb']->queries) === 2, 'Age and overflow deletion must execute once each.');
expectRetention(get_transient('spcrc_retention_lock') === false, 'Retention lock must be released.');

$GLOBALS['retention_hold'] = 'true';
$before = count($GLOBALS['wpdb']->queries);
$held = $manager->run();
expectRetention($held['status'] === 'held', 'Retention hold must stop deletion.');
expectRetention(count($GLOBALS['wpdb']->queries) === $before, 'Retention hold must not execute delete queries.');
$GLOBALS['retention_hold'] = false;

set_transient('spcrc_retention_lock', 'another-run', 900);
$locked = $manager->run();
expectRetention($locked['status'] === 'locked', 'Concurrent retention must be skipped.');
delete_transient('spcrc_retention_lock');

$GLOBALS['wpdb']->tableExists = false;
$missing = $manager->run();
expectRetention($missing['status'] === 'failed' && $missing['error_code'] === 'events_table_unavailable', 'Missing event table must fail closed.');
expectRetention(get_transient('spcrc_retention_lock') === false, 'Failed retention must release its lock.');

echo "PASS: bounded retention lifecycle and failure controls\n";
