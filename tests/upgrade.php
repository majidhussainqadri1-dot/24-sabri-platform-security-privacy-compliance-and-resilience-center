<?php

declare(strict_types=1);

namespace {
    define('SPCRC_VERSION', '0.25.4');
    $GLOBALS['options'] = [];
    $GLOBALS['actions'] = [];

    final class WP_Error
    {
        public function __construct(private string $code, private string $message) {}
        public function get_error_code(): string { return $this->code; }
        public function get_error_message(): string { return $this->message; }
    }

    function get_option(string $key, mixed $default = false): mixed { return $GLOBALS['options'][$key] ?? $default; }
    function update_option(string $key, mixed $value, bool $autoload = true): bool { $GLOBALS['options'][$key] = $value; return true; }
    function delete_option(string $key): bool { unset($GLOBALS['options'][$key]); return true; }
    function do_action(string $hook, mixed ...$args): void { $GLOBALS['actions'][] = [$hook, $args]; }
    function is_wp_error(mixed $value): bool { return $value instanceof WP_Error; }
}

namespace Sabri\Platform\Security\Storage {
    final class Schema
    {
        public const VERSION = '0.25.3';
        public static true|\WP_Error $result = true;
        public static function install(): true|\WP_Error { return self::$result; }
    }
}

namespace Sabri\Platform\Security\Retention {
    final class RetentionManager
    {
        public static int $scheduleCalls = 0;
        public static bool $result = true;
        public static function ensureScheduled(): bool { ++self::$scheduleCalls; return self::$result; }
    }
}

namespace Sabri\Platform\Security {
    final class Capabilities
    {
        public static int $installCalls = 0;
        public static function install(): void { ++self::$installCalls; }
    }

    require_once dirname(__DIR__) . '/plugin/sabri-security-center/src/UpgradeManager.php';

    use Sabri\Platform\Security\Retention\RetentionManager;
    use Sabri\Platform\Security\Storage\Schema;

    function expectUpgrade(bool $condition, string $message): void
    {
        if (! $condition) {
            fwrite(STDERR, "FAIL: {$message}\n");
            exit(1);
        }
    }

    Schema::$result = new \WP_Error('spcrc_schema_install_failed', 'Required table missing.');
    $failed = UpgradeManager::maybeUpgrade();
    expectUpgrade(is_wp_error($failed) && $failed->get_error_code() === 'spcrc_schema_install_failed', 'Failed schema install must return a boot-blocking error.');
    expectUpgrade(get_option('spcrc_version', '') === '', 'Failed schema install must not advance plugin version.');
    expectUpgrade(get_option('spcrc_schema_version', '') === '', 'Failed schema install must not advance schema version.');
    $failure = get_option('spcrc_last_upgrade_error', []);
    expectUpgrade(($failure['error_code'] ?? '') === 'spcrc_schema_install_failed', 'Upgrade failure code must be retained.');
    expectUpgrade(Capabilities::$installCalls === 0 && RetentionManager::$scheduleCalls === 0, 'Failed upgrade must not apply capabilities or schedules.');

    Schema::$result = true;
    $installed = UpgradeManager::maybeUpgrade();
    expectUpgrade($installed === true, 'Successful upgrade must return an explicit success contract.');
    expectUpgrade(get_option('spcrc_version', '') === SPCRC_VERSION, 'Successful upgrade must store plugin version.');
    expectUpgrade(get_option('spcrc_schema_version', '') === Schema::VERSION, 'Successful upgrade must store schema version.');
    expectUpgrade(Capabilities::$installCalls === 1 && RetentionManager::$scheduleCalls === 1, 'Successful upgrade must apply capabilities and retention schedule.');
    expectUpgrade(get_option('spcrc_last_upgrade_error', null) === null, 'Successful upgrade must clear prior failure evidence.');

    $GLOBALS['options']['spcrc_version'] = '0.25.3';
    $GLOBALS['options']['spcrc_schema_version'] = '0.25.2';
    Capabilities::$installCalls = 0;
    RetentionManager::$scheduleCalls = 0;
    $migrated = UpgradeManager::maybeUpgrade();
    expectUpgrade($migrated === true, 'Verified-privacy migration must return explicit success.');
    expectUpgrade(get_option('spcrc_version', '') === '0.25.4', 'Corrective release must advance the plugin version.');
    expectUpgrade(get_option('spcrc_schema_version', '') === '0.25.3', 'Verification-evidence migration must advance the schema version.');
    expectUpgrade(Capabilities::$installCalls === 1 && RetentionManager::$scheduleCalls === 1, 'Migration must reapply capabilities and schedules after integrity verification.');

    RetentionManager::$result = false;
    Capabilities::$installCalls = 0;
    RetentionManager::$scheduleCalls = 0;
    $scheduleFailure = UpgradeManager::maybeUpgrade();
    expectUpgrade(is_wp_error($scheduleFailure) && $scheduleFailure->get_error_code() === 'spcrc_retention_schedule_failed', 'Retention schedule failure must block normal runtime boot.');
    expectUpgrade(Capabilities::$installCalls === 1 && RetentionManager::$scheduleCalls === 1, 'Same-version integrity verification must check capabilities and retention schedule exactly once.');
    expectUpgrade((get_option('spcrc_last_upgrade_error', [])['error_code'] ?? '') === 'spcrc_retention_schedule_failed', 'Retention schedule failure evidence must be durable.');

    echo "PASS: upgrade failure integrity, runtime blocking and verified-privacy schema migration\n";
}
