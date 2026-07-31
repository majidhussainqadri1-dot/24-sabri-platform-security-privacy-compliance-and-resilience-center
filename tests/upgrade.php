<?php

declare(strict_types=1);

namespace {
    define('SPCRC_VERSION', '0.25.3');
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
        public const VERSION = '0.25.2';
        public static true|\WP_Error $result = true;
        public static function install(): true|\WP_Error { return self::$result; }
    }
}

namespace Sabri\Platform\Security\Retention {
    final class RetentionManager
    {
        public static int $scheduleCalls = 0;
        public static function ensureScheduled(): bool { ++self::$scheduleCalls; return true; }
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
    UpgradeManager::maybeUpgrade();
    expectUpgrade(get_option('spcrc_version', '') === '', 'Failed schema install must not advance plugin version.');
    expectUpgrade(get_option('spcrc_schema_version', '') === '', 'Failed schema install must not advance schema version.');
    $failure = get_option('spcrc_last_upgrade_error', []);
    expectUpgrade(($failure['error_code'] ?? '') === 'spcrc_schema_install_failed', 'Upgrade failure code must be retained.');
    expectUpgrade(Capabilities::$installCalls === 0 && RetentionManager::$scheduleCalls === 0, 'Failed upgrade must not apply capabilities or schedules.');

    Schema::$result = true;
    UpgradeManager::maybeUpgrade();
    expectUpgrade(get_option('spcrc_version', '') === SPCRC_VERSION, 'Successful upgrade must store plugin version.');
    expectUpgrade(get_option('spcrc_schema_version', '') === Schema::VERSION, 'Successful upgrade must store schema version.');
    expectUpgrade(Capabilities::$installCalls === 1 && RetentionManager::$scheduleCalls === 1, 'Successful upgrade must apply capabilities and retention schedule.');
    expectUpgrade(get_option('spcrc_last_upgrade_error', null) === null, 'Successful upgrade must clear prior failure evidence.');

    $GLOBALS['options']['spcrc_version'] = '0.25.2';
    $GLOBALS['options']['spcrc_schema_version'] = Schema::VERSION;
    Capabilities::$installCalls = 0;
    RetentionManager::$scheduleCalls = 0;
    UpgradeManager::maybeUpgrade();
    expectUpgrade(get_option('spcrc_version', '') === '0.25.3', 'Code-only patch must advance plugin version without inventing a schema revision.');
    expectUpgrade(get_option('spcrc_schema_version', '') === '0.25.2', 'Code-only patch must preserve the existing schema version.');
    expectUpgrade(Capabilities::$installCalls === 1 && RetentionManager::$scheduleCalls === 1, 'Code-only patch must reapply capabilities and schedules after integrity verification.');

    echo "PASS: upgrade failure integrity and code-only version separation\n";
}
