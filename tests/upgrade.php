<?php

declare(strict_types=1);

namespace {
    define('SPCRC_VERSION', '0.25.6');
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
        public const VERSION = '0.25.4';
        public static true|\WP_Error $result = true;
        public static function install(): true|\WP_Error { return self::$result; }
        public static function verify(): true|\WP_Error { return self::$result; }
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

namespace Sabri\Platform\Security\Privacy {
    final class RecoveryManager
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

    use Sabri\Platform\Security\Privacy\RecoveryManager;
    use Sabri\Platform\Security\Retention\RetentionManager;
    use Sabri\Platform\Security\Storage\Schema;

    function expectUpgrade(bool $condition, string $message): void
    {
        if (! $condition) { fwrite(STDERR, "FAIL: {$message}\n"); exit(1); }
    }

    Schema::$result = new \WP_Error('spcrc_schema_install_failed', 'Required table missing.');
    $failed = UpgradeManager::maybeUpgrade();
    expectUpgrade(is_wp_error($failed) && $failed->get_error_code() === 'spcrc_schema_install_failed', 'Failed schema install must return a boot-blocking error.');
    expectUpgrade(get_option('spcrc_version', '') === '' && get_option('spcrc_schema_version', '') === '', 'Failed schema install must not advance versions.');
    expectUpgrade((get_option('spcrc_last_upgrade_error', [])['error_code'] ?? '') === 'spcrc_schema_install_failed', 'Upgrade failure code must be retained.');
    expectUpgrade(Capabilities::$installCalls === 0 && RetentionManager::$scheduleCalls === 0 && RecoveryManager::$scheduleCalls === 0, 'Failed schema install must not apply runtime integrity changes.');

    Schema::$result = true;
    $installed = UpgradeManager::maybeUpgrade();
    expectUpgrade($installed === true, 'Successful upgrade must return an explicit success contract.');
    expectUpgrade(get_option('spcrc_version', '') === SPCRC_VERSION && get_option('spcrc_schema_version', '') === Schema::VERSION, 'Successful upgrade must store plugin and schema versions.');
    expectUpgrade(Capabilities::$installCalls === 1 && RetentionManager::$scheduleCalls === 1 && RecoveryManager::$scheduleCalls === 1, 'Successful upgrade must apply capabilities and both required schedules.');
    expectUpgrade(get_option('spcrc_last_upgrade_error', null) === null, 'Successful upgrade must clear prior failure evidence.');

    $GLOBALS['options']['spcrc_version'] = '0.25.4';
    $GLOBALS['options']['spcrc_schema_version'] = '0.25.3';
    Capabilities::$installCalls = 0;
    RetentionManager::$scheduleCalls = 0;
    RecoveryManager::$scheduleCalls = 0;
    $migrated = UpgradeManager::maybeUpgrade();
    expectUpgrade($migrated === true, 'Assurance schema migration must return explicit success.');
    expectUpgrade(get_option('spcrc_version', '') === '0.25.6' && get_option('spcrc_schema_version', '') === '0.25.4', 'Corrective release must advance plugin and schema versions.');
    expectUpgrade(Capabilities::$installCalls === 1 && RetentionManager::$scheduleCalls === 1 && RecoveryManager::$scheduleCalls === 1, 'Migration must verify complete runtime integrity.');

    RetentionManager::$result = false;
    Capabilities::$installCalls = 0;
    RetentionManager::$scheduleCalls = 0;
    RecoveryManager::$scheduleCalls = 0;
    $retentionFailure = UpgradeManager::maybeUpgrade();
    expectUpgrade(is_wp_error($retentionFailure) && $retentionFailure->get_error_code() === 'spcrc_retention_schedule_failed', 'Retention schedule failure must block normal runtime boot.');
    expectUpgrade(Capabilities::$installCalls === 1 && RetentionManager::$scheduleCalls === 1 && RecoveryManager::$scheduleCalls === 0, 'Retention failure must stop before privacy-recovery scheduling.');
    expectUpgrade((get_option('spcrc_last_upgrade_error', [])['error_code'] ?? '') === 'spcrc_retention_schedule_failed', 'Retention schedule failure evidence must be durable.');

    RetentionManager::$result = true;
    RecoveryManager::$result = false;
    Capabilities::$installCalls = 0;
    RetentionManager::$scheduleCalls = 0;
    RecoveryManager::$scheduleCalls = 0;
    $recoveryFailure = UpgradeManager::maybeUpgrade();
    expectUpgrade(is_wp_error($recoveryFailure) && $recoveryFailure->get_error_code() === 'spcrc_privacy_recovery_schedule_failed', 'Privacy-recovery schedule failure must block normal runtime boot.');
    expectUpgrade(Capabilities::$installCalls === 1 && RetentionManager::$scheduleCalls === 1 && RecoveryManager::$scheduleCalls === 1, 'Privacy-recovery failure must occur after retention verification.');
    expectUpgrade((get_option('spcrc_last_upgrade_error', [])['error_code'] ?? '') === 'spcrc_privacy_recovery_schedule_failed', 'Privacy-recovery failure evidence must be durable.');

    RecoveryManager::$result = true;
    $recovered = UpgradeManager::maybeUpgrade();
    expectUpgrade($recovered === true && get_option('spcrc_last_upgrade_error', null) === null, 'Recovered same-version integrity must clear stale failure evidence.');

    echo "PASS: upgrade failure integrity, dual-schedule runtime blocking and assurance schema migration\n";
}
