<?php

declare(strict_types=1);

namespace {
    const ABSPATH = '/tmp/file24-activation/';
    const SPCRC_PLUGIN_FILE = __FILE__;
    const SPCRC_VERSION = '0.27.0';
    @mkdir(ABSPATH . 'wp-admin/includes', 0777, true);
    file_put_contents(ABSPATH . 'wp-admin/includes/plugin.php', "<?php\n");

    $GLOBALS['wp_version'] = '7.0.1';
    $GLOBALS['activation_options'] = [];
    $GLOBALS['activation_deactivated'] = false;

    final class WP_Error
    {
        public function __construct(private string $code, private string $message) {}
        public function get_error_code(): string { return $this->code; }
        public function get_error_message(): string { return $this->message; }
    }
    final class ActivationAbort extends \RuntimeException {}

    function __ (string $text, string $domain = ''): string { return $text; }
    function esc_html(string $text): string { return $text; }
    function plugin_basename(string $file): string { return basename($file); }
    function deactivate_plugins(string $file): void { $GLOBALS['activation_deactivated'] = true; }
    function wp_die(string $message): void { throw new ActivationAbort($message); }
    function is_wp_error(mixed $value): bool { return $value instanceof WP_Error; }
    function update_option(string $key, mixed $value, bool $autoload = true): bool { $GLOBALS['activation_options'][$key] = $value; return true; }
    function get_option(string $key, mixed $default = false): mixed { return $GLOBALS['activation_options'][$key] ?? $default; }
    function delete_option(string $key): bool { unset($GLOBALS['activation_options'][$key]); return true; }
}

namespace Sabri\Platform\Security\Storage {
    final class Schema
    {
        public const VERSION = '0.25.5';
        public static bool|\WP_Error $result = true;
        public static function install(): bool|\WP_Error { return self::$result; }
    }
}

namespace Sabri\Platform\Security\Retention {
    final class RetentionManager
    {
        public static bool $result = true;
        public static int $unscheduleCalls = 0;
        public static function ensureScheduled(): bool { return self::$result; }
        public static function unschedule(): void { ++self::$unscheduleCalls; }
    }
}

namespace Sabri\Platform\Security\Privacy {
    final class RecoveryManager
    {
        public static bool $result = true;
        public static int $unscheduleCalls = 0;
        public static function ensureScheduled(): bool { return self::$result; }
        public static function unschedule(): void { ++self::$unscheduleCalls; }
    }
}

namespace Sabri\Platform\Security {
    final class Capabilities { public static function install(): void {} }

    require_once dirname(__DIR__) . '/plugin/sabri-security-center/src/Activation.php';

    use Sabri\Platform\Security\Privacy\RecoveryManager;
    use Sabri\Platform\Security\Retention\RetentionManager;

    function expectActivation(bool $condition, string $message): void
    {
        if (! $condition) { fwrite(STDERR, "FAIL: {$message}\n"); exit(1); }
    }

    RetentionManager::$result = false;
    try { Activation::activate(); } catch (\ActivationAbort $e) {}
    expectActivation(($GLOBALS['activation_options']['spcrc_last_upgrade_error']['error_code'] ?? '') === 'spcrc_retention_schedule_failed', 'Retention schedule failure must be durably recorded.');
    expectActivation($GLOBALS['activation_deactivated'] === true, 'Failed activation must deactivate the plugin.');
    expectActivation(! isset($GLOBALS['activation_options']['spcrc_version']), 'Failed activation must not claim plugin version success.');

    $GLOBALS['activation_options'] = [];
    $GLOBALS['activation_deactivated'] = false;
    RetentionManager::$result = true;
    RecoveryManager::$result = false;
    try { Activation::activate(); } catch (\ActivationAbort $e) {}
    expectActivation(($GLOBALS['activation_options']['spcrc_last_upgrade_error']['error_code'] ?? '') === 'spcrc_privacy_recovery_schedule_failed', 'Privacy recovery schedule failure must block activation.');
    expectActivation(! isset($GLOBALS['activation_options']['spcrc_schema_version']), 'Recovery schedule failure must not claim schema version success.');
    expectActivation(RetentionManager::$unscheduleCalls > 0 && RecoveryManager::$unscheduleCalls > 0, 'Failed activation must remove any partially created schedules.');

    $GLOBALS['activation_options'] = [];
    $GLOBALS['activation_deactivated'] = false;
    RecoveryManager::$result = true;
    Activation::activate();
    expectActivation(($GLOBALS['activation_options']['spcrc_version'] ?? '') === '0.27.0', 'Successful activation must persist plugin version.');
    expectActivation(($GLOBALS['activation_options']['spcrc_schema_version'] ?? '') === '0.25.5', 'Successful activation must persist schema version.');
    expectActivation(! isset($GLOBALS['activation_options']['spcrc_last_upgrade_error']), 'Successful activation must clear prior failure evidence.');

    echo "PASS: activation fail-closed schedule and version-state contracts\n";
}
