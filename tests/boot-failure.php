<?php

declare(strict_types=1);

namespace {
    define('SPCRC_PLUGIN_FILE', __FILE__);
    $GLOBALS['boot_hooks'] = [];
    $GLOBALS['boot_actions'] = [];

    final class WP_Error
    {
        public function __construct(private string $code, private string $message) {}
        public function get_error_code(): string { return $this->code; }
        public function get_error_message(): string { return $this->message; }
    }

    function load_plugin_textdomain(string $domain, bool $deprecated = false, string $path = ''): bool { return true; }
    function plugin_basename(string $file): string { return basename($file); }
    function is_wp_error(mixed $value): bool { return $value instanceof WP_Error; }
    function add_action(string $hook, callable $callback, int $priority = 10, int $acceptedArgs = 1): void
    {
        $GLOBALS['boot_hooks'][$hook][] = [$callback, $priority, $acceptedArgs];
    }
    function do_action(string $hook, mixed ...$args): void { $GLOBALS['boot_actions'][] = [$hook, $args]; }
    function current_user_can(string $capability): bool { return $capability === 'activate_plugins'; }
    function esc_html_e(string $text, string $domain = 'default'): void { echo htmlspecialchars($text, ENT_QUOTES, 'UTF-8'); }
}

namespace Sabri\Platform\Security {
    final class UpgradeManager
    {
        public static int $calls = 0;
        public static function maybeUpgrade(): \WP_Error
        {
            ++self::$calls;
            return new \WP_Error('spcrc_schema_install_failed', 'Schema failed.');
        }
    }

    require_once dirname(__DIR__) . '/plugin/sabri-security-center/src/Plugin.php';

    function expectBootFailure(bool $condition, string $message): void
    {
        if (! $condition) { fwrite(STDERR, "FAIL: {$message}\n"); exit(1); }
    }

    Plugin::instance()->boot();
    expectBootFailure(UpgradeManager::$calls === 1, 'Plugin boot must evaluate upgrade integrity exactly once.');
    expectBootFailure(isset($GLOBALS['boot_hooks']['admin_notices']), 'Blocked boot must register a privileged administrator notice.');

    $actions = array_column($GLOBALS['boot_actions'], 0);
    expectBootFailure(in_array('spcrc/boot_blocked', $actions, true), 'Upgrade failure must emit a boot-blocked event.');
    expectBootFailure(! in_array('spcrc/booted', $actions, true), 'Upgrade failure must never emit the normal boot-complete event.');
    expectBootFailure(! isset($GLOBALS['boot_hooks']['init']), 'No operational File 24 service hook may be registered after upgrade failure.');

    ob_start();
    ($GLOBALS['boot_hooks']['admin_notices'][0][0])();
    $notice = (string) ob_get_clean();
    expectBootFailure(str_contains($notice, 'did not start'), 'Administrator notice must state that File 24 did not start.');
    expectBootFailure(! str_contains($notice, 'Schema failed.'), 'Administrator notice must not disclose internal exception or database details.');

    echo "PASS: upgrade failure blocks all File 24 runtime services\n";
}
