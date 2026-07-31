<?php

declare(strict_types=1);

namespace {
    define('SPCRC_VERSION', '0.25.6');
    define('SPCRC_PLUGIN_FILE', __FILE__);
    define('SPCRC_PLUGIN_DIR', dirname(__DIR__) . '/plugin/sabri-security-center/');
    define('SPCRC_PLUGIN_URL', 'https://example.test/plugins/sabri-security-center/');
    define('MINUTE_IN_SECONDS', 60);
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
    function add_action(string $hook, callable $callback, int $priority = 10, int $acceptedArgs = 1): void { $GLOBALS['boot_hooks'][$hook][] = [$callback, $priority, $acceptedArgs]; }
    function add_filter(string $hook, callable $callback, int $priority = 10, int $acceptedArgs = 1): void { add_action($hook, $callback, $priority, $acceptedArgs); }
    function do_action(string $hook, mixed ...$args): void { $GLOBALS['boot_actions'][] = [$hook, $args]; }
    function is_wp_error(mixed $value): bool { return $value instanceof WP_Error; }
    function get_option(string $key, mixed $default = false): mixed { return $default; }
    function update_option(string $key, mixed $value, bool $autoload = true): bool { return true; }

    spl_autoload_register(static function (string $class): void {
        $prefix = 'Sabri\\Platform\\Security\\';
        if (! str_starts_with($class, $prefix)) return;
        $path = SPCRC_PLUGIN_DIR . 'src/' . str_replace('\\', '/', substr($class, strlen($prefix))) . '.php';
        if (is_readable($path)) require_once $path;
    });
}

namespace Sabri\Platform\Security {
    final class UpgradeManager
    {
        public static int $calls = 0;
        public static function maybeUpgrade(): true|\WP_Error { ++self::$calls; return true; }
    }

    require_once dirname(__DIR__) . '/plugin/sabri-security-center/src/Plugin.php';

    function expectBoot(bool $condition, string $message): void
    {
        if (! $condition) { fwrite(STDERR, "FAIL: {$message}\n"); exit(1); }
    }

    Plugin::instance()->boot();
    expectBoot(UpgradeManager::$calls === 1, 'Successful boot must verify upgrade integrity exactly once.');
    expectBoot(in_array('spcrc/booted', array_column($GLOBALS['boot_actions'], 0), true), 'Successful runtime must emit booted event.');
    expectBoot(isset($GLOBALS['boot_hooks']['admin_post_spcrc_upsert_assurance']), 'Assurance mutations must be registered only through the private admin-post workflow.');
    expectBoot(isset($GLOBALS['boot_hooks']['spcrc/backup_evidence']), 'Assurance repository must register its read-only backup evidence adapter.');
    expectBoot(isset($GLOBALS['boot_hooks']['admin_post_spcrc_run_repair']), 'Dashboard must own the non-destructive repair action.');

    echo "PASS: successful boot wires assurance and repair services without missing methods\n";
}
