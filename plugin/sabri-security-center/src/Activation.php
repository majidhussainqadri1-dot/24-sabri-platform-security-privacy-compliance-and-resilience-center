<?php

declare(strict_types=1);

namespace Sabri\Platform\Security;

use Sabri\Platform\Security\Retention\RetentionManager;
use Sabri\Platform\Security\Storage\Schema;

final class Activation
{
    public static function activate(): void
    {
        global $wp_version;

        if (version_compare(PHP_VERSION, '8.0', '<')) {
            self::abort(__('Sabri Security Center requires PHP 8.0 or newer.', 'sabri-security-center'));
        }

        if (version_compare((string) $wp_version, '6.5', '<')) {
            self::abort(__('Sabri Security Center requires WordPress 6.5 or newer.', 'sabri-security-center'));
        }

        $installed = Schema::install();
        if (is_wp_error($installed)) {
            self::abort($installed->get_error_message());
        }

        Capabilities::install();
        RetentionManager::ensureScheduled();

        update_option('spcrc_version', SPCRC_VERSION, false);
        update_option('spcrc_schema_version', Schema::VERSION, false);
        if (get_option('spcrc_installed_at', '') === '') {
            update_option('spcrc_installed_at', gmdate('c'), false);
        }
        delete_option('spcrc_last_upgrade_error');
    }

    private static function abort(string $message): void
    {
        if (! function_exists('deactivate_plugins')) {
            require_once ABSPATH . 'wp-admin/includes/plugin.php';
        }

        deactivate_plugins(plugin_basename(SPCRC_PLUGIN_FILE));
        wp_die(esc_html($message));
    }
}
