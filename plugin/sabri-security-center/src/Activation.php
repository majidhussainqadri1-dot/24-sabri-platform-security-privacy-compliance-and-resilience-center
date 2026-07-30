<?php

declare(strict_types=1);

namespace Sabri\Platform\Security;

use Sabri\Platform\Security\Storage\Retention;
use Sabri\Platform\Security\Storage\Schema;

final class Activation
{
    public static function activate(bool $networkWide = false): void
    {
        if ($networkWide && is_multisite()) {
            wp_die(esc_html__('Network-wide activation is not supported in this foundation release. Activate the plugin on the intended site only.', 'sabri-security-center'));
        }

        if (version_compare(PHP_VERSION, '8.0', '<')) {
            deactivate_plugins(plugin_basename(SPCRC_PLUGIN_FILE));
            wp_die(esc_html__('Sabri Security Center requires PHP 8.0 or newer.', 'sabri-security-center'));
        }

        if (version_compare((string) get_bloginfo('version'), '6.5', '<')) {
            deactivate_plugins(plugin_basename(SPCRC_PLUGIN_FILE));
            wp_die(esc_html__('Sabri Security Center requires WordPress 6.5 or newer.', 'sabri-security-center'));
        }

        if (! Schema::install()) {
            deactivate_plugins(plugin_basename(SPCRC_PLUGIN_FILE));
            wp_die(esc_html__('Sabri Security Center could not verify its database schema. No production use is permitted.', 'sabri-security-center'));
        }

        Capabilities::install();
        Retention::schedule();

        update_option('spcrc_version', SPCRC_VERSION, false);
        update_option('spcrc_schema_version', Schema::VERSION, false);
        add_option('spcrc_installed_at', gmdate('c'), '', false);
        update_option('spcrc_last_activated_at', gmdate('c'), false);
    }
}
