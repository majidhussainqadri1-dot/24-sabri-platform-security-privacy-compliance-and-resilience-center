<?php

declare(strict_types=1);

namespace Sabri\Platform\Security;

use Sabri\Platform\Security\Storage\Schema;

final class Activation
{
    public static function activate(): void
    {
        if (version_compare(PHP_VERSION, '8.0', '<')) {
            deactivate_plugins(plugin_basename(SPCRC_PLUGIN_FILE));
            wp_die(esc_html__('Sabri Security Center requires PHP 8.0 or newer.', 'sabri-security-center'));
        }

        Schema::install();
        Capabilities::install();

        update_option('spcrc_version', SPCRC_VERSION, false);
        update_option('spcrc_schema_version', Schema::VERSION, false);
        update_option('spcrc_installed_at', gmdate('c'), false);
    }
}
