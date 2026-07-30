<?php

declare(strict_types=1);

namespace Sabri\Platform\Security;

use Sabri\Platform\Security\Storage\Schema;

final class UpgradeManager
{
    private const LOCK = 'spcrc_schema_upgrade_lock';

    public static function maybeUpgrade(): void
    {
        $installedSchema = (string) get_option('spcrc_schema_version', '');
        $installedPlugin = (string) get_option('spcrc_version', '');

        if ($installedSchema === Schema::VERSION && $installedPlugin === SPCRC_VERSION) {
            return;
        }

        if (get_transient(self::LOCK)) {
            return;
        }

        set_transient(self::LOCK, 1, 5 * MINUTE_IN_SECONDS);

        try {
            if ($installedSchema !== Schema::VERSION) {
                $result = Schema::install();
                if (is_wp_error($result)) {
                    update_option('spcrc_last_upgrade_error', $result->get_error_message(), false);
                    do_action('spcrc/upgrade_failed', $installedSchema, Schema::VERSION, $result);
                    return;
                }

                update_option('spcrc_schema_version', Schema::VERSION, false);
            }

            update_option('spcrc_version', SPCRC_VERSION, false);
            update_option('spcrc_last_upgraded_at', gmdate('c'), false);
            delete_option('spcrc_last_upgrade_error');

            do_action('spcrc/upgraded', $installedSchema, Schema::VERSION, $installedPlugin, SPCRC_VERSION);
        } finally {
            delete_transient(self::LOCK);
        }
    }
}
