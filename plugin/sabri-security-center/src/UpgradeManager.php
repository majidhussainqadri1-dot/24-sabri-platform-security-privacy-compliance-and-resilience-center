<?php

declare(strict_types=1);

namespace Sabri\Platform\Security;

use Sabri\Platform\Security\Storage\Retention;
use Sabri\Platform\Security\Storage\Schema;

final class UpgradeManager
{
    private const LOCK_OPTION = 'spcrc_upgrade_lock';
    private const LOCK_TTL = 600;

    public static function maybeUpgrade(): bool
    {
        $installedSchema = (string) get_option('spcrc_schema_version', '');
        $installedVersion = (string) get_option('spcrc_version', '');

        if ($installedSchema !== '' && version_compare($installedSchema, Schema::VERSION, '>')) {
            update_option('spcrc_downgrade_blocked', [
                'installed_schema' => $installedSchema,
                'code_schema' => Schema::VERSION,
                'detected_at' => gmdate('c'),
            ], false);
            return false;
        }

        if ($installedSchema === Schema::VERSION && $installedVersion === SPCRC_VERSION) {
            if ((string) get_option('spcrc_capability_version', '') !== Capabilities::VERSION) {
                Capabilities::install();
            }
            Retention::schedule();
            return true;
        }

        if (! self::acquireLock()) {
            return false;
        }

        try {
            if (! Schema::install()) {
                update_option('spcrc_upgrade_failed', [
                    'from_schema' => $installedSchema,
                    'to_schema' => Schema::VERSION,
                    'failed_at' => gmdate('c'),
                ], false);
                return false;
            }

            Capabilities::install();
            Retention::schedule();
            delete_option('spcrc_upgrade_failed');
            delete_option('spcrc_downgrade_blocked');
            update_option('spcrc_schema_version', Schema::VERSION, false);
            update_option('spcrc_version', SPCRC_VERSION, false);
            update_option('spcrc_last_upgraded_at', gmdate('c'), false);

            do_action('spcrc/upgraded', $installedSchema, Schema::VERSION);
            return true;
        } finally {
            delete_option(self::LOCK_OPTION);
        }
    }

    public static function blockedNotice(): void
    {
        if (! current_user_can('activate_plugins')) {
            return;
        }

        $downgrade = get_option('spcrc_downgrade_blocked', []);
        $failed = get_option('spcrc_upgrade_failed', []);
        $message = is_array($downgrade) && $downgrade !== []
            ? __('Sabri Security Center runtime is paused because the installed database schema is newer than this plugin code. Restore the matching or newer code; do not downgrade the database.', 'sabri-security-center')
            : __('Sabri Security Center runtime is paused because its schema upgrade could not be verified. Review database permissions and the recorded upgrade failure before retrying.', 'sabri-security-center');

        if ($downgrade === [] && $failed === []) {
            $message = __('Sabri Security Center runtime is temporarily paused while another upgrade request holds the migration lock.', 'sabri-security-center');
        }

        echo '<div class="notice notice-error"><p>' . esc_html($message) . '</p></div>';
    }

    private static function acquireLock(): bool
    {
        $now = time();
        if (add_option(self::LOCK_OPTION, $now, '', false)) {
            return true;
        }

        $lockedAt = (int) get_option(self::LOCK_OPTION, 0);
        if ($lockedAt > 0 && ($now - $lockedAt) > self::LOCK_TTL) {
            delete_option(self::LOCK_OPTION);
            return add_option(self::LOCK_OPTION, $now, '', false);
        }

        return false;
    }
}
