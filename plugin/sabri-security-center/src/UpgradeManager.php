<?php

declare(strict_types=1);

namespace Sabri\Platform\Security;

use Sabri\Platform\Security\Retention\RetentionManager;
use Sabri\Platform\Security\Storage\Schema;

final class UpgradeManager
{
    /** @return true|\WP_Error */
    public static function maybeUpgrade(): true|\WP_Error
    {
        $installedSchema = (string) get_option('spcrc_schema_version', '');
        $installedPlugin = (string) get_option('spcrc_version', '');
        if ($installedSchema === Schema::VERSION && $installedPlugin === SPCRC_VERSION) {
            Capabilities::install();
            if (! RetentionManager::ensureScheduled()) {
                $error = new \WP_Error('spcrc_retention_schedule_failed', 'Required retention schedule could not be verified.');
                self::recordFailure([
                    'error_code' => $error->get_error_code(),
                    'from_schema' => $installedSchema,
                    'target_schema' => Schema::VERSION,
                ]);
                do_action('spcrc/upgrade_failed', $error, $installedSchema, Schema::VERSION);
                return $error;
            }
            return true;
        }

        try {
            $installed = Schema::install();
            if (is_wp_error($installed)) {
                self::recordFailure([
                    'error_code' => $installed->get_error_code(),
                    'from_schema' => $installedSchema,
                    'target_schema' => Schema::VERSION,
                ]);
                do_action('spcrc/upgrade_failed', $installed, $installedSchema, Schema::VERSION);
                return $installed;
            }

            Capabilities::install();
            if (! RetentionManager::ensureScheduled()) {
                $error = new \WP_Error('spcrc_retention_schedule_failed', 'Required retention schedule could not be established.');
                self::recordFailure([
                    'error_code' => $error->get_error_code(),
                    'from_schema' => $installedSchema,
                    'target_schema' => Schema::VERSION,
                ]);
                do_action('spcrc/upgrade_failed', $error, $installedSchema, Schema::VERSION);
                return $error;
            }

            update_option('spcrc_schema_version', Schema::VERSION, false);
            update_option('spcrc_version', SPCRC_VERSION, false);
            update_option('spcrc_last_upgraded_at', gmdate('c'), false);
            delete_option('spcrc_last_upgrade_error');
            do_action('spcrc/upgraded', $installedSchema, Schema::VERSION, $installedPlugin, SPCRC_VERSION);
            return true;
        } catch (\Throwable $exception) {
            $error = new \WP_Error('spcrc_upgrade_exception', 'File 24 upgrade failed unexpectedly.');
            self::recordFailure([
                'error_code' => $error->get_error_code(),
                'exception_class' => get_class($exception),
                'from_schema' => $installedSchema,
                'target_schema' => Schema::VERSION,
            ]);
            do_action('spcrc/upgrade_failed', $exception, $installedSchema, Schema::VERSION);
            return $error;
        }
    }

    /** @param array<string,string> $details */
    private static function recordFailure(array $details): void
    {
        update_option('spcrc_last_upgrade_error', ['at' => gmdate('c')] + $details, false);
    }
}
