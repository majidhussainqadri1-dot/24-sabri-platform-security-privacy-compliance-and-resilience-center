<?php

declare(strict_types=1);

namespace Sabri\Platform\Security;

use Sabri\Platform\Security\Privacy\RecoveryManager;
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
            $schemaIntegrity = Schema::verify();
            if (is_wp_error($schemaIntegrity)) {
                self::fail($schemaIntegrity, $installedSchema);
                return $schemaIntegrity;
            }

            $integrity = self::ensureRuntimeIntegrity($installedSchema);
            if (is_wp_error($integrity)) {
                return $integrity;
            }
            delete_option('spcrc_last_upgrade_error');
            return true;
        }

        try {
            $installed = Schema::install();
            if (is_wp_error($installed)) {
                self::fail($installed, $installedSchema);
                return $installed;
            }

            $integrity = self::ensureRuntimeIntegrity($installedSchema);
            if (is_wp_error($integrity)) {
                return $integrity;
            }

            update_option('spcrc_schema_version', Schema::VERSION, false);
            update_option('spcrc_version', SPCRC_VERSION, false);
            if (
                (string) get_option('spcrc_schema_version', '') !== Schema::VERSION
                || (string) get_option('spcrc_version', '') !== SPCRC_VERSION
            ) {
                $error = new \WP_Error(
                    'spcrc_upgrade_version_state_failed',
                    'File 24 upgrade version state could not be verified.'
                );
                self::fail($error, $installedSchema);
                return $error;
            }

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

    /** @return true|\WP_Error */
    private static function ensureRuntimeIntegrity(string $installedSchema): true|\WP_Error
    {
        Capabilities::install();
        if (! RetentionManager::ensureScheduled()) {
            $error = new \WP_Error(
                'spcrc_retention_schedule_failed',
                'Required retention schedule could not be verified.'
            );
            self::fail($error, $installedSchema);
            return $error;
        }
        if (! RecoveryManager::ensureScheduled()) {
            $error = new \WP_Error(
                'spcrc_privacy_recovery_schedule_failed',
                'Required privacy recovery schedule could not be verified.'
            );
            self::fail($error, $installedSchema);
            return $error;
        }

        return true;
    }

    private static function fail(\WP_Error $error, string $installedSchema): void
    {
        self::recordFailure([
            'error_code' => $error->get_error_code(),
            'from_schema' => $installedSchema,
            'target_schema' => Schema::VERSION,
        ]);
        do_action('spcrc/upgrade_failed', $error, $installedSchema, Schema::VERSION);
    }

    /** @param array<string,mixed> $details */
    private static function recordFailure(array $details): void
    {
        update_option('spcrc_last_upgrade_error', ['at' => gmdate('c')] + $details, false);
    }
}
