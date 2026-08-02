<?php

declare(strict_types=1);

namespace Sabri\Platform\Security;

use Sabri\Platform\Security\Privacy\RecoveryManager;
use Sabri\Platform\Security\Retention\RetentionManager;
use Sabri\Platform\Security\Storage\Schema;

final class UpgradeManager
{
    private const LOCK_OPTION = 'spcrc_upgrade_lock';
    private const LOCK_TTL = 120;

    /** @return bool|\WP_Error */
    public static function maybeUpgrade(): bool|\WP_Error
    {
        $installedSchema = (string) get_option('spcrc_schema_version', '');
        $installedPlugin = (string) get_option('spcrc_version', '');

        if (
            ($installedSchema !== '' && version_compare($installedSchema, Schema::VERSION, '>'))
            || ($installedPlugin !== '' && version_compare($installedPlugin, SPCRC_VERSION, '>'))
        ) {
            $error = new \WP_Error(
                'spcrc_downgrade_blocked',
                'File 24 detected a newer installed version and refused an unsafe downgrade.'
            );
            self::fail($error, $installedSchema);
            return $error;
        }

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

        $lockToken = self::acquireLock();
        if ($lockToken === '') {
            $error = new \WP_Error(
                'spcrc_upgrade_locked',
                'Another File 24 upgrade is already in progress. Runtime remains blocked until it completes.'
            );
            do_action('spcrc/upgrade_lock_contended', $installedSchema, Schema::VERSION);
            return $error;
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
        } finally {
            self::releaseLock($lockToken);
        }
    }

    /** @return bool|\WP_Error */
    private static function ensureRuntimeIntegrity(string $installedSchema): bool|\WP_Error
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

    private static function acquireLock(): string
    {
        $now = time();
        $existing = get_option(self::LOCK_OPTION, []);
        if (is_array($existing) && (int) ($existing['expires_at'] ?? 0) <= $now) {
            delete_option(self::LOCK_OPTION);
        }

        $token = function_exists('wp_generate_uuid4') ? wp_generate_uuid4() : bin2hex(random_bytes(16));
        $added = add_option(
            self::LOCK_OPTION,
            ['token' => $token, 'expires_at' => $now + self::LOCK_TTL],
            '',
            false
        );
        return $added ? $token : '';
    }

    private static function releaseLock(string $token): void
    {
        $existing = get_option(self::LOCK_OPTION, []);
        if (is_array($existing) && hash_equals((string) ($existing['token'] ?? ''), $token)) {
            delete_option(self::LOCK_OPTION);
        }
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
