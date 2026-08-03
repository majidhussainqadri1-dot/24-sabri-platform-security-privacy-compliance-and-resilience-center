<?php

declare(strict_types=1);

namespace Sabri\Platform\Security;

use Sabri\Platform\Security\Privacy\RecoveryManager;
use Sabri\Platform\Security\Retention\RetentionManager;
use Sabri\Platform\Security\Storage\Schema;
use Sabri\Platform\Security\Support\AtomicOptionLock;

if (! class_exists(AtomicOptionLock::class, false)) {
    require_once __DIR__ . '/Support/AtomicOptionLock.php';
}

final class UpgradeManager
{
    private const LOCK_OPTION = 'spcrc_upgrade_lock';
    private const LOCK_TTL = 120;

    /** @return bool|\WP_Error */
    public static function maybeUpgrade(): bool|\WP_Error
    {
        $installedSchema = (string) get_option('spcrc_schema_version', '');
        $installedPlugin = (string) get_option('spcrc_version', '');
        foreach (['schema' => $installedSchema, 'plugin' => $installedPlugin] as $kind => $version) {
            if ($version !== '' && preg_match('/^\d+\.\d+\.\d+(?:\.\d+)?$/', $version) !== 1) {
                $error = new \WP_Error('spcrc_installed_version_invalid', sprintf('Installed File 24 %s version state is malformed.', $kind));
                self::fail($error, $installedSchema);
                return $error;
            }
        }

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
        if (is_wp_error($lockToken)) {
            $contended = in_array($lockToken->get_error_code(), ['spcrc_atomic_lock_contended'], true);
            $error = new \WP_Error(
                $contended ? 'spcrc_upgrade_locked' : 'spcrc_upgrade_lock_unavailable',
                $contended
                    ? 'Another File 24 upgrade is already in progress. Runtime remains blocked until it completes.'
                    : 'The File 24 upgrade lock could not be verified or acquired safely.'
            );
            if ($contended) {
                do_action('spcrc/upgrade_lock_contended', $installedSchema, Schema::VERSION);
            } else {
                self::fail($error, $installedSchema);
            }
            return $error;
        }

        try {
            if (! self::refreshLock($lockToken)) {
                $error = new \WP_Error('spcrc_upgrade_lock_lost', 'File 24 upgrade lock ownership was lost before schema installation.');
                self::fail($error, $installedSchema);
                return $error;
            }
            $installed = Schema::install();
            if (is_wp_error($installed)) {
                self::fail($installed, $installedSchema);
                return $installed;
            }

            if (! self::refreshLock($lockToken)) {
                $error = new \WP_Error('spcrc_upgrade_lock_lost', 'File 24 upgrade lock ownership was lost after schema installation.');
                self::fail($error, $installedSchema);
                return $error;
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
        $capabilitiesInstalled = Capabilities::install();
        if ($capabilitiesInstalled === false) {
            $error = new \WP_Error('spcrc_capability_install_failed', 'Required File 24 capabilities could not be installed and verified.');
            self::fail($error, $installedSchema);
            return $error;
        }
        $retentionExisted = function_exists('wp_next_scheduled') && (bool) wp_next_scheduled(RetentionManager::CRON_HOOK);
        $recoveryExisted = function_exists('wp_next_scheduled') && (bool) wp_next_scheduled(RecoveryManager::EVENT);
        if (! RetentionManager::ensureScheduled()) {
            $error = new \WP_Error(
                'spcrc_retention_schedule_failed',
                'Required retention schedule could not be verified.'
            );
            self::cleanupNewSchedules($retentionExisted, $recoveryExisted);
            self::fail($error, $installedSchema);
            return $error;
        }
        if (! RecoveryManager::ensureScheduled()) {
            $error = new \WP_Error(
                'spcrc_privacy_recovery_schedule_failed',
                'Required privacy recovery schedule could not be verified.'
            );
            self::cleanupNewSchedules($retentionExisted, $recoveryExisted);
            self::fail($error, $installedSchema);
            return $error;
        }

        return true;
    }

    /** @return string|\WP_Error */
    private static function acquireLock(): string|\WP_Error
    {
        return AtomicOptionLock::acquire(self::LOCK_OPTION, self::LOCK_TTL);
    }


    private static function refreshLock(string $token): bool
    {
        return AtomicOptionLock::refresh(self::LOCK_OPTION, $token, self::LOCK_TTL);
    }

    private static function cleanupNewSchedules(bool $retentionExisted, bool $recoveryExisted): void
    {
        if (! $retentionExisted && method_exists(RetentionManager::class, 'unschedule')) {
            RetentionManager::unschedule();
        }
        if (! $recoveryExisted && method_exists(RecoveryManager::class, 'unschedule')) {
            RecoveryManager::unschedule();
        }
    }

    private static function releaseLock(string $token): void
    {
        if (! AtomicOptionLock::release(self::LOCK_OPTION, $token)) {
            do_action('spcrc/upgrade_lock_release_failed', $token);
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
        $failure = ['at' => gmdate('c')] + $details;
        $updated = update_option('spcrc_last_upgrade_error', $failure, false);
        if (! $updated && get_option('spcrc_last_upgrade_error', null) !== $failure) {
            do_action('spcrc/upgrade_failure_evidence_unavailable', $failure);
        }
    }
}
