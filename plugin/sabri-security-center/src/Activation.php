<?php

declare(strict_types=1);

namespace Sabri\Platform\Security;

use Sabri\Platform\Security\Privacy\RecoveryManager;
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
            self::recordFailure($installed->get_error_code(), '', Schema::VERSION);
            self::abort($installed->get_error_message());
        }

        Capabilities::install();
        if (! RetentionManager::ensureScheduled()) {
            self::cleanupSchedules();
            self::recordFailure('spcrc_retention_schedule_failed', Schema::VERSION, Schema::VERSION);
            self::abort(__('Required File 24 retention schedule could not be established.', 'sabri-security-center'));
        }
        if (! RecoveryManager::ensureScheduled()) {
            self::cleanupSchedules();
            self::recordFailure('spcrc_privacy_recovery_schedule_failed', Schema::VERSION, Schema::VERSION);
            self::abort(__('Required File 24 privacy recovery schedule could not be established.', 'sabri-security-center'));
        }

        update_option('spcrc_version', SPCRC_VERSION, false);
        update_option('spcrc_schema_version', Schema::VERSION, false);
        if (
            (string) get_option('spcrc_version', '') !== SPCRC_VERSION
            || (string) get_option('spcrc_schema_version', '') !== Schema::VERSION
        ) {
            self::cleanupSchedules();
            self::recordFailure('spcrc_activation_version_state_failed', '', Schema::VERSION);
            self::abort(__('File 24 activation state could not be verified.', 'sabri-security-center'));
        }

        if (get_option('spcrc_installed_at', '') === '') {
            update_option('spcrc_installed_at', gmdate('c'), false);
        }
        delete_option('spcrc_last_upgrade_error');
    }

    private static function cleanupSchedules(): void
    {
        RetentionManager::unschedule();
        RecoveryManager::unschedule();
    }

    private static function recordFailure(string $code, string $fromSchema, string $targetSchema): void
    {
        update_option('spcrc_last_upgrade_error', [
            'at' => gmdate('c'),
            'error_code' => $code,
            'from_schema' => $fromSchema,
            'target_schema' => $targetSchema,
        ], false);
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
