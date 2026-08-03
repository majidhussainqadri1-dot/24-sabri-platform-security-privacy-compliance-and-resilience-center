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

        $stateSnapshot = self::stateSnapshot();
        $scheduleSnapshot = self::scheduleSnapshot();
        $installed = Schema::install();
        if (is_wp_error($installed)) {
            self::recordFailure($installed->get_error_code(), '', Schema::VERSION);
            self::abort($installed->get_error_message());
        }

        $capabilitiesInstalled = Capabilities::install();
        if ($capabilitiesInstalled === false) {
            self::restoreState($stateSnapshot);
            self::recordFailure('spcrc_capability_install_failed', '', Schema::VERSION);
            self::abort(__('Required File 24 capabilities could not be installed and verified.', 'sabri-security-center'));
        }
        if (! RetentionManager::ensureScheduled()) {
            self::cleanupSchedules($scheduleSnapshot);
            self::restoreState($stateSnapshot);
            self::recordFailure('spcrc_retention_schedule_failed', Schema::VERSION, Schema::VERSION);
            self::abort(__('Required File 24 retention schedule could not be established.', 'sabri-security-center'));
        }
        if (! RecoveryManager::ensureScheduled()) {
            self::cleanupSchedules($scheduleSnapshot);
            self::restoreState($stateSnapshot);
            self::recordFailure('spcrc_privacy_recovery_schedule_failed', Schema::VERSION, Schema::VERSION);
            self::abort(__('Required File 24 privacy recovery schedule could not be established.', 'sabri-security-center'));
        }

        update_option('spcrc_version', SPCRC_VERSION, false);
        update_option('spcrc_schema_version', Schema::VERSION, false);
        if (
            (string) get_option('spcrc_version', '') !== SPCRC_VERSION
            || (string) get_option('spcrc_schema_version', '') !== Schema::VERSION
        ) {
            self::cleanupSchedules($scheduleSnapshot);
            self::restoreState($stateSnapshot);
            self::recordFailure('spcrc_activation_version_state_failed', '', Schema::VERSION);
            self::abort(__('File 24 activation state could not be verified.', 'sabri-security-center'));
        }

        if (get_option('spcrc_installed_at', '') === '') {
            $installedAt = gmdate('c');
            update_option('spcrc_installed_at', $installedAt, false);
            if ((string) get_option('spcrc_installed_at', '') !== $installedAt) {
                self::cleanupSchedules($scheduleSnapshot);
                self::restoreState($stateSnapshot);
                self::recordFailure('spcrc_activation_installed_at_failed', '', Schema::VERSION);
                self::abort(__('File 24 installation timestamp could not be verified.', 'sabri-security-center'));
            }
        }
        delete_option('spcrc_last_upgrade_error');
    }


    /** @return array<string,mixed> */
    private static function stateSnapshot(): array
    {
        return [
            'version' => get_option('spcrc_version', null),
            'schema_version' => get_option('spcrc_schema_version', null),
            'installed_at' => get_option('spcrc_installed_at', null),
        ];
    }

    /** @param array<string,mixed> $snapshot */
    private static function restoreState(array $snapshot): void
    {
        foreach (['version' => 'spcrc_version', 'schema_version' => 'spcrc_schema_version', 'installed_at' => 'spcrc_installed_at'] as $key => $option) {
            if (($snapshot[$key] ?? null) === null) {
                delete_option($option);
            } else {
                update_option($option, $snapshot[$key], false);
            }
        }
    }

    /** @return array{retention:bool,recovery:bool} */
    private static function scheduleSnapshot(): array
    {
        return [
            'retention' => function_exists('wp_next_scheduled') && (bool) wp_next_scheduled(RetentionManager::CRON_HOOK),
            'recovery' => function_exists('wp_next_scheduled') && (bool) wp_next_scheduled(RecoveryManager::EVENT),
        ];
    }

    /** @param array{retention:bool,recovery:bool} $snapshot */
    private static function cleanupSchedules(array $snapshot): void
    {
        if (! $snapshot['retention']) {
            RetentionManager::unschedule();
        }
        if (! $snapshot['recovery']) {
            RecoveryManager::unschedule();
        }
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
