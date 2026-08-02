<?php

declare(strict_types=1);

namespace Sabri\Platform\Security\System;

use Sabri\Platform\Security\Capabilities;
use Sabri\Platform\Security\Privacy\RecoveryManager;
use Sabri\Platform\Security\Retention\RetentionManager;
use Sabri\Platform\Security\Storage\Schema;

final class Repair
{
    /** @return array<string,mixed>|\WP_Error */
    public function run(): array|\WP_Error
    {
        $schema = Schema::install();
        if (is_wp_error($schema)) {
            return $schema;
        }

        Capabilities::install();
        if (! RetentionManager::ensureScheduled()) {
            return new \WP_Error(
                'spcrc_retention_schedule_failed',
                'Non-destructive repair could not verify the retention schedule.'
            );
        }
        if (! RecoveryManager::ensureScheduled()) {
            return new \WP_Error(
                'spcrc_privacy_recovery_schedule_failed',
                'Non-destructive repair could not verify the privacy recovery schedule.'
            );
        }

        update_option('spcrc_schema_version', Schema::VERSION, false);
        update_option('spcrc_version', SPCRC_VERSION, false);
        if (
            (string) get_option('spcrc_schema_version', '') !== Schema::VERSION
            || (string) get_option('spcrc_version', '') !== SPCRC_VERSION
        ) {
            return new \WP_Error(
                'spcrc_repair_version_state_failed',
                'Non-destructive repair state could not be verified.'
            );
        }

        delete_option('spcrc_last_upgrade_error');

        $result = [
            'schema_version' => Schema::VERSION,
            'plugin_version' => SPCRC_VERSION,
            'capabilities_reapplied' => true,
            'retention_schedule_verified' => true,
            'privacy_recovery_schedule_verified' => true,
            'completed_at' => gmdate('c'),
        ];
        do_action('spcrc/non_destructive_repair_completed', $result);
        return $result;
    }
}
