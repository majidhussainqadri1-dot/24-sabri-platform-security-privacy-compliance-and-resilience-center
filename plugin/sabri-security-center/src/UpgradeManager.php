<?php

declare(strict_types=1);

namespace Sabri\Platform\Security;

use Sabri\Platform\Security\Retention\RetentionManager;
use Sabri\Platform\Security\Storage\Schema;

final class UpgradeManager
{
    public static function maybeUpgrade(): void
    {
        $installedSchema = (string) get_option('spcrc_schema_version', '');
        $installedPlugin = (string) get_option('spcrc_version', '');
        if ($installedSchema === Schema::VERSION && $installedPlugin === SPCRC_VERSION) {
            Capabilities::install();
            RetentionManager::ensureScheduled();
            return;
        }

        try {
            Schema::install();
            Capabilities::install();
            RetentionManager::ensureScheduled();
            update_option('spcrc_schema_version', Schema::VERSION, false);
            update_option('spcrc_version', SPCRC_VERSION, false);
            update_option('spcrc_last_upgraded_at', gmdate('c'), false);
            delete_option('spcrc_last_upgrade_error');
            do_action('spcrc/upgraded', $installedSchema, Schema::VERSION, $installedPlugin, SPCRC_VERSION);
        } catch (\Throwable $exception) {
            update_option('spcrc_last_upgrade_error', [
                'at' => gmdate('c'),
                'from_schema' => $installedSchema,
                'target_schema' => Schema::VERSION,
                'exception_class' => get_class($exception),
            ], false);
            do_action('spcrc/upgrade_failed', $exception, $installedSchema, Schema::VERSION);
        }
    }
}
