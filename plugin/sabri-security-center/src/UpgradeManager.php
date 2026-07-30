<?php

declare(strict_types=1);

namespace Sabri\Platform\Security;

use Sabri\Platform\Security\Storage\Schema;

final class UpgradeManager
{
    public static function maybeUpgrade(): void
    {
        $installedSchema = (string) get_option('spcrc_schema_version', '');
        if ($installedSchema === Schema::VERSION) {
            return;
        }

        Schema::install();
        update_option('spcrc_schema_version', Schema::VERSION, false);
        update_option('spcrc_version', SPCRC_VERSION, false);
        update_option('spcrc_last_upgraded_at', gmdate('c'), false);

        do_action('spcrc/upgraded', $installedSchema, Schema::VERSION);
    }
}
