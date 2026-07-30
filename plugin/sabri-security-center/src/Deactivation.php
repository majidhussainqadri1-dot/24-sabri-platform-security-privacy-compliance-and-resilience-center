<?php

declare(strict_types=1);

namespace Sabri\Platform\Security;

use Sabri\Platform\Security\Retention\RetentionManager;

final class Deactivation
{
    public static function deactivate(): void
    {
        RetentionManager::unschedule();
        update_option('spcrc_last_deactivated_at', gmdate('c'), false);

        // Preserve evidence and schema. Native modules must remain secure without File 24.
        do_action('spcrc/deactivated');
    }
}
