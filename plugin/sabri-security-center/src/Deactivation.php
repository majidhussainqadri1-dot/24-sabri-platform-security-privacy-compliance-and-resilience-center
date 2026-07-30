<?php

declare(strict_types=1);

namespace Sabri\Platform\Security;

use Sabri\Platform\Security\Storage\Retention;

final class Deactivation
{
    public static function deactivate(): void
    {
        Retention::unschedule();

        // Preserve evidence and schema. Native modules must remain secure without File 24.
        do_action('spcrc/deactivated');
    }
}
