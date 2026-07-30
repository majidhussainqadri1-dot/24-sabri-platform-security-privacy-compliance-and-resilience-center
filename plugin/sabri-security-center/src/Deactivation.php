<?php

declare(strict_types=1);

namespace Sabri\Platform\Security;

final class Deactivation
{
    public static function deactivate(): void
    {
        // Preserve evidence and schema. Native modules must remain secure without File 24.
        do_action('spcrc/deactivated');
    }
}
