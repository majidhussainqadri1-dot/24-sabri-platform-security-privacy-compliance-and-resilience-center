<?php

declare(strict_types=1);

namespace Sabri\Platform\Security\System;

use Sabri\Platform\Security\Capabilities;
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
        update_option('spcrc_schema_version', Schema::VERSION, false);
        delete_option('spcrc_last_upgrade_error');

        $result = [
            'schema_version' => Schema::VERSION,
            'capabilities_reapplied' => true,
            'completed_at' => gmdate('c'),
        ];
        do_action('spcrc/non_destructive_repair_completed', $result);
        return $result;
    }
}
