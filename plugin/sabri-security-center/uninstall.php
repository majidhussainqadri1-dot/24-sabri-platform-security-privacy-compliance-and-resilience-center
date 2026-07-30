<?php
/**
 * Uninstall policy: preserve security evidence and governance records by default.
 * Destructive deletion requires a future explicit, separately authorized retention workflow.
 */

declare(strict_types=1);

if (! defined('WP_UNINSTALL_PLUGIN')) {
    exit;
}

// Intentionally non-destructive.
