<?php
/**
 * Uninstall policy: preserve security evidence and governance records by default.
 * Destructive deletion requires a future explicit, separately authorized retention workflow.
 */

declare(strict_types=1);

if (! defined('WP_UNINSTALL_PLUGIN')) {
    exit;
}

$capabilities = [
    'spcrc_view_overview',
    'spcrc_view_module_posture',
    'spcrc_manage_controls',
    'spcrc_manage_risks',
    'spcrc_view_security_events',
    'spcrc_manage_incidents',
    'spcrc_manage_privacy_requests',
    'spcrc_run_security_assessments',
    'spcrc_manage_security_settings',
];

$roles = function_exists('wp_roles') ? wp_roles() : null;
if ($roles && is_array($roles->role_objects ?? null)) {
    foreach ($roles->role_objects as $role) {
        foreach ($capabilities as $capability) {
            $role->remove_cap($capability);
        }
    }
}

// Remove ephemeral coordination state, but retain evidence, incidents, risks,
// controls, privacy metadata, manifests, schema/version records, and tables.
delete_option('spcrc_security_state_requests');
delete_option('spcrc_last_upgrade_error');
delete_transient('spcrc_upgrade_lock');
