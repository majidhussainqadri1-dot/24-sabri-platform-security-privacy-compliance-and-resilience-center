<?php
/**
 * Uninstall policy: preserve security evidence and governance records by default.
 * Operational capabilities and scheduled jobs are removed to prevent stale privileges.
 * Destructive evidence deletion requires a future explicit, separately authorized retention workflow.
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

$roles = wp_roles();
if ($roles) {
    foreach (array_keys($roles->roles) as $roleName) {
        $role = get_role((string) $roleName);
        if (! $role) {
            continue;
        }
        foreach ($capabilities as $capability) {
            $role->remove_cap($capability);
        }
    }
}

$hook = 'spcrc_daily_retention';
$timestamp = wp_next_scheduled($hook);
while ($timestamp) {
    if (! wp_unschedule_event($timestamp, $hook)) {
        break;
    }
    $timestamp = wp_next_scheduled($hook);
}

delete_option('spcrc_capability_version');
delete_option('spcrc_upgrade_lock');
delete_option('spcrc_upgrade_failed');
delete_option('spcrc_downgrade_blocked');

// Evidence tables and governance records are intentionally preserved.
