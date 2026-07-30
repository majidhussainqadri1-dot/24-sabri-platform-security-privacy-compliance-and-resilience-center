<?php

declare(strict_types=1);

namespace Sabri\Platform\Security;

final class Capabilities
{
    /** @return string[] */
    public static function all(): array
    {
        return [
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
    }

    public static function install(): void
    {
        $administrator = get_role('administrator');
        if (! $administrator) {
            return;
        }

        foreach (self::all() as $capability) {
            $administrator->add_cap($capability);
        }
    }

    /**
     * File 24 deliberately does not auto-grant operational security capabilities
     * to the Founder or any other identity label. Delegation must be explicit,
     * reviewable and reversible through WordPress roles/capabilities.
     */
    public static function register(): void
    {
        do_action('spcrc/capabilities_registered', self::all());
    }
}
