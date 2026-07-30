<?php

declare(strict_types=1);

namespace Sabri\Platform\Security;

final class Capabilities
{
    public const VERSION = '0.25.1';

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

        update_option('spcrc_capability_version', self::VERSION, false);
    }

    public static function removeFromAllRoles(): void
    {
        $roles = wp_roles();
        if (! $roles) {
            return;
        }

        foreach (array_keys($roles->roles) as $roleName) {
            $role = get_role((string) $roleName);
            if (! $role) {
                continue;
            }

            foreach (self::all() as $capability) {
                $role->remove_cap($capability);
            }
        }
    }
}
