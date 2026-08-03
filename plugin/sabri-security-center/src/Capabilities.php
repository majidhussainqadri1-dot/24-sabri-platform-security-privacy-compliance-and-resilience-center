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
            'spcrc_manage_findings',
            'spcrc_accept_critical_risk',
            'spcrc_manage_risks',
            'spcrc_view_security_events',
            'spcrc_manage_incidents',
            'spcrc_manage_privacy_requests',
            'spcrc_manage_assurance',
            'spcrc_request_governance_decision',
            'spcrc_approve_governance_decision',
            'spcrc_run_security_assessments',
            'spcrc_manage_security_settings',
        ];
    }

    /** @return string[] */
    public static function autoGranted(): array
    {
        return array_values(array_diff(self::all(), ['spcrc_accept_critical_risk', 'spcrc_approve_governance_decision']));
    }

    public static function install(): bool
    {
        $administrator = get_role('administrator');
        if (! $administrator) {
            return false;
        }

        $added = [];
        foreach (self::autoGranted() as $capability) {
            if (self::roleHasCapability($administrator, $capability)) {
                continue;
            }
            $administrator->add_cap($capability);
            if (! self::roleHasCapability($administrator, $capability)) {
                self::rollbackAddedCapabilities($administrator, $added);
                return false;
            }
            $added[] = $capability;
        }
        return true;
    }


    private static function roleHasCapability(object $role, string $capability): bool
    {
        if (method_exists($role, 'has_cap')) {
            return (bool) $role->has_cap($capability);
        }
        $caps = is_array($role->caps ?? null)
            ? $role->caps
            : (is_array($role->capabilities ?? null) ? $role->capabilities : []);
        return ! empty($caps[$capability]);
    }

    /** @param string[] $capabilities */
    private static function rollbackAddedCapabilities(object $role, array $capabilities): void
    {
        if (! method_exists($role, 'remove_cap')) {
            do_action('spcrc/capability_install_rollback_unavailable', $capabilities);
            return;
        }
        foreach (array_reverse($capabilities) as $capability) {
            $role->remove_cap($capability);
        }
    }

    public static function registerHooks(): void
    {
        add_action('init', [self::class, 'register'], 1);
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
