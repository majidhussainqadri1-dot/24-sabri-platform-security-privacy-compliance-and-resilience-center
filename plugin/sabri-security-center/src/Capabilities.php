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
            'spcrc_manage_policies',
            'spcrc_manage_assets',
            'spcrc_manage_vulnerabilities',
            'spcrc_manage_integrations',
            'spcrc_manage_resilience',
            'spcrc_manage_trust_center',
            'spcrc_manage_performance',
            'spcrc_manage_release_gates',
            'spcrc_manage_training',
            'spcrc_view_forensic_metadata',
            'spcrc_manage_key_metadata',
            'spcrc_manage_compliance',
            'spcrc_manage_vendors',
            'spcrc_run_restore_operations',
            'spcrc_close_critical_incidents',
        ];
    }

    /**
     * WordPress administrators receive only bounded read access automatically.
     * Operational File 24 duties must be delegated explicitly to separate roles
     * or users so that a generic site-administration role is not also the
     * Security Administrator, Privacy Officer, Incident Commander, Backup
     * Operator and Auditor by default.
     *
     * @return string[]
     */
    public static function autoGranted(): array
    {
        return [
            'spcrc_view_overview',
            'spcrc_view_module_posture',
        ];
    }

    /** @return array<string,string[]> */
    public static function dutyBundles(): array
    {
        return [
            'security_administrator' => [
                'spcrc_manage_controls',
                'spcrc_manage_findings',
                'spcrc_manage_risks',
                'spcrc_view_security_events',
                'spcrc_run_security_assessments',
                'spcrc_manage_security_settings',
                'spcrc_manage_policies',
                'spcrc_manage_assets',
                'spcrc_manage_vulnerabilities',
                'spcrc_manage_integrations',
                'spcrc_manage_performance',
                'spcrc_manage_release_gates',
                'spcrc_manage_training',
            ],
            'privacy_officer' => [
                'spcrc_manage_privacy_requests',
                'spcrc_manage_compliance',
                'spcrc_manage_vendors',
            ],
            'incident_commander' => [
                'spcrc_view_security_events',
                'spcrc_manage_incidents',
            ],
            'backup_operator' => [
                'spcrc_manage_assurance',
                'spcrc_manage_resilience',
            ],
            'auditor' => [
                'spcrc_view_overview',
                'spcrc_view_module_posture',
                'spcrc_view_forensic_metadata',
            ],
        ];
    }

    public static function install(): bool
    {
        $administrator = get_role('administrator');
        if (! $administrator) {
            return false;
        }

        $snapshot = self::snapshotRole($administrator);
        $readOnly = array_fill_keys(self::autoGranted(), true);

        foreach (self::all() as $capability) {
            $shouldHave = isset($readOnly[$capability]);
            $hasCapability = self::roleHasCapability($administrator, $capability);

            if ($shouldHave && ! $hasCapability) {
                $administrator->add_cap($capability);
            } elseif (! $shouldHave && $hasCapability) {
                if (! method_exists($administrator, 'remove_cap')) {
                    self::restoreRoleSnapshot($administrator, $snapshot);
                    return false;
                }
                $administrator->remove_cap($capability);
            }

            if (self::roleHasCapability($administrator, $capability) !== $shouldHave) {
                self::restoreRoleSnapshot($administrator, $snapshot);
                return false;
            }
        }

        return true;
    }

    /** @return array<string,bool>|false */
    public static function snapshot(): array|false
    {
        $administrator = get_role('administrator');
        return $administrator ? self::snapshotRole($administrator) : false;
    }

    /** @param array<string,bool> $snapshot */
    public static function restoreSnapshot(array $snapshot): bool
    {
        $administrator = get_role('administrator');
        return $administrator ? self::restoreRoleSnapshot($administrator, $snapshot) : false;
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

    /** @return array<string,bool> */
    private static function snapshotRole(object $role): array
    {
        $snapshot = [];
        foreach (self::all() as $capability) {
            $snapshot[$capability] = self::roleHasCapability($role, $capability);
        }
        return $snapshot;
    }

    /** @param array<string,bool> $snapshot */
    private static function restoreRoleSnapshot(object $role, array $snapshot): bool
    {
        if (! method_exists($role, 'add_cap') || ! method_exists($role, 'remove_cap')) {
            do_action('spcrc/capability_snapshot_restore_unavailable', array_keys($snapshot));
            return false;
        }

        foreach (self::all() as $capability) {
            $shouldHave = ! empty($snapshot[$capability]);
            if ($shouldHave) {
                $role->add_cap($capability);
            } else {
                $role->remove_cap($capability);
            }
        }

        foreach (self::all() as $capability) {
            if (self::roleHasCapability($role, $capability) !== ! empty($snapshot[$capability])) {
                do_action('spcrc/capability_snapshot_restore_failed', $capability);
                return false;
            }
        }
        return true;
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
        do_action('spcrc/capabilities_registered', self::all(), self::dutyBundles());
    }
}
