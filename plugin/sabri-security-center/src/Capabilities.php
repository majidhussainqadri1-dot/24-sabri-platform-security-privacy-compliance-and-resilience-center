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

    public static function register(): void
    {
        add_filter('map_meta_cap', [self::class, 'mapFounderCapabilities'], 10, 4);
    }

    /**
     * @param string[] $caps
     * @param mixed[]  $args
     * @return string[]
     */
    public static function mapFounderCapabilities(array $caps, string $cap, int $userId, array $args): array
    {
        if (! in_array($cap, self::all(), true)) {
            return $caps;
        }

        $isFounder = (bool) apply_filters('spcrc/is_founder_user', false, $userId);
        if ($isFounder) {
            return ['read'];
        }

        return $caps;
    }
}
