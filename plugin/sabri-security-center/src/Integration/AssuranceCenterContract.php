<?php

declare(strict_types=1);

namespace Sabri\Platform\Security\Integration;

/** File-specific F24-CEN-01 ownership and dashboard contract. */
final class AssuranceCenterContract
{
    /** @var list<string> */
    private const REQUIRED_DASHBOARDS = ['controls','evidence','exceptions','incidents','disaster_recovery'];

    /** @var list<string> */
    private const NATIVE_CONTROLS = ['authorization','encryption','rate_limiting','validation'];

    /** @param array<string,mixed> $manifest @return array<string,mixed> */
    public static function evaluate(array $manifest): array
    {
        $dashboards = self::list($manifest['dashboards'] ?? []);
        $native = self::list($manifest['native_controls_preserved'] ?? []);
        $missingDashboards = array_values(array_diff(self::REQUIRED_DASHBOARDS, $dashboards));
        $missingNative = array_values(array_diff(self::NATIVE_CONTROLS, $native));
        $takeover = ! empty($manifest['file24_native_control_takeover']);
        $singlePoint = ! empty($manifest['security_single_point_of_failure']);
        $privateOpsPublic = ! empty($manifest['private_operations_public']);
        $complete = $missingDashboards === [] && $missingNative === [] && ! $takeover && ! $singlePoint && ! $privateOpsPublic;

        return [
            'state' => $complete ? 'compatible' : 'blocked',
            'missing_dashboards' => $missingDashboards,
            'missing_native_controls' => $missingNative,
            'native_control_takeover' => $takeover,
            'security_single_point_of_failure' => $singlePoint,
            'private_operations_public' => $privateOpsPublic,
            'activation_allowed' => $complete,
        ];
    }

    /** @param mixed $value @return list<string> */
    private static function list(mixed $value): array
    {
        if (! is_array($value)) { return []; }
        $out = [];
        foreach ($value as $item) {
            if (! is_string($item)) { continue; }
            $item = strtolower(trim($item));
            if ($item !== '' && preg_match('/^[a-z0-9][a-z0-9_-]{0,79}$/', $item) === 1) { $out[$item] = true; }
        }
        return array_keys($out);
    }
}
