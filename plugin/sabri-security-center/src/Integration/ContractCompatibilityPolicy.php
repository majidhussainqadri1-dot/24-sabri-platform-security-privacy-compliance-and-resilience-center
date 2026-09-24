<?php

declare(strict_types=1);

namespace Sabri\Platform\Security\Integration;

/**
 * Executable compatibility/deprecation policy for versioned File 24 contracts.
 *
 * "compatible" means the supplied version is inside the explicitly supported
 * half-open range [minimum, maximumExclusive). Versions below the minimum are
 * deprecated and must not be treated as current assurance. Versions at/above a
 * new major boundary are blocked until a reviewed adapter explicitly supports
 * them.
 */
final class ContractCompatibilityPolicy
{
    public const MANIFEST_CURRENT = '1.2.0';
    public const MANIFEST_MINIMUM = '1.2.0';
    public const MANIFEST_NEXT_MAJOR = '2.0.0';

    public static function evaluate(string $version, string $minimum, string $maximumExclusive): string
    {
        $version = trim($version);
        $minimum = trim($minimum);
        $maximumExclusive = trim($maximumExclusive);
        foreach ([$version, $minimum, $maximumExclusive] as $candidate) {
            if (preg_match('/^\d+\.\d+(?:\.\d+)?$/', $candidate) !== 1) {
                return 'blocked';
            }
        }
        if (version_compare($minimum, $maximumExclusive, '>=')) {
            return 'blocked';
        }
        if (version_compare($version, $minimum, '<')) {
            return 'deprecated';
        }
        if (version_compare($version, $maximumExclusive, '>=')) {
            return 'blocked';
        }
        return 'compatible';
    }

    public static function manifestState(string $version): string
    {
        return self::evaluate($version, self::MANIFEST_MINIMUM, self::MANIFEST_NEXT_MAJOR);
    }

    public static function manifestCompatible(string $version): bool
    {
        return self::manifestState($version) === 'compatible';
    }

    /** @return array<string,mixed> */
    public static function summary(): array
    {
        return [
            'current' => self::MANIFEST_CURRENT,
            'minimum_supported' => self::MANIFEST_MINIMUM,
            'maximum_exclusive' => self::MANIFEST_NEXT_MAJOR,
            'versions_below_minimum' => 'deprecated',
            'new_major_versions' => 'blocked_pending_reviewed_adapter',
        ];
    }

    public static function repositoryCodingComplete(): bool
    {
        return self::manifestState(self::MANIFEST_CURRENT) === 'compatible'
            && self::manifestState('1.1.9') === 'deprecated'
            && self::manifestState('2.0.0') === 'blocked';
    }
}
