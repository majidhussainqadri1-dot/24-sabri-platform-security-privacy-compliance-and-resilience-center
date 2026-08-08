<?php

declare(strict_types=1);

namespace Sabri\Platform\Security\Security;

use Sabri\Platform\Security\Support\Sanitizer;

final class NetworkPolicy
{
    public static function sameOriginUrl(string $url): bool
    {
        $url = trim($url);
        if ($url === '' || strlen($url) > 2048 || preg_match('/[\r\n]/', $url) === 1) {
            return false;
        }
        $homeUrl = home_url();
        $home = wp_parse_url($homeUrl, PHP_URL_HOST);
        $host = wp_parse_url($url, PHP_URL_HOST);
        $homeScheme = strtolower((string) wp_parse_url($homeUrl, PHP_URL_SCHEME));
        $scheme = strtolower((string) wp_parse_url($url, PHP_URL_SCHEME));
        $homePort = wp_parse_url($homeUrl, PHP_URL_PORT);
        $port = wp_parse_url($url, PHP_URL_PORT);
        $homeEffectivePort = is_int($homePort) ? $homePort : ($homeScheme === 'https' ? 443 : 80);
        $effectivePort = is_int($port) ? $port : ($scheme === 'https' ? 443 : 80);
        return is_string($home) && is_string($host)
            && $home !== ''
            && hash_equals(strtolower($home), strtolower($host))
            && $homeScheme === 'https'
            && $scheme === $homeScheme
            && $homeEffectivePort === $effectivePort
            && wp_parse_url($url, PHP_URL_USER) === null
            && wp_parse_url($url, PHP_URL_PASS) === null;
    }

    public static function safeExternalEndpoint(string $url, array $allowedHosts = []): bool
    {
        $url = trim($url);
        if ($url === '' || strlen($url) > 2048 || preg_match('/[\r\n]/', $url) === 1) {
            return false;
        }
        $scheme = strtolower((string) wp_parse_url($url, PHP_URL_SCHEME));
        $host = strtolower((string) wp_parse_url($url, PHP_URL_HOST));
        if ($scheme !== 'https' || $host === '' || wp_parse_url($url, PHP_URL_USER) !== null || wp_parse_url($url, PHP_URL_PASS) !== null) {
            return false;
        }
        if ($allowedHosts !== []) {
            $normalized = array_map(static fn (mixed $value): string => strtolower(Sanitizer::text($value, 253)), $allowedHosts);
            if (! in_array($host, $normalized, true)) {
                return false;
            }
        }
        if (filter_var($host, FILTER_VALIDATE_IP)) {
            return self::publicIp($host);
        }
        if (in_array($host, ['localhost', 'localhost.localdomain'], true) || str_ends_with($host, '.local')) {
            return false;
        }
        $resolved = apply_filters('spcrc/resolve_endpoint_ips', [], $host);
        if (! is_array($resolved)) {
            $resolved = [];
        }
        if ($resolved === [] && function_exists('dns_get_record')) {
            $records = @dns_get_record($host, DNS_A | DNS_AAAA);
            if (is_array($records)) {
                foreach ($records as $record) {
                    if (isset($record['ip']) && is_string($record['ip'])) {
                        $resolved[] = $record['ip'];
                    }
                    if (isset($record['ipv6']) && is_string($record['ipv6'])) {
                        $resolved[] = $record['ipv6'];
                    }
                }
            }
        }
        if ($resolved === []) {
            return false;
        }
        foreach (array_values(array_unique($resolved)) as $ip) {
            if (! is_string($ip) || ! self::publicIp($ip)) {
                return false;
            }
        }
        return true;
    }

    public static function publicIp(string $ip): bool
    {
        return filter_var(
            $ip,
            FILTER_VALIDATE_IP,
            FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE
        ) !== false;
    }

    public static function maskIp(string $ip): string
    {
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            $parts = explode('.', $ip);
            return $parts[0] . '.' . $parts[1] . '.x.x';
        }
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            $parts = explode(':', $ip);
            return implode(':', array_slice($parts, 0, 3)) . '::/48';
        }
        return '';
    }
}
