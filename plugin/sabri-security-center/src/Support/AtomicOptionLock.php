<?php

declare(strict_types=1);

namespace Sabri\Platform\Security\Support;

/**
 * Atomic, owner-token option lock.
 *
 * WordPress `get_option()` followed by `delete_option()` is not a safe stale-
 * lock takeover: two workers can delete or replace each other's locks. This
 * helper uses conditional SQL against the exact serialized option value and
 * invalidates the option cache after a successful compare-and-swap/delete.
 */
final class AtomicOptionLock
{
    /** @return string|\WP_Error */
    public static function acquire(string $option, int $ttl): string|\WP_Error
    {
        $option = self::optionName($option);
        $ttl = max(5, min(86400, $ttl));
        if ($option === '' || ! function_exists('add_option') || ! function_exists('get_option')) {
            return new \WP_Error('spcrc_atomic_lock_storage_unavailable', 'Atomic option-lock storage is unavailable.');
        }

        $token = function_exists('wp_generate_uuid4')
            ? wp_generate_uuid4()
            : bin2hex(random_bytes(16));
        $replacement = ['token' => $token, 'expires_at' => time() + $ttl];
        if (add_option($option, $replacement, '', false)) {
            return $token;
        }

        $existing = get_option($option, null);
        if (! self::validPayload($existing)) {
            return new \WP_Error('spcrc_atomic_lock_malformed', 'The existing coordination lock is malformed and was not overwritten.');
        }
        if ((int) $existing['expires_at'] > time()) {
            return new \WP_Error('spcrc_atomic_lock_contended', 'Another operation currently owns the coordination lock.');
        }

        if (self::compareAndSwap($option, $existing, $replacement)) {
            return $token;
        }

        $current = get_option($option, null);
        return self::validPayload($current) && (int) $current['expires_at'] > time()
            ? new \WP_Error('spcrc_atomic_lock_contended', 'Another operation reclaimed the coordination lock concurrently.')
            : new \WP_Error('spcrc_atomic_lock_unavailable', 'The expired coordination lock could not be reclaimed atomically.');
    }

    public static function refresh(string $option, string $token, int $ttl): bool
    {
        $option = self::optionName($option);
        $ttl = max(5, min(86400, $ttl));
        if ($option === '' || $token === '') {
            return false;
        }

        $existing = get_option($option, null);
        if (! self::validPayload($existing) || ! hash_equals((string) $existing['token'], $token)) {
            return false;
        }

        return self::compareAndSwap(
            $option,
            $existing,
            ['token' => $token, 'expires_at' => time() + $ttl]
        );
    }

    public static function owned(string $option, string $token): bool
    {
        $option = self::optionName($option);
        $existing = $option === '' ? null : get_option($option, null);
        return self::validPayload($existing)
            && hash_equals((string) $existing['token'], $token)
            && (int) $existing['expires_at'] > time();
    }

    public static function release(string $option, string $token): bool
    {
        $option = self::optionName($option);
        if ($option === '' || $token === '') {
            return false;
        }

        $existing = get_option($option, null);
        if (! self::validPayload($existing) || ! hash_equals((string) $existing['token'], $token)) {
            return false;
        }

        return self::compareAndDelete($option, $existing);
    }

    private static function validPayload(mixed $payload): bool
    {
        return is_array($payload)
            && is_string($payload['token'] ?? null)
            && $payload['token'] !== ''
            && is_numeric($payload['expires_at'] ?? null);
    }

    private static function optionName(string $option): string
    {
        $option = strtolower(trim($option));
        $option = preg_replace('/[^a-z0-9_\-]/', '', $option) ?? '';
        return substr($option, 0, 191);
    }

    /** @param array<string,mixed> $expected @param array<string,mixed> $replacement */
    private static function compareAndSwap(string $option, array $expected, array $replacement): bool
    {
        global $wpdb;
        if (! isset($wpdb) || ! is_object($wpdb) || ! isset($wpdb->options) || ! method_exists($wpdb, 'prepare') || ! method_exists($wpdb, 'query')) {
            return false;
        }

        $updated = $wpdb->query($wpdb->prepare(
            "UPDATE {$wpdb->options} SET option_value = %s WHERE option_name = %s AND option_value = %s",
            maybe_serialize($replacement),
            $option,
            maybe_serialize($expected)
        ));
        if ($updated !== 1) {
            return false;
        }
        self::flushCache($option);
        return true;
    }

    /** @param array<string,mixed> $expected */
    private static function compareAndDelete(string $option, array $expected): bool
    {
        global $wpdb;
        if (! isset($wpdb) || ! is_object($wpdb) || ! isset($wpdb->options) || ! method_exists($wpdb, 'prepare') || ! method_exists($wpdb, 'query')) {
            return false;
        }

        $deleted = $wpdb->query($wpdb->prepare(
            "DELETE FROM {$wpdb->options} WHERE option_name = %s AND option_value = %s",
            $option,
            maybe_serialize($expected)
        ));
        if ($deleted !== 1) {
            return false;
        }
        self::flushCache($option);
        return true;
    }

    private static function flushCache(string $option): void
    {
        if (function_exists('wp_cache_delete')) {
            wp_cache_delete($option, 'options');
            wp_cache_delete('alloptions', 'options');
        }
    }
}
