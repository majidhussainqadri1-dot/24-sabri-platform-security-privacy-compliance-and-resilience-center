<?php

declare(strict_types=1);

namespace Sabri\Platform\Security\Security;

use Sabri\Platform\Security\Support\AtomicOptionLock;
use Sabri\Platform\Security\Support\Sanitizer;

/**
 * Privacy-conscious fixed-window limiter with progressive challenge levels.
 * Raw IP/device/account identifiers are never stored.
 */
final class RateLimiter
{
    private const MAX_LIMIT = 10000;
    private const MAX_WINDOW = 86400;

    /** @return array<string,mixed>|\WP_Error */
    public function check(string $scope, string $identifier, int $limit, int $windowSeconds, int $cost = 1): array|\WP_Error
    {
        $scope = Sanitizer::key($scope, 80);
        $identifier = trim($identifier);
        $limit = max(1, min(self::MAX_LIMIT, $limit));
        $windowSeconds = max(1, min(self::MAX_WINDOW, $windowSeconds));
        $cost = max(1, min($limit, $cost));
        if ($scope === '' || $identifier === '') {
            return new \WP_Error('spcrc_rate_limit_identity_invalid', 'Rate-limit scope and identifier are required.');
        }

        $salt = $this->salt();
        if (is_wp_error($salt)) {
            return $salt;
        }

        $bucket = substr(hash_hmac('sha256', $scope . '|' . $identifier, $salt), 0, 40);
        $option = 'spcrc_rate_' . $bucket;
        $lock = 'spcrc_rate_lock_' . $bucket;
        $token = AtomicOptionLock::acquire($lock, 15);
        if (is_wp_error($token)) {
            return new \WP_Error('spcrc_rate_limit_contended', 'Rate-limit state is temporarily unavailable.');
        }

        try {
            $now = time();
            $state = get_option($option, []);
            if (! is_array($state)
                || ! isset($state['window_started'], $state['count'], $state['expires_at'])
                || (int) $state['expires_at'] <= $now
                || (int) $state['window_started'] > $now
            ) {
                $state = [
                    'window_started' => $now,
                    'count' => 0,
                    'expires_at' => $now + $windowSeconds,
                    'violations' => 0,
                ];
            }

            $nextCount = (int) $state['count'] + $cost;
            $allowed = $nextCount <= $limit;
            if ($allowed) {
                $state['count'] = $nextCount;
            } else {
                $state['violations'] = min(20, (int) ($state['violations'] ?? 0) + 1);
            }
            update_option($option, $state, false);
            if (get_option($option, null) !== $state) {
                return new \WP_Error('spcrc_rate_limit_write_failed', 'Rate-limit state could not be stored and verified.');
            }

            $violations = (int) ($state['violations'] ?? 0);
            $challenge = $violations >= 8 ? 'temporary-block' : ($violations >= 3 ? 'challenge' : 'none');
            return [
                'allowed' => $allowed,
                'scope' => $scope,
                'remaining' => max(0, $limit - (int) $state['count']),
                'retry_after' => $allowed ? 0 : max(1, (int) $state['expires_at'] - $now),
                'challenge' => $challenge,
                'identifier_ref' => 'rate:' . $bucket,
            ];
        } finally {
            AtomicOptionLock::release($lock, $token);
        }
    }

    public function reset(string $scope, string $identifier): bool
    {
        $scope = Sanitizer::key($scope, 80);
        if ($scope === '' || $identifier === '') {
            return false;
        }

        $salt = $this->salt();
        if (is_wp_error($salt)) {
            return false;
        }

        $bucket = substr(hash_hmac('sha256', $scope . '|' . $identifier, $salt), 0, 40);
        $lock = 'spcrc_rate_lock_' . $bucket;
        $token = AtomicOptionLock::acquire($lock, 15);
        if (is_wp_error($token)) {
            return false;
        }
        try {
            return delete_option('spcrc_rate_' . $bucket);
        } finally {
            AtomicOptionLock::release($lock, $token);
        }
    }

    /** @return string|\WP_Error */
    private function salt(): string|\WP_Error
    {
        $salt = defined('AUTH_SALT') ? (string) AUTH_SALT : '';
        if ($salt === '' && function_exists('wp_salt')) {
            $salt = (string) wp_salt('auth');
        }
        if ($salt === '') {
            $candidate = apply_filters('spcrc/rate_limit_pseudonymization_key', '');
            $salt = is_string($candidate) ? trim($candidate) : '';
        }
        if (strlen($salt) < 16) {
            return new \WP_Error('spcrc_rate_limit_key_unavailable', 'A private pseudonymization key is required before rate limiting can run.');
        }
        return $salt;
    }
}
