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
            if ($state === []) {
                $state = $this->newState($now, $windowSeconds);
            } elseif (! is_array($state)) {
                return new \WP_Error('spcrc_rate_limit_state_invalid', 'Persisted rate-limit state is malformed and was not trusted.');
            } else {
                $windowStarted = Sanitizer::strictInteger($state['window_started'] ?? null, 1, PHP_INT_MAX);
                $count = Sanitizer::strictInteger($state['count'] ?? null, 0, self::MAX_LIMIT);
                $expiresAt = Sanitizer::strictInteger($state['expires_at'] ?? null, 1, PHP_INT_MAX);
                $violations = Sanitizer::strictInteger($state['violations'] ?? 0, 0, 20);
                if (
                    $windowStarted === null
                    || $count === null
                    || $expiresAt === null
                    || $violations === null
                    || $windowStarted > $now
                    || $expiresAt <= $windowStarted
                    || $expiresAt > $windowStarted + self::MAX_WINDOW
                ) {
                    return new \WP_Error('spcrc_rate_limit_state_invalid', 'Persisted rate-limit state is malformed and was not trusted.');
                }
                if ($expiresAt <= $now) {
                    $state = $this->newState($now, $windowSeconds);
                } else {
                    $state['window_started'] = $windowStarted;
                    $state['count'] = $count;
                    $state['expires_at'] = $expiresAt;
                    $state['violations'] = $violations;
                }
            }

            $nextCount = $state['count'] + $cost;
            $allowed = $nextCount <= $limit;
            if ($allowed) {
                $state['count'] = $nextCount;
            } else {
                $state['violations'] = min(20, $state['violations'] + 1);
            }
            update_option($option, $state, false);
            if (get_option($option, null) !== $state) {
                return new \WP_Error('spcrc_rate_limit_write_failed', 'Rate-limit state could not be stored and verified.');
            }

            $violations = $state['violations'];
            $challenge = $violations >= 8 ? 'temporary-block' : ($violations >= 3 ? 'challenge' : 'none');
            return [
                'allowed' => $allowed,
                'scope' => $scope,
                'remaining' => max(0, $limit - $state['count']),
                'retry_after' => $allowed ? 0 : max(1, $state['expires_at'] - $now),
                'challenge' => $challenge,
                'identifier_ref' => 'rate:' . $bucket,
            ];
        } finally {
            AtomicOptionLock::release($lock, $token);
        }
    }

    /** @return array{window_started:int,count:int,expires_at:int,violations:int} */
    private function newState(int $now, int $windowSeconds): array
    {
        return [
            'window_started' => $now,
            'count' => 0,
            'expires_at' => $now + $windowSeconds,
            'violations' => 0,
        ];
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
