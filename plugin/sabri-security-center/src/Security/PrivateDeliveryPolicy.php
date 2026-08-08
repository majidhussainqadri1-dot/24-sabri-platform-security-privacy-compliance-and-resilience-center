<?php

declare(strict_types=1);

namespace Sabri\Platform\Security\Security;

use Sabri\Platform\Security\Support\AtomicOptionLock;
use Sabri\Platform\Security\Support\Sanitizer;
use Sabri\Platform\Security\Support\SecureIdentifier;

/**
 * Issues short-lived opaque delivery grants. It never stores file paths or
 * bypasses native-owner authorization.
 */
final class PrivateDeliveryPolicy
{
    /** @param callable(int,string,string):bool $authorizer @return array<string,mixed>|\WP_Error */
    public function issue(int $userId, string $assetRef, string $purpose, int $ttl, callable $authorizer): array|\WP_Error
    {
        $assetRef = Sanitizer::opaqueReference($assetRef);
        $purpose = Sanitizer::key($purpose, 80);
        $ttl = max(30, min(900, $ttl));
        if ($userId < 1 || $assetRef === '' || $purpose === '' || ! $authorizer($userId, $assetRef, $purpose)) {
            return new \WP_Error('spcrc_private_delivery_forbidden', 'Native-owner authorization did not permit private delivery.');
        }

        $token = SecureIdentifier::uuid4('private-delivery');
        if (is_wp_error($token)) {
            return $token;
        }
        $hash = hash('sha256', $token);
        $option = 'spcrc_delivery_' . substr($hash, 0, 40);
        $record = [
            'token_hash' => $hash,
            'user_id' => $userId,
            'asset_ref' => $assetRef,
            'purpose' => $purpose,
            'expires_at' => time() + $ttl,
            'consumed_at' => 0,
        ];
        if (! add_option($option, $record, '', false)) {
            return new \WP_Error('spcrc_private_delivery_issue_failed', 'Private delivery grant could not be created.');
        }
        return [
            'grant' => 'delivery:' . $token,
            'expires_at' => gmdate('c', (int) $record['expires_at']),
            'asset_ref' => $assetRef,
            'purpose' => $purpose,
        ];
    }

    /** @param callable(int,string,string):bool $authorizer @return array<string,mixed>|\WP_Error */
    public function consume(string $grant, int $userId, callable $authorizer): array|\WP_Error
    {
        if (! str_starts_with($grant, 'delivery:')) {
            return new \WP_Error('spcrc_private_delivery_grant_invalid', 'Private delivery grant is invalid.');
        }
        $token = substr($grant, 9);
        $hash = hash('sha256', $token);
        $option = 'spcrc_delivery_' . substr($hash, 0, 40);
        $lockOption = 'spcrc_private_delivery_consume_lock_' . substr($hash, 0, 32);
        $lock = AtomicOptionLock::acquire($lockOption, 30);
        if (is_wp_error($lock)) {
            return new \WP_Error('spcrc_private_delivery_consume_contended', 'Private delivery grant is already being consumed by another request.');
        }

        try {
            $record = get_option($option, null);
            if (! is_array($record)
                || ! hash_equals((string) ($record['token_hash'] ?? ''), $hash)
                || (int) ($record['expires_at'] ?? 0) <= time()
                || (int) ($record['consumed_at'] ?? 0) > 0
                || (int) ($record['user_id'] ?? 0) !== $userId
            ) {
                return new \WP_Error('spcrc_private_delivery_expired', 'Private delivery grant is expired, consumed or invalid.');
            }
            $assetRef = Sanitizer::opaqueReference($record['asset_ref'] ?? '');
            $purpose = Sanitizer::key($record['purpose'] ?? '', 80);
            if ($assetRef === '' || $purpose === '' || ! $authorizer($userId, $assetRef, $purpose)) {
                return new \WP_Error('spcrc_private_delivery_reauthorization_failed', 'Native-owner authorization no longer permits delivery.');
            }
            $record['consumed_at'] = time();
            $updated = update_option($option, $record, false);
            $persisted = get_option($option, null);
            if (! ($updated || (is_array($persisted) && $persisted === $record))
                || ! is_array($persisted)
                || ! hash_equals((string) ($persisted['token_hash'] ?? ''), $hash)
                || (int) ($persisted['consumed_at'] ?? 0) < 1
            ) {
                return new \WP_Error('spcrc_private_delivery_consume_failed', 'Private delivery grant consumption could not be durably recorded.');
            }
            return [
                'authorized' => true,
                'asset_ref' => $assetRef,
                'purpose' => $purpose,
                'user_id' => $userId,
                'cache_control' => 'private, no-store, max-age=0',
            ];
        } finally {
            AtomicOptionLock::release($lockOption, $lock);
        }
    }

    public function revoke(string $grant): bool
    {
        if (! str_starts_with($grant, 'delivery:')) {
            return false;
        }
        $hash = hash('sha256', substr($grant, 9));
        return delete_option('spcrc_delivery_' . substr($hash, 0, 40));
    }
}
