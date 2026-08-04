<?php

declare(strict_types=1);

namespace Sabri\Platform\Security\Security;

use Sabri\Platform\Security\Support\Sanitizer;
use Sabri\Platform\Security\Support\SecureIdentifier;

/**
 * Shared REST/AJAX/webhook guard. Availability checks never grant authority.
 */
final class EndpointGuard
{
    public function __construct(private ?RateLimiter $rateLimiter = null)
    {
        $this->rateLimiter ??= new RateLimiter();
    }

    /**
     * @param array<string,mixed> $policy
     * @param array<string,mixed> $request
     * @return array<string,mixed>|\WP_Error
     */
    public function authorize(array $policy, array $request): array|\WP_Error
    {
        $method = strtoupper(Sanitizer::text($request['method'] ?? '', 12));
        $allowedMethods = Sanitizer::textList($policy['methods'] ?? ['POST'], 8, 12);
        $allowedMethods = array_map('strtoupper', $allowedMethods);
        if ($method === '' || ! in_array($method, $allowedMethods, true)) {
            return new \WP_Error('spcrc_endpoint_method_not_allowed', 'Request method is not allowed.');
        }

        $requireAuth = ! array_key_exists('require_auth', $policy) || Sanitizer::boolean($policy['require_auth']);
        $userId = get_current_user_id();
        if ($requireAuth && $userId < 1) {
            return new \WP_Error('spcrc_endpoint_authentication_required', 'Authentication is required.');
        }

        $capability = Sanitizer::key($policy['capability'] ?? '', 100);
        if ($capability !== '' && ! current_user_can($capability)) {
            return new \WP_Error('spcrc_endpoint_forbidden', 'Current user is not authorized for this operation.');
        }

        $nonceAction = Sanitizer::key($policy['nonce_action'] ?? '', 100);
        if ($nonceAction !== '') {
            $nonce = Sanitizer::text($request['nonce'] ?? '', 200);
            if ($nonce === '' || ! function_exists('wp_verify_nonce') || ! wp_verify_nonce($nonce, $nonceAction)) {
                return new \WP_Error('spcrc_endpoint_nonce_invalid', 'Request verification failed.');
            }
        }

        if (Sanitizer::boolean($policy['same_origin'] ?? true)) {
            $origin = Sanitizer::text($request['origin'] ?? '', 2048);
            if ($origin !== '' && ! NetworkPolicy::sameOriginUrl($origin)) {
                return new \WP_Error('spcrc_endpoint_origin_invalid', 'Cross-origin request is not permitted.');
            }
        }

        $authorizer = $policy['object_authorizer'] ?? null;
        if (is_callable($authorizer) && ! (bool) $authorizer($request, $policy)) {
            return new \WP_Error('spcrc_endpoint_object_forbidden', 'Object-level authorization failed.');
        }

        $rateScope = Sanitizer::key($policy['rate_scope'] ?? '', 80);
        if ($rateScope !== '') {
            $identifier = $userId > 0
                ? 'user:' . $userId
                : 'network:' . Sanitizer::text($request['network_identifier'] ?? '', 200);
            $rate = $this->rateLimiter->check(
                $rateScope,
                $identifier,
                absint($policy['rate_limit'] ?? 30),
                absint($policy['rate_window'] ?? 60)
            );
            if (is_wp_error($rate)) {
                return $rate;
            }
            if (empty($rate['allowed'])) {
                return new \WP_Error('spcrc_endpoint_rate_limited', 'Request rate limit exceeded.');
            }
        }

        $idempotencyRef = '';
        if (Sanitizer::boolean($policy['require_idempotency'] ?? false)) {
            $idempotency = Sanitizer::opaqueReference($request['idempotency_key'] ?? '', 180);
            if ($idempotency === '') {
                return new \WP_Error('spcrc_endpoint_idempotency_missing', 'A bounded idempotency key is required.');
            }
            $idempotencyRef = $this->claimIdempotency($rateScope !== '' ? $rateScope : 'endpoint', $idempotency);
            if ($idempotencyRef === '') {
                return new \WP_Error('spcrc_endpoint_replay_detected', 'Duplicate or replayed request was blocked.');
            }
        }

        return [
            'authorized' => true,
            'user_id' => $userId,
            'method' => $method,
            'capability' => $capability,
            'idempotency_ref' => $idempotencyRef,
        ];
    }

    /**
     * @param callable(string):string $secretResolver
     * @return array<string,mixed>|\WP_Error
     */
    public function verifyWebhook(
        string $provider,
        string $body,
        string $signature,
        int $timestamp,
        callable $secretResolver,
        int $tolerance = 300
    ): array|\WP_Error {
        $provider = Sanitizer::key($provider, 80);
        $signature = strtolower(trim($signature));
        $tolerance = max(30, min(900, $tolerance));
        if ($provider === '' || $body === '' || strlen($body) > 1048576 || abs(time() - $timestamp) > $tolerance) {
            return new \WP_Error('spcrc_webhook_request_invalid', 'Webhook identity, size or timestamp is invalid.');
        }
        if (preg_match('/^[a-f0-9]{64}$/', $signature) !== 1) {
            return new \WP_Error('spcrc_webhook_signature_invalid', 'Webhook signature format is invalid.');
        }

        $secret = (string) $secretResolver($provider);
        if ($secret === '' || strlen($secret) < 32) {
            return new \WP_Error('spcrc_webhook_secret_unavailable', 'Webhook verification secret is unavailable.');
        }
        $expected = hash_hmac('sha256', $timestamp . '.' . $body, $secret);
        if (! hash_equals($expected, $signature)) {
            return new \WP_Error('spcrc_webhook_signature_invalid', 'Webhook signature verification failed.');
        }

        $replayKey = 'spcrc_webhook_seen_' . substr(hash('sha256', $provider . '|' . $timestamp . '|' . $signature), 0, 40);
        if (! add_option($replayKey, ['expires_at' => time() + $tolerance], '', false)) {
            return new \WP_Error('spcrc_webhook_replay_detected', 'Webhook replay was blocked.');
        }

        return [
            'verified' => true,
            'provider' => $provider,
            'request_ref' => 'webhook:' . substr(hash('sha256', $signature), 0, 32),
            'verified_at' => gmdate('c'),
        ];
    }

    private function claimIdempotency(string $scope, string $key): string
    {
        $option = 'spcrc_idempotency_' . substr(hash('sha256', $scope . '|' . $key), 0, 40);
        $claim = SecureIdentifier::uuid4('idempotency');
        if (is_wp_error($claim)) {
            return '';
        }
        $record = ['claim' => $claim, 'expires_at' => time() + 86400];
        return add_option($option, $record, '', false) ? 'idem:' . substr(hash('sha256', $claim), 0, 32) : '';
    }
}
