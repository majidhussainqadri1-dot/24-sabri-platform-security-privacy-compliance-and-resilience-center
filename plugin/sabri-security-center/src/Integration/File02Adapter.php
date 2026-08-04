<?php

declare(strict_types=1);

namespace Sabri\Platform\Security\Integration;

use Sabri\Platform\Security\Support\Sanitizer;

/**
 * File 02 credential-authentication assurance adapter.
 *
 * File 24 consumes bounded assertions only and never reads passwords, provider
 * tokens, recovery secrets or session cookies.
 */
final class File02Adapter
{
    public function registerHooks(): void
    {
        add_filter('spcrc/authentication_authority_available', [$this, 'available'], 10, 1);
        add_filter('spcrc/authentication_assurance', [$this, 'assurance'], 10, 4);
        add_filter('spcrc/file02_contract_state', [$this, 'contractState'], 10, 2);
        add_filter('spcrc/module_manifests', [$this, 'manifest'], 20, 1);
    }

    public function available(bool $current = false): bool
    {
        if ($current) {
            return true;
        }
        return defined('SAUTH_VERSION')
            || function_exists('sauth_session_assurance')
            || has_filter('sauth/session_assurance');
    }

    /** @return array<string,mixed> */
    public function assurance(mixed $current, int $userId, string $purpose, array $context = []): array
    {
        $base = is_array($current) ? $current : [];
        if (function_exists('sauth_session_assurance')) {
            $received = sauth_session_assurance($userId, $purpose, $context);
            if (is_array($received)) {
                $base = array_merge($base, $received);
            }
        }
        $filtered = apply_filters('sauth/session_assurance', $base, $userId, $purpose, $context);
        $raw = is_array($filtered) ? $filtered : [];
        return [
            'available' => $this->available(),
            'authenticated' => Sanitizer::boolean($raw['authenticated'] ?? false),
            'recent_authentication' => Sanitizer::boolean($raw['recent_authentication'] ?? false),
            'mfa_satisfied' => Sanitizer::boolean($raw['mfa_satisfied'] ?? false),
            'session_risk' => Sanitizer::key($raw['session_risk'] ?? 'unknown', 20),
            'assurance_ref' => Sanitizer::opaqueReference($raw['assurance_ref'] ?? ''),
        ];
    }

    public function contractState(string $current, array $definition = []): string
    {
        return $this->available() ? 'compatible' : 'missing';
    }

    /** @param mixed $manifests @return array<int,array<string,mixed>> */
    public function manifest(mixed $manifests): array
    {
        $manifests = is_array($manifests) ? $manifests : [];
        $manifests[] = [
            'module_key' => 'file-02-authentication',
            'name' => 'Authentication and Accounts',
            'version' => defined('SAUTH_VERSION') ? (string) SAUTH_VERSION : '',
            'owner' => 'file-02',
            'data_classes' => ['C2', 'C3', 'C5'],
            'routes' => [],
            'capabilities' => [],
            'vendors' => [],
            'secrets' => ['credential-provider-secrets'],
            'privacy_handlers' => [],
            'emergency_callbacks' => [],
            'security_tested_at' => '',
            'posture' => $this->available() ? 'assessed' : 'unassessed',
            'evidence_ref' => '',
        ];
        return $manifests;
    }
}
