<?php

declare(strict_types=1);

namespace Sabri\Platform\Security\Integration;

final class File00Adapter
{
    public function registerHooks(): void
    {
        add_filter('spcrc/identity_authority_available', [$this, 'identityAvailable']);
        add_filter('spcrc/is_founder_user', [$this, 'isFounder'], 10, 2);
        add_filter('spcrc/module_manifests', [$this, 'manifest']);
        add_filter('spcrc/public_browsing_compatible', [$this, 'publicBrowsingCompatible']);
        add_filter('spcrc/privacy_request/file-00-membership-core', [$this, 'privacyHandler'], 10, 3);
    }

    public function available(): bool
    {
        return defined('SMC_VERSION')
            && function_exists('smc_user_status')
            && function_exists('smc_is_founder');
    }

    public function identityAvailable(bool $current): bool
    {
        return $current || $this->available();
    }

    public function isFounder(bool $current, int $userId): bool
    {
        return $current || ($this->available() && $userId > 0 && (bool) smc_is_founder($userId));
    }

    public function publicBrowsingCompatible(bool $current): bool
    {
        if (! $current || ! $this->available()) {
            return $current;
        }

        if (! class_exists('SMC_Security') || ! method_exists('SMC_Security', 'frontend_gate')) {
            return $current;
        }

        $priority = function_exists('has_action')
            ? has_action('template_redirect', ['SMC_Security', 'frontend_gate'])
            : false;

        return $priority === false;
    }


    /** @param mixed $result
     *  @param array<string,mixed> $request
     *  @return array<string,mixed>|mixed
     */
    public function privacyHandler(mixed $result, string $type, array $request): mixed
    {
        if ($result !== null || ! $this->available()) {
            return $result;
        }

        $userId = absint($request['requester_user_id'] ?? 0);
        if ($userId < 1 || ! get_userdata($userId)) {
            return new \WP_Error('spcrc_file00_user_missing', 'The File 00 privacy subject could not be resolved.');
        }

        if (in_array($type, ['access', 'portability'], true) && is_callable(['SMC_Security', 'export_personal_data'])) {
            return ['ok' => true, 'status' => 'native-exporter-available', 'reference' => 'wp-privacy-exporter:sabri-membership'];
        }

        if ($type === 'deletion' && is_callable(['SMC_Security', 'erase_personal_data'])) {
            return ['ok' => true, 'status' => 'native-eraser-available', 'reference' => 'wp-privacy-eraser:sabri-membership'];
        }

        return new \WP_Error('spcrc_file00_privacy_unavailable', 'The requested File 00 privacy operation is not available.');
    }

    /** @param mixed $manifests
     *  @return array<int,array<string,mixed>>
     */
    public function manifest(mixed $manifests): array
    {
        $manifests = is_array($manifests) ? $manifests : [];
        if (! $this->available()) {
            return $manifests;
        }

        $manifests[] = [
            'module_key' => 'file-00-membership-core',
            'name' => 'Sabri Membership Core',
            'version' => (string) SMC_VERSION,
            'owner' => 'File 00',
            'posture' => 'foundation',
            'data_classes' => ['C2 Personal', 'C3 Sensitive Personal', 'C4 Restricted Identity'],
            'public_routes' => ['/sabri-login/', '/sabri-register/'],
            'private_routes' => ['/sabri-profile/', '/sabri-security-center/', '/sabri-verification-status/'],
            'capabilities' => ['smc_review_verification', 'smc_view_private_documents', 'smc_moderate_members'],
            'external_vendors' => [],
            'privacy_operations' => ['access', 'deletion', 'portability'],
            'last_security_test' => '',
        ];

        return $manifests;
    }
}
