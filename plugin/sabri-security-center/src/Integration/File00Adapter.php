<?php

declare(strict_types=1);

namespace Sabri\Platform\Security\Integration;

use Sabri\Platform\Security\Support\Sanitizer;

final class File00Adapter
{
    public function registerHooks(): void
    {
        add_filter('spcrc/identity_authority_available', [$this, 'identityAvailable']);
        add_filter('spcrc/is_founder_user', [$this, 'isFounder'], 10, 2);
        add_filter('spcrc/module_manifests', [$this, 'manifest']);
        add_filter('spcrc/public_browsing_compatible', [$this, 'publicBrowsingCompatible']);
        add_filter('spcrc/privacy_request/file-00-membership-core', [$this, 'privacyHandler'], 10, 3);
        add_filter('spcrc/step_up_assurance_available', [$this, 'stepUpAvailable']);
        add_filter('spcrc/verify_step_up_assurance', [$this, 'verifyStepUp'], 10, 4);
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

    public function stepUpAvailable(bool $current): bool
    {
        return $current || ($this->available() && function_exists('smc_verify_step_up_assertion'));
    }

    public function verifyStepUp(bool $current, int $userId, string $purpose, string $reference): bool
    {
        if ($current) {
            return true;
        }
        if (! $this->available() || ! function_exists('smc_verify_step_up_assertion')) {
            return false;
        }

        return $userId > 0
            && $purpose !== ''
            && Sanitizer::opaqueReference($reference) !== ''
            && (bool) smc_verify_step_up_assertion($userId, $purpose, $reference);
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
            return [
                'ok' => true,
                'status' => 'pending',
                'reference' => 'wp-privacy-exporter-available:sabri-membership',
                'message' => 'Native exporter is available, but this adapter has not started the WordPress export workflow. An authorized operator must initiate and later confirm native completion.',
            ];
        }

        if ($type === 'deletion' && is_callable(['SMC_Security', 'erase_personal_data'])) {
            return [
                'ok' => true,
                'status' => 'pending',
                'reference' => 'wp-privacy-eraser-available:sabri-membership',
                'message' => 'Native eraser is available, but this adapter has not started the WordPress erasure workflow. An authorized operator must initiate and later confirm native completion.',
            ];
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
            'contract_version' => '1.1.2',
            'canonical_data_owner' => 'File 00',
            'canonical_action_owner' => 'File 00 / File 02 split',
            'evidence_source' => 'module:file-00-membership-core',
            'degraded_behavior' => 'Privileged writes fail closed when identity assertions are unavailable.',
            'release_gate' => 'Hostinger staging, provider, recovery and rollback acceptance',
        ];

        return $manifests;
    }
}
