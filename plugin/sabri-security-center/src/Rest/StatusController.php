<?php

declare(strict_types=1);

namespace Sabri\Platform\Security\Rest;

use Sabri\Platform\Security\Registry\ModuleRegistry;
use Sabri\Platform\Security\Registry\SecurityStateRegistry;
use Sabri\Platform\Security\System\SystemCheck;

final class StatusController
{
    private const NAMESPACE = 'sabri-security/v1';

    public function __construct(
        private ModuleRegistry $modules,
        private SecurityStateRegistry $states,
        private SystemCheck $checks
    ) {
    }

    public function registerHooks(): void
    {
        add_action('rest_api_init', [$this, 'registerRoutes']);
    }

    public function registerRoutes(): void
    {
        register_rest_route(self::NAMESPACE, '/status', [
            'methods' => 'GET',
            'callback' => [$this, 'status'],
            'permission_callback' => static fn (): bool => current_user_can('spcrc_view_overview'),
        ]);

        register_rest_route(self::NAMESPACE, '/trust', [
            'methods' => 'GET',
            'callback' => [$this, 'trust'],
            'permission_callback' => '__return_true',
        ]);
    }

    public function status(): \WP_REST_Response
    {
        return new \WP_REST_Response([
            'version' => SPCRC_VERSION,
            'environment' => wp_get_environment_type(),
            'modules' => array_values($this->modules->all()),
            'security_state_requests' => array_values($this->states->all()),
            'checks' => $this->checks->run(),
            'generated_at' => gmdate('c'),
        ]);
    }

    public function trust(): \WP_REST_Response
    {
        $payload = [
            'platform' => 'Sabri Social Homeopathy Platform',
            'security_program' => 'Foundation under active development',
            'privacy_request_available' => true,
            'responsible_disclosure_available' => true,
            'unsupported_claims' => [
                'No claim of unhackable security',
                'No claim of certification without independent evidence',
                'No claim of end-to-end encryption without audited implementation',
            ],
            'updated_at' => gmdate('c'),
        ];

        return new \WP_REST_Response(apply_filters('spcrc/public_trust_payload', $payload));
    }
}
