<?php

declare(strict_types=1);

namespace Sabri\Platform\Security\Rest;

use Sabri\Platform\Security\Registry\ModuleRegistry;
use Sabri\Platform\Security\Registry\SecurityStateRegistry;
use Sabri\Platform\Security\Storage\AssuranceRepository;
use Sabri\Platform\Security\Storage\ControlRepository;
use Sabri\Platform\Security\Storage\FindingRepository;
use Sabri\Platform\Security\Storage\IncidentRepository;
use Sabri\Platform\Security\Storage\RiskRepository;
use Sabri\Platform\Security\Support\Sanitizer;
use Sabri\Platform\Security\System\SystemCheck;

final class StatusController
{
    private const NAMESPACE = 'sabri-security/v1';

    public function __construct(
        private ModuleRegistry $modules,
        private SecurityStateRegistry $states,
        private SystemCheck $checks,
        private ?RiskRepository $risks = null,
        private ?IncidentRepository $incidents = null,
        private ?ControlRepository $controls = null,
        private ?FindingRepository $findings = null,
        private ?AssuranceRepository $assurance = null
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
            'permission_callback' => static fn (): bool => current_user_can('spcrc_view_overview')
                && current_user_can('spcrc_view_module_posture'),
        ]);

        register_rest_route(self::NAMESPACE, '/trust', [
            'methods' => 'GET',
            'callback' => [$this, 'trust'],
            'permission_callback' => '__return_true',
        ]);
    }

    public function status(): \WP_REST_Response
    {
        $counts = [];
        if ($this->findings && current_user_can('spcrc_manage_findings')) {
            $counts['open_findings'] = $this->findings->openCount();
        }
        if ($this->risks && current_user_can('spcrc_manage_risks')) {
            $counts['open_risks'] = $this->risks->openCount();
        }
        if ($this->incidents && current_user_can('spcrc_manage_incidents')) {
            $counts['open_incidents'] = $this->incidents->openCount();
        }
        if ($this->controls && current_user_can('spcrc_manage_controls')) {
            $counts['controls'] = $this->controls->count();
        }
        if ($this->assurance && current_user_can('spcrc_manage_assurance')) {
            $counts['assurance_records'] = $this->assurance->count();
            $counts['compliance_records'] = $this->assurance->count('compliance');
            $counts['vendor_records'] = $this->assurance->count('vendor');
            $counts['backup_records'] = $this->assurance->count('backup');
        }

        $response = new \WP_REST_Response([
            'version' => SPCRC_VERSION,
            'schema_version' => (string) get_option('spcrc_schema_version', ''),
            'environment' => Sanitizer::key(wp_get_environment_type(), 30),
            'modules' => array_values(array_map([$this, 'publicModuleSummary'], $this->modules->all())),
            'security_state_requests' => array_values(array_map([$this, 'stateSummary'], $this->states->all())),
            'counts' => $counts,
            'checks' => $this->checks->run(),
            'generated_at' => gmdate('c'),
        ]);
        $response->header('Cache-Control', 'private, no-store, max-age=0');
        $response->header('X-Content-Type-Options', 'nosniff');
        return $response;
    }

    public function trust(): \WP_REST_Response
    {
        $payload = [
            'platform' => 'Sabri Social Homeopathy Platform',
            'security_program' => 'Foundation under active development',
            'privacy_request_available' => Sanitizer::boolean(apply_filters('spcrc/privacy_request_intake_available', false)),
            'responsible_disclosure_available' => Sanitizer::boolean(apply_filters('spcrc/responsible_disclosure_channel_available', false)),
            'unsupported_claims' => [
                'No claim of unhackable security',
                'No claim of certification without independent evidence',
                'No claim of end-to-end encryption without audited implementation',
            ],
            'version' => SPCRC_VERSION,
        ];

        $filtered = apply_filters('spcrc/public_trust_payload', $payload);
        $safe = $this->sanitizeTrustPayload(is_array($filtered) ? $filtered : $payload);
        $response = new \WP_REST_Response($safe);
        $response->header('Cache-Control', 'public, max-age=300');
        $response->header('X-Content-Type-Options', 'nosniff');
        return $response;
    }

    /** @param array<string,mixed> $manifest
     *  @return array<string,mixed>
     */
    private function publicModuleSummary(array $manifest): array
    {
        return [
            'module_key' => Sanitizer::key($manifest['module_key'] ?? '', 120),
            'name' => Sanitizer::text($manifest['name'] ?? '', 200),
            'version' => Sanitizer::text($manifest['version'] ?? '', 60),
            'owner' => Sanitizer::text($manifest['owner'] ?? '', 120),
            'posture' => Sanitizer::key($manifest['posture'] ?? 'unassessed', 40),
            'last_security_test' => Sanitizer::isoTime($manifest['last_security_test'] ?? ''),
        ];
    }

    /** @param array<string,mixed> $state
     *  @return array<string,mixed>
     */
    private function stateSummary(array $state): array
    {
        return [
            'request_id' => Sanitizer::uuid($state['request_id'] ?? ''),
            'module_key' => Sanitizer::key($state['module_key'] ?? '', 120),
            'state' => Sanitizer::key($state['state'] ?? '', 40),
            'requested_at' => Sanitizer::isoTime($state['requested_at'] ?? ''),
            'expires_at' => Sanitizer::isoTime($state['expires_at'] ?? ''),
            'status' => Sanitizer::key($state['status'] ?? 'open', 40),
        ];
    }

    /** @param array<string,mixed> $payload
     *  @return array<string,mixed>
     */
    private function sanitizeTrustPayload(array $payload): array
    {
        return [
            'platform' => Sanitizer::text($payload['platform'] ?? 'Sabri Social Homeopathy Platform', 120),
            'security_program' => Sanitizer::text($payload['security_program'] ?? 'Foundation under active development', 200),
            'privacy_request_available' => Sanitizer::boolean($payload['privacy_request_available'] ?? false),
            'responsible_disclosure_available' => Sanitizer::boolean($payload['responsible_disclosure_available'] ?? false),
            'unsupported_claims' => Sanitizer::textList($payload['unsupported_claims'] ?? [], 10, 180),
            'version' => SPCRC_VERSION,
        ];
    }
}
