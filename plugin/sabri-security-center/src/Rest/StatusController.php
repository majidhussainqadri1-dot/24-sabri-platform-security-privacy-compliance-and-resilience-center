<?php

declare(strict_types=1);

namespace Sabri\Platform\Security\Rest;

use Sabri\Platform\Security\Monitoring\PerformanceMonitor;
use Sabri\Platform\Security\Registry\GovernedArtifactRegistry;
use Sabri\Platform\Security\Registry\ModuleRegistry;
use Sabri\Platform\Security\Registry\PlatformIntegrationMatrix;
use Sabri\Platform\Security\Registry\RequirementCatalog;
use Sabri\Platform\Security\Registry\SecurityStateRegistry;
use Sabri\Platform\Security\Release\ReleaseStatus;
use Sabri\Platform\Security\Resilience\ResilienceCoordinator;
use Sabri\Platform\Security\Storage\AssuranceRepository;
use Sabri\Platform\Security\Storage\ControlRepository;
use Sabri\Platform\Security\Storage\FindingRepository;
use Sabri\Platform\Security\Storage\GovernanceRepository;
use Sabri\Platform\Security\Storage\IncidentRepository;
use Sabri\Platform\Security\Storage\RiskRepository;
use Sabri\Platform\Security\Support\Sanitizer;
use Sabri\Platform\Security\System\SystemCheck;
use Sabri\Platform\Security\Trust\TrustCenterService;

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
        private ?AssuranceRepository $assurance = null,
        private ?GovernanceRepository $governance = null,
        private ?GovernedArtifactRegistry $artifacts = null,
        private ?TrustCenterService $trustCenter = null,
        private ?PerformanceMonitor $performance = null,
        private ?ResilienceCoordinator $resilience = null
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
        $started = microtime(true);
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
        if ($this->governance && current_user_can('spcrc_request_governance_decision')) {
            $counts['pending_governance_decisions'] = $this->governance->pendingCount();
        }
        if ($this->assurance && current_user_can('spcrc_manage_assurance')) {
            $counts['assurance_records'] = $this->assurance->count();
            $counts['compliance_records'] = $this->assurance->count('compliance');
            $counts['vendor_records'] = $this->assurance->count('vendor');
            $counts['backup_records'] = $this->assurance->count('backup');
        }
        if ($this->artifacts) {
            $counts['governed_artifacts'] = $this->artifacts->count();
            foreach (['policy', 'vulnerability', 'alert', 'release-gate', 'drill'] as $type) {
                $counts[$type . '_records'] = $this->artifacts->count($type);
            }
        }

        $payload = [
            'version' => defined('SPCRC_VERSION') ? SPCRC_VERSION : '',
            'schema_version' => (string) get_option('spcrc_schema_version', ''),
            'environment' => Sanitizer::key(wp_get_environment_type(), 30),
            'release' => class_exists(ReleaseStatus::class) ? ReleaseStatus::summary() : [],
            'requirements' => class_exists(RequirementCatalog::class) ? RequirementCatalog::summary() : [],
            'integration_matrix' => class_exists(PlatformIntegrationMatrix::class) ? PlatformIntegrationMatrix::evaluate() : [],
            'modules' => array_values(array_map([$this, 'publicModuleSummary'], $this->modules->all())),
            'security_state_requests' => array_values(array_map([$this, 'stateSummary'], $this->states->all())),
            'counts' => $counts,
            'resilience' => $this->resilience ? $this->resilience->posture() : [],
            'checks' => $this->checks->run(),
            'generated_at' => gmdate('c'),
        ];
        if ($this->performance) {
            $this->performance->record('status_endpoint_latency_ms', (microtime(true) - $started) * 1000, 'ms');
            $payload['performance'] = ['status_endpoint_latency_ms' => $this->performance->summary('status_endpoint_latency_ms')];
        }

        $response = new \WP_REST_Response($payload);
        $response->header('Cache-Control', 'private, no-store, max-age=0');
        $response->header('X-Robots-Tag', 'noindex, noarchive');
        $response->header('X-Content-Type-Options', 'nosniff');
        return $response;
    }

    public function trust(): \WP_REST_Response
    {
        $payload = $this->trustCenter ? $this->trustCenter->payload() : [
            'platform' => 'Sabri Social Homeopathy Platform',
            'program_status' => 'Repository code-complete candidate; production assurance pending',
            'security_program' => 'Foundation candidate; production assurance pending',
            'claims' => [],
            'unsupported_claims' => [
                'No claim of unhackable security',
                'No claim of certification without independent evidence',
                'No claim of end-to-end encryption without audited implementation',
            ],
            'generated_at' => gmdate('c'),
        ];

        // Public security/privacy facts may only originate from the evidence-gated
        // TrustCenterService. A general WordPress filter must not be able to add,
        // replace or forge claims after approval and expiry checks have completed.
        $safe = $this->sanitizeTrustPayload($payload);
        $response = new \WP_REST_Response($safe);
        $maxAge = $this->trustCacheMaxAge($safe);
        $response->header('Cache-Control', 'public, max-age=' . $maxAge . ($maxAge === 0 ? ', must-revalidate' : ''));
        $response->header('X-Content-Type-Options', 'nosniff');
        return $response;
    }

    /** @param array<string,mixed> $manifest @return array<string,mixed> */
    private function publicModuleSummary(array $manifest): array
    {
        return [
            'module_key' => Sanitizer::key($manifest['module_key'] ?? '', 120),
            'name' => Sanitizer::text($manifest['name'] ?? '', 200),
            'version' => Sanitizer::text($manifest['version'] ?? '', 60),
            'owner' => Sanitizer::text($manifest['owner'] ?? '', 120),
            'posture' => Sanitizer::key($manifest['posture'] ?? 'unassessed', 40),
            'last_security_test' => Sanitizer::isoTime($manifest['last_security_test'] ?? ''),
            'contract_version' => Sanitizer::text($manifest['contract_version'] ?? 'unversioned', 40),
            'degraded_behavior' => Sanitizer::text($manifest['degraded_behavior'] ?? '', 300),
            'release_gate' => Sanitizer::text($manifest['release_gate'] ?? '', 300),
        ];
    }

    /** @param array<string,mixed> $state @return array<string,mixed> */
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

    /** @param array<string,mixed> $payload */
    private function trustCacheMaxAge(array $payload): int
    {
        $now = time();
        $maxAge = 300;
        foreach (is_array($payload['claims'] ?? null) ? $payload['claims'] : [] as $claim) {
            if (! is_array($claim)) {
                continue;
            }
            $expiresAt = Sanitizer::isoTime($claim['expires_at'] ?? '');
            $expires = $expiresAt === '' ? false : strtotime($expiresAt);
            if ($expires === false) {
                return 0;
            }
            $maxAge = min($maxAge, max(0, $expires - $now));
        }
        return max(0, min(300, $maxAge));
    }

    /** @param array<string,mixed> $payload @return array<string,mixed> */
    private function sanitizeTrustPayload(array $payload): array
    {
        $claims = [];
        foreach (array_slice(is_array($payload['claims'] ?? null) ? $payload['claims'] : [], 0, 50) as $claim) {
            if (! is_array($claim)) {
                continue;
            }
            $key = Sanitizer::key($claim['key'] ?? '', 120);
            $type = Sanitizer::key($claim['type'] ?? '', 80);
            $verifiedAt = Sanitizer::isoTime($claim['verified_at'] ?? '');
            $expiresAt = Sanitizer::isoTime($claim['expires_at'] ?? '');
            if ($key === '' || $type === '' || $verifiedAt === '' || $expiresAt === '' || strtotime($expiresAt) <= time()) {
                continue;
            }
            $claims[] = [
                'key' => $key,
                'type' => $type,
                'title' => Sanitizer::text($claim['title'] ?? '', 200),
                'summary' => Sanitizer::text($claim['summary'] ?? '', 500),
                'verified_at' => $verifiedAt,
                'expires_at' => $expiresAt,
            ];
        }

        $claimTypes = array_fill_keys(array_column($claims, 'type'), true);
        return [
            'platform' => Sanitizer::text($payload['platform'] ?? 'Sabri Social Homeopathy Platform', 120),
            'program_status' => 'Repository code-complete candidate; production assurance pending',
            'security_program' => 'Foundation candidate; production assurance pending',
            'claims' => $claims,
            'privacy_request_available' => isset($claimTypes['rights-request']),
            'responsible_disclosure_available' => isset($claimTypes['responsible-disclosure']),
            'unsupported_claims' => Sanitizer::textList($payload['unsupported_claims'] ?? [], 10, 180),
            'version' => defined('SPCRC_VERSION') ? SPCRC_VERSION : '',
        ];
    }
}
