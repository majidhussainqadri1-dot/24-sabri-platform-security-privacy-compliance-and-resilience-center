<?php

declare(strict_types=1);

namespace Sabri\Platform\Security\Rest;

use Sabri\Platform\Security\Registry\GovernedArtifactRegistry;
use Sabri\Platform\Security\Registry\PlatformIntegrationMatrix;
use Sabri\Platform\Security\Registry\RequirementCatalog;
use Sabri\Platform\Security\Release\ReleaseStatus;
use Sabri\Platform\Security\Support\Sanitizer;

/** Versioned, bounded REST interface for File 24 governance metadata. */
final class GovernanceController
{
    private const NAMESPACE = 'sabri-security/v1';

    public function __construct(private GovernedArtifactRegistry $artifacts)
    {
    }

    public function registerHooks(): void
    {
        add_action('rest_api_init', [$this, 'registerRoutes']);
    }

    public function registerRoutes(): void
    {
        register_rest_route(self::NAMESPACE, '/governance/types', [
            'methods' => 'GET',
            'callback' => [$this, 'types'],
            'permission_callback' => static fn (): bool => current_user_can('spcrc_view_overview'),
        ]);
        register_rest_route(self::NAMESPACE, '/governance/artifacts', [
            [
                'methods' => 'GET',
                'callback' => [$this, 'listArtifacts'],
                'permission_callback' => static fn (): bool => current_user_can('spcrc_view_overview'),
            ],
            [
                'methods' => 'POST',
                'callback' => [$this, 'saveArtifact'],
                'permission_callback' => [$this, 'canSave'],
            ],
        ]);
        register_rest_route(self::NAMESPACE, '/governance/traceability', [
            'methods' => 'GET',
            'callback' => [$this, 'traceability'],
            'permission_callback' => static fn (): bool => current_user_can('spcrc_view_overview'),
        ]);
    }

    public function canSave(mixed $request): bool
    {
        $type = Sanitizer::key($this->param($request, 'artifact_type'), 60);
        return $type !== '' && current_user_can(GovernedArtifactRegistry::capability($type));
    }

    public function types(): \WP_REST_Response
    {
        $data = [];
        foreach (GovernedArtifactRegistry::types() as $type) {
            $data[] = ['type' => $type, 'statuses' => GovernedArtifactRegistry::statuses($type), 'capability' => GovernedArtifactRegistry::capability($type)];
        }
        return $this->privateResponse(['types' => $data]);
    }

    public function listArtifacts(mixed $request): \WP_REST_Response
    {
        $type = Sanitizer::key($this->param($request, 'artifact_type'), 60);
        $limit = max(1, min(100, absint($this->param($request, 'limit') ?: 50)));
        return $this->privateResponse(['artifacts' => $this->artifacts->recent($type !== '' ? $type : null, $limit)]);
    }

    public function saveArtifact(mixed $request): \WP_REST_Response|\WP_Error
    {
        $data = $this->allParams($request);
        $data['owner_user_id'] = get_current_user_id();
        $result = $this->artifacts->save($data, absint($data['expected_version'] ?? 0));
        if (is_wp_error($result)) {
            return $result;
        }
        return $this->privateResponse(['artifact_uuid' => $result, 'saved' => true]);
    }

    public function traceability(): \WP_REST_Response
    {
        return $this->privateResponse([
            'requirements' => RequirementCatalog::summary(),
            'release' => ReleaseStatus::summary(),
            'integration_matrix' => PlatformIntegrationMatrix::evaluate(),
        ]);
    }

    private function privateResponse(array $data): \WP_REST_Response
    {
        $response = new \WP_REST_Response($data);
        $response->header('Cache-Control', 'private, no-store, max-age=0');
        $response->header('X-Robots-Tag', 'noindex, noarchive');
        $response->header('X-Content-Type-Options', 'nosniff');
        return $response;
    }

    private function param(mixed $request, string $key): mixed
    {
        if (is_object($request) && method_exists($request, 'get_param')) {
            return $request->get_param($key);
        }
        return is_array($request) ? ($request[$key] ?? null) : null;
    }

    /** @return array<string,mixed> */
    private function allParams(mixed $request): array
    {
        if (is_object($request) && method_exists($request, 'get_json_params')) {
            $params = $request->get_json_params();
            return is_array($params) ? $params : [];
        }
        return is_array($request) ? $request : [];
    }
}
