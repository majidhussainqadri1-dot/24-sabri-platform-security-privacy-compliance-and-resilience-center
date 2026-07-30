<?php

declare(strict_types=1);

namespace Sabri\Platform\Security\Privacy;

use Sabri\Platform\Security\Storage\AuditLogger;

final class RequestDispatcher
{
    public function __construct(private AuditLogger $audit)
    {
    }

    public function registerHooks(): void
    {
        add_action('spcrc/dispatch_privacy_request', [$this, 'dispatch'], 10, 2);
    }

    /**
     * @param array<string,mixed> $request
     * @param array<int,string> $moduleKeys
     * @return array<string,mixed>
     */
    public function dispatch(array $request, array $moduleKeys = []): array
    {
        $requestId = sanitize_text_field((string) ($request['request_uuid'] ?? wp_generate_uuid4()));
        $requestType = sanitize_key((string) ($request['request_type'] ?? 'access'));
        $allowed = ['access', 'correction', 'deletion', 'portability', 'restriction', 'objection', 'consent-withdrawal'];

        if (! in_array($requestType, $allowed, true)) {
            return ['ok' => false, 'request_uuid' => $requestId, 'error' => 'invalid_request_type'];
        }

        $results = [];
        foreach ($moduleKeys as $moduleKey) {
            $moduleKey = sanitize_key((string) $moduleKey);
            if ($moduleKey === '') {
                continue;
            }

            $result = apply_filters("spcrc/privacy_request/{$moduleKey}", null, $requestType, $request);
            $results[$moduleKey] = $this->normalizeResult($result);
        }

        $this->audit->record(
            'privacy_request_dispatched',
            'file-24-security-center',
            'dispatched',
            'medium',
            ['request_uuid' => $requestId, 'request_type' => $requestType, 'modules' => array_keys($results)]
        );

        return ['ok' => true, 'request_uuid' => $requestId, 'results' => $results];
    }

    /** @return array<string,mixed> */
    private function normalizeResult($result): array
    {
        if (is_wp_error($result)) {
            return ['ok' => false, 'code' => $result->get_error_code(), 'message' => $result->get_error_message()];
        }

        if (is_array($result)) {
            return ['ok' => (bool) ($result['ok'] ?? true)] + $result;
        }

        return ['ok' => $result !== false, 'status' => is_scalar($result) ? (string) $result : 'accepted'];
    }
}
