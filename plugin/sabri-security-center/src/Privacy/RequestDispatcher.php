<?php

declare(strict_types=1);

namespace Sabri\Platform\Security\Privacy;

use Sabri\Platform\Security\Registry\ModuleRegistry;
use Sabri\Platform\Security\Storage\AuditLogger;
use Sabri\Platform\Security\Support\Sanitizer;

final class RequestDispatcher
{
    private const ALLOWED_TYPES = ['access', 'correction', 'deletion', 'portability', 'restriction', 'objection', 'consent-withdrawal'];

    public function __construct(private AuditLogger $audit, private ModuleRegistry $modules)
    {
    }

    public function registerHooks(): void
    {
        add_action('spcrc/dispatch_privacy_request', [$this, 'dispatch'], 10, 2);
        add_filter('spcrc/privacy_request_dispatch', [$this, 'filterDispatch'], 10, 3);
    }

    /** @param mixed $current
     *  @param array<string,mixed> $request
     *  @param string[] $moduleKeys
     *  @return array<string,mixed>
     */
    public function filterDispatch(mixed $current, array $request, array $moduleKeys = []): array
    {
        return $this->dispatch($request, $moduleKeys);
    }

    /** @param array<string,mixed> $request
     *  @param string[] $moduleKeys
     *  @return array<string,mixed>
     */
    public function dispatch(array $request, array $moduleKeys = []): array
    {
        $requestId = Sanitizer::uuid($request['request_uuid'] ?? '');
        if ($requestId === '') {
            $requestId = wp_generate_uuid4();
        }

        $requestType = Sanitizer::key($request['request_type'] ?? 'access', 40);
        if (! in_array($requestType, self::ALLOWED_TYPES, true)) {
            return ['ok' => false, 'request_uuid' => $requestId, 'error' => 'invalid_request_type'];
        }

        $moduleKeys = array_values(array_unique(array_filter(array_map(
            static fn (mixed $key): string => Sanitizer::key($key, 120),
            array_slice($moduleKeys, 0, 100)
        ))));
        if ($moduleKeys === []) {
            return ['ok' => false, 'request_uuid' => $requestId, 'error' => 'no_modules_requested'];
        }

        $requesterUserId = absint($request['requester_user_id'] ?? get_current_user_id());
        $jurisdiction = Sanitizer::text($request['jurisdiction'] ?? '', 80);
        $dueAt = Sanitizer::isoTime($request['due_at'] ?? '');
        $metadataStored = $this->persist($requestId, $requesterUserId, $requestType, 'dispatching', $jurisdiction, $dueAt);

        $results = [];
        foreach ($moduleKeys as $moduleKey) {
            $manifest = $this->modules->get($moduleKey);
            if ($manifest === null) {
                $results[$moduleKey] = ['ok' => false, 'code' => 'unknown_module', 'message' => 'Module is not registered.'];
                continue;
            }

            $operations = (array) ($manifest['privacy_operations'] ?? []);
            if (! in_array($requestType, $operations, true)) {
                $results[$moduleKey] = ['ok' => false, 'code' => 'operation_not_declared', 'message' => 'Module did not declare this privacy operation.'];
                continue;
            }

            $result = apply_filters("spcrc/privacy_request/{$moduleKey}", null, $requestType, [
                'request_uuid' => $requestId,
                'request_type' => $requestType,
                'requester_user_id' => $requesterUserId,
                'jurisdiction' => $jurisdiction,
                'due_at' => $dueAt,
            ]);
            $results[$moduleKey] = $this->normalizeResult($result);
        }

        $successful = array_filter($results, static fn (array $result): bool => (bool) ($result['ok'] ?? false));
        $ok = $results !== [] && count($successful) === count($results);
        $status = $ok ? 'completed' : ($successful === [] ? 'failed' : 'partial');
        $metadataStored = $this->persist($requestId, $requesterUserId, $requestType, $status, $jurisdiction, $dueAt) && $metadataStored;
        if (! $metadataStored) {
            $ok = false;
            $status = 'storage-failed';
        }

        $this->audit->record(
            'privacy_request_dispatched',
            'file-24-security-center',
            $status,
            $ok ? 'informational' : 'medium',
            ['request_uuid' => $requestId, 'request_type' => $requestType, 'modules' => array_keys($results)]
        );

        $response = ['ok' => $ok, 'request_uuid' => $requestId, 'status' => $status, 'results' => $results];
        do_action('spcrc/privacy_request_dispatched', $response);
        return $response;
    }

    /** @return array<string,mixed> */
    private function normalizeResult(mixed $result): array
    {
        if (is_wp_error($result)) {
            return ['ok' => false, 'code' => $result->get_error_code(), 'message' => Sanitizer::text($result->get_error_message(), 300)];
        }

        if ($result === null) {
            return ['ok' => false, 'code' => 'handler_missing', 'message' => 'No privacy handler accepted the request.'];
        }

        if (is_array($result)) {
            return [
                'ok' => Sanitizer::boolean($result['ok'] ?? false),
                'status' => Sanitizer::key($result['status'] ?? '', 40),
                'reference' => Sanitizer::text($result['reference'] ?? '', 200),
                'message' => Sanitizer::text($result['message'] ?? '', 300),
            ];
        }

        if (is_bool($result)) {
            return ['ok' => $result, 'status' => $result ? 'accepted' : 'rejected'];
        }

        return ['ok' => false, 'code' => 'invalid_handler_response', 'message' => 'Privacy handler returned an invalid response.'];
    }

    private function persist(string $requestId, int $requesterUserId, string $requestType, string $status, string $jurisdiction, string $dueAt): bool
    {
        global $wpdb;
        $table = $wpdb->prefix . 'spcrc_privacy_requests';
        $existing = $wpdb->get_row(
            $wpdb->prepare("SELECT id, requester_user_id, request_type FROM {$table} WHERE request_uuid = %s", $requestId),
            ARRAY_A
        );
        if (is_array($existing)) {
            $existingRequester = absint($existing['requester_user_id'] ?? 0);
            $existingType = Sanitizer::key($existing['request_type'] ?? '', 40);
            if ($existingRequester !== $requesterUserId || ($existingType !== '' && $existingType !== $requestType)) {
                do_action('spcrc/privacy_request_collision', $requestId, $requesterUserId, $requestType);
                return false;
            }
        }

        $data = [
            'requester_user_id' => $requesterUserId ?: null,
            'request_type' => $requestType,
            'status' => Sanitizer::key($status, 40),
            'jurisdiction' => $jurisdiction,
            'due_at' => $dueAt !== '' ? gmdate('Y-m-d H:i:s', (int) strtotime($dueAt)) : null,
            'updated_at' => current_time('mysql', true),
        ];

        if (is_array($existing)) {
            return $wpdb->update($table, $data, ['request_uuid' => $requestId], ['%d', '%s', '%s', '%s', '%s', '%s'], ['%s']) !== false;
        }

        $data['request_uuid'] = $requestId;
        $data['created_at'] = current_time('mysql', true);
        return $wpdb->insert($table, $data, ['%d', '%s', '%s', '%s', '%s', '%s', '%s', '%s']) !== false;
    }
}
