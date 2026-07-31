<?php

declare(strict_types=1);

namespace Sabri\Platform\Security\Privacy;

use Sabri\Platform\Security\Registry\ModuleRegistry;
use Sabri\Platform\Security\Storage\AuditLogger;
use Sabri\Platform\Security\Storage\PrivacyRequestRepository;
use Sabri\Platform\Security\Support\Sanitizer;

final class RequestDispatcher
{
    private PrivacyRequestRepository $requests;

    public function __construct(
        private AuditLogger $audit,
        private ModuleRegistry $modules,
        ?PrivacyRequestRepository $requests = null
    ) {
        if ($requests === null && ! class_exists(PrivacyRequestRepository::class, false)) {
            require_once dirname(__DIR__) . '/Storage/PrivacyRequestRepository.php';
        }
        $this->requests = $requests ?? new PrivacyRequestRepository();
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
        if ($current !== null) {
            return is_array($current)
                ? $current
                : ['ok' => false, 'status' => 'failed', 'error' => 'invalid_upstream_privacy_result'];
        }

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

        $requestType = Sanitizer::key($request['request_type'] ?? '', 40);
        if (! in_array($requestType, PrivacyRequestRepository::types(), true)) {
            return ['ok' => false, 'request_uuid' => $requestId, 'status' => 'failed', 'error' => 'invalid_request_type'];
        }

        $moduleKeys = array_values(array_unique(array_filter(array_map(
            static fn (mixed $key): string => Sanitizer::key($key, 120),
            array_slice($moduleKeys, 0, 100)
        ))));
        if ($moduleKeys === []) {
            return ['ok' => false, 'request_uuid' => $requestId, 'status' => 'failed', 'error' => 'no_modules_requested'];
        }

        $begin = $this->requests->begin([
            'request_uuid' => $requestId,
            'request_type' => $requestType,
            'requester_user_id' => $request['requester_user_id'] ?? 0,
            'assigned_user_id' => $request['assigned_user_id'] ?? get_current_user_id(),
            'jurisdiction' => $request['jurisdiction'] ?? '',
            'due_at' => $request['due_at'] ?? '',
        ]);
        if (is_wp_error($begin)) {
            $this->audit->record(
                'privacy_request_rejected_before_dispatch',
                'file-24-security-center',
                'blocked',
                'medium',
                ['request_uuid' => $requestId, 'request_type' => $requestType, 'error_code' => $begin->get_error_code()]
            );

            return [
                'ok' => false,
                'request_uuid' => $requestId,
                'status' => 'failed',
                'error' => $begin->get_error_code(),
                'message' => Sanitizer::text($begin->get_error_message(), 300),
            ];
        }

        $requesterUserId = absint($begin['requester_user_id'] ?? 0);
        $jurisdiction = Sanitizer::text($begin['jurisdiction'] ?? '', 80);
        $dueAt = Sanitizer::isoTime($begin['due_at'] ?? '');
        $results = [];

        foreach ($moduleKeys as $moduleKey) {
            $manifest = $this->modules->get($moduleKey);
            if ($manifest === null) {
                $results[$moduleKey] = ['ok' => false, 'status' => 'failed', 'code' => 'unknown_module', 'message' => 'Module is not registered.'];
                continue;
            }

            $operations = (array) ($manifest['privacy_operations'] ?? []);
            if (! in_array($requestType, $operations, true)) {
                $results[$moduleKey] = ['ok' => false, 'status' => 'failed', 'code' => 'operation_not_declared', 'message' => 'Module did not declare this privacy operation.'];
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

        $aggregate = $this->aggregate($results);
        $finalized = $this->requests->finalize($requestId, $aggregate['status']);
        if (is_wp_error($finalized)) {
            $this->audit->record(
                'privacy_request_finalization_failed',
                'file-24-security-center',
                'storage-failed',
                'high',
                [
                    'request_uuid' => $requestId,
                    'request_type' => $requestType,
                    'intended_status' => $aggregate['status'],
                    'error_code' => $finalized->get_error_code(),
                ]
            );
            do_action('spcrc/privacy_request_recovery_required', $requestId, $aggregate, $results);
            $aggregate = ['ok' => false, 'status' => 'storage-failed'];
        }

        $this->audit->record(
            'privacy_request_dispatched',
            'file-24-security-center',
            $aggregate['status'],
            $aggregate['ok'] ? 'informational' : ($aggregate['status'] === 'storage-failed' ? 'high' : 'medium'),
            ['request_uuid' => $requestId, 'request_type' => $requestType, 'modules' => array_keys($results)]
        );

        $response = [
            'ok' => $aggregate['ok'],
            'request_uuid' => $requestId,
            'status' => $aggregate['status'],
            'results' => $results,
        ];
        do_action('spcrc/privacy_request_dispatched', $response);
        return $response;
    }

    /** @return array<string,mixed> */
    private function normalizeResult(mixed $result): array
    {
        if (is_wp_error($result)) {
            return [
                'ok' => false,
                'status' => 'failed',
                'code' => Sanitizer::key($result->get_error_code(), 120),
                'message' => Sanitizer::text($result->get_error_message(), 300),
            ];
        }

        if ($result === null) {
            return ['ok' => false, 'status' => 'failed', 'code' => 'handler_missing', 'message' => 'No privacy handler accepted the request.'];
        }

        if (is_array($result)) {
            $ok = Sanitizer::boolean($result['ok'] ?? false);
            $status = Sanitizer::key($result['status'] ?? '', 40);
            $allowed = ['completed', 'pending', 'queued', 'accepted', 'rejected', 'failed', 'unavailable'];
            if (! in_array($status, $allowed, true)) {
                $status = $ok ? 'accepted' : 'failed';
            }

            return [
                'ok' => $ok,
                'status' => $status,
                'reference' => Sanitizer::text($result['reference'] ?? '', 200),
                'message' => Sanitizer::text($result['message'] ?? '', 300),
            ];
        }

        if (is_bool($result)) {
            return ['ok' => $result, 'status' => $result ? 'accepted' : 'failed'];
        }

        return ['ok' => false, 'status' => 'failed', 'code' => 'invalid_handler_response', 'message' => 'Privacy handler returned an invalid response.'];
    }

    /** @param array<string,array<string,mixed>> $results
     *  @return array{ok:bool,status:string}
     */
    private function aggregate(array $results): array
    {
        if ($results === []) {
            return ['ok' => false, 'status' => 'failed'];
        }

        $failed = 0;
        $pending = 0;
        foreach ($results as $result) {
            if (! Sanitizer::boolean($result['ok'] ?? false)) {
                ++$failed;
                continue;
            }
            if (($result['status'] ?? '') !== 'completed') {
                ++$pending;
            }
        }

        if ($failed === count($results)) {
            return ['ok' => false, 'status' => 'failed'];
        }
        if ($failed > 0) {
            return ['ok' => false, 'status' => 'partial'];
        }
        if ($pending > 0) {
            return ['ok' => true, 'status' => 'pending'];
        }

        return ['ok' => true, 'status' => 'completed'];
    }
}
