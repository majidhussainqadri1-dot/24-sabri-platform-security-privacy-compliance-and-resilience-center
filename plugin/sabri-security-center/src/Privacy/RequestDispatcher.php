<?php

declare(strict_types=1);

namespace Sabri\Platform\Security\Privacy;

use Sabri\Platform\Security\Registry\ModuleRegistry;
use Sabri\Platform\Security\Storage\AuditGapStore;
use Sabri\Platform\Security\Storage\AuditLogger;
use Sabri\Platform\Security\Storage\PrivacyRequestRepository;
use Sabri\Platform\Security\Support\Sanitizer;

if (! class_exists(AuditGapStore::class, false)) {
    require_once dirname(__DIR__) . '/Storage/AuditGapStore.php';
}

final class RequestDispatcher
{
    private PrivacyRequestPolicy $requests;

    public function __construct(
        private AuditLogger $audit,
        private ModuleRegistry $modules,
        PrivacyRequestPolicy|PrivacyRequestRepository|null $requests = null
    ) {
        if (! class_exists(PrivacyRequestRepository::class, false)) {
            require_once dirname(__DIR__) . '/Storage/PrivacyRequestRepository.php';
        }
        if (! class_exists(PrivacyRequestPolicy::class, false)) {
            require_once __DIR__ . '/PrivacyRequestPolicy.php';
        }
        $this->requests = $requests instanceof PrivacyRequestPolicy
            ? $requests
            : new PrivacyRequestPolicy($requests instanceof PrivacyRequestRepository ? $requests : new PrivacyRequestRepository());
    }

    public function registerHooks(): void
    {
        add_action('spcrc/dispatch_privacy_request', [$this, 'dispatch'], 10, 2);
        add_filter('spcrc/privacy_request_dispatch', [$this, 'filterDispatch'], 10, 3);
        add_filter('spcrc/privacy_request_retry', [$this, 'filterRetry'], 10, 4);
        add_filter('spcrc/privacy_request_module_result', [$this, 'filterModuleResult'], 10, 4);
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

    /** @param array<string,mixed> $authorization
     *  @return array<string,mixed>
     */
    public function filterRetry(mixed $current, string $requestUuid, int $assignedUserId = 0, array $authorization = []): array
    {
        if ($current !== null) {
            return is_array($current)
                ? $current
                : ['ok' => false, 'status' => 'failed', 'error' => 'invalid_upstream_privacy_retry_result'];
        }
        return $this->retry($requestUuid, $assignedUserId, $authorization);
    }

    /** @param array<string,mixed> $result
     *  @return array<string,mixed>
     */
    public function filterModuleResult(mixed $current, string $requestUuid, string $moduleKey, array $result): array
    {
        if ($current !== null) {
            return is_array($current)
                ? $current
                : ['ok' => false, 'status' => 'failed', 'error' => 'invalid_upstream_privacy_callback_result'];
        }
        return $this->completeModule($requestUuid, $moduleKey, $result);
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
        if (! in_array($requestType, PrivacyRequestPolicy::types(), true)) {
            return ['ok' => false, 'request_uuid' => $requestId, 'status' => 'failed', 'error' => 'invalid_request_type'];
        }

        $moduleKeys = $this->moduleKeys($moduleKeys);
        if ($moduleKeys === []) {
            return ['ok' => false, 'request_uuid' => $requestId, 'status' => 'failed', 'error' => 'no_modules_requested'];
        }

        $preflight = $this->preflightModules($moduleKeys, $requestType);
        if (is_wp_error($preflight)) {
            return $this->rejectedResponse($requestId, $requestType, $preflight, 'privacy_request_preflight_rejected');
        }

        $begin = $this->requests->begin([
            'request_uuid' => $requestId,
            'request_type' => $requestType,
            'requester_user_id' => $request['requester_user_id'] ?? 0,
            'assigned_user_id' => $request['assigned_user_id'] ?? get_current_user_id(),
            'jurisdiction' => $request['jurisdiction'] ?? '',
            'due_at' => $request['due_at'] ?? '',
            'verification_method' => $request['verification_method'] ?? '',
            'authority_basis' => $request['authority_basis'] ?? '',
            'verification_reference' => $request['verification_reference'] ?? '',
            'verified_by_user_id' => $request['verified_by_user_id'] ?? 0,
            'verified_at' => $request['verified_at'] ?? '',
            'verification_attested' => $request['verification_attested'] ?? false,
            'module_keys' => $moduleKeys,
        ]);
        if (is_wp_error($begin)) {
            return $this->rejectedResponse($requestId, $requestType, $begin);
        }

        $this->runModules(
            $requestId,
            $moduleKeys,
            $requestType,
            [
                'request_uuid' => $requestId,
                'request_type' => $requestType,
                'requester_user_id' => absint($begin['requester_user_id'] ?? 0),
                'jurisdiction' => Sanitizer::text($begin['jurisdiction'] ?? '', 80),
                'due_at' => Sanitizer::isoTime($begin['due_at'] ?? ''),
                'verification_method' => Sanitizer::key($begin['verification_method'] ?? '', 40),
                'authority_basis' => Sanitizer::key($begin['authority_basis'] ?? '', 40),
                'verification_reference' => Sanitizer::text($begin['verification_reference'] ?? '', 200),
                'verified_by_user_id' => absint($begin['verified_by_user_id'] ?? 0),
                'verified_at' => Sanitizer::isoTime($begin['verified_at'] ?? ''),
            ]
        );

        return $this->finalizeResponse($requestId, $requestType, 'dispatching');
    }

    /** @return array<string,mixed> */
    public function retry(string $requestUuid, int $assignedUserId = 0, array $authorization = []): array
    {
        $requestUuid = Sanitizer::uuid($requestUuid);
        $claim = $this->requests->claimRetry($requestUuid, $assignedUserId > 0 ? $assignedUserId : get_current_user_id(), $authorization);
        if (is_wp_error($claim)) {
            return $this->rejectedResponse($requestUuid, '', $claim, 'privacy_request_retry_rejected');
        }

        $requestType = Sanitizer::key($claim['request_type'] ?? '', 40);
        $retryModules = $this->moduleKeys($claim['retry_modules'] ?? []);
        $this->runModules(
            $requestUuid,
            $retryModules,
            $requestType,
            [
                'request_uuid' => $requestUuid,
                'request_type' => $requestType,
                'requester_user_id' => absint($claim['requester_user_id'] ?? 0),
                'jurisdiction' => Sanitizer::text($claim['jurisdiction'] ?? '', 80),
                'due_at' => Sanitizer::isoTime($claim['due_at'] ?? ''),
                'verification_method' => Sanitizer::key($claim['verification_method'] ?? '', 40),
                'authority_basis' => Sanitizer::key($claim['authority_basis'] ?? '', 40),
                'verification_reference' => Sanitizer::text($claim['verification_reference'] ?? '', 200),
                'verified_by_user_id' => absint($claim['verified_by_user_id'] ?? 0),
                'verified_at' => Sanitizer::isoTime($claim['verified_at'] ?? ''),
                'retry' => true,
            ]
        );

        $response = $this->finalizeResponse($requestUuid, $requestType, 'dispatching');
        $audit = $this->recordAudit(
            'privacy_request_retry_dispatched',
            'file-24-security-center',
            Sanitizer::key($response['status'] ?? 'failed', 40),
            ! empty($response['ok']) ? 'informational' : 'medium',
            ['request_uuid' => $requestUuid, 'modules' => $retryModules]
        );
        if (is_wp_error($audit)) {
            $response['ok'] = false;
            $response['status'] = 'audit-evidence-missing';
            $response['error'] = 'spcrc_privacy_audit_gap';
        }
        return $response;
    }

    /** @param array<string,mixed> $result
     *  @return array<string,mixed>
     */
    public function completeModule(string $requestUuid, string $moduleKey, array $result): array
    {
        $stored = $this->requests->completeModule($requestUuid, $moduleKey, $result);
        if (is_wp_error($stored)) {
            $this->recordAudit(
                'privacy_request_module_callback_rejected',
                Sanitizer::key($moduleKey, 120),
                'blocked',
                'medium',
                [
                    'request_uuid' => Sanitizer::uuid($requestUuid),
                    'error_code' => $stored->get_error_code(),
                ]
            );
            return [
                'ok' => false,
                'request_uuid' => Sanitizer::uuid($requestUuid),
                'module_key' => Sanitizer::key($moduleKey, 120),
                'status' => 'failed',
                'error' => $stored->get_error_code(),
                'message' => Sanitizer::text($stored->get_error_message(), 300),
            ];
        }

        $audit = $this->recordAudit(
            'privacy_request_module_callback_stored',
            Sanitizer::key($moduleKey, 120),
            Sanitizer::key($stored['status'] ?? 'pending', 40),
            ! empty($stored['ok']) ? 'informational' : (Sanitizer::key($stored['status'] ?? '', 40) === 'recovery-required' ? 'high' : 'medium'),
            ['request_uuid' => Sanitizer::uuid($requestUuid)]
        );
        do_action('spcrc/privacy_request_module_result_stored', $requestUuid, $moduleKey, $stored);

        if (is_wp_error($audit)) {
            return [
                'ok' => false,
                'request_uuid' => Sanitizer::uuid($requestUuid),
                'module_key' => Sanitizer::key($moduleKey, 120),
                'status' => 'audit-evidence-missing',
                'error' => 'spcrc_privacy_audit_gap',
            ];
        }

        return [
            'ok' => ! empty($stored['ok']),
            'request_uuid' => Sanitizer::uuid($requestUuid),
            'module_key' => Sanitizer::key($moduleKey, 120),
            'status' => Sanitizer::key($stored['status'] ?? 'pending', 40),
        ];
    }

    /** @param string[] $moduleKeys
     *  @param array<string,mixed> $context
     */
    private function runModules(string $requestUuid, array $moduleKeys, string $requestType, array $context): void
    {
        foreach ($moduleKeys as $moduleKey) {
            $claimed = $this->requests->claimModule($requestUuid, $moduleKey);
            if (is_wp_error($claimed)) {
                $this->recordAudit(
                    'privacy_request_module_claim_failed',
                    $moduleKey,
                    'recovery-required',
                    'high',
                    ['request_uuid' => $requestUuid, 'error_code' => $claimed->get_error_code()]
                );
                continue;
            }

            $manifest = $this->modules->get($moduleKey);
            if ($manifest === null) {
                $result = ['ok' => false, 'status' => 'failed', 'code' => 'unknown_module', 'message' => 'Module is not registered.', 'retry_safe' => false];
            } elseif (! in_array($requestType, (array) ($manifest['privacy_operations'] ?? []), true)) {
                $result = ['ok' => false, 'status' => 'failed', 'code' => 'operation_not_declared', 'message' => 'Module did not declare this privacy operation.', 'retry_safe' => false];
            } else {
                try {
                    $nativeResult = apply_filters("spcrc/privacy_request/{$moduleKey}", null, $requestType, $context);
                    $result = $this->normalizeResult($nativeResult);
                } catch (\Throwable $exception) {
                    $result = [
                        'ok' => false,
                        'status' => 'recovery-required',
                        'code' => 'handler_exception',
                        'message' => 'Native privacy handler failed after dispatch; manual reconciliation is required before retry.',
                        'retry_safe' => false,
                    ];
                    do_action('spcrc/privacy_request_handler_exception', $moduleKey, $requestType, $exception);
                }
            }

            $stored = $this->requests->storeModuleResult($requestUuid, $moduleKey, $result);
            if (is_wp_error($stored)) {
                $this->recordAudit(
                    'privacy_request_module_result_storage_failed',
                    $moduleKey,
                    'recovery-required',
                    'high',
                    ['request_uuid' => $requestUuid, 'error_code' => $stored->get_error_code()]
                );
                do_action('spcrc/privacy_request_module_reconciliation_required', $requestUuid, $moduleKey, $result, $stored);
            }
        }
    }

    /** @return array<string,mixed> */
    private function finalizeResponse(string $requestId, string $requestType, string $expectedStatus): array
    {
        $results = $this->requests->moduleResults($requestId);
        $aggregate = PrivacyRequestPolicy::aggregateResults($results);
        $errorCode = $this->firstFailureCode($results);
        $finalized = $this->requests->finalize($requestId, $aggregate['status'], $expectedStatus, $errorCode);
        if (is_wp_error($finalized)) {
            $this->recordAudit(
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

        $audit = $this->recordAudit(
            'privacy_request_dispatched',
            'file-24-security-center',
            $aggregate['status'],
            $aggregate['ok'] ? 'informational' : ($aggregate['status'] === 'storage-failed' ? 'high' : 'medium'),
            ['request_uuid' => $requestId, 'request_type' => $requestType, 'modules' => array_keys($results)]
        );
        if (is_wp_error($audit)) {
            $aggregate = ['ok' => false, 'status' => 'audit-evidence-missing'];
        }

        $response = [
            'ok' => $aggregate['ok'],
            'request_uuid' => $requestId,
            'status' => $aggregate['status'],
            'results' => $results,
        ];
        do_action('spcrc/privacy_request_dispatched', $response);
        return $response;
    }

    private function rejectedResponse(string $requestId, string $requestType, \WP_Error $error, string $event = 'privacy_request_rejected_before_dispatch'): array
    {
        $this->recordAudit(
            $event,
            'file-24-security-center',
            'blocked',
            'medium',
            ['request_uuid' => $requestId, 'request_type' => $requestType, 'error_code' => $error->get_error_code()]
        );

        return [
            'ok' => false,
            'request_uuid' => $requestId,
            'status' => 'failed',
            'error' => $error->get_error_code(),
            'message' => Sanitizer::text($error->get_error_message(), 300),
        ];
    }

    /** @return array<string,mixed> */
    private function normalizeResult(mixed $result): array
    {
        if (is_wp_error($result)) {
            return [
                'ok' => false,
                'status' => 'recovery-required',
                'code' => Sanitizer::key($result->get_error_code(), 120),
                'message' => 'Native privacy handler reported failure after dispatch; manual reconciliation is required before retry.',
                'retry_safe' => false,
            ];
        }

        if ($result === null) {
            return ['ok' => false, 'status' => 'failed', 'code' => 'handler_missing', 'message' => 'No privacy handler accepted the request.', 'retry_safe' => false];
        }

        if (is_array($result)) {
            $ok = Sanitizer::boolean($result['ok'] ?? false);
            $status = Sanitizer::key($result['status'] ?? '', 40);
            $allowed = ['completed', 'pending', 'queued', 'accepted', 'rejected', 'failed', 'unavailable'];
            if (! in_array($status, $allowed, true)) {
                $status = $ok ? 'accepted' : 'failed';
            }
            $retrySafe = Sanitizer::boolean($result['retry_safe'] ?? false);
            if (! $ok && in_array($status, ['failed', 'rejected', 'unavailable'], true) && ! $retrySafe) {
                $status = 'recovery-required';
            }

            return [
                'ok' => $ok,
                'status' => $status,
                'code' => Sanitizer::key($result['code'] ?? '', 120),
                'reference' => Sanitizer::opaqueReference($result['reference'] ?? '', 200),
                'message' => Sanitizer::text($result['message'] ?? '', 300),
                'retry_safe' => $retrySafe,
            ];
        }

        if (is_bool($result)) {
            return $result
                ? ['ok' => true, 'status' => 'accepted', 'code' => '', 'retry_safe' => false]
                : ['ok' => false, 'status' => 'recovery-required', 'code' => 'ambiguous_native_failure', 'message' => 'Native handler returned an ambiguous failure; reconciliation is required.', 'retry_safe' => false];
        }

        return ['ok' => false, 'status' => 'recovery-required', 'code' => 'invalid_handler_response', 'message' => 'Privacy handler returned an invalid response after dispatch; reconciliation is required.', 'retry_safe' => false];
    }

    /** @param array<string,array<string,mixed>> $results */
    private function firstFailureCode(array $results): string
    {
        foreach ($results as $result) {
            if (! Sanitizer::boolean($result['ok'] ?? false)) {
                return Sanitizer::key($result['code'] ?? 'module_failed', 120);
            }
        }
        return '';
    }

    /** @param string[] $moduleKeys
     *  @return bool|\WP_Error
     */
    private function preflightModules(array $moduleKeys, string $requestType): bool|\WP_Error
    {
        foreach ($moduleKeys as $moduleKey) {
            $manifest = $this->modules->get($moduleKey);
            if ($manifest === null) {
                return new \WP_Error(
                    'spcrc_privacy_module_unknown',
                    sprintf('Privacy module is not registered: %s', $moduleKey)
                );
            }
            if (! in_array($requestType, (array) ($manifest['privacy_operations'] ?? []), true)) {
                return new \WP_Error(
                    'spcrc_privacy_operation_not_declared',
                    sprintf('Module %s did not declare privacy operation %s.', $moduleKey, $requestType)
                );
            }
        }

        return true;
    }

    /** @return string[] */
    private function moduleKeys(mixed $moduleKeys): array
    {
        if (! is_array($moduleKeys)) {
            return [];
        }

        return array_values(array_unique(array_filter(array_map(
            static fn (mixed $key): string => Sanitizer::key($key, 120),
            array_slice($moduleKeys, 0, 100)
        ))));
    }
    /** @param array<string,mixed> $context
     *  @return string|\WP_Error
     */
    private function recordAudit(
        string $eventType,
        string $moduleKey,
        string $result = 'recorded',
        string $riskLevel = 'low',
        array $context = []
    ): string|\WP_Error {
        $recorded = $this->audit->record($eventType, $moduleKey, $result, $riskLevel, $context);
        if (is_wp_error($recorded)) {
            $entityId = Sanitizer::uuid($context['request_uuid'] ?? '');
            AuditGapStore::record(
                'spcrc_privacy_audit_gap',
                'privacy_request',
                $entityId !== '' ? $entityId : Sanitizer::key($eventType, 120),
                'audit_write_failed',
                ['event_type' => $eventType, 'module_key' => $moduleKey]
            );
        }
        return $recorded;
    }

}
