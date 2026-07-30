<?php

declare(strict_types=1);

namespace Sabri\Platform\Security\Privacy;

use Sabri\Platform\Security\Storage\AuditLogger;
use Sabri\Platform\Security\Storage\Schema;

final class RequestDispatcher
{
    private const ALLOWED_TYPES = [
        'access',
        'correction',
        'deletion',
        'portability',
        'restriction',
        'objection',
        'consent-withdrawal',
    ];

    public function __construct(private AuditLogger $audit)
    {
    }

    public function registerHooks(): void
    {
        add_action('spcrc/dispatch_privacy_request', [$this, 'dispatchAction'], 10, 2);
        add_filter('spcrc/privacy_dispatch', [$this, 'dispatchFilter'], 10, 3);
    }

    /** @param array<string,mixed> $request
     *  @param string[] $moduleKeys
     */
    public function dispatchAction(array $request, array $moduleKeys = []): void
    {
        $result = $this->dispatch($request, $moduleKeys);
        $metadata = [
            'request_uuid' => (string) ($result['request_uuid'] ?? ''),
            'request_type' => sanitize_key((string) ($request['request_type'] ?? 'access')),
        ];
        do_action('spcrc/privacy_request_dispatch_completed', $result, $metadata, $moduleKeys);
    }

    /** @param mixed $current
     *  @param array<string,mixed> $request
     *  @param string[] $moduleKeys
     *  @return array<string,mixed>
     */
    public function dispatchFilter($current, array $request, array $moduleKeys = []): array
    {
        return $this->dispatch($request, $moduleKeys);
    }

    /** @param array<string,mixed> $request
     *  @param string[] $moduleKeys
     *  @return array<string,mixed>
     */
    public function dispatch(array $request, array $moduleKeys = []): array
    {
        global $wpdb;

        $requestId = sanitize_text_field((string) ($request['request_uuid'] ?? ''));
        if ($requestId === '') {
            $requestId = wp_generate_uuid4();
        }
        if (! $this->isUuid($requestId)) {
            return ['ok' => false, 'request_uuid' => $requestId, 'error' => 'invalid_request_uuid'];
        }

        $requestType = sanitize_key((string) ($request['request_type'] ?? 'access'));
        if (! in_array($requestType, self::ALLOWED_TYPES, true)) {
            return ['ok' => false, 'request_uuid' => $requestId, 'error' => 'invalid_request_type'];
        }

        $moduleKeys = array_values(array_unique(array_filter(array_map(
            fn ($key): string => $this->truncate(sanitize_key((string) $key), 120),
            array_slice($moduleKeys, 0, 100)
        ))));
        if ($moduleKeys === []) {
            return ['ok' => false, 'request_uuid' => $requestId, 'error' => 'no_modules_requested'];
        }

        $requester = max(0, (int) ($request['requester_user_id'] ?? get_current_user_id()));
        $jurisdiction = $this->truncate(sanitize_text_field((string) ($request['jurisdiction'] ?? '')), 80);
        $rawDueAt = (string) ($request['due_at'] ?? '');
        $dueAt = $this->normalizeDate($rawDueAt);
        if ($rawDueAt !== '' && $dueAt === null) {
            return ['ok' => false, 'request_uuid' => $requestId, 'error' => 'invalid_due_at'];
        }

        $now = current_time('mysql', true);
        $table = Schema::tables()['privacy'];
        $existing = $wpdb->get_row(
            $wpdb->prepare("SELECT id, requester_user_id, request_type, status FROM {$table} WHERE request_uuid = %s", $requestId),
            ARRAY_A
        );
        $existingId = is_array($existing) ? (int) ($existing['id'] ?? 0) : 0;

        if ($existingId > 0) {
            if ((int) ($existing['requester_user_id'] ?? 0) !== $requester || (string) ($existing['request_type'] ?? '') !== $requestType) {
                return ['ok' => false, 'request_uuid' => $requestId, 'error' => 'request_uuid_conflict'];
            }

            $existingStatus = sanitize_key((string) ($existing['status'] ?? 'received'));
            $retryRequested = (bool) ($request['retry'] ?? false);
            $retryAuthorized = $retryRequested && (
                current_user_can('spcrc_manage_privacy_requests')
                || (bool) apply_filters('spcrc/privacy_retry_authorized', false, $requestId, $existingStatus)
            );

            if (! $retryAuthorized || $existingStatus === 'dispatching') {
                return [
                    'ok' => $existingStatus === 'completed',
                    'request_uuid' => $requestId,
                    'status' => $existingStatus,
                    'replayed' => true,
                    'error' => $existingStatus === 'completed' ? '' : 'request_already_exists',
                ];
            }

            $persisted = $wpdb->update(
                $table,
                [
                    'status' => 'dispatching',
                    'jurisdiction' => $jurisdiction,
                    'due_at' => $dueAt,
                    'updated_at' => $now,
                ],
                ['id' => $existingId],
                ['%s', '%s', '%s', '%s'],
                ['%d']
            );
        } else {
            $persisted = $wpdb->insert(
                $table,
                [
                    'request_uuid' => $requestId,
                    'requester_user_id' => $requester,
                    'request_type' => $requestType,
                    'status' => 'dispatching',
                    'assigned_user_id' => 0,
                    'jurisdiction' => $jurisdiction,
                    'due_at' => $dueAt,
                    'created_at' => $now,
                    'updated_at' => $now,
                ],
                ['%s', '%d', '%s', '%s', '%d', '%s', '%s', '%s', '%s']
            );
        }

        if ($persisted === false) {
            return ['ok' => false, 'request_uuid' => $requestId, 'error' => 'request_persistence_failed'];
        }

        // Only bounded orchestration metadata is sent to modules. Arbitrary request payloads never fan out.
        $dispatchMetadata = [
            'request_uuid' => $requestId,
            'request_type' => $requestType,
            'requester_user_id' => $requester,
            'jurisdiction' => $jurisdiction,
            'due_at' => $dueAt,
            'evidence_ref' => $this->truncate(sanitize_text_field((string) ($request['evidence_ref'] ?? '')), 255),
        ];

        $results = [];
        foreach ($moduleKeys as $moduleKey) {
            $result = apply_filters("spcrc/privacy_request/{$moduleKey}", null, $requestType, $dispatchMetadata);
            $results[$moduleKey] = $this->normalizeResult($result);
        }

        $successes = count(array_filter($results, static fn (array $result): bool => (bool) ($result['ok'] ?? false)));
        $status = $successes === count($results) ? 'completed' : ($successes > 0 ? 'partial' : 'failed');
        $statusUpdated = $wpdb->update(
            $table,
            ['status' => $status, 'updated_at' => current_time('mysql', true)],
            ['request_uuid' => $requestId],
            ['%s', '%s'],
            ['%s']
        );
        if ($statusUpdated === false) {
            $this->audit->record('privacy_request_status_persist_failed', 'file-24-security-center', 'failed', 'high', [
                'request_uuid' => $requestId,
                'intended_status' => $status,
            ]);
            return [
                'ok' => false,
                'request_uuid' => $requestId,
                'error' => 'request_status_persistence_failed',
                'results' => $results,
            ];
        }

        $this->audit->record(
            'privacy_request_dispatched',
            'file-24-security-center',
            $status,
            $status === 'completed' ? 'medium' : 'high',
            [
                'request_uuid' => $requestId,
                'request_type' => $requestType,
                'modules' => array_keys($results),
                'successful_modules' => $successes,
            ]
        );

        return [
            'ok' => $status === 'completed',
            'request_uuid' => $requestId,
            'status' => $status,
            'results' => $results,
        ];
    }

    /** @return array<string,mixed> */
    private function normalizeResult($result): array
    {
        if ($result === null) {
            return ['ok' => false, 'code' => 'not_handled', 'message' => 'No module handler responded.'];
        }

        if (is_wp_error($result)) {
            return [
                'ok' => false,
                'code' => sanitize_key((string) $result->get_error_code()),
                'message' => $this->truncate(sanitize_text_field((string) $result->get_error_message()), 500),
            ];
        }

        if (is_array($result)) {
            $allowed = ['ok', 'status', 'code', 'message', 'evidence_ref', 'count'];
            $normalized = [];
            foreach ($allowed as $key) {
                if (array_key_exists($key, $result) && (is_scalar($result[$key]) || $result[$key] === null)) {
                    $normalized[$key] = is_string($result[$key])
                        ? $this->truncate(sanitize_text_field($result[$key]), $key === 'message' ? 500 : 255)
                        : $result[$key];
                }
            }
            $normalized['ok'] = (bool) ($result['ok'] ?? false);
            return $normalized;
        }

        if (is_bool($result)) {
            return ['ok' => $result, 'status' => $result ? 'accepted' : 'rejected'];
        }

        if (is_scalar($result)) {
            return ['ok' => false, 'status' => $this->truncate(sanitize_text_field((string) $result), 255)];
        }

        return ['ok' => false, 'code' => 'invalid_handler_result'];
    }

    private function normalizeDate(string $raw): ?string
    {
        if ($raw === '') {
            return null;
        }

        $timestamp = strtotime($raw);
        return $timestamp === false ? null : gmdate('Y-m-d H:i:s', $timestamp);
    }

    private function isUuid(string $value): bool
    {
        return preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i', $value) === 1;
    }

    private function truncate(string $value, int $length): string
    {
        return function_exists('mb_substr') ? mb_substr($value, 0, $length) : substr($value, 0, $length);
    }
}
