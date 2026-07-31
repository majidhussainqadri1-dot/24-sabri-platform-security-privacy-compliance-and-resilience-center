<?php

declare(strict_types=1);

namespace Sabri\Platform\Security\Storage;

use Sabri\Platform\Security\Support\Sanitizer;

final class PrivacyRequestRepository
{
    private const TYPES = ['access', 'correction', 'deletion', 'portability', 'restriction', 'objection', 'consent-withdrawal'];
    private const FINAL_STATUSES = ['completed', 'pending', 'partial', 'failed'];
    private const ACTIVE_STATUSES = ['received', 'dispatching', 'pending', 'partial'];

    /** @return string[] */
    public static function types(): array
    {
        return self::TYPES;
    }

    /**
     * Creates the durable pre-dispatch record or atomically advances a received request.
     * No native-module privacy operation may run unless this method succeeds.
     *
     * @param array<string,mixed> $request
     * @return array<string,mixed>|\WP_Error
     */
    public function begin(array $request): array|\WP_Error
    {
        global $wpdb;

        $requestUuid = Sanitizer::uuid($request['request_uuid'] ?? '');
        if ($requestUuid === '') {
            $requestUuid = wp_generate_uuid4();
        }

        $requestType = Sanitizer::key($request['request_type'] ?? '', 40);
        if (! in_array($requestType, self::TYPES, true)) {
            return new \WP_Error('spcrc_privacy_type_invalid', 'Privacy request type is invalid.');
        }

        $requesterUserId = absint($request['requester_user_id'] ?? 0);
        if ($requesterUserId < 1 || ! get_userdata($requesterUserId)) {
            return new \WP_Error('spcrc_privacy_subject_unverified', 'A verified WordPress privacy subject is required before dispatch.');
        }

        $jurisdiction = Sanitizer::text($request['jurisdiction'] ?? '', 80);
        $dueAt = Sanitizer::isoTime($request['due_at'] ?? '');
        $assignedUserId = absint($request['assigned_user_id'] ?? get_current_user_id()) ?: null;
        $table = $wpdb->prefix . 'spcrc_privacy_requests';
        $existing = $this->get($requestUuid);

        if ($existing !== null) {
            if (
                absint($existing['requester_user_id'] ?? 0) !== $requesterUserId
                || Sanitizer::key($existing['request_type'] ?? '', 40) !== $requestType
            ) {
                do_action('spcrc/privacy_request_collision', $requestUuid, $requesterUserId, $requestType);
                return new \WP_Error('spcrc_privacy_request_collision', 'Privacy request UUID is already bound to another subject or type.');
            }

            $existingStatus = Sanitizer::key($existing['status'] ?? '', 40);
            if ($existingStatus !== 'received') {
                return new \WP_Error(
                    $existingStatus === 'dispatching' ? 'spcrc_privacy_already_dispatching' : 'spcrc_privacy_already_processed',
                    $existingStatus === 'dispatching'
                        ? 'Privacy request is already dispatching.'
                        : 'Privacy request UUID has already been processed and cannot be replayed.'
                );
            }

            $updated = $wpdb->update(
                $table,
                [
                    'status' => 'dispatching',
                    'assigned_user_id' => $assignedUserId,
                    'jurisdiction' => $jurisdiction,
                    'due_at' => $this->mysqlTime($dueAt),
                    'updated_at' => current_time('mysql', true),
                ],
                ['request_uuid' => $requestUuid, 'status' => 'received'],
                ['%s', '%d', '%s', '%s', '%s'],
                ['%s', '%s']
            );
            if ($updated === false) {
                return new \WP_Error('spcrc_privacy_begin_failed', 'Privacy request could not enter dispatching state.');
            }
            if ($updated !== 1) {
                return new \WP_Error('spcrc_privacy_concurrent_change', 'Privacy request changed concurrently. Refresh and try again.');
            }
        } else {
            $now = current_time('mysql', true);
            $inserted = $wpdb->insert(
                $table,
                [
                    'request_uuid' => $requestUuid,
                    'requester_user_id' => $requesterUserId,
                    'request_type' => $requestType,
                    'status' => 'dispatching',
                    'assigned_user_id' => $assignedUserId,
                    'jurisdiction' => $jurisdiction,
                    'due_at' => $this->mysqlTime($dueAt),
                    'created_at' => $now,
                    'updated_at' => $now,
                ],
                ['%s', '%d', '%s', '%s', '%d', '%s', '%s', '%s', '%s']
            );
            if ($inserted === false) {
                $raced = $this->get($requestUuid);
                return new \WP_Error(
                    $raced === null ? 'spcrc_privacy_begin_failed' : 'spcrc_privacy_concurrent_change',
                    $raced === null
                        ? 'Privacy request metadata could not be stored before dispatch.'
                        : 'Privacy request UUID was claimed concurrently. No module operation was dispatched.'
                );
            }
        }

        return [
            'request_uuid' => $requestUuid,
            'requester_user_id' => $requesterUserId,
            'request_type' => $requestType,
            'status' => 'dispatching',
            'assigned_user_id' => $assignedUserId,
            'jurisdiction' => $jurisdiction,
            'due_at' => $dueAt,
        ];
    }

    /** @return true|\WP_Error */
    public function finalize(string $requestUuid, string $status, string $expectedStatus = 'dispatching'): true|\WP_Error
    {
        global $wpdb;

        $requestUuid = Sanitizer::uuid($requestUuid);
        $status = Sanitizer::key($status, 40);
        $expectedStatus = Sanitizer::key($expectedStatus, 40);
        if ($requestUuid === '' || ! in_array($status, self::FINAL_STATUSES, true) || $expectedStatus === '') {
            return new \WP_Error('spcrc_privacy_finalize_invalid', 'Privacy request final state is invalid.');
        }

        $updated = $wpdb->update(
            $wpdb->prefix . 'spcrc_privacy_requests',
            ['status' => $status, 'updated_at' => current_time('mysql', true)],
            ['request_uuid' => $requestUuid, 'status' => $expectedStatus],
            ['%s', '%s'],
            ['%s', '%s']
        );
        if ($updated === false) {
            return new \WP_Error('spcrc_privacy_finalize_failed', 'Privacy request final state could not be stored.');
        }
        if ($updated !== 1) {
            return new \WP_Error('spcrc_privacy_finalize_concurrent', 'Privacy request changed before finalization.');
        }

        return true;
    }

    /** @return array<string,mixed>|null */
    public function get(string $requestUuid): ?array
    {
        global $wpdb;

        $requestUuid = Sanitizer::uuid($requestUuid);
        if ($requestUuid === '') {
            return null;
        }

        $row = $wpdb->get_row(
            $wpdb->prepare(
                "SELECT request_uuid, requester_user_id, request_type, status, assigned_user_id, jurisdiction, due_at, created_at, updated_at FROM {$wpdb->prefix}spcrc_privacy_requests WHERE request_uuid = %s",
                $requestUuid
            ),
            ARRAY_A
        );

        return is_array($row) ? $row : null;
    }

    public function activeCount(): int
    {
        global $wpdb;

        $statuses = "'" . implode("','", self::ACTIVE_STATUSES) . "'";
        return (int) $wpdb->get_var(
            "SELECT COUNT(*) FROM {$wpdb->prefix}spcrc_privacy_requests WHERE status IN ({$statuses})"
        );
    }

    /** @return array<int,array<string,mixed>> */
    public function recent(int $limit = 50): array
    {
        global $wpdb;

        $limit = max(1, min(100, $limit));
        $rows = $wpdb->get_results(
            $wpdb->prepare(
                "SELECT request_uuid, requester_user_id, request_type, status, assigned_user_id, jurisdiction, due_at, created_at, updated_at FROM {$wpdb->prefix}spcrc_privacy_requests ORDER BY updated_at DESC LIMIT %d",
                $limit
            ),
            ARRAY_A
        );

        return is_array($rows) ? $rows : [];
    }

    private function mysqlTime(string $isoTime): ?string
    {
        if ($isoTime === '') {
            return null;
        }

        $timestamp = strtotime($isoTime);
        return $timestamp === false ? null : gmdate('Y-m-d H:i:s', $timestamp);
    }
}
