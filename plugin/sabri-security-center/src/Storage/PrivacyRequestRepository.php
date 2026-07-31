<?php

declare(strict_types=1);

namespace Sabri\Platform\Security\Storage;

use Sabri\Platform\Security\Support\Sanitizer;

final class PrivacyRequestRepository
{
    private const TYPES = ['access', 'correction', 'deletion', 'portability', 'restriction', 'objection', 'consent-withdrawal'];
    private const REQUEST_STATUSES = ['received', 'dispatching', 'pending', 'partial', 'failed', 'recovery-required', 'completed'];
    private const ACTIVE_STATUSES = ['received', 'dispatching', 'pending', 'partial', 'recovery-required'];
    private const RETRYABLE_REQUEST_STATUSES = ['failed', 'partial', 'recovery-required'];
    private const RETRYABLE_MODULE_STATUSES = ['not-started', 'failed', 'rejected', 'unavailable', 'recovery-required'];
    private const MODULE_STATUSES = ['not-started', 'dispatching', 'completed', 'pending', 'queued', 'accepted', 'failed', 'rejected', 'unavailable', 'recovery-required'];

    /** @return string[] */
    public static function types(): array
    {
        return self::TYPES;
    }

    /** @return string[] */
    public static function retryableStatuses(): array
    {
        return self::RETRYABLE_REQUEST_STATUSES;
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

        $moduleKeys = $this->moduleKeys($request['module_keys'] ?? []);
        if ($moduleKeys === []) {
            return new \WP_Error('spcrc_privacy_modules_required', 'At least one bounded native module is required before dispatch.');
        }

        $moduleResults = [];
        foreach ($moduleKeys as $moduleKey) {
            $moduleResults[$moduleKey] = [
                'ok' => false,
                'status' => 'not-started',
                'code' => '',
                'reference' => '',
                'message' => '',
            ];
        }

        $encodedResults = $this->encodeResults($moduleResults);
        if (is_wp_error($encodedResults)) {
            return $encodedResults;
        }

        $jurisdiction = Sanitizer::text($request['jurisdiction'] ?? '', 80);
        $dueAt = Sanitizer::isoTime($request['due_at'] ?? '');
        $assignedUserId = absint($request['assigned_user_id'] ?? get_current_user_id()) ?: null;
        $table = $wpdb->prefix . 'spcrc_privacy_requests';
        $existing = $this->get($requestUuid);
        $now = current_time('mysql', true);

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

            $lockVersion = absint($existing['lock_version'] ?? 0);
            $updated = $wpdb->update(
                $table,
                [
                    'status' => 'dispatching',
                    'assigned_user_id' => $assignedUserId,
                    'jurisdiction' => $jurisdiction,
                    'due_at' => $this->mysqlTime($dueAt),
                    'module_results_json' => $encodedResults,
                    'dispatch_attempts' => max(1, absint($existing['dispatch_attempts'] ?? 0) + 1),
                    'lock_version' => $lockVersion + 1,
                    'next_retry_at' => null,
                    'last_error_code' => '',
                    'completed_at' => null,
                    'updated_at' => $now,
                ],
                ['request_uuid' => $requestUuid, 'status' => 'received', 'lock_version' => $lockVersion],
                ['%s', '%d', '%s', '%s', '%s', '%d', '%d', '%s', '%s', '%s', '%s'],
                ['%s', '%s', '%d']
            );
            if ($updated === false) {
                return new \WP_Error('spcrc_privacy_begin_failed', 'Privacy request could not enter dispatching state.');
            }
            if ($updated !== 1) {
                return new \WP_Error('spcrc_privacy_concurrent_change', 'Privacy request changed concurrently. Refresh and try again.');
            }
        } else {
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
                    'module_results_json' => $encodedResults,
                    'dispatch_attempts' => 1,
                    'lock_version' => 1,
                    'next_retry_at' => null,
                    'last_error_code' => '',
                    'completed_at' => null,
                    'created_at' => $now,
                    'updated_at' => $now,
                ],
                ['%s', '%d', '%s', '%s', '%d', '%s', '%s', '%s', '%d', '%d', '%s', '%s', '%s', '%s', '%s']
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
            'module_results' => $moduleResults,
        ];
    }

    /** @return true|\WP_Error */
    public function claimModule(string $requestUuid, string $moduleKey): true|\WP_Error
    {
        $requestUuid = Sanitizer::uuid($requestUuid);
        $moduleKey = Sanitizer::key($moduleKey, 120);
        $existing = $this->get($requestUuid);
        if ($requestUuid === '' || $moduleKey === '' || $existing === null) {
            return new \WP_Error('spcrc_privacy_module_claim_invalid', 'Privacy module dispatch claim is invalid.');
        }
        if (Sanitizer::key($existing['status'] ?? '', 40) !== 'dispatching') {
            return new \WP_Error('spcrc_privacy_module_claim_closed', 'Privacy request is not accepting new module dispatch claims.');
        }

        $results = $this->decodeResults($existing['module_results_json'] ?? '');
        if (! isset($results[$moduleKey])) {
            return new \WP_Error('spcrc_privacy_module_claim_unknown', 'Module is not part of this privacy request.');
        }
        if (Sanitizer::key($results[$moduleKey]['status'] ?? '', 40) !== 'not-started') {
            return new \WP_Error('spcrc_privacy_module_already_claimed', 'Privacy module operation has already been claimed or completed.');
        }

        $results[$moduleKey]['status'] = 'dispatching';
        $results[$moduleKey]['ok'] = false;
        $results[$moduleKey]['code'] = '';
        $results[$moduleKey]['message'] = '';

        return $this->writeModuleResults($existing, $results, 'spcrc_privacy_module_claim_failed');
    }

    /** @param array<string,mixed> $result
     *  @return true|\WP_Error
     */
    public function storeModuleResult(string $requestUuid, string $moduleKey, array $result): true|\WP_Error
    {
        $requestUuid = Sanitizer::uuid($requestUuid);
        $moduleKey = Sanitizer::key($moduleKey, 120);
        $existing = $this->get($requestUuid);
        if ($requestUuid === '' || $moduleKey === '' || $existing === null) {
            return new \WP_Error('spcrc_privacy_module_result_invalid', 'Privacy module result is invalid.');
        }
        if (Sanitizer::key($existing['status'] ?? '', 40) !== 'dispatching') {
            return new \WP_Error('spcrc_privacy_module_result_closed', 'Privacy request is not accepting synchronous module results.');
        }

        $results = $this->decodeResults($existing['module_results_json'] ?? '');
        if (! isset($results[$moduleKey])) {
            return new \WP_Error('spcrc_privacy_module_result_unknown', 'Module is not part of this privacy request.');
        }
        if (Sanitizer::key($results[$moduleKey]['status'] ?? '', 40) !== 'dispatching') {
            return new \WP_Error('spcrc_privacy_module_result_unclaimed', 'Privacy module result cannot be stored without a dispatch claim.');
        }

        $results[$moduleKey] = $this->sanitizeModuleResult($result);
        return $this->writeModuleResults($existing, $results, 'spcrc_privacy_module_result_write_failed');
    }

    /**
     * @return true|\WP_Error
     */
    public function finalize(
        string $requestUuid,
        string $status,
        string $expectedStatus = 'dispatching',
        string $lastErrorCode = ''
    ): true|\WP_Error {
        global $wpdb;

        $requestUuid = Sanitizer::uuid($requestUuid);
        $status = Sanitizer::key($status, 40);
        $expectedStatus = Sanitizer::key($expectedStatus, 40);
        if (
            $requestUuid === ''
            || ! in_array($status, self::REQUEST_STATUSES, true)
            || in_array($status, ['received', 'dispatching'], true)
            || $expectedStatus === ''
        ) {
            return new \WP_Error('spcrc_privacy_finalize_invalid', 'Privacy request final state is invalid.');
        }

        $existing = $this->get($requestUuid);
        if ($existing === null) {
            return new \WP_Error('spcrc_privacy_request_missing', 'Privacy request could not be found.');
        }
        if (Sanitizer::key($existing['status'] ?? '', 40) !== $expectedStatus) {
            return new \WP_Error('spcrc_privacy_finalize_concurrent', 'Privacy request changed before finalization.');
        }

        $lockVersion = absint($existing['lock_version'] ?? 0);
        $now = current_time('mysql', true);
        $updated = $wpdb->update(
            $wpdb->prefix . 'spcrc_privacy_requests',
            [
                'status' => $status,
                'lock_version' => $lockVersion + 1,
                'last_error_code' => Sanitizer::key($lastErrorCode, 120),
                'next_retry_at' => in_array($status, self::RETRYABLE_REQUEST_STATUSES, true)
                    ? gmdate('Y-m-d H:i:s', time() + 900)
                    : null,
                'completed_at' => $status === 'completed' ? $now : null,
                'updated_at' => $now,
            ],
            ['request_uuid' => $requestUuid, 'status' => $expectedStatus, 'lock_version' => $lockVersion],
            ['%s', '%d', '%s', '%s', '%s', '%s'],
            ['%s', '%s', '%d']
        );
        if ($updated === false) {
            return new \WP_Error('spcrc_privacy_finalize_failed', 'Privacy request final state could not be stored.');
        }
        if ($updated !== 1) {
            return new \WP_Error('spcrc_privacy_finalize_concurrent', 'Privacy request changed before finalization.');
        }

        return true;
    }

    /** @return array<string,mixed>|\WP_Error */
    public function claimRetry(string $requestUuid, int $assignedUserId): array|\WP_Error
    {
        global $wpdb;

        $requestUuid = Sanitizer::uuid($requestUuid);
        $existing = $this->get($requestUuid);
        if ($requestUuid === '' || $existing === null) {
            return new \WP_Error('spcrc_privacy_request_missing', 'Privacy request could not be found.');
        }

        $status = Sanitizer::key($existing['status'] ?? '', 40);
        if (! in_array($status, self::RETRYABLE_REQUEST_STATUSES, true)) {
            return new \WP_Error('spcrc_privacy_retry_forbidden', 'Only failed, partial or recovery-required requests may be retried.');
        }

        $results = $this->decodeResults($existing['module_results_json'] ?? '');
        $retryModules = [];
        foreach ($results as $moduleKey => $result) {
            if (in_array(Sanitizer::key($result['status'] ?? '', 40), self::RETRYABLE_MODULE_STATUSES, true)) {
                $retryModules[] = $moduleKey;
                $results[$moduleKey]['ok'] = false;
                $results[$moduleKey]['status'] = 'not-started';
                $results[$moduleKey]['code'] = '';
                $results[$moduleKey]['message'] = '';
            }
        }
        if ($retryModules === []) {
            return new \WP_Error('spcrc_privacy_retry_modules_missing', 'No safely retryable module result is available. Pending, dispatching or completed modules are never replayed.');
        }

        $encodedResults = $this->encodeResults($results);
        if (is_wp_error($encodedResults)) {
            return $encodedResults;
        }

        $lockVersion = absint($existing['lock_version'] ?? 0);
        $updated = $wpdb->update(
            $wpdb->prefix . 'spcrc_privacy_requests',
            [
                'status' => 'dispatching',
                'assigned_user_id' => $assignedUserId > 0 ? $assignedUserId : null,
                'module_results_json' => $encodedResults,
                'dispatch_attempts' => max(1, absint($existing['dispatch_attempts'] ?? 0) + 1),
                'lock_version' => $lockVersion + 1,
                'next_retry_at' => null,
                'last_error_code' => '',
                'updated_at' => current_time('mysql', true),
            ],
            ['request_uuid' => $requestUuid, 'status' => $status, 'lock_version' => $lockVersion],
            ['%s', '%d', '%s', '%d', '%d', '%s', '%s', '%s'],
            ['%s', '%s', '%d']
        );
        if ($updated === false) {
            return new \WP_Error('spcrc_privacy_retry_claim_failed', 'Privacy request retry could not be claimed.');
        }
        if ($updated !== 1) {
            return new \WP_Error('spcrc_privacy_retry_concurrent', 'Privacy request changed before retry. Refresh and try again.');
        }

        return array_merge($existing, [
            'status' => 'dispatching',
            'assigned_user_id' => $assignedUserId,
            'module_results' => $results,
            'retry_modules' => $retryModules,
        ]);
    }

    /**
     * Records a native module completion callback and recalculates the canonical request status.
     *
     * @param array<string,mixed> $result
     * @return array<string,mixed>|\WP_Error
     */
    public function completeModule(string $requestUuid, string $moduleKey, array $result): array|\WP_Error
    {
        global $wpdb;

        $requestUuid = Sanitizer::uuid($requestUuid);
        $moduleKey = Sanitizer::key($moduleKey, 120);
        $existing = $this->get($requestUuid);
        if ($requestUuid === '' || $moduleKey === '' || $existing === null) {
            return new \WP_Error('spcrc_privacy_callback_invalid', 'Privacy completion callback is invalid.');
        }

        $requestStatus = Sanitizer::key($existing['status'] ?? '', 40);
        if (! in_array($requestStatus, ['dispatching', 'pending', 'partial', 'recovery-required'], true)) {
            return new \WP_Error('spcrc_privacy_callback_closed', 'Privacy request is not open for module completion.');
        }

        $results = $this->decodeResults($existing['module_results_json'] ?? '');
        if (! array_key_exists($moduleKey, $results)) {
            return new \WP_Error('spcrc_privacy_callback_module_unknown', 'Module is not part of this privacy request.');
        }
        if (Sanitizer::key($results[$moduleKey]['status'] ?? '', 40) === 'completed') {
            return new \WP_Error('spcrc_privacy_callback_module_completed', 'Completed module evidence cannot be overwritten.');
        }

        $normalized = $this->sanitizeModuleResult($result);
        if (! in_array($normalized['status'], ['completed', 'pending', 'failed'], true)) {
            return new \WP_Error('spcrc_privacy_callback_status_invalid', 'Native completion callbacks may report only completed, pending or failed.');
        }
        $results[$moduleKey] = $normalized;
        $aggregate = self::aggregateResults($results);
        $encodedResults = $this->encodeResults($results);
        if (is_wp_error($encodedResults)) {
            return $encodedResults;
        }

        $lockVersion = absint($existing['lock_version'] ?? 0);
        $now = current_time('mysql', true);
        $updated = $wpdb->update(
            $wpdb->prefix . 'spcrc_privacy_requests',
            [
                'status' => $aggregate['status'],
                'module_results_json' => $encodedResults,
                'lock_version' => $lockVersion + 1,
                'last_error_code' => $aggregate['status'] === 'failed' ? Sanitizer::key($normalized['code'] ?? 'module_failed', 120) : '',
                'next_retry_at' => in_array($aggregate['status'], self::RETRYABLE_REQUEST_STATUSES, true)
                    ? gmdate('Y-m-d H:i:s', time() + 900)
                    : null,
                'completed_at' => $aggregate['status'] === 'completed' ? $now : null,
                'updated_at' => $now,
            ],
            ['request_uuid' => $requestUuid, 'status' => $requestStatus, 'lock_version' => $lockVersion],
            ['%s', '%s', '%d', '%s', '%s', '%s', '%s'],
            ['%s', '%s', '%d']
        );
        if ($updated === false) {
            return new \WP_Error('spcrc_privacy_callback_write_failed', 'Privacy completion callback could not be stored.');
        }
        if ($updated !== 1) {
            return new \WP_Error('spcrc_privacy_callback_concurrent', 'Privacy request changed before callback storage. Retry the callback with fresh state.');
        }

        return ['ok' => $aggregate['ok'], 'status' => $aggregate['status'], 'results' => $results];
    }

    public function markStaleDispatching(int $ageSeconds = 900, int $limit = 100): int|\WP_Error
    {
        global $wpdb;

        $ageSeconds = max(300, min(86400, $ageSeconds));
        $limit = max(1, min(500, $limit));
        $cutoff = gmdate('Y-m-d H:i:s', time() - $ageSeconds);
        $rows = $wpdb->get_results(
            $wpdb->prepare(
                "SELECT request_uuid, status, lock_version, updated_at FROM {$wpdb->prefix}spcrc_privacy_requests WHERE status = %s AND updated_at < %s ORDER BY updated_at ASC LIMIT %d",
                'dispatching',
                $cutoff,
                $limit
            ),
            ARRAY_A
        );
        if (! is_array($rows)) {
            return new \WP_Error('spcrc_privacy_stale_scan_failed', 'Stale privacy-request scan could not be completed.');
        }

        $marked = 0;
        foreach ($rows as $row) {
            if (Sanitizer::key($row['status'] ?? '', 40) !== 'dispatching') {
                continue;
            }
            $updatedAt = strtotime((string) ($row['updated_at'] ?? '') . ' UTC');
            if ($updatedAt === false || $updatedAt >= time() - $ageSeconds) {
                continue;
            }
            $uuid = Sanitizer::uuid($row['request_uuid'] ?? '');
            $lockVersion = absint($row['lock_version'] ?? 0);
            if ($uuid === '') {
                continue;
            }
            $updated = $wpdb->update(
                $wpdb->prefix . 'spcrc_privacy_requests',
                [
                    'status' => 'recovery-required',
                    'lock_version' => $lockVersion + 1,
                    'last_error_code' => 'stale_dispatch',
                    'next_retry_at' => current_time('mysql', true),
                    'updated_at' => current_time('mysql', true),
                ],
                ['request_uuid' => $uuid, 'status' => 'dispatching', 'lock_version' => $lockVersion],
                ['%s', '%d', '%s', '%s', '%s'],
                ['%s', '%s', '%d']
            );
            if ($updated === false) {
                return new \WP_Error('spcrc_privacy_stale_mark_failed', 'A stale privacy request could not be marked for recovery.');
            }
            if ($updated === 1) {
                ++$marked;
            }
        }

        return $marked;
    }

    /** @return array<string,array<string,mixed>> */
    public function moduleResults(string $requestUuid): array
    {
        $existing = $this->get($requestUuid);
        return $existing === null ? [] : $this->decodeResults($existing['module_results_json'] ?? '');
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
                "SELECT request_uuid, requester_user_id, request_type, status, assigned_user_id, jurisdiction, due_at, module_results_json, dispatch_attempts, lock_version, next_retry_at, last_error_code, completed_at, created_at, updated_at FROM {$wpdb->prefix}spcrc_privacy_requests WHERE request_uuid = %s",
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
                "SELECT request_uuid, requester_user_id, request_type, status, assigned_user_id, jurisdiction, due_at, dispatch_attempts, next_retry_at, last_error_code, completed_at, created_at, updated_at FROM {$wpdb->prefix}spcrc_privacy_requests ORDER BY updated_at DESC LIMIT %d",
                $limit
            ),
            ARRAY_A
        );

        return is_array($rows) ? $rows : [];
    }

    /**
     * @param array<string,array<string,mixed>> $results
     * @return array{ok:bool,status:string}
     */
    public static function aggregateResults(array $results): array
    {
        if ($results === []) {
            return ['ok' => false, 'status' => 'failed'];
        }

        $failed = 0;
        $pending = 0;
        $uncertain = 0;
        foreach ($results as $result) {
            $ok = Sanitizer::boolean($result['ok'] ?? false);
            $status = Sanitizer::key($result['status'] ?? '', 40);
            if (in_array($status, ['dispatching', 'not-started', 'recovery-required'], true)) {
                ++$uncertain;
                continue;
            }
            if (! $ok || in_array($status, ['failed', 'rejected', 'unavailable'], true)) {
                ++$failed;
                continue;
            }
            if ($status !== 'completed') {
                ++$pending;
            }
        }

        if ($uncertain > 0) {
            return ['ok' => false, 'status' => 'recovery-required'];
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

    /** @param array<string,mixed> $existing
     *  @param array<string,array<string,mixed>> $results
     *  @return true|\WP_Error
     */
    private function writeModuleResults(array $existing, array $results, string $errorCode): true|\WP_Error
    {
        global $wpdb;

        $encodedResults = $this->encodeResults($results);
        if (is_wp_error($encodedResults)) {
            return $encodedResults;
        }

        $requestUuid = Sanitizer::uuid($existing['request_uuid'] ?? '');
        $requestStatus = Sanitizer::key($existing['status'] ?? '', 40);
        $lockVersion = absint($existing['lock_version'] ?? 0);
        if ($requestUuid === '' || $requestStatus === '') {
            return new \WP_Error($errorCode, 'Privacy module evidence is missing its canonical request identity.');
        }

        $updated = $wpdb->update(
            $wpdb->prefix . 'spcrc_privacy_requests',
            [
                'module_results_json' => $encodedResults,
                'lock_version' => $lockVersion + 1,
                'updated_at' => current_time('mysql', true),
            ],
            ['request_uuid' => $requestUuid, 'status' => $requestStatus, 'lock_version' => $lockVersion],
            ['%s', '%d', '%s'],
            ['%s', '%s', '%d']
        );
        if ($updated === false) {
            return new \WP_Error($errorCode, 'Privacy module evidence could not be stored.');
        }
        if ($updated !== 1) {
            return new \WP_Error('spcrc_privacy_module_concurrent', 'Privacy request changed during module evidence storage.');
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

    /** @param array<string,array<string,mixed>> $results
     *  @return array<string,array<string,mixed>>
     */
    private function sanitizeResults(array $results): array
    {
        $safe = [];
        foreach (array_slice($results, 0, 100, true) as $moduleKey => $result) {
            $moduleKey = Sanitizer::key($moduleKey, 120);
            if ($moduleKey === '' || ! is_array($result)) {
                continue;
            }
            $safe[$moduleKey] = $this->sanitizeModuleResult($result);
        }
        return $safe;
    }

    /** @param array<string,mixed> $result
     *  @return array<string,mixed>
     */
    private function sanitizeModuleResult(array $result): array
    {
        $status = Sanitizer::key($result['status'] ?? 'failed', 40);
        if (! in_array($status, self::MODULE_STATUSES, true)) {
            $status = Sanitizer::boolean($result['ok'] ?? false) ? 'accepted' : 'failed';
        }

        return [
            'ok' => Sanitizer::boolean($result['ok'] ?? false),
            'status' => $status,
            'code' => Sanitizer::key($result['code'] ?? '', 120),
            'reference' => Sanitizer::text($result['reference'] ?? '', 200),
            'message' => Sanitizer::text($result['message'] ?? '', 300),
        ];
    }

    /** @param array<string,array<string,mixed>> $results
     *  @return string|\WP_Error
     */
    private function encodeResults(array $results): string|\WP_Error
    {
        $encoded = wp_json_encode($this->sanitizeResults($results), JSON_UNESCAPED_SLASHES);
        return is_string($encoded)
            ? $encoded
            : new \WP_Error('spcrc_privacy_results_encode_failed', 'Privacy module results could not be encoded.');
    }

    /** @return array<string,array<string,mixed>> */
    private function decodeResults(mixed $encoded): array
    {
        if (! is_string($encoded) || $encoded === '') {
            return [];
        }
        $decoded = json_decode($encoded, true);
        return is_array($decoded) ? $this->sanitizeResults($decoded) : [];
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
