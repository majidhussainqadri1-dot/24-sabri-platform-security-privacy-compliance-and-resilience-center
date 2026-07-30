<?php

declare(strict_types=1);

namespace Sabri\Platform\Security\Registry;

use Sabri\Platform\Security\Storage\AuditLogger;
use Sabri\Platform\Security\Storage\Schema;

final class SecurityStateRegistry
{
    private const ALLOWED_STATES = [
        'normal',
        'elevated-monitoring',
        'restricted-writes',
        'upload-lockdown',
        'messaging-lockdown',
        'identity-lockdown',
        'publishing-read-only',
        'platform-read-only',
        'incident-containment',
    ];

    public function __construct(private AuditLogger $audit)
    {
    }

    public function registerHooks(): void
    {
        add_action('spcrc/request_security_state', [$this, 'request'], 10, 3);
        add_action('spcrc/resolve_security_state', [$this, 'resolve'], 10, 2);
        add_filter('spcrc/security_state_requests', [$this, 'filterAll']);
    }

    /** @param array<string,mixed> $context */
    public function request(string $moduleKey, string $state, array $context = []): bool
    {
        global $wpdb;

        $moduleKey = $this->truncate(sanitize_key($moduleKey), 120);
        $state = sanitize_key($state);
        if ($moduleKey === '' || ! in_array($state, self::ALLOWED_STATES, true)) {
            return false;
        }

        $reason = $this->truncate(sanitize_text_field((string) ($context['reason'] ?? '')), 500);
        if ($reason === '') {
            return false;
        }

        $requestedAt = time();
        $expiresAt = $this->expiryTimestamp((string) ($context['expires_at'] ?? ''), $requestedAt);
        if ($expiresAt === null) {
            return false;
        }

        $table = Schema::tables()['state_requests'];
        $nowMysql = current_time('mysql', true);
        $duplicate = $wpdb->get_var($wpdb->prepare(
            "SELECT request_uuid FROM {$table} WHERE module_key = %s AND requested_state = %s AND status = 'open' AND expires_at > %s LIMIT 1",
            $moduleKey,
            $state,
            $nowMysql
        ));
        if (is_string($duplicate) && $duplicate !== '') {
            do_action('spcrc/security_state_request_duplicate', $duplicate, $moduleKey, $state);
            return false;
        }

        $requestId = wp_generate_uuid4();
        $record = [
            'request_uuid' => $requestId,
            'module_key' => $moduleKey,
            'requested_state' => $state,
            'reason' => $reason,
            'status' => 'open',
            'requested_by' => max(0, (int) get_current_user_id()),
            'requested_at' => gmdate('Y-m-d H:i:s', $requestedAt),
            'expires_at' => gmdate('Y-m-d H:i:s', $expiresAt),
        ];

        $inserted = $wpdb->insert(
            $table,
            $record,
            ['%s', '%s', '%s', '%s', '%s', '%d', '%s', '%s']
        );
        if ($inserted === false) {
            do_action('spcrc/security_state_request_failed', $record, (string) $wpdb->last_error);
            return false;
        }

        $publicRecord = [
            'request_id' => $requestId,
            'module_key' => $moduleKey,
            'state' => $state,
            'reason' => $record['reason'],
            'requested_by' => $record['requested_by'],
            'requested_at' => gmdate('c', $requestedAt),
            'expires_at' => gmdate('c', $expiresAt),
            'status' => 'open',
        ];

        $this->audit->record('security_state_requested', $moduleKey, 'open', 'high', [
            'request_uuid' => $requestId,
            'state' => $state,
            'expires_at' => $publicRecord['expires_at'],
        ]);
        do_action('spcrc/security_state_requested', $publicRecord);

        return true;
    }

    public function resolve(string $requestId, string $status = 'resolved'): bool
    {
        global $wpdb;

        $requestId = sanitize_text_field($requestId);
        $status = sanitize_key($status);
        if (! $this->isUuid($requestId) || ! in_array($status, ['resolved', 'rejected'], true)) {
            return false;
        }

        $updated = $wpdb->update(
            Schema::tables()['state_requests'],
            ['status' => $status, 'resolved_at' => current_time('mysql', true)],
            ['request_uuid' => $requestId, 'status' => 'open'],
            ['%s', '%s'],
            ['%s', '%s']
        );
        if (! is_int($updated) || $updated < 1) {
            return false;
        }

        $this->audit->record('security_state_resolved', 'file-24-security-center', $status, 'medium', [
            'request_uuid' => $requestId,
        ]);
        do_action('spcrc/security_state_resolved', $requestId, $status);
        return true;
    }

    /** @return array<int,array<string,mixed>> */
    public function all(): array
    {
        global $wpdb;
        $table = Schema::tables()['state_requests'];
        $now = current_time('mysql', true);

        $wpdb->query($wpdb->prepare(
            "UPDATE {$table} SET status = 'expired', resolved_at = %s WHERE status = 'open' AND expires_at <= %s",
            $now,
            $now
        ));

        $rows = $wpdb->get_results(
            $wpdb->prepare(
                "SELECT request_uuid, module_key, requested_state, reason, status, requested_by, requested_at, expires_at FROM {$table} WHERE status = %s AND expires_at > %s ORDER BY requested_at DESC LIMIT %d",
                'open',
                $now,
                100
            ),
            ARRAY_A
        );

        if (! is_array($rows)) {
            return [];
        }

        return array_map(static function (array $row): array {
            return [
                'request_id' => (string) $row['request_uuid'],
                'module_key' => (string) $row['module_key'],
                'state' => (string) $row['requested_state'],
                'reason' => (string) $row['reason'],
                'status' => (string) $row['status'],
                'requested_by' => (int) $row['requested_by'],
                'requested_at' => mysql2date('c', (string) $row['requested_at'], false),
                'expires_at' => mysql2date('c', (string) $row['expires_at'], false),
            ];
        }, $rows);
    }

    /** @param mixed $current
     *  @return array<int,array<string,mixed>>
     */
    public function filterAll($current = null): array
    {
        return $this->all();
    }

    private function expiryTimestamp(string $raw, int $now): ?int
    {
        $maximum = $now + (7 * DAY_IN_SECONDS);
        if ($raw === '') {
            return $now + HOUR_IN_SECONDS;
        }

        $timestamp = strtotime($raw);
        if ($timestamp === false || $timestamp <= $now || $timestamp > $maximum) {
            return null;
        }

        return $timestamp;
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
