<?php

declare(strict_types=1);

namespace Sabri\Platform\Security\Storage;

use Sabri\Platform\Security\Support\Sanitizer;

final class FindingRepository
{
    private const SEVERITIES = ['informational', 'low', 'medium', 'high', 'critical'];
    private const STATUSES = ['open', 'triaged', 'in-progress', 'resolved', 'accepted-risk', 'false-positive'];
    private const OPEN_STATUSES = ['open', 'triaged', 'in-progress'];
    private const TRANSITIONS = [
        'open' => ['triaged', 'in-progress', 'resolved', 'false-positive'],
        'triaged' => ['in-progress', 'resolved', 'accepted-risk', 'false-positive'],
        'in-progress' => ['triaged', 'resolved', 'accepted-risk', 'false-positive'],
        'resolved' => ['triaged'],
        'accepted-risk' => ['triaged'],
        'false-positive' => ['triaged'],
    ];

    public function __construct(private ?AuditLogger $audit = null)
    {
    }

    public function registerHooks(): void
    {
        add_filter('spcrc/security_finding_create', [$this, 'filterCreate'], 10, 2);
        add_filter('spcrc/security_finding_status', [$this, 'filterStatus'], 10, 4);
    }

    /** @param array<string,mixed> $data */
    public function filterCreate(mixed $current, array $data): mixed
    {
        return $current !== null ? $current : $this->create($data);
    }

    /** @param array<string,mixed> $context */
    public function filterStatus(mixed $current, string $findingUuid, string $status, array $context = []): mixed
    {
        return $current !== null ? $current : $this->setStatus($findingUuid, $status, $context);
    }

    /** @return string[] */
    public static function severities(): array
    {
        return self::SEVERITIES;
    }

    /** @return string[] */
    public static function allowedNextStatuses(string $currentStatus): array
    {
        $currentStatus = Sanitizer::key($currentStatus, 40);
        return self::TRANSITIONS[$currentStatus] ?? [];
    }

    /** @param array<string,mixed> $data
     *  @return string|\WP_Error
     */
    public function create(array $data): string|\WP_Error
    {
        global $wpdb;

        $title = Sanitizer::text($data['title'] ?? '', 200);
        $moduleKey = Sanitizer::key($data['module_key'] ?? '', 120);
        $severity = Sanitizer::key($data['severity'] ?? 'medium', 20);
        if ($title === '' || $moduleKey === '') {
            return new \WP_Error('spcrc_finding_invalid', 'Finding title and module are required.');
        }
        if (! in_array($severity, self::SEVERITIES, true)) {
            $severity = 'medium';
        }

        $uuid = wp_generate_uuid4();
        $now = current_time('mysql', true);
        $actor = absint($data['owner_user_id'] ?? get_current_user_id()) ?: null;
        $inserted = $wpdb->insert(
            $wpdb->prefix . 'spcrc_findings',
            [
                'finding_uuid' => $uuid,
                'module_key' => $moduleKey,
                'title' => $title,
                'severity' => $severity,
                'status' => 'open',
                'owner_user_id' => $actor,
                'due_at' => $this->mysqlTime($data['due_at'] ?? ''),
                'evidence_ref' => Sanitizer::text($data['evidence_ref'] ?? '', 255),
                'created_at' => $now,
                'updated_at' => $now,
            ],
            ['%s', '%s', '%s', '%s', '%s', '%d', '%s', '%s', '%s', '%s']
        );

        if ($inserted === false) {
            return new \WP_Error('spcrc_finding_write_failed', 'Finding could not be stored.');
        }

        $this->audit?->record(
            'security_finding_created',
            $moduleKey,
            'created',
            $severity,
            ['finding_uuid' => $uuid, 'severity' => $severity]
        );

        do_action('spcrc/security_finding_created', $uuid, $moduleKey, $severity);
        return $uuid;
    }

    /** @param array<string,mixed> $context
     *  @return true|\WP_Error
     */
    public function setStatus(string $findingUuid, string $status, array $context = []): true|\WP_Error
    {
        global $wpdb;

        $findingUuid = Sanitizer::uuid($findingUuid);
        $status = Sanitizer::key($status, 40);
        $expectedStatus = Sanitizer::key($context['expected_status'] ?? '', 40);
        $note = Sanitizer::text($context['note'] ?? '', 500);

        if ($findingUuid === '' || ! in_array($status, self::STATUSES, true)) {
            return new \WP_Error('spcrc_finding_status_invalid', 'Finding UUID or status is invalid.');
        }

        $table = $wpdb->prefix . 'spcrc_findings';
        $existing = $wpdb->get_row($wpdb->prepare(
            "SELECT status, module_key, severity FROM {$table} WHERE finding_uuid = %s",
            $findingUuid
        ), ARRAY_A);
        if (! is_array($existing) || ($existing['status'] ?? '') === '') {
            return new \WP_Error('spcrc_finding_not_found', 'Finding could not be found.');
        }

        $currentStatus = Sanitizer::key($existing['status'] ?? '', 40);
        $moduleKey = Sanitizer::key($existing['module_key'] ?? 'file-24-security-center', 120);
        $severity = Sanitizer::key($existing['severity'] ?? 'medium', 20);

        if ($expectedStatus !== '' && $expectedStatus !== $currentStatus) {
            return new \WP_Error('spcrc_finding_stale_status', 'Finding status changed before this update. Refresh and try again.');
        }
        if ($currentStatus === $status) {
            return true;
        }
        if (! in_array($status, self::TRANSITIONS[$currentStatus] ?? [], true)) {
            return new \WP_Error('spcrc_finding_transition_invalid', 'This finding status transition is not allowed.');
        }
        if ($note === '') {
            return new \WP_Error('spcrc_finding_note_required', 'A sanitized accountability note is required for every status transition.');
        }
        if ($status === 'accepted-risk' && (! function_exists('current_user_can') || ! current_user_can('spcrc_accept_critical_risk'))) {
            return new \WP_Error('spcrc_finding_risk_acceptance_forbidden', 'You are not allowed to accept security risk.');
        }

        $now = current_time('mysql', true);
        $updated = $wpdb->update(
            $table,
            ['status' => $status, 'updated_at' => $now],
            ['finding_uuid' => $findingUuid, 'status' => $currentStatus],
            ['%s', '%s'],
            ['%s', '%s']
        );
        if ($updated === false) {
            return new \WP_Error('spcrc_finding_status_write_failed', 'Finding status could not be stored.');
        }
        if ($updated !== 1) {
            return new \WP_Error('spcrc_finding_concurrent_change', 'Finding changed concurrently. Refresh and try again.');
        }

        $this->audit?->record(
            'security_finding_status_changed',
            $moduleKey !== '' ? $moduleKey : 'file-24-security-center',
            $status,
            in_array($severity, self::SEVERITIES, true) ? $severity : 'medium',
            [
                'finding_uuid' => $findingUuid,
                'previous_status' => $currentStatus,
                'new_status' => $status,
                'accountability_note' => $note,
                'accountability_note_hash' => hash('sha256', $note),
            ]
        );
        do_action('spcrc/security_finding_status_changed', $findingUuid, $currentStatus, $status);

        return true;
    }

    public function openCount(): int
    {
        global $wpdb;
        $statuses = "'" . implode("','", self::OPEN_STATUSES) . "'";
        return (int) $wpdb->get_var("SELECT COUNT(*) FROM {$wpdb->prefix}spcrc_findings WHERE status IN ({$statuses})");
    }

    /** @return array<int,array<string,mixed>> */
    public function recent(int $limit = 20): array
    {
        global $wpdb;
        $limit = max(1, min(100, $limit));
        $rows = $wpdb->get_results(
            $wpdb->prepare("SELECT finding_uuid, module_key, title, severity, status, owner_user_id, due_at, evidence_ref, created_at, updated_at FROM {$wpdb->prefix}spcrc_findings ORDER BY updated_at DESC LIMIT %d", $limit),
            ARRAY_A
        );
        return is_array($rows) ? $rows : [];
    }

    private function mysqlTime(mixed $value): ?string
    {
        $iso = Sanitizer::isoTime($value);
        return $iso === '' ? null : gmdate('Y-m-d H:i:s', (int) strtotime($iso));
    }
}
