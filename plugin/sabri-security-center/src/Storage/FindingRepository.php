<?php

declare(strict_types=1);

namespace Sabri\Platform\Security\Storage;

use Sabri\Platform\Security\Support\Sanitizer;

final class FindingRepository
{
    private const SEVERITIES = ['informational', 'low', 'medium', 'high', 'critical'];
    private const STATUSES = ['open', 'triaged', 'in-progress', 'resolved', 'accepted-risk', 'false-positive'];
    private const OPEN_STATUSES = ['open', 'triaged', 'in-progress'];

    public function __construct(private ?AuditLogger $audit = null)
    {
    }

    public function registerHooks(): void
    {
        add_filter('spcrc/security_finding_create', [$this, 'filterCreate'], 10, 2);
        add_filter('spcrc/security_finding_status', [$this, 'filterStatus'], 10, 3);
    }

    /** @param array<string,mixed> $data */
    public function filterCreate(mixed $current, array $data): mixed
    {
        return $current !== null ? $current : $this->create($data);
    }

    public function filterStatus(mixed $current, string $findingUuid, string $status): mixed
    {
        return $current !== null ? $current : $this->setStatus($findingUuid, $status);
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
        $inserted = $wpdb->insert(
            $wpdb->prefix . 'spcrc_findings',
            [
                'finding_uuid' => $uuid,
                'module_key' => $moduleKey,
                'title' => $title,
                'severity' => $severity,
                'status' => 'open',
                'owner_user_id' => absint($data['owner_user_id'] ?? get_current_user_id()) ?: null,
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
            in_array($severity, ['high', 'critical'], true) ? 'high' : 'medium',
            ['finding_uuid' => $uuid, 'severity' => $severity]
        );

        do_action('spcrc/security_finding_created', $uuid, $moduleKey, $severity);
        return $uuid;
    }

    /** @return true|\WP_Error */
    public function setStatus(string $findingUuid, string $status): true|\WP_Error
    {
        global $wpdb;

        $findingUuid = Sanitizer::uuid($findingUuid);
        $status = Sanitizer::key($status, 40);
        if ($findingUuid === '' || ! in_array($status, self::STATUSES, true)) {
            return new \WP_Error('spcrc_finding_status_invalid', 'Finding UUID or status is invalid.');
        }

        $table = $wpdb->prefix . 'spcrc_findings';
        $existingStatus = $wpdb->get_var($wpdb->prepare(
            "SELECT status FROM {$table} WHERE finding_uuid = %s",
            $findingUuid
        ));
        if (! is_string($existingStatus) || $existingStatus === '') {
            return new \WP_Error('spcrc_finding_not_found', 'Finding could not be found.');
        }
        if ($existingStatus === $status) {
            return true;
        }

        $updated = $wpdb->update(
            $table,
            ['status' => $status, 'updated_at' => current_time('mysql', true)],
            ['finding_uuid' => $findingUuid],
            ['%s', '%s'],
            ['%s']
        );
        if ($updated === false) {
            return new \WP_Error('spcrc_finding_status_write_failed', 'Finding status could not be stored.');
        }

        $this->audit?->record(
            'security_finding_status_changed',
            'file-24-security-center',
            $status,
            'medium',
            ['finding_uuid' => $findingUuid, 'status' => $status]
        );
        do_action('spcrc/security_finding_status_changed', $findingUuid, $status);

        return true;
    }

    public function openCount(): int
    {
        global $wpdb;
        $statuses = "'" . implode("','", self::OPEN_STATUSES) . "'";
        return (int) $wpdb->get_var("SELECT COUNT(*) FROM {$wpdb->prefix}spcrc_findings WHERE status IN ({$statuses})");
    }

    /** @return array<int,array<string,mixed>> */
    public function recent(int $limit = 10): array
    {
        global $wpdb;
        $limit = max(1, min(50, $limit));
        $rows = $wpdb->get_results(
            $wpdb->prepare("SELECT finding_uuid, module_key, title, severity, status, due_at, evidence_ref, created_at, updated_at FROM {$wpdb->prefix}spcrc_findings ORDER BY updated_at DESC LIMIT %d", $limit),
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
