<?php

declare(strict_types=1);

namespace Sabri\Platform\Security\Storage;

use Sabri\Platform\Security\Support\Sanitizer;

final class IncidentRepository
{
    private const SEVERITIES = ['sev0', 'sev1', 'sev2', 'sev3', 'sev4'];

    /** @param array<string,mixed> $data
     *  @return string|\WP_Error
     */
    public function create(array $data): string|\WP_Error
    {
        global $wpdb;
        $title = Sanitizer::text($data['title'] ?? '', 200);
        $severity = Sanitizer::key($data['severity'] ?? 'sev4', 20);
        if ($title === '') {
            return new \WP_Error('spcrc_incident_invalid', 'Incident title is required.');
        }
        if (! in_array($severity, self::SEVERITIES, true)) {
            $severity = 'sev4';
        }

        $uuid = wp_generate_uuid4();
        $now = current_time('mysql', true);
        $inserted = $wpdb->insert(
            $wpdb->prefix . 'spcrc_incidents',
            [
                'incident_uuid' => $uuid,
                'title' => $title,
                'severity' => $severity,
                'status' => 'open',
                'owner_user_id' => absint($data['owner_user_id'] ?? get_current_user_id()) ?: null,
                'summary' => Sanitizer::text($data['summary'] ?? '', 1000),
                'opened_at' => $now,
                'updated_at' => $now,
                'closed_at' => null,
            ],
            ['%s', '%s', '%s', '%s', '%d', '%s', '%s', '%s', '%s']
        );

        return $inserted === false
            ? new \WP_Error('spcrc_incident_write_failed', 'Incident could not be stored.')
            : $uuid;
    }

    public function openCount(): int
    {
        global $wpdb;
        return (int) $wpdb->get_var("SELECT COUNT(*) FROM {$wpdb->prefix}spcrc_incidents WHERE status = 'open'");
    }

    /** @return array<int,array<string,mixed>> */
    public function recent(int $limit = 10): array
    {
        global $wpdb;
        $limit = max(1, min(50, $limit));
        $rows = $wpdb->get_results(
            $wpdb->prepare("SELECT incident_uuid, title, severity, status, opened_at, updated_at FROM {$wpdb->prefix}spcrc_incidents ORDER BY updated_at DESC LIMIT %d", $limit),
            ARRAY_A
        );
        return is_array($rows) ? $rows : [];
    }
}
