<?php

declare(strict_types=1);

namespace Sabri\Platform\Security\Storage;

use Sabri\Platform\Security\Support\Sanitizer;

final class ControlRepository
{
    /** @param array<string,mixed> $data
     *  @return string|\WP_Error
     */
    public function upsert(array $data): string|\WP_Error
    {
        global $wpdb;
        $key = Sanitizer::key($data['control_key'] ?? '', 120);
        $title = Sanitizer::text($data['title'] ?? '', 200);
        if ($key === '' || $title === '') {
            return new \WP_Error('spcrc_control_invalid', 'Control key and title are required.');
        }

        $status = Sanitizer::key($data['status'] ?? 'unassessed', 40);
        if (! in_array($status, ['unassessed', 'planned', 'implemented', 'tested', 'failed', 'accepted'], true)) {
            $status = 'unassessed';
        }

        $table = $wpdb->prefix . 'spcrc_controls';
        $existing = $wpdb->get_var($wpdb->prepare("SELECT id FROM {$table} WHERE control_key = %s", $key));
        $now = current_time('mysql', true);
        $payload = [
            'title' => $title,
            'framework' => Sanitizer::text($data['framework'] ?? '', 120),
            'status' => $status,
            'owner_user_id' => absint($data['owner_user_id'] ?? get_current_user_id()) ?: null,
            'evidence_ref' => Sanitizer::text($data['evidence_ref'] ?? '', 255),
            'last_tested_at' => $this->mysqlTime($data['last_tested_at'] ?? ''),
            'updated_at' => $now,
        ];

        if ($existing) {
            $written = $wpdb->update(
                $table,
                $payload,
                ['control_key' => $key],
                ['%s', '%s', '%s', '%d', '%s', '%s', '%s'],
                ['%s']
            );
        } else {
            $payload = array_merge(['control_key' => $key, 'created_at' => $now], $payload);
            $written = $wpdb->insert(
                $table,
                $payload,
                ['%s', '%s', '%s', '%s', '%s', '%d', '%s', '%s', '%s']
            );
        }

        return $written === false
            ? new \WP_Error('spcrc_control_write_failed', 'Control could not be stored.')
            : $key;
    }

    public function count(): int
    {
        global $wpdb;
        return (int) $wpdb->get_var("SELECT COUNT(*) FROM {$wpdb->prefix}spcrc_controls");
    }

    /** @return array<int,array<string,mixed>> */
    public function recent(int $limit = 10): array
    {
        global $wpdb;
        $limit = max(1, min(50, $limit));
        $rows = $wpdb->get_results(
            $wpdb->prepare("SELECT control_key, title, framework, status, evidence_ref, last_tested_at, updated_at FROM {$wpdb->prefix}spcrc_controls ORDER BY updated_at DESC LIMIT %d", $limit),
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
