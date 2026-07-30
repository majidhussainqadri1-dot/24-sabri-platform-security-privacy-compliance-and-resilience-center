<?php

declare(strict_types=1);

namespace Sabri\Platform\Security\Storage;

use Sabri\Platform\Security\Support\Sanitizer;

final class RiskRepository
{
    /** @param array<string,mixed> $data
     *  @return string|\WP_Error
     */
    public function create(array $data): string|\WP_Error
    {
        global $wpdb;

        $title = Sanitizer::text($data['title'] ?? '', 200);
        $moduleKey = Sanitizer::key($data['module_key'] ?? 'file-24-security-center', 120);
        $likelihood = max(1, min(5, absint($data['likelihood'] ?? 1)));
        $impact = max(1, min(5, absint($data['impact'] ?? 1)));
        $treatment = Sanitizer::key($data['treatment'] ?? 'mitigate', 30);
        if (! in_array($treatment, ['avoid', 'mitigate', 'transfer', 'accept'], true)) {
            $treatment = 'mitigate';
        }
        if ($title === '' || $moduleKey === '') {
            return new \WP_Error('spcrc_risk_invalid', 'Risk title and module are required.');
        }

        $uuid = wp_generate_uuid4();
        $now = current_time('mysql', true);
        $inserted = $wpdb->insert(
            $wpdb->prefix . 'spcrc_risks',
            [
                'risk_uuid' => $uuid,
                'module_key' => $moduleKey,
                'title' => $title,
                'likelihood' => $likelihood,
                'impact' => $impact,
                'inherent_score' => $likelihood * $impact,
                'status' => 'open',
                'treatment' => $treatment,
                'owner_user_id' => absint($data['owner_user_id'] ?? get_current_user_id()) ?: null,
                'due_at' => $this->mysqlTime($data['due_at'] ?? ''),
                'created_at' => $now,
                'updated_at' => $now,
            ],
            ['%s', '%s', '%s', '%d', '%d', '%d', '%s', '%s', '%d', '%s', '%s', '%s']
        );

        return $inserted === false
            ? new \WP_Error('spcrc_risk_write_failed', 'Risk could not be stored.')
            : $uuid;
    }

    public function openCount(): int
    {
        global $wpdb;
        return (int) $wpdb->get_var("SELECT COUNT(*) FROM {$wpdb->prefix}spcrc_risks WHERE status = 'open'");
    }

    /** @return array<int,array<string,mixed>> */
    public function recent(int $limit = 10): array
    {
        global $wpdb;
        $limit = max(1, min(50, $limit));
        $rows = $wpdb->get_results(
            $wpdb->prepare("SELECT risk_uuid, module_key, title, likelihood, impact, inherent_score, status, treatment, due_at, created_at FROM {$wpdb->prefix}spcrc_risks ORDER BY updated_at DESC LIMIT %d", $limit),
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
