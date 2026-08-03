<?php

declare(strict_types=1);

namespace Sabri\Platform\Security\Storage;

use Sabri\Platform\Security\Support\AtomicOptionLock;
use Sabri\Platform\Security\Support\Sanitizer;

if (! class_exists(AuditGapStore::class, false)) {
    require_once __DIR__ . '/AuditGapStore.php';
}
if (! class_exists(AuditLogger::class, false)) {
    require_once __DIR__ . '/AuditLogger.php';
}
if (! class_exists(AtomicOptionLock::class, false)) {
    require_once dirname(__DIR__) . '/Support/AtomicOptionLock.php';
}

final class ControlRepository
{
    private const LOCK_TTL = 60;

    private AuditLogger $audit;

    public function __construct(?AuditLogger $audit = null)
    {
        $this->audit = $audit ?? new AuditLogger();
    }

    /** @param array<string,mixed> $data
     *  @return string|\WP_Error
     */
    public function upsert(array $data): string|\WP_Error
    {
        global $wpdb;
        $key = Sanitizer::key($data['control_key'] ?? '', 120);
        $title = Sanitizer::text($data['title'] ?? '', 200);
        $framework = Sanitizer::text($data['framework'] ?? '', 120);
        if ($key === '' || $title === '' || Sanitizer::containsSensitiveMaterial($title) || Sanitizer::containsSensitiveMaterial($framework)) {
            return new \WP_Error('spcrc_control_invalid', 'A bounded, non-sensitive control key, title and framework are required.');
        }

        $status = Sanitizer::key($data['status'] ?? 'unassessed', 40);
        if (! in_array($status, ['unassessed', 'planned', 'implemented', 'tested', 'failed', 'accepted'], true)) {
            $status = 'unassessed';
        }

        $evidenceRef = Sanitizer::opaqueReference($data['evidence_ref'] ?? '');
        $lastTestedAt = $this->mysqlTime($data['last_tested_at'] ?? '');
        if (in_array($status, ['tested', 'accepted'], true) && ($evidenceRef === '' || $lastTestedAt === null)) {
            return new \WP_Error('spcrc_control_evidence_missing', 'Tested or accepted controls require an opaque evidence reference and completed test timestamp.');
        }

        $lockOption = 'spcrc_control_lock_' . substr(hash('sha256', $key), 0, 32);
        $lockToken = AtomicOptionLock::acquire($lockOption, self::LOCK_TTL);
        if (is_wp_error($lockToken)) {
            return new \WP_Error('spcrc_control_locked', 'This control is being changed by another request. Refresh and try again.');
        }

        try {
            $table = $wpdb->prefix . 'spcrc_controls';
            $existing = $wpdb->get_row($wpdb->prepare("SELECT * FROM {$table} WHERE control_key = %s", $key), ARRAY_A);
            $now = current_time('mysql', true);
            $payload = [
                'title' => $title,
                'framework' => $framework,
                'status' => $status,
                'owner_user_id' => absint($data['owner_user_id'] ?? get_current_user_id()) ?: null,
                'evidence_ref' => $evidenceRef,
                'last_tested_at' => $lastTestedAt,
                'updated_at' => $now,
            ];

            if (! AtomicOptionLock::refresh($lockOption, $lockToken, self::LOCK_TTL)) {
                return new \WP_Error('spcrc_control_lock_lost', 'Control ownership was lost before the change was stored.');
            }

            if (is_array($existing)) {
                $written = $wpdb->update(
                    $table,
                    $payload,
                    ['control_key' => $key, 'updated_at' => (string) ($existing['updated_at'] ?? '')],
                    ['%s', '%s', '%s', '%d', '%s', '%s', '%s'],
                    ['%s', '%s']
                );
                if ($written === 0) {
                    $current = $wpdb->get_row($wpdb->prepare("SELECT * FROM {$table} WHERE control_key = %s", $key), ARRAY_A);
                    if (! is_array($current) || ! $this->payloadMatches($current, $payload)) {
                        return new \WP_Error('spcrc_control_concurrent_change', 'Control changed concurrently before the update completed.');
                    }
                }
            } else {
                $payload = array_merge(['control_key' => $key, 'created_at' => $now], $payload);
                $written = $wpdb->insert(
                    $table,
                    $payload,
                    ['%s', '%s', '%s', '%s', '%s', '%d', '%s', '%s', '%s']
                );
            }
            if ($written === false || (! is_array($existing) && $written !== 1)) {
                return new \WP_Error('spcrc_control_write_failed', 'Control could not be stored.');
            }

            if (! AtomicOptionLock::refresh($lockOption, $lockToken, self::LOCK_TTL)) {
                AuditGapStore::record(
                    'spcrc_control_audit_gap',
                    'control_key',
                    $key,
                    'control_lock_lost_after_write',
                    ['status' => $status]
                );
                return new \WP_Error('spcrc_control_lock_lost_after_write', 'Control was stored but exclusive ownership was lost before audit evidence could be completed. Reconciliation is required.');
            }

            $audit = $this->audit->record(
                is_array($existing) ? 'security_control_updated' : 'security_control_created',
                'file-24-security-center',
                $status,
                $status === 'failed' ? 'high' : 'medium',
                ['control_key' => $key, 'status' => $status, 'evidence_ref' => $evidenceRef]
            );
            if (is_wp_error($audit)) {
                if (! AtomicOptionLock::refresh($lockOption, $lockToken, self::LOCK_TTL)) {
                    AuditGapStore::record(
                        'spcrc_control_audit_gap',
                        'control_key',
                        $key,
                        'audit_failed_control_lock_lost',
                        ['audit_error_code' => $audit->get_error_code()]
                    );
                    return new \WP_Error('spcrc_control_audit_gap', 'Control was stored but audit evidence and safe rollback could not be completed. Reconciliation is required.');
                }

                $rolledBack = is_array($existing)
                    ? $wpdb->update(
                        $table,
                        [
                            'title' => $existing['title'] ?? '',
                            'framework' => $existing['framework'] ?? '',
                            'status' => $existing['status'] ?? 'unassessed',
                            'owner_user_id' => $existing['owner_user_id'] ?? null,
                            'evidence_ref' => $existing['evidence_ref'] ?? '',
                            'last_tested_at' => $existing['last_tested_at'] ?? null,
                            'updated_at' => $existing['updated_at'] ?? $now,
                        ],
                        ['control_key' => $key, 'updated_at' => $now]
                    )
                    : $wpdb->delete($table, ['control_key' => $key], ['%s']);
                if ($rolledBack !== 1) {
                    AuditGapStore::record(
                        'spcrc_control_audit_gap',
                        'control_key',
                        $key,
                        'write_rollback_failed',
                        ['audit_error_code' => $audit->get_error_code()]
                    );
                }
                return new \WP_Error('spcrc_control_audit_failed', 'Control change was rolled back because audit evidence could not be stored.');
            }

            return $key;
        } finally {
            if (! AtomicOptionLock::release($lockOption, $lockToken)) {
                do_action('spcrc/control_lock_release_failed', $key);
            }
        }
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

    /** @param array<string,mixed> $row @param array<string,mixed> $payload */
    private function payloadMatches(array $row, array $payload): bool
    {
        foreach ($payload as $field => $value) {
            if (($row[$field] ?? null) != $value) {
                return false;
            }
        }
        return true;
    }

    private function mysqlTime(mixed $value): ?string
    {
        $iso = Sanitizer::isoTime($value);
        return $iso === '' ? null : gmdate('Y-m-d H:i:s', (int) strtotime($iso));
    }
}
