<?php

declare(strict_types=1);

namespace Sabri\Platform\Security\Storage;

use Sabri\Platform\Security\Support\Sanitizer;
use Sabri\Platform\Security\Support\SecureIdentifier;

if (! class_exists(AuditGapStore::class, false)) {
    require_once __DIR__ . '/AuditGapStore.php';
}
if (! class_exists(AuditLogger::class, false)) {
    require_once __DIR__ . '/AuditLogger.php';
}
if (! class_exists(SecureIdentifier::class, false)) {
    require_once dirname(__DIR__) . '/Support/SecureIdentifier.php';
}

final class IncidentRepository
{
    private const SEVERITIES = ['sev0', 'sev1', 'sev2', 'sev3', 'sev4'];

    private AuditLogger $audit;

    public function __construct(?AuditLogger $audit = null)
    {
        $this->audit = $audit ?? new AuditLogger();
    }

    /** @param array<string,mixed> $data
     *  @return string|\WP_Error
     */
    public function create(array $data): string|\WP_Error
    {
        global $wpdb;
        $title = Sanitizer::text($data['title'] ?? '', 200);
        $severity = Sanitizer::key($data['severity'] ?? 'sev4', 20);
        $summary = Sanitizer::text($data['summary'] ?? '', 1000);
        $evidenceRef = Sanitizer::opaqueReference($data['evidence_ref'] ?? '');
        if ($title === '' || Sanitizer::containsSensitiveMaterial($title)) {
            return new \WP_Error('spcrc_incident_invalid', 'A bounded, non-sensitive incident title is required.');
        }
        if (! in_array($severity, self::SEVERITIES, true)) {
            $severity = 'sev4';
        }
        if (Sanitizer::containsSensitiveMaterial($summary)) {
            return new \WP_Error('spcrc_incident_summary_sensitive', 'Incident summary contains sensitive material; store details privately and use an opaque evidence reference.');
        }
        if (in_array($severity, ['sev0', 'sev1'], true) && $evidenceRef === '') {
            return new \WP_Error('spcrc_incident_evidence_required', 'SEV0/SEV1 incidents require an opaque private evidence reference.');
        }

        $uuid = SecureIdentifier::uuid4('incident');
        if (is_wp_error($uuid)) {
            return $uuid;
        }
        $now = current_time('mysql', true);
        $table = $wpdb->prefix . 'spcrc_incidents';
        $inserted = $wpdb->insert(
            $table,
            [
                'incident_uuid' => $uuid,
                'title' => $title,
                'severity' => $severity,
                'status' => 'open',
                'owner_user_id' => absint($data['owner_user_id'] ?? get_current_user_id()) ?: null,
                'summary' => $summary,
                'evidence_ref' => $evidenceRef,
                'opened_at' => $now,
                'updated_at' => $now,
                'closed_at' => null,
            ],
            ['%s', '%s', '%s', '%s', '%d', '%s', '%s', '%s', '%s', '%s']
        );
        if ($inserted !== 1) {
            return new \WP_Error('spcrc_incident_write_failed', 'Incident could not be stored exactly once.');
        }

        $audit = $this->audit->record(
            'security_incident_created',
            'file-24-security-center',
            'open',
            in_array($severity, ['sev0', 'sev1'], true) ? 'critical' : ($severity === 'sev2' ? 'high' : 'medium'),
            ['incident_uuid' => $uuid, 'severity' => $severity, 'evidence_ref' => $evidenceRef]
        );
        if (is_wp_error($audit)) {
            $deleted = $wpdb->delete($table, ['incident_uuid' => $uuid], ['%s']);
            if ($deleted !== 1) {
                AuditGapStore::record('spcrc_incident_audit_gap', 'incident_uuid', $uuid, 'create_rollback_failed');
            }
            return new \WP_Error('spcrc_incident_audit_failed', 'Incident creation was rolled back because audit evidence could not be stored.');
        }

        do_action('spcrc/security_incident_created', $uuid, $severity);
        return $uuid;
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
            $wpdb->prepare("SELECT incident_uuid, title, severity, status, evidence_ref, opened_at, updated_at FROM {$wpdb->prefix}spcrc_incidents ORDER BY updated_at DESC LIMIT %d", $limit),
            ARRAY_A
        );
        return is_array($rows) ? $rows : [];
    }
}
