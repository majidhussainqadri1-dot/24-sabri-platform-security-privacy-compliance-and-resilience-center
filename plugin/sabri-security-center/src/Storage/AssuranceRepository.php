<?php

declare(strict_types=1);

namespace Sabri\Platform\Security\Storage;

use Sabri\Platform\Security\Support\Sanitizer;

if (! class_exists(AuditGapStore::class, false)) {
    require_once __DIR__ . '/AuditGapStore.php';
}

/**
 * Stores bounded compliance-applicability, vendor-assurance and backup/restore
 * evidence metadata. Raw contracts, credentials, backup locations, identity
 * documents and forensic evidence belong outside this public control-plane.
 */
final class AssuranceRepository
{
    private const TYPES = ['compliance', 'vendor', 'backup'];
    private const STATUSES = [
        'compliance' => ['not-assessed', 'possibly-applicable', 'applicable', 'not-applicable', 'blocked'],
        'vendor' => ['unassessed', 'under-review', 'approved', 'restricted', 'rejected', 'exited'],
        'backup' => ['unknown', 'scheduled', 'failed', 'successful', 'verified'],
    ];

    public function __construct(private ?AuditLogger $audit = null)
    {
    }

    public function registerHooks(): void
    {
        // Read-only bridge for the System Check. Mutations deliberately require
        // an explicit capability-protected admin workflow or a direct trusted
        // repository call; there is no generic write-through filter/action.
        add_filter('spcrc/backup_evidence', [$this, 'backupEvidence'], 20, 1);
    }

    /** @return string[] */
    public static function types(): array
    {
        return self::TYPES;
    }

    /** @return string[] */
    public static function statuses(string $type): array
    {
        return self::STATUSES[Sanitizer::key($type, 40)] ?? [];
    }

    /** @param array<string,mixed> $data
     *  @return string|\WP_Error
     */
    public function upsert(array $data): string|\WP_Error
    {
        global $wpdb;

        $type = Sanitizer::key($data['record_type'] ?? '', 40);
        $key = Sanitizer::key($data['record_key'] ?? '', 120);
        $title = Sanitizer::text($data['title'] ?? '', 200);
        if (! in_array($type, self::TYPES, true) || $key === '' || $title === '') {
            return new \WP_Error(
                'spcrc_assurance_identity_invalid',
                'A valid assurance type, record key and title are required.'
            );
        }

        $status = Sanitizer::key($data['status'] ?? '', 40);
        if (! in_array($status, self::statuses($type), true)) {
            return new \WP_Error('spcrc_assurance_status_invalid', 'Assurance status is invalid for the selected record type.');
        }

        $ownerUserId = absint($data['owner_user_id'] ?? get_current_user_id());
        if ($ownerUserId < 1 || ! get_userdata($ownerUserId)) {
            return new \WP_Error('spcrc_assurance_owner_invalid', 'A valid assurance owner is required.');
        }

        $evidenceRef = Sanitizer::opaqueReference($data['evidence_ref'] ?? '');
        $rawEvidenceRef = Sanitizer::text($data['evidence_ref'] ?? '', 255);
        if ($rawEvidenceRef !== '' && $evidenceRef === '') {
            return new \WP_Error(
                'spcrc_assurance_evidence_reference_invalid',
                'Evidence must be represented by a bounded opaque reference, not a URL, path or raw evidence.'
            );
        }

        $notes = Sanitizer::text($data['notes'] ?? '', 500);
        if (Sanitizer::containsSensitiveMaterial($notes)) {
            return new \WP_Error(
                'spcrc_assurance_notes_sensitive',
                'Assurance notes appear to contain credentials, personal contact data, an identity number, a URL or a storage path.'
            );
        }

        $reviewedAt = $this->mysqlTime($data['reviewed_at'] ?? '');
        $nextReviewAt = $this->mysqlTime($data['next_review_at'] ?? '');
        $backupCompletedAt = $this->mysqlTime($data['backup_completed_at'] ?? '');
        $restoreTestedAt = $this->mysqlTime($data['restore_tested_at'] ?? '');

        foreach (['reviewed_at' => $reviewedAt, 'backup_completed_at' => $backupCompletedAt, 'restore_tested_at' => $restoreTestedAt] as $field => $value) {
            if ($value !== null && strtotime($value . ' UTC') > time() + 300) {
                return new \WP_Error(
                    'spcrc_assurance_completed_time_future',
                    sprintf('Completed assurance timestamp cannot be in the future: %s.', $field)
                );
            }
        }

        if ($reviewedAt !== null && $nextReviewAt !== null && strtotime($nextReviewAt . ' UTC') <= strtotime($reviewedAt . ' UTC')) {
            return new \WP_Error(
                'spcrc_assurance_review_window_invalid',
                'The next review must be later than the completed review.'
            );
        }

        $finalDetermination = ($type === 'compliance' && in_array($status, ['applicable', 'not-applicable'], true))
            || ($type === 'vendor' && in_array($status, ['approved', 'rejected', 'exited'], true));
        if ($finalDetermination && ($reviewedAt === null || $evidenceRef === '')) {
            return new \WP_Error(
                'spcrc_assurance_determination_evidence_missing',
                'A final assurance determination requires a completed review timestamp and an opaque evidence reference.'
            );
        }
        $timeBoundDetermination = ($type === 'compliance' && in_array($status, ['applicable', 'not-applicable'], true))
            || ($type === 'vendor' && in_array($status, ['approved', 'restricted'], true));
        if ($timeBoundDetermination && $nextReviewAt === null) {
            return new \WP_Error('spcrc_assurance_next_review_missing', 'Current compliance and vendor determinations require a future review date.');
        }

        if ($type !== 'backup') {
            $backupCompletedAt = null;
            $restoreTestedAt = null;
        } else {
            if ($restoreTestedAt !== null && $backupCompletedAt === null) {
                return new \WP_Error(
                    'spcrc_backup_restore_chronology_invalid',
                    'Restore-test evidence requires a related successful backup timestamp.'
                );
            }
            if (
                $restoreTestedAt !== null
                && $backupCompletedAt !== null
                && strtotime($restoreTestedAt . ' UTC') < strtotime($backupCompletedAt . ' UTC')
            ) {
                return new \WP_Error(
                    'spcrc_backup_restore_chronology_invalid',
                    'Restore-test evidence cannot predate the related successful backup.'
                );
            }
            if (in_array($status, ['successful', 'verified'], true) && $backupCompletedAt === null) {
                return new \WP_Error(
                    'spcrc_backup_success_evidence_missing',
                    'A successful backup timestamp is required for this status.'
                );
            }
            if ($status === 'verified' && $restoreTestedAt === null) {
                return new \WP_Error(
                    'spcrc_backup_restore_evidence_missing',
                    'Verified backup status requires a completed restore test.'
                );
            }
            if ($status === 'verified' && $evidenceRef === '') {
                return new \WP_Error(
                    'spcrc_backup_evidence_reference_missing',
                    'Verified backup status requires an opaque evidence reference to the private restore record.'
                );
            }
        }

        $dataClasses = Sanitizer::textList($data['data_classes'] ?? [], 20, 80);
        $dataClassesJson = wp_json_encode($dataClasses, JSON_UNESCAPED_SLASHES);
        if (! is_string($dataClassesJson)) {
            return new \WP_Error('spcrc_assurance_data_classes_invalid', 'Assurance data classes could not be encoded.');
        }

        $table = $wpdb->prefix . 'spcrc_assurance_records';
        $existingRaw = $this->getRaw($type, $key);
        $existing = is_array($existingRaw) ? $this->normalizeRow($existingRaw) : null;
        $now = current_time('mysql', true);
        $payload = [
            'title' => $title,
            'status' => $status,
            'owner_user_id' => $ownerUserId,
            'jurisdiction' => Sanitizer::text($data['jurisdiction'] ?? '', 80),
            'data_classes_json' => $dataClassesJson,
            'evidence_ref' => $evidenceRef,
            'notes' => $notes,
            'reviewed_at' => $reviewedAt,
            'next_review_at' => $nextReviewAt,
            'backup_completed_at' => $backupCompletedAt,
            'restore_tested_at' => $restoreTestedAt,
            'updated_at' => $now,
        ];

        if (is_array($existing)) {
            $recordUuid = Sanitizer::uuid($existing['record_uuid'] ?? '');
            if ($recordUuid === '') {
                return new \WP_Error('spcrc_assurance_stored_identity_invalid', 'Stored assurance identity is invalid.');
            }
            $written = $wpdb->update(
                $table,
                $payload,
                ['record_uuid' => $recordUuid, 'record_type' => $type, 'record_key' => $key],
                ['%s', '%s', '%d', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s'],
                ['%s', '%s', '%s']
            );
            if ($written === false) {
                return new \WP_Error('spcrc_assurance_write_failed', 'Assurance record could not be updated.');
            }
            if ($written === 0) {
                $current = $this->get($type, $key);
                if (! is_array($current) || ! $this->matchesPayload($current, $payload)) {
                    return new \WP_Error(
                        'spcrc_assurance_concurrent_update',
                        'Assurance record changed concurrently and was not overwritten.'
                    );
                }
            }
        } else {
            $recordUuid = wp_generate_uuid4();
            $written = $wpdb->insert(
                $table,
                array_merge([
                    'record_uuid' => $recordUuid,
                    'record_type' => $type,
                    'record_key' => $key,
                    'created_at' => $now,
                ], $payload),
                ['%s', '%s', '%s', '%s', '%s', '%s', '%d', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s']
            );
            if ($written === false) {
                $concurrent = $this->get($type, $key);
                if (! is_array($concurrent)) {
                    return new \WP_Error('spcrc_assurance_write_failed', 'Assurance record could not be created.');
                }
                return new \WP_Error(
                    'spcrc_assurance_concurrent_insert',
                    'Assurance record was created concurrently and was not overwritten.'
                );
            }
        }

        $auditResult = $this->recordAudit('assurance_record_saved', $type, 'completed', 'informational', [
            'record_uuid' => $recordUuid,
            'record_key' => $key,
            'status' => $status,
        ]);
        if (is_wp_error($auditResult)) {
            $rolledBack = is_array($existingRaw)
                ? $this->restoreRaw($table, $existingRaw)
                : $wpdb->delete($table, ['record_uuid' => $recordUuid], ['%s']) === 1;
            if (! $rolledBack) {
                $this->recordAuditGap($recordUuid, 'assurance_audit_rollback_failed');
            }
            return new \WP_Error(
                'spcrc_assurance_audit_failed',
                'Assurance record was not accepted because its audit evidence could not be stored.'
            );
        }
        return $recordUuid;
    }

    /** @return array<string,mixed>|null */
    public function get(string $type, string $key): ?array
    {
        global $wpdb;

        $type = Sanitizer::key($type, 40);
        $key = Sanitizer::key($key, 120);
        if (! in_array($type, self::TYPES, true) || $key === '') {
            return null;
        }

        $row = $this->getRaw($type, $key);
        return is_array($row) ? $this->normalizeRow($row) : null;
    }

    public function count(?string $type = null): int
    {
        global $wpdb;

        $requestedType = $type;
        $type = $type === null ? '' : Sanitizer::key($type, 40);
        if ($requestedType !== null && ! in_array($type, self::TYPES, true)) {
            return 0;
        }
        if ($type !== '') {
            return (int) $wpdb->get_var(
                $wpdb->prepare(
                    "SELECT COUNT(*) FROM {$wpdb->prefix}spcrc_assurance_records WHERE record_type = %s",
                    $type
                )
            );
        }
        return (int) $wpdb->get_var("SELECT COUNT(*) FROM {$wpdb->prefix}spcrc_assurance_records");
    }

    /** @return array<int,array<string,mixed>> */
    public function recent(?string $type = null, int $limit = 50): array
    {
        global $wpdb;

        $limit = max(1, min(100, $limit));
        $requestedType = $type;
        $type = $type === null ? '' : Sanitizer::key($type, 40);
        if ($requestedType !== null && ! in_array($type, self::TYPES, true)) {
            return [];
        }
        if ($type !== '') {
            $rows = $wpdb->get_results(
                $wpdb->prepare(
                    "SELECT * FROM {$wpdb->prefix}spcrc_assurance_records WHERE record_type = %s ORDER BY updated_at DESC LIMIT %d",
                    $type,
                    $limit
                ),
                ARRAY_A
            );
        } else {
            $rows = $wpdb->get_results(
                $wpdb->prepare(
                    "SELECT * FROM {$wpdb->prefix}spcrc_assurance_records ORDER BY updated_at DESC LIMIT %d",
                    $limit
                ),
                ARRAY_A
            );
        }

        if (! is_array($rows)) {
            return [];
        }
        return array_values(array_map([$this, 'normalizeRow'], $rows));
    }

    /** @param mixed $upstream
     *  @return array<string,mixed>
     */
    public function backupEvidence(mixed $upstream): array
    {
        $upstreamEvidence = $this->normalizeBackupEvidence(is_array($upstream) ? $upstream : []);
        if (($upstreamEvidence['status'] ?? '') === 'verified') {
            return $upstreamEvidence;
        }

        $record = $this->latestVerifiedBackup();
        if (is_array($record)) {
            $storedEvidence = $this->normalizeBackupEvidence([
                'status' => $record['status'] ?? '',
                'last_success_at' => $record['backup_completed_at'] ?? '',
                'restore_tested_at' => $record['restore_tested_at'] ?? '',
                'evidence_ref' => $record['evidence_ref'] ?? '',
            ]);
            if (($storedEvidence['status'] ?? '') === 'verified') {
                return $storedEvidence;
            }
        }

        return $upstreamEvidence;
    }

    /** @return array<string,mixed>|null */
    public function latestVerifiedBackup(): ?array
    {
        global $wpdb;

        $row = $wpdb->get_row(
            "SELECT * FROM {$wpdb->prefix}spcrc_assurance_records WHERE record_type = 'backup' AND status = 'verified' AND backup_completed_at IS NOT NULL AND restore_tested_at IS NOT NULL ORDER BY restore_tested_at DESC LIMIT 1",
            ARRAY_A
        );
        return is_array($row) ? $this->normalizeRow($row) : null;
    }

    /** @return array<string,mixed>|null */
    private function getRaw(string $type, string $key): ?array
    {
        global $wpdb;

        $row = $wpdb->get_row(
            $wpdb->prepare(
                "SELECT * FROM {$wpdb->prefix}spcrc_assurance_records WHERE record_type = %s AND record_key = %s",
                $type,
                $key
            ),
            ARRAY_A
        );
        return is_array($row) ? $row : null;
    }

    /** @param array<string,mixed> $row */
    private function restoreRaw(string $table, array $row): bool
    {
        global $wpdb;

        $recordUuid = Sanitizer::uuid($row['record_uuid'] ?? '');
        $type = Sanitizer::key($row['record_type'] ?? '', 40);
        $key = Sanitizer::key($row['record_key'] ?? '', 120);
        if ($recordUuid === '' || ! in_array($type, self::TYPES, true) || $key === '') {
            return false;
        }

        $payload = [
            'title' => (string) ($row['title'] ?? ''),
            'status' => (string) ($row['status'] ?? ''),
            'owner_user_id' => isset($row['owner_user_id']) ? (int) $row['owner_user_id'] : null,
            'jurisdiction' => (string) ($row['jurisdiction'] ?? ''),
            'data_classes_json' => (string) ($row['data_classes_json'] ?? '[]'),
            'evidence_ref' => (string) ($row['evidence_ref'] ?? ''),
            'notes' => (string) ($row['notes'] ?? ''),
            'reviewed_at' => $row['reviewed_at'] ?? null,
            'next_review_at' => $row['next_review_at'] ?? null,
            'backup_completed_at' => $row['backup_completed_at'] ?? null,
            'restore_tested_at' => $row['restore_tested_at'] ?? null,
            'updated_at' => (string) ($row['updated_at'] ?? current_time('mysql', true)),
        ];
        $restored = $wpdb->update(
            $table,
            $payload,
            ['record_uuid' => $recordUuid, 'record_type' => $type, 'record_key' => $key],
            ['%s', '%s', '%d', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s'],
            ['%s', '%s', '%s']
        );
        if ($restored === false) {
            return false;
        }

        $current = $this->getRaw($type, $key);
        if (! is_array($current)) {
            return false;
        }
        foreach ($payload as $field => $value) {
            if (($current[$field] ?? null) != $value) {
                return false;
            }
        }
        return true;
    }

    /** @param array<string,mixed> $input
     *  @return array<string,string>
     */
    private function normalizeBackupEvidence(array $input): array
    {
        $last = Sanitizer::isoTime($input['last_success_at'] ?? '');
        $restore = Sanitizer::isoTime($input['restore_tested_at'] ?? '');
        $reference = Sanitizer::opaqueReference($input['evidence_ref'] ?? '');
        $status = Sanitizer::key($input['status'] ?? 'unknown', 40);
        if (! in_array($status, self::STATUSES['backup'], true)) {
            $status = 'unknown';
        }

        $lastTimestamp = $last === '' ? false : strtotime($last);
        $restoreTimestamp = $restore === '' ? false : strtotime($restore);
        $verified = $status === 'verified'
            && $lastTimestamp !== false
            && $restoreTimestamp !== false
            && $restoreTimestamp >= $lastTimestamp
            && $lastTimestamp <= time() + 300
            && $restoreTimestamp <= time() + 300
            && $reference !== '';

        return [
            'status' => $verified ? 'verified' : ($status === 'verified' ? 'unknown' : $status),
            'last_success_at' => $last,
            'restore_tested_at' => $restore,
            'evidence_ref' => $reference,
        ];
    }

    private function recordAuditGap(string $recordUuid, string $reason): bool
    {
        $recordUuid = Sanitizer::uuid($recordUuid);
        if ($recordUuid === '') {
            return false;
        }
        return AuditGapStore::record(
            'spcrc_assurance_audit_gap',
            'assurance_record',
            $recordUuid,
            $reason
        );
    }

    /** @param array<string,mixed> $row
     *  @return array<string,mixed>
     */
    private function normalizeRow(array $row): array
    {
        $classes = json_decode((string) ($row['data_classes_json'] ?? '[]'), true);
        return [
            'record_uuid' => Sanitizer::uuid($row['record_uuid'] ?? ''),
            'record_type' => Sanitizer::key($row['record_type'] ?? '', 40),
            'record_key' => Sanitizer::key($row['record_key'] ?? '', 120),
            'title' => Sanitizer::text($row['title'] ?? '', 200),
            'status' => Sanitizer::key($row['status'] ?? '', 40),
            'owner_user_id' => absint($row['owner_user_id'] ?? 0),
            'jurisdiction' => Sanitizer::text($row['jurisdiction'] ?? '', 80),
            'data_classes' => Sanitizer::textList(is_array($classes) ? $classes : [], 20, 80),
            'evidence_ref' => Sanitizer::opaqueReference($row['evidence_ref'] ?? ''),
            'notes' => Sanitizer::containsSensitiveMaterial($row['notes'] ?? '')
                ? '[REDACTED]'
                : Sanitizer::text($row['notes'] ?? '', 500),
            'reviewed_at' => Sanitizer::isoTime($row['reviewed_at'] ?? ''),
            'next_review_at' => Sanitizer::isoTime($row['next_review_at'] ?? ''),
            'backup_completed_at' => Sanitizer::isoTime($row['backup_completed_at'] ?? ''),
            'restore_tested_at' => Sanitizer::isoTime($row['restore_tested_at'] ?? ''),
            'created_at' => Sanitizer::isoTime($row['created_at'] ?? ''),
            'updated_at' => Sanitizer::isoTime($row['updated_at'] ?? ''),
        ];
    }

    /** @param array<string,mixed> $record
     *  @param array<string,mixed> $payload
     */
    private function matchesPayload(array $record, array $payload): bool
    {
        $comparisons = [
            'title' => Sanitizer::text($record['title'] ?? '', 200),
            'status' => Sanitizer::key($record['status'] ?? '', 40),
            'owner_user_id' => absint($record['owner_user_id'] ?? 0),
            'jurisdiction' => Sanitizer::text($record['jurisdiction'] ?? '', 80),
            'evidence_ref' => Sanitizer::opaqueReference($record['evidence_ref'] ?? ''),
            'notes' => Sanitizer::text($record['notes'] ?? '', 500),
            'reviewed_at' => $this->mysqlTime($record['reviewed_at'] ?? ''),
            'next_review_at' => $this->mysqlTime($record['next_review_at'] ?? ''),
            'backup_completed_at' => $this->mysqlTime($record['backup_completed_at'] ?? ''),
            'restore_tested_at' => $this->mysqlTime($record['restore_tested_at'] ?? ''),
        ];
        foreach ($comparisons as $field => $value) {
            if (($payload[$field] ?? null) !== $value) {
                return false;
            }
        }

        $storedClasses = Sanitizer::textList($record['data_classes'] ?? [], 20, 80);
        $payloadClasses = json_decode((string) ($payload['data_classes_json'] ?? '[]'), true);
        return $storedClasses === Sanitizer::textList(is_array($payloadClasses) ? $payloadClasses : [], 20, 80);
    }

    private function mysqlTime(mixed $value): ?string
    {
        $iso = Sanitizer::isoTime($value);
        return $iso === '' ? null : gmdate('Y-m-d H:i:s', (int) strtotime($iso));
    }

    /** @param array<string,mixed> $context
     *  @return bool|\WP_Error
     */
    private function recordAudit(string $type, string $module, string $result, string $risk, array $context): bool|\WP_Error
    {
        if ($this->audit === null) {
            return true;
        }
        $recorded = $this->audit->record($type, $module, $result, $risk, $context);
        return is_wp_error($recorded) ? $recorded : true;
    }
}
