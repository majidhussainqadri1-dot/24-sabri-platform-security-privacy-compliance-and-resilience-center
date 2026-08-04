<?php

declare(strict_types=1);

namespace Sabri\Platform\Security\Registry;

use Sabri\Platform\Security\Storage\AuditGapStore;
use Sabri\Platform\Security\Storage\AuditLogger;
use Sabri\Platform\Security\Support\AtomicOptionLock;
use Sabri\Platform\Security\Support\Sanitizer;
use Sabri\Platform\Security\Support\SecureIdentifier;

/**
 * Bounded, audit-bound registry for File 24 governance and assurance metadata.
 *
 * Raw contracts, credentials, patient records, message bodies, private runbooks,
 * forensic payloads and backup locations are explicitly rejected.
 */
final class GovernedArtifactRegistry
{
    private const INDEX_OPTION = 'spcrc_governed_artifact_index_v1';
    private const LOCK_OPTION = 'spcrc_governed_artifact_registry_lock';
    private const LOCK_TTL = 90;
    private const MAX_RECORDS = 2000;
    private const MAX_PAYLOAD_BYTES = 24000;

    /** @var array<string,string[]> */
    private const STATUSES = [
        'policy' => ['draft', 'under-review', 'approved', 'superseded', 'retired'],
        'exception' => ['requested', 'approved', 'rejected', 'expired', 'revoked'],
        'asset' => ['unassessed', 'active', 'restricted', 'retired'],
        'data-inventory' => ['draft', 'active', 'blocked', 'retired'],
        'processing-activity' => ['draft', 'under-review', 'approved', 'blocked', 'retired'],
        'consent' => ['recorded', 'withdrawn', 'expired', 'superseded'],
        'legal-hold' => ['requested', 'active', 'released', 'expired'],
        'vulnerability' => ['reported', 'validated', 'contained', 'remediated', 'verified', 'accepted', 'closed'],
        'external-dependency' => ['unknown', 'available', 'degraded', 'blocked', 'retired'],
        'secret-metadata' => ['planned', 'active', 'rotation-due', 'compromised', 'retired'],
        'key-metadata' => ['planned', 'active', 'rotation-due', 'recovery-required', 'retired'],
        'continuity-plan' => ['draft', 'approved', 'active', 'retired'],
        'bia' => ['draft', 'approved', 'superseded'],
        'recovery-objective' => ['provisional', 'measured', 'approved', 'unachievable', 'retired'],
        'drill' => ['planned', 'running', 'passed', 'failed', 'cancelled'],
        'trust-claim' => ['draft', 'verified', 'expired', 'revoked'],
        'performance-objective' => ['provisional', 'measured', 'approved', 'breached', 'retired'],
        'release-gate' => ['pending', 'passed', 'failed', 'waived', 'not-applicable'],
        'training' => ['planned', 'available', 'completed', 'expired', 'retired'],
        'integration' => ['unassessed', 'compatible', 'degraded', 'blocked', 'retired'],
        'security-test' => ['planned', 'running', 'passed', 'failed', 'accepted-risk'],
        'deletion-ledger' => ['pending', 'blocked-hold', 'dispatching', 'reconciled', 'failed', 'closed'],
        'alert' => ['open', 'acknowledged', 'investigating', 'resolved', 'suppressed'],
        'remote-evidence' => ['queued', 'delivering', 'delivered', 'retry', 'dead-letter'],
        'job' => ['queued', 'running', 'succeeded', 'failed', 'cancelled', 'dead-letter'],
        'incident-action' => ['planned', 'in-progress', 'completed', 'failed', 'cancelled'],
        'upload-assurance' => ['pending', 'quarantined', 'scanning', 'approved', 'rejected', 'expired'],
        'private-delivery' => ['issued', 'consumed', 'revoked', 'expired'],
    ];

    /** @var array<string,string> */
    private const CAPABILITIES = [
        'policy' => 'spcrc_manage_policies',
        'exception' => 'spcrc_manage_policies',
        'asset' => 'spcrc_manage_assets',
        'data-inventory' => 'spcrc_manage_assets',
        'processing-activity' => 'spcrc_manage_privacy_requests',
        'consent' => 'spcrc_manage_privacy_requests',
        'legal-hold' => 'spcrc_manage_privacy_requests',
        'vulnerability' => 'spcrc_manage_vulnerabilities',
        'external-dependency' => 'spcrc_manage_integrations',
        'secret-metadata' => 'spcrc_manage_security_settings',
        'key-metadata' => 'spcrc_manage_security_settings',
        'continuity-plan' => 'spcrc_manage_resilience',
        'bia' => 'spcrc_manage_resilience',
        'recovery-objective' => 'spcrc_manage_resilience',
        'drill' => 'spcrc_manage_resilience',
        'trust-claim' => 'spcrc_manage_trust_center',
        'performance-objective' => 'spcrc_manage_performance',
        'release-gate' => 'spcrc_manage_release_gates',
        'training' => 'spcrc_manage_training',
        'integration' => 'spcrc_manage_integrations',
        'security-test' => 'spcrc_run_security_assessments',
        'deletion-ledger' => 'spcrc_manage_privacy_requests',
        'alert' => 'spcrc_view_security_events',
        'remote-evidence' => 'spcrc_view_security_events',
        'job' => 'spcrc_manage_integrations',
        'incident-action' => 'spcrc_manage_incidents',
        'upload-assurance' => 'spcrc_manage_assurance',
        'private-delivery' => 'spcrc_manage_assurance',
    ];

    private AuditLogger $audit;

    public function __construct(?AuditLogger $audit = null)
    {
        $this->audit = $audit ?? new AuditLogger();
    }

    /** @return string[] */
    public static function types(): array
    {
        return array_keys(self::STATUSES);
    }

    /** @return string[] */
    public static function statuses(string $type): array
    {
        return self::STATUSES[Sanitizer::key($type, 60)] ?? [];
    }

    public static function capability(string $type): string
    {
        return self::CAPABILITIES[Sanitizer::key($type, 60)] ?? 'spcrc_manage_assurance';
    }

    /**
     * @param array<string,mixed> $data
     * @return string|\WP_Error
     */
    public function save(array $data, int $expectedVersion = 0): string|\WP_Error
    {
        $type = Sanitizer::key($data['artifact_type'] ?? '', 60);
        $key = Sanitizer::key($data['artifact_key'] ?? '', 120);
        $title = Sanitizer::text($data['title'] ?? '', 200);
        $status = Sanitizer::key($data['status'] ?? '', 40);

        if (! isset(self::STATUSES[$type]) || $key === '' || $title === '') {
            return new \WP_Error('spcrc_artifact_identity_invalid', 'A supported artifact type, stable key and bounded title are required.');
        }
        if (! in_array($status, self::STATUSES[$type], true)) {
            return new \WP_Error('spcrc_artifact_status_invalid', 'Artifact status is invalid for the selected logical domain.');
        }
        if (Sanitizer::containsSensitiveMaterial($title)) {
            return new \WP_Error('spcrc_artifact_title_sensitive', 'Artifact title appears to contain sensitive material.');
        }

        $classification = strtoupper(Sanitizer::text($data['classification'] ?? 'C1', 2));
        if (! in_array($classification, ['C0', 'C1', 'C2', 'C3', 'C4', 'C5'], true)) {
            return new \WP_Error('spcrc_artifact_classification_invalid', 'Artifact classification must be C0 through C5.');
        }
        if ($classification === 'C5' && in_array($type, ['trust-claim', 'training'], true)) {
            return new \WP_Error('spcrc_artifact_public_secret_conflict', 'Public-facing artifact types cannot carry C5 classification.');
        }

        $evidenceRef = Sanitizer::opaqueReference($data['evidence_ref'] ?? '');
        $rawEvidence = Sanitizer::text($data['evidence_ref'] ?? '', 255);
        if ($rawEvidence !== '' && $evidenceRef === '') {
            return new \WP_Error('spcrc_artifact_evidence_invalid', 'Evidence must be represented by a bounded opaque reference.');
        }

        $payload = $this->sanitizePayload($data['payload'] ?? []);
        if (is_wp_error($payload)) {
            return $payload;
        }
        $payloadJson = wp_json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        if (! is_string($payloadJson) || strlen($payloadJson) > self::MAX_PAYLOAD_BYTES) {
            return new \WP_Error('spcrc_artifact_payload_too_large', 'Artifact payload exceeds the bounded registry limit.');
        }

        $effectiveAt = Sanitizer::isoTime($data['effective_at'] ?? '');
        $expiresAt = Sanitizer::isoTime($data['expires_at'] ?? '');
        $reviewedAt = Sanitizer::isoTime($data['reviewed_at'] ?? '');
        $nextReviewAt = Sanitizer::isoTime($data['next_review_at'] ?? '');
        if ($effectiveAt !== '' && $expiresAt !== '' && strtotime($expiresAt) <= strtotime($effectiveAt)) {
            return new \WP_Error('spcrc_artifact_time_window_invalid', 'Artifact expiry must be later than its effective time.');
        }
        if ($reviewedAt !== '' && $nextReviewAt !== '' && strtotime($nextReviewAt) <= strtotime($reviewedAt)) {
            return new \WP_Error('spcrc_artifact_review_window_invalid', 'Next review must be later than the completed review.');
        }

        $gate = $this->validateEvidenceGates($type, $status, $evidenceRef, $expiresAt, $reviewedAt, $nextReviewAt);
        if (is_wp_error($gate)) {
            return $gate;
        }

        $ownerUserId = absint($data['owner_user_id'] ?? get_current_user_id());
        $moduleKey = Sanitizer::key($data['module_key'] ?? 'file-24-security-center', 120);
        if ($moduleKey === '') {
            $moduleKey = 'file-24-security-center';
        }

        $token = AtomicOptionLock::acquire(self::LOCK_OPTION, self::LOCK_TTL);
        if (is_wp_error($token)) {
            return new \WP_Error('spcrc_artifact_registry_locked', 'The governed artifact registry is being changed by another request.');
        }

        try {
            $index = $this->index();
            $identity = $type . ':' . $key;
            $existing = $this->get($type, $key);
            if (! is_array($existing) && count($index) >= self::MAX_RECORDS) {
                return new \WP_Error('spcrc_artifact_capacity_exhausted', 'The bounded artifact registry is at capacity; unresolved records were not evicted.');
            }
            if (is_array($existing) && $expectedVersion > 0 && (int) ($existing['version'] ?? 0) !== $expectedVersion) {
                return new \WP_Error('spcrc_artifact_concurrent_update', 'Artifact changed concurrently and was not overwritten.');
            }

            $uuid = is_array($existing) ? Sanitizer::uuid($existing['artifact_uuid'] ?? '') : '';
            if ($uuid === '') {
                $uuid = SecureIdentifier::uuid4('governed-artifact');
                if (is_wp_error($uuid)) {
                    return $uuid;
                }
            }
            $version = is_array($existing) ? ((int) ($existing['version'] ?? 0) + 1) : 1;
            $now = gmdate('c');
            $record = [
                'artifact_uuid' => $uuid,
                'artifact_type' => $type,
                'artifact_key' => $key,
                'module_key' => $moduleKey,
                'title' => $title,
                'status' => $status,
                'classification' => $classification,
                'owner_user_id' => $ownerUserId,
                'version' => $version,
                'payload' => $payload,
                'evidence_ref' => $evidenceRef,
                'effective_at' => $effectiveAt,
                'expires_at' => $expiresAt,
                'reviewed_at' => $reviewedAt,
                'next_review_at' => $nextReviewAt,
                'created_at' => is_array($existing) ? (string) ($existing['created_at'] ?? $now) : $now,
                'updated_at' => $now,
            ];

            $option = self::recordOption($type, $key);
            $previousOption = get_option($option, null);
            $previousIndex = $index;

            update_option($option, $record, false);
            if (get_option($option, null) !== $record) {
                return new \WP_Error('spcrc_artifact_write_failed', 'Artifact could not be stored and verified.');
            }

            $index[$identity] = [
                'artifact_uuid' => $uuid,
                'artifact_type' => $type,
                'artifact_key' => $key,
                'updated_at' => $now,
            ];
            uasort($index, static fn (array $a, array $b): int => strcmp((string) ($b['updated_at'] ?? ''), (string) ($a['updated_at'] ?? '')));
            update_option(self::INDEX_OPTION, $index, false);
            if (get_option(self::INDEX_OPTION, null) !== $index) {
                $this->restoreOption($option, $previousOption);
                return new \WP_Error('spcrc_artifact_index_write_failed', 'Artifact index could not be stored and verified.');
            }

            $audit = $this->audit->record(
                'governed_artifact_saved',
                $moduleKey,
                is_array($existing) ? 'updated' : 'created',
                $type === 'vulnerability' ? 'high' : 'informational',
                [
                    'artifact_uuid' => $uuid,
                    'artifact_type' => $type,
                    'artifact_key' => $key,
                    'artifact_version' => $version,
                    'evidence_ref' => $evidenceRef,
                ]
            );
            if (is_wp_error($audit)) {
                $this->restoreOption($option, $previousOption);
                update_option(self::INDEX_OPTION, $previousIndex, false);
                if (get_option(self::INDEX_OPTION, null) !== $previousIndex) {
                    AuditGapStore::record(
                        'spcrc_artifact_audit_gap',
                        'artifact_uuid',
                        $uuid,
                        'artifact_audit_rollback_failed',
                        ['artifact_type' => $type, 'artifact_key' => $key]
                    );
                }
                return new \WP_Error('spcrc_artifact_audit_failed', 'Artifact change was rolled back because audit evidence could not be stored.');
            }

            do_action('spcrc/governed_artifact_saved', $record, $existing);
            return $uuid;
        } finally {
            AtomicOptionLock::release(self::LOCK_OPTION, $token);
        }
    }

    /** @return array<string,mixed>|null */
    public function get(string $type, string $key): ?array
    {
        $type = Sanitizer::key($type, 60);
        $key = Sanitizer::key($key, 120);
        if (! isset(self::STATUSES[$type]) || $key === '') {
            return null;
        }
        $record = get_option(self::recordOption($type, $key), null);
        return is_array($record) ? $this->normalizeRecord($record) : null;
    }

    /** @return array<int,array<string,mixed>> */
    public function recent(?string $type = null, int $limit = 50): array
    {
        $limit = max(1, min(200, $limit));
        $type = $type === null ? '' : Sanitizer::key($type, 60);
        if ($type !== '' && ! isset(self::STATUSES[$type])) {
            return [];
        }

        $rows = [];
        foreach ($this->index() as $item) {
            if (! is_array($item)) {
                continue;
            }
            if ($type !== '' && ($item['artifact_type'] ?? '') !== $type) {
                continue;
            }
            $record = $this->get((string) ($item['artifact_type'] ?? ''), (string) ($item['artifact_key'] ?? ''));
            if (is_array($record)) {
                $rows[] = $record;
            }
            if (count($rows) >= $limit) {
                break;
            }
        }
        return $rows;
    }

    public function count(?string $type = null): int
    {
        $type = $type === null ? '' : Sanitizer::key($type, 60);
        if ($type !== '' && ! isset(self::STATUSES[$type])) {
            return 0;
        }
        if ($type === '') {
            return count($this->index());
        }
        $count = 0;
        foreach ($this->index() as $item) {
            if (is_array($item) && ($item['artifact_type'] ?? '') === $type) {
                ++$count;
            }
        }
        return $count;
    }

    /**
     * @param array<string,mixed> $payloadPatch
     * @return string|\WP_Error
     */
    public function transition(string $type, string $key, string $status, int $expectedVersion, array $payloadPatch = []): string|\WP_Error
    {
        $existing = $this->get($type, $key);
        if (! is_array($existing)) {
            return new \WP_Error('spcrc_artifact_not_found', 'Governed artifact does not exist.');
        }
        $payload = is_array($existing['payload'] ?? null) ? $existing['payload'] : [];
        $payload = array_replace_recursive($payload, $payloadPatch);
        $existing['status'] = $status;
        $existing['payload'] = $payload;
        return $this->save($existing, $expectedVersion);
    }

    /** @return array<string,array<string,mixed>> */
    private function index(): array
    {
        $raw = get_option(self::INDEX_OPTION, []);
        if (! is_array($raw)) {
            return [];
        }
        $safe = [];
        $count = 0;
        foreach ($raw as $identity => $item) {
            if (++$count > self::MAX_RECORDS) {
                break;
            }
            if (! is_string($identity) || ! is_array($item)) {
                continue;
            }
            $type = Sanitizer::key($item['artifact_type'] ?? '', 60);
            $key = Sanitizer::key($item['artifact_key'] ?? '', 120);
            $uuid = Sanitizer::uuid($item['artifact_uuid'] ?? '');
            $updated = Sanitizer::isoTime($item['updated_at'] ?? '');
            if (! isset(self::STATUSES[$type]) || $key === '' || $uuid === '' || $updated === '') {
                continue;
            }
            $safe[$type . ':' . $key] = [
                'artifact_uuid' => $uuid,
                'artifact_type' => $type,
                'artifact_key' => $key,
                'updated_at' => $updated,
            ];
        }
        return $safe;
    }

    /** @param mixed $payload
     *  @return array<string,mixed>|\WP_Error
     */
    private function sanitizePayload(mixed $payload, int $depth = 0): array|\WP_Error
    {
        if (! is_array($payload) || $depth > 4) {
            return new \WP_Error('spcrc_artifact_payload_invalid', 'Artifact payload must be a bounded associative array.');
        }
        $safe = [];
        $items = 0;
        foreach ($payload as $rawKey => $value) {
            if (++$items > 80) {
                return new \WP_Error('spcrc_artifact_payload_items_exceeded', 'Artifact payload contains too many fields.');
            }
            $key = Sanitizer::key($rawKey, 80);
            if ($key === '') {
                continue;
            }
            if (is_array($value)) {
                if ($this->isList($value)) {
                    $list = [];
                    $listCount = 0;
                    foreach ($value as $item) {
                        if (++$listCount > 50) {
                            break;
                        }
                        if (is_array($item)) {
                            $nested = $this->sanitizePayload($item, $depth + 1);
                            if (is_wp_error($nested)) {
                                return $nested;
                            }
                            $list[] = $nested;
                        } elseif (is_bool($item) || is_int($item) || is_float($item)) {
                            $list[] = $item;
                        } else {
                            $text = Sanitizer::text($item, 500);
                            if ($text !== '' && Sanitizer::containsSensitiveMaterial($text)) {
                                return new \WP_Error('spcrc_artifact_payload_sensitive', 'Artifact payload appears to contain sensitive material.');
                            }
                            if ($text !== '') {
                                $list[] = $text;
                            }
                        }
                    }
                    $safe[$key] = $list;
                } else {
                    $nested = $this->sanitizePayload($value, $depth + 1);
                    if (is_wp_error($nested)) {
                        return $nested;
                    }
                    $safe[$key] = $nested;
                }
                continue;
            }
            if (is_bool($value) || is_int($value) || is_float($value)) {
                $safe[$key] = $value;
                continue;
            }
            $text = Sanitizer::text($value, 1000);
            if ($text !== '' && Sanitizer::containsSensitiveMaterial($text)) {
                return new \WP_Error('spcrc_artifact_payload_sensitive', 'Artifact payload appears to contain sensitive material.');
            }
            $safe[$key] = $text;
        }
        return $safe;
    }

    /** @return bool|\WP_Error */
    private function validateEvidenceGates(
        string $type,
        string $status,
        string $evidenceRef,
        string $expiresAt,
        string $reviewedAt,
        string $nextReviewAt
    ): bool|\WP_Error {
        $requiresEvidence = [
            'policy' => ['approved'],
            'exception' => ['approved', 'rejected', 'revoked'],
            'processing-activity' => ['approved', 'blocked'],
            'legal-hold' => ['active', 'released'],
            'vulnerability' => ['remediated', 'verified', 'accepted', 'closed'],
            'continuity-plan' => ['approved', 'active'],
            'bia' => ['approved'],
            'recovery-objective' => ['measured', 'approved', 'unachievable'],
            'drill' => ['passed', 'failed'],
            'trust-claim' => ['verified'],
            'performance-objective' => ['measured', 'approved', 'breached'],
            'release-gate' => ['passed', 'failed', 'waived'],
            'security-test' => ['passed', 'failed', 'accepted-risk'],
            'deletion-ledger' => ['reconciled', 'failed', 'closed'],
        ];
        if (in_array($status, $requiresEvidence[$type] ?? [], true) && $evidenceRef === '') {
            return new \WP_Error('spcrc_artifact_evidence_required', 'An opaque evidence reference is required for this artifact determination.');
        }
        if ($type === 'trust-claim' && $status === 'verified' && ($reviewedAt === '' || $expiresAt === '')) {
            return new \WP_Error('spcrc_trust_claim_review_invalid', 'Verified public trust claims require review and expiry timestamps.');
        }
        if (in_array($type, ['policy', 'continuity-plan', 'bia', 'performance-objective'], true)
            && in_array($status, ['approved', 'active', 'measured'], true)
            && $nextReviewAt === ''
        ) {
            return new \WP_Error('spcrc_artifact_next_review_required', 'Approved governance artifacts require a future review date.');
        }
        return true;
    }

    /** @param array<string,mixed> $record
     *  @return array<string,mixed>
     */
    private function normalizeRecord(array $record): array
    {
        return [
            'artifact_uuid' => Sanitizer::uuid($record['artifact_uuid'] ?? ''),
            'artifact_type' => Sanitizer::key($record['artifact_type'] ?? '', 60),
            'artifact_key' => Sanitizer::key($record['artifact_key'] ?? '', 120),
            'module_key' => Sanitizer::key($record['module_key'] ?? '', 120),
            'title' => Sanitizer::text($record['title'] ?? '', 200),
            'status' => Sanitizer::key($record['status'] ?? '', 40),
            'classification' => strtoupper(Sanitizer::text($record['classification'] ?? 'C1', 2)),
            'owner_user_id' => absint($record['owner_user_id'] ?? 0),
            'version' => max(1, absint($record['version'] ?? 1)),
            'payload' => is_array($record['payload'] ?? null) ? $record['payload'] : [],
            'evidence_ref' => Sanitizer::opaqueReference($record['evidence_ref'] ?? ''),
            'effective_at' => Sanitizer::isoTime($record['effective_at'] ?? ''),
            'expires_at' => Sanitizer::isoTime($record['expires_at'] ?? ''),
            'reviewed_at' => Sanitizer::isoTime($record['reviewed_at'] ?? ''),
            'next_review_at' => Sanitizer::isoTime($record['next_review_at'] ?? ''),
            'created_at' => Sanitizer::isoTime($record['created_at'] ?? ''),
            'updated_at' => Sanitizer::isoTime($record['updated_at'] ?? ''),
        ];
    }

    private static function recordOption(string $type, string $key): string
    {
        return 'spcrc_artifact_' . substr(hash('sha256', $type . '|' . $key), 0, 40);
    }

    private function restoreOption(string $option, mixed $previous): void
    {
        if ($previous === null) {
            delete_option($option);
            return;
        }
        update_option($option, $previous, false);
    }

    /** @param array<mixed> $value */
    private function isList(array $value): bool
    {
        $expected = 0;
        foreach ($value as $key => $unused) {
            if ($key !== $expected) {
                return false;
            }
            ++$expected;
        }
        return true;
    }
}
