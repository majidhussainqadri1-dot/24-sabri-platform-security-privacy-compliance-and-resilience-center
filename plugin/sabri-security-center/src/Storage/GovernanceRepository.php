<?php

declare(strict_types=1);

namespace Sabri\Platform\Security\Storage;

use Sabri\Platform\Security\Support\AtomicOptionLock;
use Sabri\Platform\Security\Support\Sanitizer;

if (! class_exists(AuditGapStore::class, false)) {
    require_once __DIR__ . '/AuditGapStore.php';
}
if (! class_exists(AtomicOptionLock::class, false)) {
    require_once dirname(__DIR__) . '/Support/AtomicOptionLock.php';
}

/**
 * Stores only bounded governance metadata. Full justifications, legal advice,
 * key material, incident records and private evidence remain in the protected
 * operations store and are referenced by opaque identifiers.
 */
final class GovernanceRepository
{
    private const TYPES = [
        'critical-risk-acceptance',
        'finding-risk-acceptance',
        'policy-exception',
        'production-restore',
        'key-rotation',
        'incident-closure',
        'mass-restriction',
    ];
    private const STATUSES = ['pending', 'approved', 'rejected', 'expired', 'revoked'];
    private const MAX_LIFETIME = 2592000;
    private const AUDIT_GAP_OPTION = 'spcrc_governance_audit_gap';
    private const AUDIT_GAP_LOCK_OPTION = 'spcrc_governance_audit_gap_lock';
    private const AUDIT_GAP_LOCK_TTL = 30;

    public function __construct(private ?AuditLogger $audit = null)
    {
    }

    public function registerHooks(): void
    {
        add_filter('spcrc/governance_decision', [$this, 'filterDecision'], 10, 2);
        add_action('spcrc_daily_retention', [$this, 'expirePending'], 20);
    }

    public function filterDecision(mixed $current, string $decisionUuid): mixed
    {
        return $current !== null ? $current : $this->get($decisionUuid);
    }

    /** @return string[] */
    public static function types(): array
    {
        return self::TYPES;
    }

    /** @param array<string,mixed> $data
     *  @return string|\WP_Error
     */
    public function request(array $data): string|\WP_Error
    {
        global $wpdb;

        if (! current_user_can('spcrc_request_governance_decision')) {
            return new \WP_Error('spcrc_governance_request_forbidden', 'You are not allowed to request a high-risk governance decision.');
        }

        $type = Sanitizer::key($data['decision_type'] ?? '', 60);
        $subject = Sanitizer::key($data['subject_key'] ?? '', 120);
        $module = Sanitizer::key($data['module_key'] ?? 'file-24-security-center', 120);
        $evidence = Sanitizer::opaqueReference($data['evidence_ref'] ?? '');
        $rationale = Sanitizer::text($data['rationale'] ?? '', 500);
        $requester = absint($data['requester_user_id'] ?? get_current_user_id());

        if (! in_array($type, self::TYPES, true) || $subject === '' || $module === '') {
            return new \WP_Error('spcrc_governance_identity_invalid', 'Decision type, subject and module are required.');
        }
        if ($requester < 1 || $requester !== get_current_user_id() || ! get_userdata($requester)) {
            return new \WP_Error('spcrc_governance_requester_invalid', 'The authenticated requester must own the request.');
        }
        if ($evidence === '') {
            return new \WP_Error('spcrc_governance_evidence_invalid', 'An opaque private evidence reference is required.');
        }
        if ($rationale === '' || Sanitizer::containsSensitiveMaterial($rationale)) {
            return new \WP_Error('spcrc_governance_rationale_invalid', 'A bounded, non-sensitive rationale is required.');
        }

        $requestedAt = current_time('mysql', true);
        $expiry = Sanitizer::isoTime($data['expires_at'] ?? '');
        $expiryTs = $expiry === '' ? time() + (7 * DAY_IN_SECONDS) : (int) strtotime($expiry);
        if ($expiryTs <= time() || $expiryTs > time() + self::MAX_LIFETIME) {
            return new \WP_Error('spcrc_governance_expiry_invalid', 'Decision expiry must be in the future and no more than 30 days away.');
        }

        $lockOption = 'spcrc_governance_request_lock_' . substr(hash('sha256', $type . '|' . $subject), 0, 32);
        $lockToken = AtomicOptionLock::acquire($lockOption, 30);
        if (is_wp_error($lockToken)) {
            return new \WP_Error(
                'spcrc_governance_request_locked',
                'A governance request for this subject is being created concurrently. Refresh and try again.'
            );
        }

        try {
            $duplicate = $wpdb->get_var($wpdb->prepare(
                "SELECT decision_uuid FROM {$wpdb->prefix}spcrc_governance_decisions WHERE decision_type = %s AND subject_key = %s AND status = 'pending' AND expires_at > %s LIMIT 1",
                $type,
                $subject,
                $requestedAt
            ));
            if (is_string($duplicate) && Sanitizer::uuid($duplicate) !== '') {
                return new \WP_Error('spcrc_governance_duplicate_pending', 'An active decision request already exists for this subject.');
            }

            if (! AtomicOptionLock::refresh($lockOption, $lockToken, 30)) {
                return new \WP_Error(
                    'spcrc_governance_request_lock_lost',
                    'Governance request ownership was lost before the request could be stored.'
                );
            }

            $uuid = wp_generate_uuid4();
            $inserted = $wpdb->insert(
                $wpdb->prefix . 'spcrc_governance_decisions',
                [
                    'decision_uuid' => $uuid,
                    'decision_type' => $type,
                    'subject_key' => $subject,
                    'module_key' => $module,
                    'status' => 'pending',
                    'requester_user_id' => $requester,
                    'approver_user_id' => null,
                    'evidence_ref' => $evidence,
                    'rationale_hash' => hash('sha256', $rationale),
                    'requested_at' => $requestedAt,
                    'expires_at' => gmdate('Y-m-d H:i:s', $expiryTs),
                    'decided_at' => null,
                    'revoked_at' => null,
                    'lock_version' => 0,
                ],
                ['%s', '%s', '%s', '%s', '%s', '%d', '%d', '%s', '%s', '%s', '%s', '%s', '%s', '%d']
            );
            if ($inserted !== 1) {
                return new \WP_Error('spcrc_governance_write_failed', 'Governance decision request could not be stored exactly once.');
            }

            if (! AtomicOptionLock::refresh($lockOption, $lockToken, 30)) {
                $deleted = $wpdb->delete(
                    $wpdb->prefix . 'spcrc_governance_decisions',
                    ['decision_uuid' => $uuid, 'status' => 'pending'],
                    ['%s', '%s']
                );
                if ($deleted !== 1) {
                    $this->recordAuditGap($uuid, 'request_lock_lost_rollback_failed');
                }
                return new \WP_Error(
                    'spcrc_governance_request_lock_lost_after_write',
                    'Governance request ownership was lost after storage; the request was rolled back before audit admission.'
                );
            }

            $audit = $this->audit?->record('governance_decision_requested', $module, 'pending', 'high', [
                'decision_uuid' => $uuid,
                'decision_type' => $type,
                'subject_key' => $subject,
                'evidence_ref' => $evidence,
            ]);
            if (is_wp_error($audit)) {
                // Governance truth must not silently exist without its audit evidence.
                $deleted = $wpdb->delete($wpdb->prefix . 'spcrc_governance_decisions', ['decision_uuid' => $uuid], ['%s']);
                if ($deleted !== 1) {
                    $this->recordAuditGap($uuid, 'request_rollback_failed');
                }
                return new \WP_Error('spcrc_governance_audit_failed', 'Governance request was rolled back because audit evidence could not be stored.');
            }

            return $uuid;
        } finally {
            if (! AtomicOptionLock::release($lockOption, $lockToken)) {
                do_action('spcrc/governance_request_lock_release_failed', $type, $subject);
            }
        }
    }

    /** @param array<string,mixed> $context
     *  @return bool|\WP_Error
     */
    public function decide(string $decisionUuid, string $status, array $context): bool|\WP_Error
    {
        global $wpdb;

        if (! current_user_can('spcrc_approve_governance_decision')) {
            return new \WP_Error('spcrc_governance_approval_forbidden', 'You are not allowed to approve or reject high-risk governance decisions.');
        }

        $decisionUuid = Sanitizer::uuid($decisionUuid);
        $status = Sanitizer::key($status, 30);
        if ($decisionUuid === '' || ! in_array($status, ['approved', 'rejected'], true)) {
            return new \WP_Error('spcrc_governance_decision_invalid', 'Decision UUID or outcome is invalid.');
        }
        $row = $this->get($decisionUuid);
        if (! is_array($row)) {
            return new \WP_Error('spcrc_governance_not_found', 'Governance decision could not be found.');
        }
        if (($row['status'] ?? '') !== 'pending') {
            return new \WP_Error('spcrc_governance_not_pending', 'Only a pending decision may be decided.');
        }
        if (strtotime((string) ($row['expires_at'] ?? '') . ' UTC') <= time()) {
            $this->expireOne($decisionUuid, (int) ($row['lock_version'] ?? 0));
            return new \WP_Error('spcrc_governance_expired', 'The governance request has expired.');
        }

        $approver = get_current_user_id();
        if ($approver < 1 || $approver === (int) ($row['requester_user_id'] ?? 0)) {
            return new \WP_Error('spcrc_governance_separation_failed', 'Requester and approver must be different authenticated users.');
        }
        $expectedLock = absint($context['expected_lock_version'] ?? -1);
        if ($expectedLock !== (int) ($row['lock_version'] ?? 0)) {
            return new \WP_Error('spcrc_governance_stale_decision', 'Governance decision changed before approval. Refresh and retry.');
        }

        $stepUpRef = Sanitizer::opaqueReference($context['step_up_reference'] ?? '');
        $stepUpOk = $stepUpRef !== '' && Sanitizer::boolean(apply_filters(
            'spcrc/verify_step_up_assurance',
            false,
            $approver,
            'governance:' . (string) ($row['decision_type'] ?? ''),
            $stepUpRef
        ));
        if (! $stepUpOk) {
            return new \WP_Error('spcrc_governance_step_up_required', 'Fresh File 00 step-up assurance is required.');
        }

        $note = Sanitizer::text($context['note'] ?? '', 500);
        if ($note === '' || Sanitizer::containsSensitiveMaterial($note)) {
            return new \WP_Error('spcrc_governance_note_invalid', 'A bounded, non-sensitive decision note is required.');
        }

        $now = current_time('mysql', true);
        $updated = $wpdb->query($wpdb->prepare(
            "UPDATE {$wpdb->prefix}spcrc_governance_decisions SET status = %s, approver_user_id = %d, decided_at = %s, lock_version = %d WHERE decision_uuid = %s AND status = 'pending' AND lock_version = %d AND expires_at > %s",
            $status,
            $approver,
            $now,
            $expectedLock + 1,
            $decisionUuid,
            $expectedLock,
            $now
        ));
        if ($updated === false) {
            return new \WP_Error('spcrc_governance_decision_write_failed', 'Governance decision could not be stored.');
        }
        if ($updated !== 1) {
            $current = $this->get($decisionUuid);
            if (is_array($current) && ($current['status'] ?? '') === 'pending' && strtotime((string) ($current['expires_at'] ?? '') . ' UTC') <= time()) {
                $this->expireOne($decisionUuid, (int) ($current['lock_version'] ?? 0));
                return new \WP_Error('spcrc_governance_expired', 'The governance request expired before the decision was committed.');
            }
            return new \WP_Error('spcrc_governance_concurrent_change', 'Governance decision changed concurrently.');
        }

        $audit = $this->audit?->record('governance_decision_' . $status, (string) ($row['module_key'] ?? 'file-24-security-center'), $status, 'critical', [
            'decision_uuid' => $decisionUuid,
            'decision_type' => $row['decision_type'] ?? '',
            'subject_key' => $row['subject_key'] ?? '',
            'decision_note_hash' => hash('sha256', $note),
            'step_up_reference_hash' => hash('sha256', $stepUpRef),
        ]);
        if (is_wp_error($audit)) {
            // The database decision is retained but a critical system state is emitted;
            // callers must treat it as unusable until reconciliation.
            $this->recordAuditGap($decisionUuid, 'decision_audit_failed');
            do_action('spcrc/governance_audit_gap', $decisionUuid, $audit);
            return new \WP_Error('spcrc_governance_audit_gap', 'Decision was stored but audit evidence failed; reconciliation is required before use.');
        }

        return true;
    }

    /** @return array<string,mixed>|null */
    public function get(string $decisionUuid): ?array
    {
        global $wpdb;
        $decisionUuid = Sanitizer::uuid($decisionUuid);
        if ($decisionUuid === '') {
            return null;
        }
        $row = $wpdb->get_row($wpdb->prepare(
            "SELECT decision_uuid, decision_type, subject_key, module_key, status, requester_user_id, approver_user_id, evidence_ref, rationale_hash, requested_at, expires_at, decided_at, revoked_at, lock_version FROM {$wpdb->prefix}spcrc_governance_decisions WHERE decision_uuid = %s",
            $decisionUuid
        ), ARRAY_A);
        return is_array($row) ? $row : null;
    }

    public function isApprovedFor(string $decisionUuid, string $type, string $subject): bool
    {
        $row = $this->get($decisionUuid);
        if (! is_array($row) || $this->hasAuditGap($decisionUuid)) {
            return false;
        }
        return ($row['status'] ?? '') === 'approved'
            && hash_equals((string) ($row['decision_type'] ?? ''), Sanitizer::key($type, 60))
            && hash_equals((string) ($row['subject_key'] ?? ''), Sanitizer::key($subject, 120))
            && strtotime((string) ($row['expires_at'] ?? '') . ' UTC') > time();
    }

    public function hasAuditGap(string $decisionUuid): bool
    {
        $decisionUuid = Sanitizer::uuid($decisionUuid);
        if ($decisionUuid === '' || isset($this->auditGaps()[$decisionUuid])) {
            return $decisionUuid !== '';
        }

        foreach (AuditGapStore::all('spcrc_governance_batch_audit_gap') as $gap) {
            if (
                Sanitizer::key($gap['entity_type'] ?? '', 80) === 'governance_decision'
                && hash_equals(Sanitizer::text($gap['entity_id'] ?? '', 160), $decisionUuid)
            ) {
                return true;
            }
        }
        return false;
    }

    /** @param array<string,mixed> $context
     *  @return bool|\WP_Error
     */
    public function reconcileAuditGap(string $decisionUuid, array $context): bool|\WP_Error
    {
        if (! current_user_can('spcrc_approve_governance_decision')) {
            return new \WP_Error('spcrc_governance_reconciliation_forbidden', 'You are not allowed to reconcile governance audit evidence.');
        }

        $decisionUuid = Sanitizer::uuid($decisionUuid);
        if ($decisionUuid === '' || ! $this->hasAuditGap($decisionUuid)) {
            return new \WP_Error('spcrc_governance_audit_gap_not_found', 'No governance audit gap exists for this decision.');
        }

        $row = $this->get($decisionUuid);
        if (! is_array($row) || ! in_array((string) ($row['status'] ?? ''), ['approved', 'rejected'], true)) {
            return new \WP_Error('spcrc_governance_reconciliation_state_invalid', 'Only a stored approved or rejected decision may be reconciled.');
        }

        $actor = get_current_user_id();
        if ($actor < 1 || $actor === (int) ($row['requester_user_id'] ?? 0)) {
            return new \WP_Error('spcrc_governance_reconciliation_separation_failed', 'The original requester cannot reconcile the decision audit gap.');
        }

        $stepUpRef = Sanitizer::opaqueReference($context['step_up_reference'] ?? '');
        $stepUpOk = $stepUpRef !== '' && Sanitizer::boolean(apply_filters(
            'spcrc/verify_step_up_assurance',
            false,
            $actor,
            'governance:audit-reconciliation',
            $stepUpRef
        ));
        if (! $stepUpOk) {
            return new \WP_Error('spcrc_governance_step_up_required', 'Fresh File 00 step-up assurance is required.');
        }

        $note = Sanitizer::text($context['note'] ?? '', 500);
        if ($note === '' || Sanitizer::containsSensitiveMaterial($note)) {
            return new \WP_Error('spcrc_governance_note_invalid', 'A bounded, non-sensitive reconciliation note is required.');
        }

        $gapLock = AtomicOptionLock::acquire(self::AUDIT_GAP_LOCK_OPTION, self::AUDIT_GAP_LOCK_TTL);
        if (is_wp_error($gapLock)) {
            return new \WP_Error(
                'spcrc_governance_reconciliation_locked',
                'Governance audit-gap evidence is being changed concurrently. Refresh and try again.'
            );
        }

        try {
            $gaps = $this->auditGaps();
            if (! isset($gaps[$decisionUuid])) {
                return new \WP_Error('spcrc_governance_audit_gap_not_found', 'The governance audit gap changed before reconciliation.');
            }

            $audit = $this->audit?->record(
                'governance_audit_gap_reconciled',
                (string) ($row['module_key'] ?? 'file-24-security-center'),
                'reconciled',
                'critical',
                [
                    'decision_uuid' => $decisionUuid,
                    'decision_type' => $row['decision_type'] ?? '',
                    'subject_key' => $row['subject_key'] ?? '',
                    'stored_status' => $row['status'] ?? '',
                    'reconciliation_note_hash' => hash('sha256', $note),
                    'step_up_reference_hash' => hash('sha256', $stepUpRef),
                ]
            );
            if (is_wp_error($audit)) {
                return new \WP_Error('spcrc_governance_reconciliation_audit_failed', 'The reconciliation audit event could not be stored.');
            }
            if (! AtomicOptionLock::refresh(self::AUDIT_GAP_LOCK_OPTION, $gapLock, self::AUDIT_GAP_LOCK_TTL)) {
                return new \WP_Error('spcrc_governance_reconciliation_lock_lost', 'Governance audit-gap ownership was lost before reconciliation could be committed.');
            }

            unset($gaps[$decisionUuid]);
            if (! $this->persistAuditGaps($gaps)) {
                return new \WP_Error('spcrc_governance_reconciliation_state_failed', 'The audit gap state could not be cleared safely.');
            }

            do_action('spcrc/governance_audit_gap_reconciled', $decisionUuid, $actor);
            return true;
        } finally {
            if (! AtomicOptionLock::release(self::AUDIT_GAP_LOCK_OPTION, $gapLock)) {
                do_action('spcrc/governance_audit_gap_lock_release_failed', $decisionUuid);
            }
        }
    }

    /** @return array<int,array<string,mixed>> */
    public function recent(int $limit = 50): array
    {
        global $wpdb;
        $limit = max(1, min(100, $limit));
        $rows = $wpdb->get_results($wpdb->prepare(
            "SELECT decision_uuid, decision_type, subject_key, module_key, status, requester_user_id, approver_user_id, evidence_ref, requested_at, expires_at, decided_at, lock_version FROM {$wpdb->prefix}spcrc_governance_decisions ORDER BY requested_at DESC LIMIT %d",
            $limit
        ), ARRAY_A);
        return is_array($rows) ? $rows : [];
    }

    public function pendingCount(): int
    {
        global $wpdb;
        return (int) $wpdb->get_var("SELECT COUNT(*) FROM {$wpdb->prefix}spcrc_governance_decisions WHERE status = 'pending' AND expires_at > UTC_TIMESTAMP()");
    }

    public function expirePending(): int
    {
        global $wpdb;
        $updated = $wpdb->query($wpdb->prepare(
            "UPDATE {$wpdb->prefix}spcrc_governance_decisions SET status = 'expired', lock_version = lock_version + 1 WHERE status = 'pending' AND expires_at <= %s",
            current_time('mysql', true)
        ));
        $count = $updated === false ? 0 : (int) $updated;
        if ($count > 0) {
            $audit = $this->audit?->record('governance_decisions_expired', 'file-24-security-center', 'expired', 'informational', ['count' => $count]);
            if (is_wp_error($audit)) {
                AuditGapStore::record('spcrc_governance_batch_audit_gap', 'expired_decision_batch', (string) $count, 'expiry_audit_failed', ['count' => $count]);
            }
        }
        return $count;
    }

    /** @return array<string,array<string,string>> */
    private function auditGaps(): array
    {
        $raw = get_option(self::AUDIT_GAP_OPTION, []);
        if (! is_array($raw)) {
            return [];
        }

        // Backward compatibility with the original single-gap option shape.
        $legacyUuid = Sanitizer::uuid($raw['decision_uuid'] ?? '');
        if ($legacyUuid !== '') {
            return [
                $legacyUuid => [
                    'reason' => Sanitizer::key($raw['reason'] ?? 'legacy_audit_gap', 80),
                    'recorded_at' => Sanitizer::isoTime($raw['recorded_at'] ?? ''),
                ],
            ];
        }

        $gaps = [];
        foreach ($raw as $uuid => $gap) {
            $safeUuid = Sanitizer::uuid($uuid);
            if ($safeUuid === '' || ! is_array($gap)) {
                continue;
            }
            $gaps[$safeUuid] = [
                'reason' => Sanitizer::key($gap['reason'] ?? 'audit_gap', 80),
                'recorded_at' => Sanitizer::isoTime($gap['recorded_at'] ?? ''),
            ];
        }
        return $gaps;
    }

    private function recordAuditGap(string $decisionUuid, string $reason): bool
    {
        $decisionUuid = Sanitizer::uuid($decisionUuid);
        $reason = Sanitizer::key($reason, 80);
        if ($decisionUuid === '' || $reason === '') {
            return false;
        }

        $gapLock = AtomicOptionLock::acquire(self::AUDIT_GAP_LOCK_OPTION, self::AUDIT_GAP_LOCK_TTL);
        if (is_wp_error($gapLock)) {
            return $this->recordFallbackAuditGap($decisionUuid, $reason, 'specific_gap_lock_unavailable');
        }

        try {
            $gaps = $this->auditGaps();
            $gaps[$decisionUuid] = [
                'reason' => $reason,
                'recorded_at' => gmdate('c'),
            ];
            if (! AtomicOptionLock::refresh(self::AUDIT_GAP_LOCK_OPTION, $gapLock, self::AUDIT_GAP_LOCK_TTL)) {
                return $this->recordFallbackAuditGap($decisionUuid, $reason, 'specific_gap_lock_lost');
            }
            if (! $this->persistAuditGaps($gaps)) {
                return $this->recordFallbackAuditGap($decisionUuid, $reason, 'specific_gap_write_failed');
            }
            return true;
        } finally {
            if (! AtomicOptionLock::release(self::AUDIT_GAP_LOCK_OPTION, $gapLock)) {
                do_action('spcrc/governance_audit_gap_lock_release_failed', $decisionUuid);
            }
        }
    }

    private function recordFallbackAuditGap(string $decisionUuid, string $reason, string $failure): bool
    {
        $recorded = AuditGapStore::record(
            'spcrc_governance_batch_audit_gap',
            'governance_decision',
            $decisionUuid,
            $failure,
            ['original_reason' => $reason]
        );
        if (! $recorded) {
            do_action('spcrc/governance_audit_gap_record_failed', $decisionUuid, $reason, $failure);
        }
        return $recorded;
    }

    /** @param array<string,array<string,string>> $gaps */
    private function persistAuditGaps(array $gaps): bool
    {
        if ($gaps === []) {
            delete_option(self::AUDIT_GAP_OPTION);
            return get_option(self::AUDIT_GAP_OPTION, false) === false;
        }

        $updated = update_option(self::AUDIT_GAP_OPTION, $gaps, false);
        return $updated || get_option(self::AUDIT_GAP_OPTION, null) === $gaps;
    }

    private function expireOne(string $decisionUuid, int $lockVersion): void
    {
        global $wpdb;
        $wpdb->update(
            $wpdb->prefix . 'spcrc_governance_decisions',
            ['status' => 'expired', 'lock_version' => $lockVersion + 1],
            ['decision_uuid' => $decisionUuid, 'status' => 'pending', 'lock_version' => $lockVersion],
            ['%s', '%d'],
            ['%s', '%s', '%d']
        );
    }
}
