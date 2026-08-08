<?php

declare(strict_types=1);

namespace Sabri\Platform\Security\Storage;

use Sabri\Platform\Security\Support\AtomicOptionLock;
use Sabri\Platform\Security\Support\Sanitizer;
use Sabri\Platform\Security\Support\SecureIdentifier;

if (! class_exists(AtomicOptionLock::class, false)) {
    require_once dirname(__DIR__) . '/Support/AtomicOptionLock.php';
}
if (! class_exists(SecureIdentifier::class, false)) {
    require_once dirname(__DIR__) . '/Support/SecureIdentifier.php';
}

/**
 * Bounded operational evidence-gap registry.
 *
 * Audit gaps are not substitutes for canonical audit events. They are a
 * fail-closed release blocker used only when an operation cannot prove that
 * its required audit evidence was durably stored.
 */
final class AuditGapStore
{
    private const MAX_GAPS = 100;
    private const LOCK_OPTION = 'spcrc_audit_gap_store_lock';
    private const LOCK_TTL = 30;
    private const CAPACITY_MARKER_OPTION = 'spcrc_audit_gap_capacity_marker';

    /** @var array<string,string> */
    private const MANAGED_OPTIONS = [
        'risk' => 'spcrc_risk_audit_gap',
        'risk-reopen' => 'spcrc_risk_reopen_audit_gap',
        'finding' => 'spcrc_finding_audit_gap',
        'finding-reopen' => 'spcrc_finding_reopen_audit_gap',
        'incident' => 'spcrc_incident_audit_gap',
        'control' => 'spcrc_control_audit_gap',
        'assurance' => 'spcrc_assurance_audit_gap',
        'governance' => 'spcrc_governance_audit_gap',
        'governance-batch' => 'spcrc_governance_batch_audit_gap',
        'privacy' => 'spcrc_privacy_audit_gap',
        'privacy-recovery' => 'spcrc_privacy_recovery_audit_gap',
        'retention' => 'spcrc_retention_audit_gap',
        'admin' => 'spcrc_admin_audit_gap',
        'security-state' => 'spcrc_security_state_audit_gap',
        'detection' => 'spcrc_detection_audit_gap',
        'remote-evidence' => 'spcrc_remote_evidence_audit_gap',
        'deletion-replay' => 'spcrc_deletion_replay_audit_gap',
    ];

    /** @param array<string,mixed> $context */
    public static function record(
        string $option,
        string $entityType,
        string $entityId,
        string $reason,
        array $context = []
    ): bool {
        $option = self::optionName($option);
        $entityType = Sanitizer::key($entityType, 80);
        $entityId = Sanitizer::text($entityId, 160);
        $reason = Sanitizer::key($reason, 100);
        if ($option === '' || $entityType === '' || $reason === '') {
            return false;
        }

        $lock = self::acquireLock();
        if (is_wp_error($lock)) {
            do_action('spcrc/audit_gap_lock_failed', $option, $entityType, $entityId, $reason, $lock->get_error_code());
            return false;
        }

        try {
            $gaps = self::normalize(get_option($option, []));
            $gapId = SecureIdentifier::uuid4('audit-gap');
            if (is_wp_error($gapId)) {
                do_action('spcrc/audit_gap_identifier_failed', $option, $entityType, $entityId, $reason, $gapId->get_error_code());
                return false;
            }
            $safeContext = self::safeContext($context);
            if (count($gaps) >= self::MAX_GAPS) {
                // Never evict an unresolved evidence gap merely to admit a new
                // one. Keeping the existing bounded set preserves the release
                // blocker; silent eviction could make an unresolved failure
                // disappear without reconciliation.
                self::recordCapacityMarker($option, $entityType, $entityId, $reason, count($gaps));
                do_action('spcrc/audit_gap_capacity_exhausted', $option, $entityType, $entityId, $reason);
                return false;
            }

            $gaps[$gapId] = [
                'entity_type' => $entityType,
                'entity_id' => self::safeEntityId($entityId),
                'reason' => $reason,
                'recorded_at' => gmdate('c'),
                'context' => $safeContext,
            ];

            if (! AtomicOptionLock::refresh(self::LOCK_OPTION, $lock, self::LOCK_TTL)) {
                do_action('spcrc/audit_gap_lock_lost', $option, $entityType, $entityId, $reason);
                return false;
            }

            $updated = update_option($option, $gaps, false);
            $persisted = get_option($option, []);
            $ok = $updated || (is_array($persisted) && $persisted === $gaps);
            if ($ok) {
                do_action('spcrc/audit_gap_recorded', $option, $gapId, $gaps[$gapId]);
            }
            return $ok;
        } finally {
            self::releaseLock($lock);
        }
    }



    /** @return array<string,string> */
    public static function managedOptions(): array
    {
        return self::MANAGED_OPTIONS;
    }

    /** @return array<string,array<string,mixed>> */
    public static function all(string $option): array
    {
        $option = self::optionName($option);
        return $option === '' ? [] : self::normalize(get_option($option, []));
    }

    /** @return bool|\WP_Error */
    public static function reconcile(
        string $option,
        string $gapId,
        string $evidenceReference,
        string $stepUpReference,
        AuditLogger $audit
    ): bool|\WP_Error {
        $option = self::optionName($option);
        $gapId = Sanitizer::key($gapId, 120);
        $evidenceReference = Sanitizer::opaqueReference($evidenceReference);
        $stepUpReference = Sanitizer::opaqueReference($stepUpReference);
        if ($option === '' || ! in_array($option, self::MANAGED_OPTIONS, true) || $gapId === '') {
            return new \WP_Error('spcrc_audit_gap_invalid', 'Audit-gap category or identifier is invalid.');
        }
        if (! function_exists('current_user_can') || ! current_user_can('spcrc_manage_security_settings')) {
            return new \WP_Error('spcrc_audit_gap_forbidden', 'You are not allowed to reconcile audit gaps.');
        }
        if ($evidenceReference === '') {
            return new \WP_Error('spcrc_audit_gap_evidence_required', 'An opaque private reconciliation evidence reference is required.');
        }
        $actor = function_exists('get_current_user_id') ? get_current_user_id() : 0;
        $stepUpOk = $actor > 0 && $stepUpReference !== '' && Sanitizer::boolean(apply_filters(
            'spcrc/verify_step_up_assurance',
            false,
            $actor,
            'audit-gap-reconciliation',
            $stepUpReference
        ));
        if (! $stepUpOk) {
            return new \WP_Error('spcrc_audit_gap_step_up_required', 'Fresh File 00 step-up assurance is required.');
        }

        $lock = self::acquireLock();
        if (is_wp_error($lock)) {
            return new \WP_Error('spcrc_audit_gap_lock_unavailable', 'Audit-gap evidence is being changed by another request. Refresh and try again.');
        }

        try {
            $gaps = self::normalize(get_option($option, []));
            if (! isset($gaps[$gapId])) {
                return new \WP_Error('spcrc_audit_gap_not_found', 'The audit gap could not be found.');
            }
            $authorizationAudit = $audit->record(
                'audit_gap_reconciliation_authorized',
                'file-24-security-center',
                'authorized',
                'critical',
                [
                    'gap_option' => $option,
                    'gap_id' => $gapId,
                    'evidence_ref' => $evidenceReference,
                    'step_up_reference_hash' => hash('sha256', $stepUpReference),
                ]
            );
            if (is_wp_error($authorizationAudit)) {
                return new \WP_Error('spcrc_audit_gap_reconciliation_audit_failed', 'Reconciliation was not applied because authorization evidence could not be audited.');
            }
            if (! AtomicOptionLock::refresh(self::LOCK_OPTION, $lock, self::LOCK_TTL)) {
                return new \WP_Error('spcrc_audit_gap_lock_lost', 'Audit-gap ownership was lost before reconciliation could be committed.');
            }

            $originalGaps = $gaps;
            $resolvedGap = $gaps[$gapId];
            unset($gaps[$gapId]);
            if ($gaps === []) {
                delete_option($option);
                $persisted = get_option($option, false) === false;
            } else {
                $updated = update_option($option, $gaps, false);
                $persisted = $updated || get_option($option, null) === $gaps;
            }
            if (! $persisted) {
                return new \WP_Error('spcrc_audit_gap_reconciliation_write_failed', 'The reconciled audit gap could not be removed.');
            }

            $completionAudit = $audit->record(
                'audit_gap_reconciled',
                'file-24-security-center',
                'reconciled',
                'critical',
                [
                    'gap_option' => $option,
                    'gap_id' => $gapId,
                    'entity_type' => (string) ($resolvedGap['entity_type'] ?? ''),
                    'evidence_ref' => $evidenceReference,
                    'authorization_audit_uuid' => $authorizationAudit,
                ]
            );
            if (is_wp_error($completionAudit)) {
                $restored = update_option($option, $originalGaps, false)
                    || get_option($option, null) === $originalGaps;
                if (! $restored) {
                    do_action('spcrc/audit_gap_reconciliation_rollback_failed', $option, $gapId, $completionAudit);
                    return new \WP_Error('spcrc_audit_gap_reconciliation_rollback_failed', 'Reconciliation completion could not be audited and the original audit gap could not be restored.');
                }
                return new \WP_Error('spcrc_audit_gap_completion_audit_failed', 'Reconciliation was rolled back because completion evidence could not be audited.');
            }

            do_action('spcrc/audit_gap_reconciled', $option, $gapId, $actor, $evidenceReference, $completionAudit);
            return true;
        } finally {
            self::releaseLock($lock);
        }
    }

    public static function count(string $option): int
    {
        $option = self::optionName($option);
        return $option === '' ? 0 : count(self::normalize(get_option($option, [])));
    }

    /** @return array<string,array<string,mixed>> */
    private static function normalize(mixed $raw): array
    {
        if (! is_array($raw) || $raw === []) {
            return [];
        }

        $nested = true;
        foreach ($raw as $value) {
            if (! is_array($value)) {
                $nested = false;
                break;
            }
        }
        if (! $nested) {
            return [
                'legacy-' . substr(hash('sha256', wp_json_encode($raw) ?: serialize($raw)), 0, 24) => [
                    'entity_type' => 'legacy',
                    'entity_id' => '',
                    'reason' => 'legacy_audit_gap',
                    'recorded_at' => Sanitizer::isoTime($raw['recorded_at'] ?? ''),
                    'context' => [],
                ],
            ];
        }

        $gaps = [];
        foreach ($raw as $id => $gap) {
            if (! is_array($gap)) {
                continue;
            }
            $safeId = Sanitizer::uuid($id);
            if ($safeId === '') {
                $safeId = Sanitizer::key($id, 120);
            }
            if ($safeId === '') {
                $safeId = 'gap-' . substr(hash('sha256', (string) $id), 0, 24);
            }
            $entityType = Sanitizer::key($gap['entity_type'] ?? '', 80);
            $entityId = Sanitizer::text($gap['entity_id'] ?? '', 160);
            $reason = Sanitizer::key($gap['reason'] ?? '', 100);
            if ($entityType === '' || $reason === '') {
                continue;
            }
            if (Sanitizer::containsSensitiveMaterial($entityId)) {
                $entityId = '[REDACTED]';
            }
            $context = [];
            if (is_array($gap['context'] ?? null)) {
                foreach (array_slice($gap['context'], 0, 10, true) as $key => $value) {
                    $key = Sanitizer::key($key, 60);
                    if ($key === '' || (! is_scalar($value) && $value !== null)) {
                        continue;
                    }
                    if (preg_match('/(^|_)(password|token|secret|authorization|cookie|session|nonce|otp|email|phone|mobile|address|identity|passport|national_id)($|_)/', $key) === 1) {
                        $context[$key] = '[REDACTED]';
                        continue;
                    }
                    $value = Sanitizer::text((string) $value, 160);
                    $context[$key] = $value !== '' && ! Sanitizer::containsSensitiveMaterial($value) ? $value : '[REDACTED]';
                }
            }
            $gaps[$safeId] = [
                'entity_type' => $entityType,
                'entity_id' => $entityId,
                'reason' => $reason,
                'recorded_at' => Sanitizer::isoTime($gap['recorded_at'] ?? ''),
                'context' => $context,
            ];
        }
        return $gaps;
    }



    /** @param array<string,mixed> $context @return array<string,string> */
    private static function safeContext(array $context): array
    {
        $safe = [];
        foreach (array_slice($context, 0, 10, true) as $key => $value) {
            $safeKey = Sanitizer::key($key, 60);
            if ($safeKey === '' || (! is_scalar($value) && $value !== null)) {
                continue;
            }
            if (preg_match('/(^|_)(password|token|secret|authorization|cookie|session|nonce|otp|email|phone|mobile|address|identity|passport|national_id|guardian)($|_)/', $safeKey) === 1) {
                $safe[$safeKey] = '[REDACTED]';
                continue;
            }
            $safeValue = Sanitizer::text((string) $value, 160);
            $safe[$safeKey] = $safeValue !== '' && ! Sanitizer::containsSensitiveMaterial($safeValue)
                ? $safeValue
                : '[REDACTED]';
        }
        return $safe;
    }

    private static function safeEntityId(string $entityId): string
    {
        if ($entityId === '') {
            return '';
        }
        if (Sanitizer::containsSensitiveMaterial($entityId)) {
            return '[REDACTED]';
        }
        $uuid = Sanitizer::uuid($entityId);
        if ($uuid !== '') {
            return $uuid;
        }
        if (preg_match('/^[a-z0-9][a-z0-9._:-]{0,159}$/i', $entityId) === 1 && ! Sanitizer::containsSensitiveMaterial($entityId)) {
            return $entityId;
        }
        $salt = function_exists('wp_salt') ? wp_salt('auth') : hash('sha256', __FILE__);
        return 'sha256:' . hash_hmac('sha256', $entityId, $salt . '|audit-gap-entity');
    }

    private static function recordCapacityMarker(string $option, string $entityType, string $entityId, string $reason, int $count): void
    {
        $marker = [
            'option' => $option,
            'entity_type' => $entityType,
            'entity_id' => self::safeEntityId($entityId),
            'reason' => $reason,
            'unresolved_count' => max(0, $count),
            'recorded_at' => gmdate('c'),
        ];
        $updated = update_option(self::CAPACITY_MARKER_OPTION, $marker, false);
        if (! $updated && get_option(self::CAPACITY_MARKER_OPTION, null) !== $marker) {
            do_action('spcrc/audit_gap_capacity_marker_failed', $marker);
        }
    }

    /** @return string|\WP_Error */
    private static function acquireLock(): string|\WP_Error
    {
        $lock = AtomicOptionLock::acquire(self::LOCK_OPTION, self::LOCK_TTL);
        if (! is_wp_error($lock)) {
            return $lock;
        }

        return new \WP_Error(
            $lock->get_error_code() === 'spcrc_atomic_lock_contended'
                ? 'spcrc_audit_gap_lock_contended'
                : 'spcrc_audit_gap_lock_storage_unavailable',
            $lock->get_error_message()
        );
    }

    private static function releaseLock(string $token): void
    {
        if (! AtomicOptionLock::release(self::LOCK_OPTION, $token)) {
            do_action('spcrc/audit_gap_lock_release_failed', $token);
        }
    }


    private static function managedOption(string $option): bool
    {
        return in_array($option, self::MANAGED_OPTIONS, true);
    }

    private static function optionName(string $option): string
    {
        $option = Sanitizer::key($option, 120);
        return preg_match('/^spcrc_[a-z0-9_]+_audit_gap$/', $option) === 1 ? $option : '';
    }
}
