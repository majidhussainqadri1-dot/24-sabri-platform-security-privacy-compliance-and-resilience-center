<?php

declare(strict_types=1);

namespace Sabri\Platform\Security\Storage;

use Sabri\Platform\Security\Support\Sanitizer;

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

    /** @var array<string,string> */
    private const MANAGED_OPTIONS = [
        'risk' => 'spcrc_risk_audit_gap',
        'risk-reopen' => 'spcrc_risk_reopen_audit_gap',
        'finding' => 'spcrc_finding_audit_gap',
        'finding-reopen' => 'spcrc_finding_reopen_audit_gap',
        'incident' => 'spcrc_incident_audit_gap',
        'control' => 'spcrc_control_audit_gap',
        'governance-batch' => 'spcrc_governance_batch_audit_gap',
        'privacy' => 'spcrc_privacy_audit_gap',
        'privacy-recovery' => 'spcrc_privacy_recovery_audit_gap',
        'retention' => 'spcrc_retention_audit_gap',
        'admin' => 'spcrc_admin_audit_gap',
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
            $gapId = function_exists('wp_generate_uuid4')
                ? wp_generate_uuid4()
                : substr(hash('sha256', $entityType . '|' . $entityId . '|' . $reason . '|' . microtime(true)), 0, 32);
            $safeContext = [];
            foreach ($context as $key => $value) {
                if (count($safeContext) >= 10) {
                    break;
                }
                $safeKey = Sanitizer::key($key, 60);
                if ($safeKey === '' || (! is_scalar($value) && $value !== null)) {
                    continue;
                }
                $safeValue = Sanitizer::text((string) $value, 160);
                if ($safeValue !== '' && ! Sanitizer::containsSensitiveMaterial($safeValue)) {
                    $safeContext[$safeKey] = $safeValue;
                }
            }
            $gaps[$gapId] = [
                'entity_type' => $entityType,
                'entity_id' => Sanitizer::containsSensitiveMaterial($entityId) ? '[REDACTED]' : $entityId,
                'reason' => $reason,
                'recorded_at' => gmdate('c'),
                'context' => $safeContext,
            ];
            if (count($gaps) > self::MAX_GAPS) {
                $gaps = array_slice($gaps, -self::MAX_GAPS, null, true);
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

            do_action('spcrc/audit_gap_reconciled', $option, $gapId, $actor, $evidenceReference);
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
            $safeId = Sanitizer::key($id, 120);
            if ($safeId === '') {
                $safeId = 'gap-' . substr(hash('sha256', (string) $id), 0, 24);
            }
            $gaps[$safeId] = $gap;
        }
        return $gaps;
    }


    /** @return string|\WP_Error */
    private static function acquireLock(): string|\WP_Error
    {
        if (! function_exists('add_option') || ! function_exists('get_option') || ! function_exists('delete_option')) {
            return new \WP_Error('spcrc_audit_gap_lock_storage_unavailable', 'Atomic audit-gap lock storage is unavailable.');
        }

        $token = function_exists('wp_generate_uuid4')
            ? wp_generate_uuid4()
            : hash('sha256', microtime(true) . '|' . mt_rand());
        $lock = ['token' => $token, 'expires_at' => time() + self::LOCK_TTL];
        if (add_option(self::LOCK_OPTION, $lock, '', false)) {
            return $token;
        }

        $existing = get_option(self::LOCK_OPTION, null);
        if (is_array($existing) && (int) ($existing['expires_at'] ?? 0) < time()) {
            delete_option(self::LOCK_OPTION);
            if (add_option(self::LOCK_OPTION, $lock, '', false)) {
                return $token;
            }
        }

        return new \WP_Error('spcrc_audit_gap_lock_contended', 'Another audit-gap mutation is already in progress.');
    }

    private static function releaseLock(string $token): void
    {
        $existing = get_option(self::LOCK_OPTION, null);
        if (is_array($existing) && hash_equals((string) ($existing['token'] ?? ''), $token)) {
            delete_option(self::LOCK_OPTION);
        }
    }

    private static function optionName(string $option): string
    {
        $option = Sanitizer::key($option, 120);
        return preg_match('/^spcrc_[a-z0-9_]+_audit_gap$/', $option) === 1 ? $option : '';
    }
}
