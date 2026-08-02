<?php

declare(strict_types=1);

namespace Sabri\Platform\Security\Storage;

use Sabri\Platform\Security\Support\Sanitizer;

if (! class_exists(AuditGapStore::class, false)) {
    require_once __DIR__ . '/AuditGapStore.php';
}

final class RiskRepository
{
    public function __construct(
        private ?AuditLogger $audit = null,
        private ?GovernanceRepository $governance = null
    ) {
    }

    public function registerHooks(): void
    {
        add_action('spcrc_daily_retention', [$this, 'reopenExpiredAcceptances'], 30);
    }

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
        if (! in_array($treatment, ['avoid', 'mitigate', 'transfer'], true)) {
            if ($treatment === 'accept') {
                return new \WP_Error('spcrc_risk_acceptance_decision_required', 'Risk acceptance requires a separate approved governance decision after the risk is recorded.');
            }
            $treatment = 'mitigate';
        }
        if ($title === '' || $moduleKey === '' || Sanitizer::containsSensitiveMaterial($title)) {
            return new \WP_Error('spcrc_risk_invalid', 'A bounded, non-sensitive risk title and module are required.');
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
                'governance_decision_uuid' => null,
                'accepted_by_user_id' => null,
                'accepted_at' => null,
                'acceptance_expires_at' => null,
                'created_at' => $now,
                'updated_at' => $now,
            ],
            ['%s', '%s', '%s', '%d', '%d', '%d', '%s', '%s', '%d', '%s', '%s', '%d', '%s', '%s', '%s', '%s']
        );
        if ($inserted === false) {
            return new \WP_Error('spcrc_risk_write_failed', 'Risk could not be stored.');
        }
        $audit = $this->audit?->record('security_risk_created', $moduleKey, 'open', $impact >= 4 ? 'high' : 'medium', [
            'risk_uuid' => $uuid,
            'score' => $likelihood * $impact,
        ]);
        if (is_wp_error($audit)) {
            $deleted = $wpdb->delete($wpdb->prefix . 'spcrc_risks', ['risk_uuid' => $uuid], ['%s']);
            if ($deleted !== 1) {
                AuditGapStore::record('spcrc_risk_audit_gap', 'risk_uuid', $uuid, 'create_rollback_failed');
            }
            return new \WP_Error('spcrc_risk_audit_failed', 'Risk creation was rolled back because audit evidence could not be stored.');
        }
        return $uuid;
    }

    /** @return bool|\WP_Error */
    public function acceptRisk(string $riskUuid, string $decisionUuid, string $expectedStatus = 'open'): bool|\WP_Error
    {
        global $wpdb;
        $riskUuid = Sanitizer::uuid($riskUuid);
        $decisionUuid = Sanitizer::uuid($decisionUuid);
        $expectedStatus = Sanitizer::key($expectedStatus, 40);
        if ($riskUuid === '' || $decisionUuid === '') {
            return new \WP_Error('spcrc_risk_acceptance_invalid', 'Risk and governance decision UUIDs are required.');
        }
        if (! current_user_can('spcrc_accept_critical_risk')) {
            return new \WP_Error('spcrc_risk_acceptance_forbidden', 'You are not allowed to accept security risk.');
        }
        if ($this->governance === null || ! $this->governance->isApprovedFor($decisionUuid, 'critical-risk-acceptance', $riskUuid)) {
            return new \WP_Error('spcrc_risk_acceptance_governance_missing', 'A current approved governance decision bound to this risk is required.');
        }

        $decision = $this->governance->get($decisionUuid);
        $acceptanceExpiresAt = is_array($decision) ? (string) ($decision['expires_at'] ?? '') : '';
        if ($acceptanceExpiresAt === '' || strtotime($acceptanceExpiresAt . ' UTC') <= time()) {
            return new \WP_Error('spcrc_risk_acceptance_expiry_invalid', 'Risk acceptance decision has no usable future expiry.');
        }

        $row = $wpdb->get_row($wpdb->prepare(
            "SELECT module_key, status, treatment, governance_decision_uuid, accepted_by_user_id, accepted_at, acceptance_expires_at, updated_at FROM {$wpdb->prefix}spcrc_risks WHERE risk_uuid = %s",
            $riskUuid
        ), ARRAY_A);
        if (! is_array($row)) {
            return new \WP_Error('spcrc_risk_not_found', 'Risk could not be found.');
        }
        if (($row['status'] ?? '') !== $expectedStatus || ! in_array($expectedStatus, ['open', 'treating'], true)) {
            return new \WP_Error('spcrc_risk_stale_status', 'Risk status changed or is not eligible for acceptance.');
        }

        $now = current_time('mysql', true);
        $updated = $wpdb->update(
            $wpdb->prefix . 'spcrc_risks',
            [
                'status' => 'accepted',
                'treatment' => 'accept',
                'governance_decision_uuid' => $decisionUuid,
                'accepted_by_user_id' => get_current_user_id(),
                'accepted_at' => $now,
                'acceptance_expires_at' => $acceptanceExpiresAt,
                'updated_at' => $now,
            ],
            ['risk_uuid' => $riskUuid, 'status' => $expectedStatus],
            ['%s', '%s', '%s', '%d', '%s', '%s', '%s'],
            ['%s', '%s']
        );
        if ($updated === false) {
            return new \WP_Error('spcrc_risk_acceptance_write_failed', 'Risk acceptance could not be stored.');
        }
        if ($updated !== 1) {
            return new \WP_Error('spcrc_risk_concurrent_change', 'Risk changed concurrently.');
        }
        $audit = $this->audit?->record('security_risk_accepted', (string) ($row['module_key'] ?? 'file-24-security-center'), 'accepted', 'critical', [
            'risk_uuid' => $riskUuid,
            'governance_decision_uuid' => $decisionUuid,
        ]);
        if (is_wp_error($audit)) {
            $rolledBack = $wpdb->update(
                $wpdb->prefix . 'spcrc_risks',
                [
                    'status' => $row['status'] ?? 'open',
                    'treatment' => $row['treatment'] ?? 'mitigate',
                    'governance_decision_uuid' => $row['governance_decision_uuid'] ?? null,
                    'accepted_by_user_id' => $row['accepted_by_user_id'] ?? null,
                    'accepted_at' => $row['accepted_at'] ?? null,
                    'acceptance_expires_at' => $row['acceptance_expires_at'] ?? null,
                    'updated_at' => $row['updated_at'] ?? $now,
                ],
                ['risk_uuid' => $riskUuid, 'status' => 'accepted']
            );
            if ($rolledBack !== 1) {
                AuditGapStore::record('spcrc_risk_audit_gap', 'risk_uuid', $riskUuid, 'acceptance_rollback_failed');
            }
            return new \WP_Error('spcrc_risk_acceptance_audit_failed', 'Risk acceptance was rolled back because audit evidence could not be stored.');
        }
        return true;
    }

    public function reopenExpiredAcceptances(): int
    {
        global $wpdb;
        $now = current_time('mysql', true);
        $updated = $wpdb->query($wpdb->prepare(
            "UPDATE {$wpdb->prefix}spcrc_risks SET status = 'open', treatment = 'mitigate', governance_decision_uuid = NULL, accepted_by_user_id = NULL, accepted_at = NULL, acceptance_expires_at = NULL, updated_at = %s WHERE status = 'accepted' AND acceptance_expires_at IS NOT NULL AND acceptance_expires_at <= %s",
            $now,
            $now
        ));
        $count = $updated === false ? 0 : (int) $updated;
        if ($count > 0) {
            $audit = $this->audit?->record('expired_risk_acceptances_reopened', 'file-24-security-center', 'reopened', 'high', ['count' => $count]);
            if (is_wp_error($audit)) {
                AuditGapStore::record('spcrc_risk_reopen_audit_gap', 'expired_acceptance_batch', (string) $count, 'reopen_audit_failed', ['count' => $count]);
            }
        }
        return $count;
    }

    public function openCount(): int
    {
        global $wpdb;
        return (int) $wpdb->get_var("SELECT COUNT(*) FROM {$wpdb->prefix}spcrc_risks WHERE status IN ('open','treating')");
    }

    /** @return array<int,array<string,mixed>> */
    public function recent(int $limit = 10): array
    {
        global $wpdb;
        $limit = max(1, min(50, $limit));
        $rows = $wpdb->get_results(
            $wpdb->prepare("SELECT risk_uuid, module_key, title, likelihood, impact, inherent_score, status, treatment, due_at, governance_decision_uuid, accepted_at, acceptance_expires_at, created_at FROM {$wpdb->prefix}spcrc_risks ORDER BY updated_at DESC LIMIT %d", $limit),
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
