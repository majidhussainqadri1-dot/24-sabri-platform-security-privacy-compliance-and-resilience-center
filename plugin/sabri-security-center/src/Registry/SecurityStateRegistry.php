<?php

declare(strict_types=1);

namespace Sabri\Platform\Security\Registry;

use Sabri\Platform\Security\Storage\AuditGapStore;
use Sabri\Platform\Security\Storage\AuditLogger;
use Sabri\Platform\Security\Support\AtomicOptionLock;
use Sabri\Platform\Security\Support\Sanitizer;

if (! class_exists(AuditGapStore::class, false)) {
    require_once dirname(__DIR__) . '/Storage/AuditGapStore.php';
}
if (! class_exists(AtomicOptionLock::class, false)) {
    require_once dirname(__DIR__) . '/Support/AtomicOptionLock.php';
}

final class SecurityStateRegistry
{
    private const OPTION = 'spcrc_security_state_requests';
    private const LOCK_OPTION = 'spcrc_security_state_lock';
    private const AUDIT_GAP_OPTION = 'spcrc_security_state_audit_gap';
    private const MAX_REQUESTS = 100;
    private const MAX_TTL = 86400;
    private const LOCK_TTL = 30;
    private const ALLOWED_STATES = [
        'elevated-monitoring',
        'restricted-writes',
        'upload-lockdown',
        'messaging-lockdown',
        'identity-lockdown',
        'publishing-read-only',
        'platform-read-only',
        'incident-containment',
    ];
    private const ALLOWED_RESOLUTIONS = ['resolved', 'withdrawn', 'superseded', 'rejected'];

    /** @var array<string,array<string,mixed>> */
    private array $requests = [];

    public function __construct(private ModuleRegistry $modules, private AuditLogger $audit)
    {
        $this->reload();
        $this->prune();
    }

    public function registerHooks(): void
    {
        add_action('spcrc/request_security_state', [$this, 'request'], 10, 3);
        add_action('spcrc/resolve_security_state_request', [$this, 'resolve'], 10, 2);
        add_filter('spcrc/security_state_requests', [$this, 'merge'], 10, 1);
    }

    /** @param array<string,mixed> $context */
    public function request(string $moduleKey, string $state, array $context = []): bool
    {
        $moduleKey = Sanitizer::key($moduleKey, 120);
        $state = Sanitizer::key($state, 40);
        if ($moduleKey === '' || ! $this->modules->has($moduleKey) || ! in_array($state, self::ALLOWED_STATES, true)) {
            return false;
        }

        $authorized = current_user_can('spcrc_manage_security_settings') || Sanitizer::boolean(apply_filters(
            'spcrc/authorize_security_state_request',
            false,
            $moduleKey,
            $state,
            $context
        ));
        if (! $authorized || ! Sanitizer::boolean(apply_filters('spcrc/allow_security_state_request', true, $moduleKey, $state, $context))) {
            return false;
        }

        $reason = Sanitizer::text($context['reason'] ?? '', 500);
        if ($reason === '' || Sanitizer::containsSensitiveMaterial($reason)) {
            return false;
        }

        $now = time();
        $expiresAt = Sanitizer::isoTime($context['expires_at'] ?? '');
        if ($expiresAt === '') {
            $ttl = (int) apply_filters('spcrc/security_state_default_ttl', HOUR_IN_SECONDS, $moduleKey, $state);
            $expiresAt = gmdate('c', $now + max(300, min($ttl, self::MAX_TTL)));
        }

        $expiresTimestamp = strtotime($expiresAt);
        if ($expiresTimestamp === false || $expiresTimestamp <= $now || $expiresTimestamp > $now + self::MAX_TTL) {
            return false;
        }

        $lockToken = $this->acquireLock();
        if ($lockToken === '') {
            do_action('spcrc/security_state_lock_failed', $moduleKey, $state);
            return false;
        }

        try {
            $this->reload();
            $this->prune(false);
            foreach ($this->requests as $existing) {
                if (
                    ($existing['status'] ?? '') === 'open'
                    && hash_equals((string) ($existing['module_key'] ?? ''), $moduleKey)
                    && hash_equals((string) ($existing['state'] ?? ''), $state)
                ) {
                    return false;
                }
            }

            $requestId = wp_generate_uuid4();
            $record = [
                'request_id' => $requestId,
                'module_key' => $moduleKey,
                'state' => $state,
                'reason' => $reason,
                'requested_by' => get_current_user_id(),
                'requested_at' => gmdate('c'),
                'expires_at' => gmdate('c', $expiresTimestamp),
                'status' => 'open',
            ];

            $this->requests[$requestId] = $record;
            if (! $this->refreshLock($lockToken) || ! $this->boundAndPersist()) {
                unset($this->requests[$requestId]);
                do_action('spcrc/security_state_persist_failed', $record);
                return false;
            }

            $audit = $this->audit->record(
                'security_state_requested',
                $moduleKey,
                'requested',
                in_array($state, ['platform-read-only', 'incident-containment'], true) ? 'high' : 'medium',
                ['request_id' => $requestId, 'state' => $state, 'expires_at' => $record['expires_at']]
            );
            if (is_wp_error($audit)) {
                if (! $this->refreshLock($lockToken)) {
                    $this->recordAuditGap($requestId, 'request_audit_failed_lock_lost');
                    do_action('spcrc/security_state_audit_failed', $record, $audit);
                    return false;
                }
                unset($this->requests[$requestId]);
                if (! $this->persist()) {
                    $this->recordAuditGap($requestId, 'request_rollback_failed');
                }
                do_action('spcrc/security_state_audit_failed', $record, $audit);
                return false;
            }

            do_action('spcrc/security_state_requested', $record);
            return true;
        } finally {
            $this->releaseLock($lockToken);
        }
    }

    public function resolve(string $requestId, string $resolution = 'resolved'): bool
    {
        $requestId = Sanitizer::uuid($requestId);
        $resolution = Sanitizer::key($resolution, 40);
        if ($requestId === '' || ! in_array($resolution, self::ALLOWED_RESOLUTIONS, true)) {
            return false;
        }

        $authorized = current_user_can('spcrc_manage_security_settings') || Sanitizer::boolean(apply_filters(
            'spcrc/authorize_security_state_resolution',
            false,
            $requestId,
            $resolution
        ));
        if (! $authorized) {
            return false;
        }

        $lockToken = $this->acquireLock();
        if ($lockToken === '') {
            do_action('spcrc/security_state_lock_failed', $requestId, $resolution);
            return false;
        }

        try {
            $this->reload();
            if (! isset($this->requests[$requestId]) || $this->hasAuditGap($requestId)) {
                return false;
            }

            $record = $this->requests[$requestId];
            unset($this->requests[$requestId]);
            if (! $this->refreshLock($lockToken) || ! $this->persist()) {
                $this->requests[$requestId] = $record;
                do_action('spcrc/security_state_persist_failed', $record);
                return false;
            }

            $audit = $this->audit->record(
                'security_state_resolved',
                (string) $record['module_key'],
                $resolution,
                'informational',
                ['request_id' => $requestId, 'state' => $record['state']]
            );
            if (is_wp_error($audit)) {
                if (! $this->refreshLock($lockToken)) {
                    $this->recordAuditGap($requestId, 'resolution_audit_failed_lock_lost');
                    do_action('spcrc/security_state_audit_failed', $record, $audit);
                    return false;
                }
                $this->requests[$requestId] = $record;
                if (! $this->persist()) {
                    $this->recordAuditGap($requestId, 'resolution_rollback_failed');
                }
                do_action('spcrc/security_state_audit_failed', $record, $audit);
                return false;
            }

            do_action('spcrc/security_state_resolved', $record, $resolution);
            return true;
        } finally {
            $this->releaseLock($lockToken);
        }
    }

    /** @return array<string,array<string,mixed>> */
    public function all(): array
    {
        $this->reload();
        $this->prune();
        return array_filter(
            $this->requests,
            fn (array $request, string $requestId): bool => ! $this->hasAuditGap($requestId),
            ARRAY_FILTER_USE_BOTH
        );
    }

    /** @param mixed $current
     *  @return array<string,array<string,mixed>>
     */
    public function merge(mixed $current): array
    {
        $current = is_array($current) ? $current : [];
        return array_replace($current, $this->all());
    }

    private function reload(): void
    {
        $stored = get_option(self::OPTION, []);
        $this->requests = is_array($stored) ? $stored : [];
    }

    private function prune(bool $persist = true): void
    {
        if (! $persist) {
            $this->pruneInMemory();
            return;
        }

        $lockToken = $this->acquireLock();
        if ($lockToken === '') {
            // Reads still exclude expired/invalid records, but no unlocked durable
            // write is attempted while another mutation owns the option.
            $this->pruneInMemory();
            return;
        }

        try {
            $this->reload();
            $expiredIds = $this->pruneInMemory();
            if ($expiredIds === []) {
                return;
            }
            if (! $this->refreshLock($lockToken) || ! $this->persist()) {
                $this->recordAuditGap('', 'expiry_persist_failed');
                return;
            }

            $audit = $this->audit->record(
                'security_state_requests_expired',
                'file-24-security-center',
                'expired',
                'informational',
                ['count' => count($expiredIds)]
            );
            if (is_wp_error($audit)) {
                $this->recordAuditGap('', 'expiry_audit_failed');
            }
        } finally {
            $this->releaseLock($lockToken);
        }
    }

    /** @return string[] */
    private function pruneInMemory(): array
    {
        $expiredIds = [];
        foreach ($this->requests as $id => $request) {
            $expires = is_array($request) ? strtotime((string) ($request['expires_at'] ?? '')) : false;
            if (! is_array($request) || $expires === false || $expires <= time()) {
                unset($this->requests[$id]);
                $expiredIds[] = (string) $id;
            }
        }
        return $expiredIds;
    }

    private function boundAndPersist(): bool
    {
        if (count($this->requests) > self::MAX_REQUESTS) {
            uasort($this->requests, static fn (array $a, array $b): int => strcmp((string) $a['requested_at'], (string) $b['requested_at']));
            $this->requests = array_slice($this->requests, -self::MAX_REQUESTS, null, true);
        }
        return $this->persist();
    }

    private function persist(): bool
    {
        $updated = update_option(self::OPTION, $this->requests, false);
        if ($updated) {
            return true;
        }

        return get_option(self::OPTION, null) === $this->requests;
    }

    private function acquireLock(): string
    {
        $lock = AtomicOptionLock::acquire(self::LOCK_OPTION, self::LOCK_TTL);
        return is_wp_error($lock) ? '' : $lock;
    }

    private function refreshLock(string $token): bool
    {
        return AtomicOptionLock::refresh(self::LOCK_OPTION, $token, self::LOCK_TTL);
    }

    private function releaseLock(string $token): void
    {
        if (! AtomicOptionLock::release(self::LOCK_OPTION, $token)) {
            do_action('spcrc/security_state_lock_release_failed', $token);
        }
    }

    private function hasAuditGap(string $requestId): bool
    {
        $requestId = Sanitizer::uuid($requestId);
        if ($requestId === '') {
            return false;
        }
        foreach (AuditGapStore::all(self::AUDIT_GAP_OPTION) as $gap) {
            if (
                Sanitizer::key($gap['entity_type'] ?? '', 80) === 'security_state_request'
                && hash_equals(Sanitizer::text($gap['entity_id'] ?? '', 160), $requestId)
            ) {
                return true;
            }
        }
        return false;
    }

    private function recordAuditGap(string $requestId, string $reason): void
    {
        $safeRequestId = Sanitizer::uuid($requestId);
        $recorded = AuditGapStore::record(
            self::AUDIT_GAP_OPTION,
            'security_state_request',
            $safeRequestId !== '' ? $safeRequestId : 'batch-' . gmdate('YmdHis'),
            $reason
        );
        if (! $recorded) {
            do_action('spcrc/security_state_audit_gap_record_failed', $safeRequestId, $reason);
        }
        do_action('spcrc/security_state_audit_gap', $safeRequestId, $reason);
    }
}
