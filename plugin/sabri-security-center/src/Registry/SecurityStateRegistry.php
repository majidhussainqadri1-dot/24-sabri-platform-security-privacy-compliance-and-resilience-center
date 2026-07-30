<?php

declare(strict_types=1);

namespace Sabri\Platform\Security\Registry;

use Sabri\Platform\Security\Storage\AuditLogger;
use Sabri\Platform\Security\Support\Sanitizer;

final class SecurityStateRegistry
{
    private const OPTION = 'spcrc_security_state_requests';
    private const MAX_REQUESTS = 100;
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

    /** @var array<string,array<string,mixed>> */
    private array $requests = [];

    public function __construct(private ModuleRegistry $modules, private AuditLogger $audit)
    {
        $stored = get_option(self::OPTION, []);
        $this->requests = is_array($stored) ? $stored : [];
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

        if (! (bool) apply_filters('spcrc/allow_security_state_request', true, $moduleKey, $state, $context)) {
            return false;
        }

        $expiresAt = Sanitizer::isoTime($context['expires_at'] ?? '');
        if ($expiresAt === '') {
            $ttl = (int) apply_filters('spcrc/security_state_default_ttl', HOUR_IN_SECONDS, $moduleKey, $state);
            $expiresAt = gmdate('c', time() + max(300, min($ttl, DAY_IN_SECONDS)));
        }

        $expiresTimestamp = strtotime($expiresAt);
        if ($expiresTimestamp === false || $expiresTimestamp <= time()) {
            return false;
        }

        $requestId = wp_generate_uuid4();
        $record = [
            'request_id' => $requestId,
            'module_key' => $moduleKey,
            'state' => $state,
            'reason' => Sanitizer::text($context['reason'] ?? '', 500),
            'requested_by' => get_current_user_id(),
            'requested_at' => gmdate('c'),
            'expires_at' => $expiresAt,
            'status' => 'open',
        ];

        $this->requests[$requestId] = $record;
        if (! $this->boundAndPersist()) {
            unset($this->requests[$requestId]);
            do_action('spcrc/security_state_persist_failed', $record);
            return false;
        }

        $this->audit->record(
            'security_state_requested',
            $moduleKey,
            'requested',
            in_array($state, ['platform-read-only', 'incident-containment'], true) ? 'high' : 'medium',
            ['request_id' => $requestId, 'state' => $state, 'expires_at' => $expiresAt]
        );
        do_action('spcrc/security_state_requested', $record);

        return true;
    }

    public function resolve(string $requestId, string $resolution = 'resolved'): bool
    {
        $requestId = Sanitizer::uuid($requestId);
        $resolution = Sanitizer::key($resolution, 40);
        if ($requestId === '' || ! isset($this->requests[$requestId])) {
            return false;
        }

        $record = $this->requests[$requestId];
        unset($this->requests[$requestId]);
        if (! $this->persist()) {
            $this->requests[$requestId] = $record;
            do_action('spcrc/security_state_persist_failed', $record);
            return false;
        }

        $this->audit->record(
            'security_state_resolved',
            (string) $record['module_key'],
            $resolution !== '' ? $resolution : 'resolved',
            'informational',
            ['request_id' => $requestId, 'state' => $record['state']]
        );
        do_action('spcrc/security_state_resolved', $record, $resolution);

        return true;
    }

    /** @return array<string,array<string,mixed>> */
    public function all(): array
    {
        $this->prune();
        return $this->requests;
    }

    /** @param mixed $current
     *  @return array<string,array<string,mixed>>
     */
    public function merge(mixed $current): array
    {
        $current = is_array($current) ? $current : [];
        return array_replace($current, $this->all());
    }

    private function prune(): void
    {
        $changed = false;
        foreach ($this->requests as $id => $request) {
            $expires = strtotime((string) ($request['expires_at'] ?? ''));
            if (! is_array($request) || $expires === false || $expires <= time()) {
                unset($this->requests[$id]);
                $changed = true;
            }
        }

        if ($changed) {
            $this->persist();
        }
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
}
