<?php

declare(strict_types=1);

namespace Sabri\Platform\Security\Registry;

final class SecurityStateRegistry
{
    /** @var array<string,array<string,mixed>> */
    private array $requests = [];

    public function registerHooks(): void
    {
        add_action('spcrc/request_security_state', [$this, 'request'], 10, 3);
        add_filter('spcrc/security_state_requests', [$this, 'all']);
    }

    /** @param array<string,mixed> $context */
    public function request(string $moduleKey, string $state, array $context = []): bool
    {
        $moduleKey = sanitize_key($moduleKey);
        $state = sanitize_key($state);
        $allowed = [
            'normal',
            'elevated-monitoring',
            'restricted-writes',
            'upload-lockdown',
            'messaging-lockdown',
            'identity-lockdown',
            'publishing-read-only',
            'platform-read-only',
            'incident-containment',
        ];

        if ($moduleKey === '' || ! in_array($state, $allowed, true)) {
            return false;
        }

        $requestId = wp_generate_uuid4();
        $record = [
            'request_id' => $requestId,
            'module_key' => $moduleKey,
            'state' => $state,
            'reason' => sanitize_text_field((string) ($context['reason'] ?? '')),
            'requested_by' => get_current_user_id(),
            'requested_at' => gmdate('c'),
            'expires_at' => sanitize_text_field((string) ($context['expires_at'] ?? '')),
        ];

        $this->requests[$requestId] = $record;
        do_action('spcrc/security_state_requested', $record);

        return true;
    }

    /**
     * @param mixed $current
     * @return array<string,array<string,mixed>>
     */
    public function all($current = null): array
    {
        return $this->requests;
    }
}
