<?php

declare(strict_types=1);

namespace Sabri\Platform\Security\Storage;

final class AuditLogger
{
    private const ALLOWED_RISK_LEVELS = ['informational', 'low', 'medium', 'high', 'critical'];

    /** @param array<string,mixed> $context */
    public function record(
        string $eventType,
        string $moduleKey,
        string $result = 'recorded',
        string $riskLevel = 'low',
        array $context = []
    ): string {
        global $wpdb;

        $eventUuid = wp_generate_uuid4();
        $riskLevel = in_array($riskLevel, self::ALLOWED_RISK_LEVELS, true) ? $riskLevel : 'low';
        $context = $this->redact($context);
        $json = wp_json_encode($context, JSON_UNESCAPED_SLASHES);

        $wpdb->insert(
            $wpdb->prefix . 'spcrc_security_events',
            [
                'event_uuid' => $eventUuid,
                'event_type' => sanitize_key($eventType),
                'module_key' => sanitize_key($moduleKey),
                'actor_user_id' => get_current_user_id() ?: null,
                'result' => sanitize_key($result),
                'risk_level' => $riskLevel,
                'correlation_id' => $this->correlationId(),
                'context_json' => is_string($json) ? $json : '{}',
                'created_at' => current_time('mysql', true),
            ],
            ['%s', '%s', '%s', '%d', '%s', '%s', '%s', '%s', '%s']
        );

        do_action('spcrc/security_event_recorded', $eventUuid, $eventType, $moduleKey, $riskLevel);
        return $eventUuid;
    }

    /**
     * @param array<string,mixed> $context
     * @return array<string,mixed>
     */
    private function redact(array $context): array
    {
        $blocked = ['password', 'pass', 'token', 'secret', 'otp', 'totp', 'recovery_code', 'cvv', 'pan', 'message_body', 'clinical_note'];

        foreach ($context as $key => $value) {
            $normalized = strtolower((string) $key);
            foreach ($blocked as $needle) {
                if (str_contains($normalized, $needle)) {
                    $context[$key] = '[REDACTED]';
                    continue 2;
                }
            }

            if (is_array($value)) {
                $context[$key] = $this->redact($value);
            } elseif (is_scalar($value) || $value === null) {
                $context[$key] = is_string($value) ? mb_substr($value, 0, 500) : $value;
            } else {
                $context[$key] = '[UNSERIALIZABLE]';
            }
        }

        return $context;
    }

    private function correlationId(): string
    {
        $incoming = isset($_SERVER['HTTP_X_CORRELATION_ID']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_X_CORRELATION_ID'])) : '';
        return $incoming !== '' ? mb_substr($incoming, 0, 80) : wp_generate_uuid4();
    }
}
