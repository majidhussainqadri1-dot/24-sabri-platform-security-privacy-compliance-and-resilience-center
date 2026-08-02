<?php

declare(strict_types=1);

namespace Sabri\Platform\Security\Storage;

use Sabri\Platform\Security\Support\Sanitizer;

final class AuditLogger
{
    private const ALLOWED_RISK_LEVELS = ['informational', 'low', 'medium', 'high', 'critical'];
    private const MAX_CONTEXT_ITEMS = 50;
    private const MAX_CONTEXT_DEPTH = 5;
    private const MAX_STRING_LENGTH = 500;

    /** @param array<string,mixed> $context
     *  @return string|\WP_Error
     */
    public function record(
        string $eventType,
        string $moduleKey,
        string $result = 'recorded',
        string $riskLevel = 'low',
        array $context = []
    ): string|\WP_Error {
        global $wpdb;

        $eventType = Sanitizer::key($eventType, 120);
        $moduleKey = Sanitizer::key($moduleKey, 120);
        $result = Sanitizer::key($result, 40);
        $riskLevel = in_array($riskLevel, self::ALLOWED_RISK_LEVELS, true) ? $riskLevel : 'low';

        if ($eventType === '' || $moduleKey === '') {
            return new \WP_Error('spcrc_invalid_audit_event', 'Audit event type and module key are required.');
        }

        $eventUuid = wp_generate_uuid4();
        $safeContext = $this->redact($context);
        $json = wp_json_encode($safeContext, JSON_UNESCAPED_SLASHES);
        if (! is_string($json)) {
            $json = '{}';
        }

        $payload = [
            'event_uuid' => $eventUuid,
            'event_type' => $eventType,
            'module_key' => $moduleKey,
            'actor_user_id' => get_current_user_id() ?: null,
            'result' => $result !== '' ? $result : 'recorded',
            'risk_level' => $riskLevel,
            'correlation_id' => $this->correlationId(),
            'context_json' => $json,
            'created_at' => current_time('mysql', true),
        ];

        $inserted = $wpdb->insert(
            $wpdb->prefix . 'spcrc_security_events',
            $payload,
            ['%s', '%s', '%s', '%d', '%s', '%s', '%s', '%s', '%s']
        );

        if ($inserted === false) {
            $error = new \WP_Error('spcrc_audit_write_failed', 'The security event could not be stored.');
            do_action('spcrc/security_event_failed', $error, $payload);
            return $error;
        }

        do_action('spcrc/security_event_recorded', $eventUuid, $eventType, $moduleKey, $riskLevel);
        do_action('spcrc/external_security_event', [
            'event_uuid' => $eventUuid,
            'event_type' => $eventType,
            'module_key' => $moduleKey,
            'actor_user_id' => $payload['actor_user_id'],
            'result' => $payload['result'],
            'risk_level' => $riskLevel,
            'correlation_id' => $payload['correlation_id'],
            'context' => $safeContext,
            'created_at' => $payload['created_at'],
        ]);

        return $eventUuid;
    }

    /** @param array<mixed> $context
     *  @return array<mixed>
     */
    private function redact(array $context, int $depth = 0): array
    {
        if ($depth >= self::MAX_CONTEXT_DEPTH) {
            return ['_truncated' => 'maximum_depth'];
        }

        $blocked = [
            'password', 'passwd', 'passphrase', 'token', 'secret', 'api_key', 'apikey',
            'authorization', 'cookie', 'session', 'nonce', 'otp', 'totp', 'recovery',
            'cvv', 'pan', 'card_number', 'message_body', 'clinical_note', 'private_key',
            'passport', 'national_id', 'identity_document',
        ];

        $safe = [];
        $items = 0;
        foreach ($context as $key => $value) {
            if ($items >= self::MAX_CONTEXT_ITEMS) {
                $safe['_truncated'] = 'maximum_items';
                break;
            }
            ++$items;

            $normalized = strtolower((string) $key);
            foreach ($blocked as $needle) {
                if (str_contains($normalized, $needle)) {
                    $safe[$key] = '[REDACTED]';
                    continue 2;
                }
            }

            if (preg_match('/(^|_)(ip|ip_address|remote_addr)($|_)/', $normalized) === 1) {
                $safe[$key] = $this->pseudonymize((string) $value, 'ip');
                continue;
            }

            if (preg_match('/(^|_)user_agent($|_)/', $normalized) === 1) {
                $safe[$key] = $this->pseudonymize((string) $value, 'ua');
                continue;
            }

            if (is_array($value)) {
                $safe[$key] = $this->redact($value, $depth + 1);
            } elseif (is_string($value)) {
                $safe[$key] = $this->redactString($value);
            } elseif (is_scalar($value) || $value === null) {
                $safe[$key] = $value;
            } else {
                $safe[$key] = '[UNSERIALIZABLE]';
            }
        }

        return $safe;
    }

    private function redactString(string $value): string
    {
        $value = Sanitizer::text($value, self::MAX_STRING_LENGTH);
        if (
            Sanitizer::containsSensitiveMaterial($value)
            || preg_match('/-----BEGIN [A-Z ]*PRIVATE KEY-----/i', $value) === 1
            || preg_match('/\bBearer\s+[A-Za-z0-9._~+\/-]+=*/i', $value) === 1
            || preg_match('/^[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}$/', $value) === 1
        ) {
            return '[REDACTED]';
        }

        return $value;
    }

    private function pseudonymize(string $value, string $purpose): string
    {
        if ($value === '') {
            return '';
        }

        return 'sha256:' . hash_hmac('sha256', $value, wp_salt('auth') . '|' . $purpose);
    }

    private function correlationId(): string
    {
        $incoming = isset($_SERVER['HTTP_X_CORRELATION_ID'])
            ? trim((string) wp_unslash($_SERVER['HTTP_X_CORRELATION_ID']))
            : '';

        if (preg_match('/^[A-Za-z0-9._-]{8,80}$/', $incoming) === 1) {
            return $incoming;
        }

        return wp_generate_uuid4();
    }
}
